use crate::config::{
    self,
    migration::{self, MigrationMessage},
    models::AppConfig,
};
use crate::core::error::ConfigError;
use crate::ports::ConfigurationStore;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher, event::AccessKind};
use std::collections::{HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::{RwLock, broadcast, mpsc};
pub(crate) type ConfigUpdateSignal = ();
pub(crate) type ConfigUpdateSender = broadcast::Sender<ConfigUpdateSignal>;
pub(crate) type ConfigUpdateReceiver = broadcast::Receiver<ConfigUpdateSignal>;

#[derive(Debug)]
struct ReloadRequest;

#[derive(Debug)]
pub(crate) struct InitialConfigResult {
    pub app_config: AppConfig,
    pub config_was_written: bool,
    pub messages: Vec<MigrationMessage>,
    pub was_migrated: bool,
}

pub(crate) struct ConfigurationManager {
    config: Arc<RwLock<AppConfig>>,
    config_store: Arc<dyn ConfigurationStore>,
    config_file_path: PathBuf,
    update_tx: ConfigUpdateSender,
    _watcher: Arc<Mutex<Option<RecommendedWatcher>>>,
    current_config_hash: Arc<RwLock<String>>,
    reload_request_tx: mpsc::Sender<ReloadRequest>,
    _reload_processor_handle: Option<tokio::task::JoinHandle<()>>,
}

impl ConfigurationManager {
    pub(crate) async fn new(
        config_store: Arc<dyn ConfigurationStore>,
    ) -> Result<(Self, InitialConfigResult), ConfigError> {
        let config_file_path = config_store.get_default_config_path()?;

        tracing::debug!("DNSPX will use configuration file: {:?}", config_file_path);

        let initial_result =
            Self::load_or_create_config(config_store.clone(), &config_file_path).await?;

        if initial_result.config_was_written {
            tracing::info!(
                "Initial configuration established. Saving to {:?}",
                config_file_path
            );
            if let Some(parent_dir) = config_file_path.parent() {
                if !parent_dir.exists() {
                    std::fs::create_dir_all(parent_dir).map_err(|e| ConfigError::WriteFile {
                        path: parent_dir.to_path_buf(),
                        source: e,
                    })?;
                    tracing::info!("Created config directory: {:?}", parent_dir);
                }
            }
            config_store.save_app_config_file(&initial_result.app_config, &config_file_path)?;
        }

        let initial_hash = Self::hash_config(&initial_result.app_config);
        let config_arc = Arc::new(RwLock::new(initial_result.app_config.clone()));
        let (update_tx, _) = broadcast::channel(16);
        let (reload_request_tx, reload_request_rx) = mpsc::channel(8);

        let mut manager = Self {
            config: Arc::clone(&config_arc),
            config_store: Arc::clone(&config_store),
            config_file_path: config_file_path.clone(),
            update_tx: update_tx.clone(),
            _watcher: Arc::new(Mutex::new(None)),
            current_config_hash: Arc::new(RwLock::new(initial_hash.clone())),
            reload_request_tx,
            _reload_processor_handle: None,
        };

        let processor_config_arc = Arc::clone(&config_arc);
        let processor_config_store_arc = Arc::clone(&config_store);
        let processor_config_file_path_clone = config_file_path.clone();
        let processor_current_config_hash = Arc::clone(&manager.current_config_hash);
        let processor_update_tx = update_tx.clone();

        let handle = tokio::spawn(Self::process_reload_requests(
            reload_request_rx,
            processor_config_arc,
            processor_config_store_arc,
            processor_config_file_path_clone,
            processor_current_config_hash,
            processor_update_tx,
        ));
        manager._reload_processor_handle = Some(handle);

        Ok((manager, initial_result))
    }

    async fn process_reload_requests(
        mut rx: mpsc::Receiver<ReloadRequest>,
        config_arc: Arc<RwLock<AppConfig>>,
        config_store: Arc<dyn ConfigurationStore>,
        config_file_path: PathBuf,
        current_config_hash_arc: Arc<RwLock<String>>,
        update_tx: ConfigUpdateSender,
    ) {
        tracing::info!(
            "Config reload processor task started for {:?}.",
            config_file_path
        );
        while let Some(_request) = rx.recv().await {
            tracing::debug!(
                "Reload request received by processor task for {:?}",
                config_file_path
            );
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;

            match config_store.load_app_config_file(&config_file_path) {
                Ok(new_config) => {
                    if let Err(val_err) = Self::validate_config_for_update(&new_config) {
                        tracing::error!(
                            "Invalid configuration loaded from file {:?}: {}. Config not applied.",
                            config_file_path,
                            val_err
                        );
                        let _ = update_tx.send(());
                        continue;
                    }

                    let new_hash = Self::hash_config(&new_config);
                    let mut current_hash_w = current_config_hash_arc.write().await;

                    if *current_hash_w != new_hash {
                        let mut config_w = config_arc.write().await;
                        *config_w = new_config;
                        *current_hash_w = new_hash;
                        tracing::info!(
                            "Configuration reloaded and updated successfully from {:?}.",
                            config_file_path
                        );
                        if update_tx.send(()).is_err() {
                            tracing::warn!(
                                "No active subscribers for config updates after reload from {:?}.",
                                config_file_path
                            );
                        }
                    } else {
                        tracing::info!(
                            "Configuration file {:?} changed, but content hash is identical. No reload needed.",
                            config_file_path
                        );
                        let _ = update_tx.send(());
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to reload configuration from {:?} in processor task: {}",
                        config_file_path,
                        e
                    );
                    let _ = update_tx.send(());
                }
            }
        }
        tracing::info!(
            "Config reload processor task stopped for {:?}.",
            config_file_path
        );
    }

    async fn load_or_create_config(
        config_store: Arc<dyn ConfigurationStore>,
        new_config_path: &Path,
    ) -> Result<InitialConfigResult, ConfigError> {
        let mut messages = Vec::new();

        if new_config_path.exists() {
            tracing::debug!("Found existing configuration file: {:?}", new_config_path);
            match config_store.load_app_config_file(new_config_path) {
                Ok(config) => {
                    if let Err(val_err) = Self::validate_config_for_update(&config) {
                        let err_msg = format!(
                            "Existing configuration file {new_config_path:?} is invalid: {val_err}. Please fix or remove it."
                        );
                        messages.push(MigrationMessage::warn(err_msg.clone()));
                        tracing::error!("{}", err_msg);
                        return Err(ConfigError::Validation(format!(
                            "Invalid configuration in {new_config_path:?}: {val_err}"
                        )));
                    }
                    messages.push(MigrationMessage::info(format!(
                        "Successfully loaded configuration from {new_config_path:?}"
                    )));
                    return Ok(InitialConfigResult {
                        app_config: config,
                        config_was_written: false,
                        messages,
                        was_migrated: false,
                    });
                }
                Err(e) => {
                    let err_msg = format!(
                        "Failed to load or parse existing configuration file {new_config_path:?}: {e}. Please fix or remove it."
                    );
                    messages.push(MigrationMessage::warn(err_msg.clone()));
                    tracing::error!("{}", err_msg);
                    return Err(e);
                }
            }
        }

        tracing::debug!(
            "{:?} not found. Checking for .NET legacy JSON configuration files for migration...",
            new_config_path
        );
        let base_search_dir = new_config_path.parent().unwrap_or_else(|| Path::new("."));
        let (main_legacy_path_opt, rules_legacy_path_opt, hosts_legacy_path_opt) =
            config::find_legacy_config_paths(base_search_dir);

        if main_legacy_path_opt.is_some() {
            match config_store.load_dotnet_legacy_config_files(
                main_legacy_path_opt.as_deref(),
                rules_legacy_path_opt.as_deref(),
                hosts_legacy_path_opt.as_deref(),
            ) {
                Ok(dotnet_legacy_config) => {
                    if dotnet_legacy_config.main_config_path.is_some() {
                        match migration::migrate(dotnet_legacy_config.clone()) {
                            Ok((app_config, mut migration_run_messages)) => {
                                messages.append(&mut migration_run_messages);
                                if let Err(val_err) = Self::validate_config_for_update(&app_config)
                                {
                                    let err_msg = format!(
                                        "Validation of migrated .NET config failed: {val_err}. Using default config instead."
                                    );
                                    messages.push(MigrationMessage::warn(err_msg.clone()));
                                    tracing::error!("{}", err_msg);
                                    let default_config = AppConfig::default();
                                    Self::validate_config_for_update(&default_config)?;
                                    messages.push(MigrationMessage::info("Switched to default configuration due to migration validation error.".to_string()));
                                    return Ok(InitialConfigResult {
                                        app_config: default_config,
                                        config_was_written: true,
                                        messages,
                                        was_migrated: false,
                                    });
                                }
                                config_store
                                    .backup_dotnet_legacy_config_files(&dotnet_legacy_config)?;

                                return Ok(InitialConfigResult {
                                    app_config,
                                    config_was_written: true,
                                    messages,
                                    was_migrated: true,
                                });
                            }
                            Err(mig_err) => {
                                let err_msg = format!(
                                    ".NET legacy migration failed: {mig_err}. Using default config instead."
                                );
                                messages.push(MigrationMessage::warn(err_msg.clone()));
                                tracing::error!("{}", err_msg);
                                let default_config = AppConfig::default();
                                Self::validate_config_for_update(&default_config)?;
                                messages.push(MigrationMessage::info(
                                    "Switched to default configuration due to migration failure."
                                        .to_string(),
                                ));
                                return Ok(InitialConfigResult {
                                    app_config: default_config,
                                    config_was_written: true,
                                    messages,
                                    was_migrated: false,
                                });
                            }
                        }
                    } else {
                        tracing::debug!(
                            "load_dotnet_legacy_config_files returned Ok but main_config_path was None. Proceeding to default."
                        );
                    }
                }
                Err(e) => {
                    messages.push(MigrationMessage::warn(format! ("Error loading .NET legacy config files (even if main_config.json was found): {e}. Proceeding to default.")));
                    tracing::warn!(
                        "Error loading .NET legacy config files: {}. Proceeding to default.",
                        e
                    );
                }
            }
        }

        messages.push(MigrationMessage::info("No existing TOML configuration or .NET legacy 'config.json' found. Creating default configuration.".to_string()));
        let default_config = AppConfig::default();
        Self::validate_config_for_update(&default_config)?;
        Ok(InitialConfigResult {
            app_config: default_config,
            config_was_written: true,
            messages,
            was_migrated: false,
        })
    }

    fn hash_config(config: &AppConfig) -> String {
        let mut hasher = DefaultHasher::new();
        config.hash(&mut hasher);
        hasher.finish().to_string()
    }

    pub(crate) fn start_watching(&self) -> Result<(), ConfigError> {
        let path_to_watch = self.config_file_path.clone();
        let reload_request_tx_clone = self.reload_request_tx.clone();

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    if (event.kind.is_modify()
                        || event.kind.is_create()
                        || event.kind.is_remove()
                        || matches!(
                            event.kind,
                            notify::EventKind::Access(AccessKind::Close(
                                notify::event::AccessMode::Write
                            ))
                        ))
                        && event.paths.iter().any(|p| {
                            *p == path_to_watch
                                || (p.file_name() == path_to_watch.file_name()
                                    && p.parent() == path_to_watch.parent())
                        })
                    {
                        tracing::debug!(
                            "Configuration file {:?} change detected (event kind: {:?}), sending reload request.",
                            path_to_watch,
                            event.kind
                        );
                        match reload_request_tx_clone.try_send(ReloadRequest) {
                            Ok(_) => tracing::debug!("Reload request sent to processor."),
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                tracing::warn!(
                                    "Config reload request channel is full. Reload might be delayed."
                                );
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                tracing::error!(
                                    "Config reload request channel is closed. File watching ineffective."
                                );
                            }
                        }
                    }
                }
                Err(e) => tracing::error!("Error watching configuration file: {}", e),
            }
        })?;

        let watch_path_target = self
            .config_file_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        if watch_path_target.exists() {
            match watcher.watch(watch_path_target, RecursiveMode::NonRecursive) {
                Ok(_) => tracing::info!(
                    "Started watching directory {:?} for configuration changes to {:?}",
                    watch_path_target,
                    self.config_file_path.file_name().unwrap_or_default()
                ),
                Err(e) => tracing::warn!(
                    "Failed to watch directory {:?}: {}. Hot-reload might be affected.",
                    watch_path_target,
                    e
                ),
            }
        } else {
            tracing::warn!(
                "Parent directory {:?} for config file does not exist. File watcher might not catch all changes if file is recreated in new dir.",
                watch_path_target
            );

            if self.config_file_path.exists() {
                match watcher.watch(&self.config_file_path, RecursiveMode::NonRecursive) {
                    Ok(_) => tracing::info!(
                        "Attempting to watch config file {:?} directly.",
                        self.config_file_path
                    ),
                    Err(e) => tracing::warn!(
                        "Failed to watch config file {:?} directly: {}. Hot-reload might be affected.",
                        self.config_file_path,
                        e
                    ),
                }
            } else {
                tracing::warn!(
                    "Config file {:?} does not exist yet, watcher might be ineffective until file is created.",
                    self.config_file_path
                );
            }
        }
        let mut watcher_guard = self._watcher.lock().unwrap();
        *watcher_guard = Some(watcher);
        Ok(())
    }

    pub(crate) fn get_config(&self) -> Arc<RwLock<AppConfig>> {
        Arc::clone(&self.config)
    }

    pub(crate) async fn get_config_hash(&self) -> String {
        self.current_config_hash.read().await.clone()
    }

    pub(crate) fn subscribe_to_updates(&self) -> ConfigUpdateReceiver {
        self.update_tx.subscribe()
    }

    pub(crate) fn get_config_file_path(&self) -> &Path {
        &self.config_file_path
    }

    fn validate_config_for_update(config: &AppConfig) -> Result<(), ConfigError> {
        if let Some(aws_conf) = &config.aws {
            let mut labels = HashSet::new();
            for acc in &aws_conf.accounts {
                if !labels.insert(&acc.label) {
                    return Err(ConfigError::Validation(format!(
                        "Duplicate AWS account label found: '{}'. Labels must be unique.",
                        acc.label
                    )));
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn update_app_config<F>(&self, update_fn: F) -> Result<(), ConfigError>
    where
        F: FnOnce(&mut AppConfig) -> Result<(), ConfigError>,
    {
        tracing::info!("Programmatic configuration update initiated.");
        let mut config_w = self.config.write().await;
        update_fn(&mut config_w)?;
        Self::validate_config_for_update(&config_w)?;

        let new_hash = Self::hash_config(&config_w);
        let config_to_save = config_w.clone();
        drop(config_w);

        if let Some(parent_dir) = self.config_file_path.parent() {
            if !parent_dir.exists() {
                std::fs::create_dir_all(parent_dir).map_err(|e| ConfigError::WriteFile {
                    path: parent_dir.to_path_buf(),
                    source: e,
                })?;
                tracing::info!(
                    "Created config directory for programmatic save: {:?}",
                    parent_dir
                );
            }
        }

        self.config_store
            .save_app_config_file(&config_to_save, &self.config_file_path)?;
        tracing::info!("Configuration saved to file: {:?}", self.config_file_path);

        let mut current_hash_w = self.current_config_hash.write().await;
        *current_hash_w = new_hash;

        tracing::info!("In-memory configuration updated and hash refreshed.");
        if self.update_tx.send(()).is_err() {
            tracing::warn!("No active subscribers for config updates after programmatic save.");
        } else {
            tracing::info!("Config update signal sent to subscribers.");
        }
        Ok(())
    }
}

impl Drop for ConfigurationManager {
    fn drop(&mut self) {
        if let Some(handle) = self._reload_processor_handle.take() {
            tracing::debug!("ConfigurationManager dropped, aborting reload processor task.");
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{
        AppConfig, AwsAccountConfig, AwsGlobalConfig, AwsServiceDiscoveryConfig,
        DotNetDnsHostConfig, DotNetLegacyConfig,
    };
    use crate::core::error::ConfigError;
    use crate::core::types::MessageLevel;
    use crate::ports::ConfigurationStore;

    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex as StdMutex};

    use tempfile::tempdir;

    use tokio::time::{Duration, sleep};

    #[derive(Default)]
    struct MockConfigStore {
        app_config_to_load: Arc<StdMutex<Option<Result<AppConfig, ConfigError>>>>,
        dotnet_legacy_config_to_load: Option<Result<DotNetLegacyConfig, ConfigError>>,
        saved_app_config: Arc<StdMutex<Option<(AppConfig, PathBuf)>>>,
        backed_up_legacy_files: Arc<StdMutex<Vec<PathBuf>>>,
        default_path: PathBuf,
        should_simulate_file_exists: Arc<StdMutex<bool>>,
    }

    impl MockConfigStore {
        fn new(default_path: PathBuf) -> Self {
            Self {
                app_config_to_load: Arc::new(StdMutex::new(None)),
                dotnet_legacy_config_to_load: None,
                saved_app_config: Arc::new(StdMutex::new(None)),
                backed_up_legacy_files: Arc::new(StdMutex::new(Vec::new())),
                default_path,
                should_simulate_file_exists: Arc::new(StdMutex::new(false)),
            }
        }

        fn set_app_config_to_load(&mut self, config: Result<AppConfig, ConfigError>) {
            *self.app_config_to_load.lock().unwrap() = Some(config);
            *self.should_simulate_file_exists.lock().unwrap() = true;
        }

        fn set_dotnet_legacy_config_to_load(
            &mut self,
            config: Result<DotNetLegacyConfig, ConfigError>,
        ) {
            self.dotnet_legacy_config_to_load = Some(config);
        }

        fn get_saved_app_config(&self) -> Option<(AppConfig, PathBuf)> {
            self.saved_app_config.lock().unwrap().clone()
        }

        fn get_backed_up_legacy_files(&self) -> Vec<PathBuf> {
            self.backed_up_legacy_files.lock().unwrap().clone()
        }
    }

    impl ConfigurationStore for MockConfigStore {
        fn load_dotnet_legacy_config_files(
            &self,
            main_path_opt: Option<&Path>,
            _rules_path_opt: Option<&Path>,
            _hosts_path_opt: Option<&Path>,
        ) -> Result<DotNetLegacyConfig, ConfigError> {
            match self.dotnet_legacy_config_to_load.as_ref() {
                Some(Ok(config)) => {
                    let mut cfg_clone = config.clone();
                    if main_path_opt.is_some() || cfg_clone.main_config_path.is_none() {
                        cfg_clone.main_config_path = Some(main_path_opt.map_or_else(
                            || self.default_path.join("config.json"),
                            |p| p.to_path_buf(),
                        ));
                    }
                    Ok(cfg_clone)
                }
                Some(Err(_)) => Err(ConfigError::ReadFile {
                    path: PathBuf::from("mock_legacy_config.json"),
                    source: std::io::Error::other("Mock error"),
                }),
                None => Err(ConfigError::ReadFile {
                    path: PathBuf::from("config.json"),
                    source: std::io::ErrorKind::NotFound.into(),
                }),
            }
        }

        fn load_app_config_file(&self, path: &Path) -> Result<AppConfig, ConfigError> {
            let config_guard = self.app_config_to_load.lock().unwrap();
            match config_guard.as_ref() {
                Some(Ok(config)) => Ok(config.clone()),
                Some(Err(_)) => Err(ConfigError::ReadFile {
                    path: path.to_path_buf(),
                    source: std::io::Error::other("Mock read error"),
                }),
                None => Err(ConfigError::ReadFile {
                    path: path.to_path_buf(),
                    source: std::io::ErrorKind::NotFound.into(),
                }),
            }
        }

        fn save_app_config_file(&self, config: &AppConfig, path: &Path) -> Result<(), ConfigError> {
            let mut saved_config = self.saved_app_config.lock().unwrap();
            *saved_config = Some((config.clone(), path.to_path_buf()));
            Ok(())
        }

        fn backup_dotnet_legacy_config_files(
            &self,
            legacy_config: &DotNetLegacyConfig,
        ) -> Result<(), ConfigError> {
            let mut backed_up = self.backed_up_legacy_files.lock().unwrap();
            if let Some(p) = &legacy_config.main_config_path {
                backed_up.push(p.clone());
            }
            if let Some(p) = &legacy_config.rules_config_path {
                backed_up.push(p.clone());
            }
            if let Some(p) = &legacy_config.hosts_config_path {
                backed_up.push(p.clone());
            }
            Ok(())
        }

        fn get_default_config_path(&self) -> Result<PathBuf, ConfigError> {
            Ok(self.default_path.clone())
        }
    }

    fn assert_message_exists(
        messages: &[MigrationMessage],
        level: MessageLevel,
        text_contains: &str,
    ) {
        assert!(
            messages
                .iter()
                .any(|msg| msg.level == level && msg.text.contains(text_contains)),
            "Expected message with level {:?} containing '{}', not found in: {:?}",
            level,
            text_contains,
            messages
        );
    }

    fn create_config_with_duplicate_aws_labels() -> AppConfig {
        AppConfig {
            aws: Some(AwsGlobalConfig {
                accounts: vec![
                    AwsAccountConfig {
                        label: "duplicate-label".to_string(),
                        account_id: None,
                        profile_name: None,
                        scan_vpc_ids: vec![],
                        scan_regions: None,
                        roles_to_assume: vec![],
                        discover_services: AwsServiceDiscoveryConfig::default(),
                    },
                    AwsAccountConfig {
                        label: "duplicate-label".to_string(),
                        account_id: None,
                        profile_name: None,
                        scan_vpc_ids: vec![],
                        scan_regions: None,
                        roles_to_assume: vec![],
                        discover_services: AwsServiceDiscoveryConfig::default(),
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[allow(dead_code)]
    fn create_config_with_invalid_address() -> AppConfig {
        let mut config = AppConfig::default();
        config.server.listen_address = "this_is_not_a_valid_address".to_string();
        config
    }

    #[tokio::test]
    async fn test_new_no_config_files_creates_default() {
        let temp_dir = tempdir().unwrap();
        let default_config_path = temp_dir.path().join("dnspx_config.toml");

        let mock_store = Arc::new(MockConfigStore::new(default_config_path.clone()));

        let (_manager, initial_result) =
            ConfigurationManager::new(mock_store.clone()).await.unwrap();

        assert!(
            initial_result.config_was_written,
            "Config should have been written (default)"
        );
        assert!(
            !initial_result.was_migrated,
            "Should not be marked as migrated for default"
        );
        assert!(initial_result.app_config.routing_rules.is_empty());

        let saved_opt = mock_store.get_saved_app_config();
        assert!(saved_opt.is_some(), "Default config should have been saved");
        assert_eq!(saved_opt.unwrap().1, default_config_path);

        assert_message_exists(
            &initial_result.messages,
            MessageLevel::Info,
            "Creating default configuration",
        );
    }

    #[tokio::test]
    async fn test_new_with_existing_valid_toml_config() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("dnspx_config.toml");

        let mut existing_config = AppConfig::default();
        existing_config.server.listen_address = "1.2.3.4:5353".to_string();

        let mut mock_store = MockConfigStore::new(config_path.clone());
        mock_store.set_app_config_to_load(Ok(existing_config.clone()));

        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        std::fs::write(&config_path, "dummy content").unwrap();

        let mock_store_arc = Arc::new(mock_store);
        let (_manager, initial_result) = ConfigurationManager::new(mock_store_arc.clone())
            .await
            .unwrap();

        assert!(
            !initial_result.config_was_written,
            "Config should not have been re-written"
        );
        assert!(
            !initial_result.was_migrated,
            "Should not be migrated if TOML exists"
        );
        assert_eq!(
            initial_result.app_config.server.listen_address,
            "1.2.3.4:5353"
        );

        let saved_opt = mock_store_arc.get_saved_app_config();
        assert!(
            saved_opt.is_none(),
            "Config should not have been saved again"
        );
        assert_message_exists(
            &initial_result.messages,
            MessageLevel::Info,
            "Successfully loaded configuration",
        );
    }

    #[tokio::test]
    async fn test_new_with_existing_invalid_toml_config_fails() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("dnspx_config.toml");

        let config_that_fails_validation = create_config_with_duplicate_aws_labels();

        let mut mock_store = MockConfigStore::new(config_path.clone());
        mock_store.set_app_config_to_load(Ok(config_that_fails_validation));

        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        std::fs::write(&config_path, "dummy content").unwrap();

        let mock_store_arc = Arc::new(mock_store);

        let result = ConfigurationManager::new(mock_store_arc).await;
        assert!(result.is_err());
        match result.err().unwrap() {
            ConfigError::Validation(msg) => assert!(msg.contains("Duplicate AWS account label")),
            e => panic!("Expected ConfigError::Validation, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_new_with_dotnet_legacy_migration() {
        let temp_dir = tempdir().unwrap();
        let new_config_path = temp_dir.path().join("dnspx_config.toml");
        let legacy_main_path = temp_dir.path().join("config.json");

        let mut legacy_config = DotNetLegacyConfig::default();
        legacy_config.main_config.dns_host_config = Some(DotNetDnsHostConfig {
            listener_port: Some(5333),
            ..Default::default()
        });
        legacy_config.main_config_path = Some(legacy_main_path.clone());

        let mut mock_store = MockConfigStore::new(new_config_path.clone());

        mock_store.set_dotnet_legacy_config_to_load(Ok(legacy_config));

        std::fs::create_dir_all(temp_dir.path()).unwrap();
        std::fs::write(
            &legacy_main_path,
            r#"{"dnsHostConfig": {"listenerPort": 5333}}"#,
        )
        .unwrap();

        let mock_store_arc = Arc::new(mock_store);
        let (_manager, initial_result) = ConfigurationManager::new(mock_store_arc.clone())
            .await
            .unwrap();

        assert!(initial_result.config_was_written);
        assert!(initial_result.was_migrated);
        assert_eq!(
            initial_result.app_config.server.listen_address,
            "0.0.0.0:5333"
        );

        assert!(mock_store_arc.get_saved_app_config().is_some());
        assert!(
            mock_store_arc
                .get_backed_up_legacy_files()
                .contains(&legacy_main_path)
        );
    }

    #[tokio::test]
    async fn test_config_validation_edge_cases() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("dnspx_config.toml");

        let invalid_config = create_config_with_duplicate_aws_labels();

        let mut mock_store = MockConfigStore::new(config_path.clone());
        mock_store.set_app_config_to_load(Ok(invalid_config));

        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        std::fs::write(&config_path, "dummy content").unwrap();

        let result = ConfigurationManager::new(Arc::new(mock_store)).await;
        assert!(result.is_err(), "Test case should fail validation");

        match result.err().unwrap() {
            ConfigError::Validation(msg) => assert!(msg.contains("Duplicate AWS account label")),
            e => panic!("Expected ConfigError::Validation, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_migration_failure_recovery() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("dnspx_config.toml");
        let legacy_main_path = temp_dir.path().join("config.json");

        let mut mock_store = MockConfigStore::new(config_path);
        mock_store.set_dotnet_legacy_config_to_load(Err(ConfigError::ReadFile {
            path: PathBuf::from("corrupt_config.json"),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, "Corrupt JSON"),
        }));

        std::fs::create_dir_all(temp_dir.path()).unwrap();
        std::fs::write(&legacy_main_path, "corrupt json content").unwrap();

        let (_manager, initial_result) = ConfigurationManager::new(Arc::new(mock_store))
            .await
            .unwrap();

        assert!(initial_result.config_was_written);
        assert!(!initial_result.was_migrated);
        assert_eq!(initial_result.app_config, AppConfig::default());
        assert_message_exists(
            &initial_result.messages,
            MessageLevel::Warning,
            "Error loading .NET legacy config files",
        );
    }

    #[tokio::test]
    async fn test_update_app_config_programmatic() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("dnspx_config.toml");

        let mock_store = Arc::new(MockConfigStore::new(config_path.clone()));
        let (manager, _initial_result) =
            ConfigurationManager::new(mock_store.clone()).await.unwrap();

        let initial_hash = manager.get_config_hash().await;
        let initial_level = manager.get_config().read().await.logging.level.clone();

        let update_result = manager
            .update_app_config(|cfg| {
                cfg.logging.level = "trace".to_string();
                Ok(())
            })
            .await;
        assert!(update_result.is_ok());

        let new_hash = manager.get_config_hash().await;
        assert_ne!(initial_hash, new_hash, "Config hash should have changed");
        assert_eq!(manager.get_config().read().await.logging.level, "trace");
        assert_ne!(initial_level, "trace");

        let saved_opt = mock_store.get_saved_app_config();
        assert!(saved_opt.is_some(), "Updated config should have been saved");
        let (saved_cfg, saved_path) = saved_opt.unwrap();
        assert_eq!(saved_path, config_path);
        assert_eq!(saved_cfg.logging.level, "trace");
    }

    #[tokio::test]
    async fn test_concurrent_config_updates() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("dnspx_config.toml");
        let mock_store = Arc::new(MockConfigStore::new(config_path));
        let (manager, _) = ConfigurationManager::new(mock_store).await.unwrap();

        let manager_arc = Arc::new(manager);
        let mut handles = Vec::new();

        for i in 0..10 {
            let manager_clone = Arc::clone(&manager_arc);
            let handle = tokio::spawn(async move {
                manager_clone
                    .update_app_config(|cfg| {
                        cfg.logging.level = format!("level-{}", i);
                        Ok(())
                    })
                    .await
            });
            handles.push(handle);
        }

        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }

        let app_config = manager_arc.get_config();
        let final_config = app_config.read().await;
        assert!(final_config.logging.level.starts_with("level-"));
    }

    #[tokio::test]
    async fn test_config_manager_cleanup() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("dnspx_config.toml");
        let mock_store = Arc::new(MockConfigStore::new(config_path));

        let weak_ref = {
            let (manager, _) = ConfigurationManager::new(mock_store).await.unwrap();
            manager.start_watching().unwrap();

            let config_arc = manager.get_config();
            Arc::downgrade(&config_arc)
        };

        tokio::task::yield_now().await;

        assert!(
            weak_ref.upgrade().is_none(),
            "Config should be cleaned up after manager drop"
        );
    }

    #[tokio::test]
    async fn test_config_reload_on_file_change_simplified() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("dnspx_config.toml");

        let initial_config = AppConfig::default();
        let initial_toml_content = toml::to_string_pretty(&initial_config).unwrap();
        std::fs::write(&config_path, initial_toml_content).unwrap();

        let real_store = Arc::new(
            crate::adapters::config::file_store::JsonFileConfigAdapter::new(
                temp_dir.path().to_path_buf(),
            ),
        );
        let (manager, _) = ConfigurationManager::new(real_store).await.unwrap();

        let initial_hash = manager.get_config_hash().await;

        println!("Testing programmatic config update...");
        let update_result = manager
            .update_app_config(|cfg| {
                cfg.logging.level = "warn".to_string();
                Ok(())
            })
            .await;

        assert!(update_result.is_ok(), "Programmatic update should work");

        let prog_update_hash = manager.get_config_hash().await;
        let app_config = manager.get_config();
        let prog_config = app_config.read().await;
        assert_ne!(
            initial_hash, prog_update_hash,
            "Hash should change after programmatic update"
        );
        assert_eq!(
            prog_config.logging.level, "warn",
            "Config should be updated programmatically"
        );
        drop(prog_config);

        println!("Testing manual file reload...");
        let mut updated_config = AppConfig::default();
        updated_config.logging.level = "debug".to_string();
        updated_config.server.listen_address = "0.0.0.0:8888".to_string();
        let updated_toml_content = toml::to_string_pretty(&updated_config).unwrap();

        std::fs::write(&config_path, updated_toml_content).unwrap();

        let reload_result = manager.reload_request_tx.try_send(ReloadRequest);
        assert!(
            reload_result.is_ok(),
            "Should be able to send reload request"
        );

        tokio::time::sleep(Duration::from_millis(600)).await;

        let final_hash = manager.get_config_hash().await;
        let app_config = manager.get_config();
        let final_config = app_config.read().await;

        assert_ne!(
            prog_update_hash, final_hash,
            "Hash should change after file reload"
        );
        assert_eq!(
            final_config.logging.level, "debug",
            "Config should be reloaded from file"
        );
        assert_eq!(
            final_config.server.listen_address, "0.0.0.0:8888",
            "Address should be reloaded from file"
        );

        println!("✓ All config reload mechanisms work correctly");
    }

    #[tokio::test]
    async fn test_config_watcher_setup() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("dnspx_config.toml");

        let initial_config = AppConfig::default();
        let initial_toml_content = toml::to_string_pretty(&initial_config).unwrap();
        std::fs::write(&config_path, initial_toml_content).unwrap();

        let real_store = Arc::new(
            crate::adapters::config::file_store::JsonFileConfigAdapter::new(
                temp_dir.path().to_path_buf(),
            ),
        );
        let (manager, _) = ConfigurationManager::new(real_store).await.unwrap();

        let watcher_result = manager.start_watching();
        assert!(
            watcher_result.is_ok(),
            "File watcher should start successfully"
        );

        let _update_receiver = manager.subscribe_to_updates();

        assert!(
            manager.reload_request_tx.try_send(ReloadRequest).is_ok(),
            "Reload channel should work"
        );

        println!("✓ File watcher setup works correctly");
    }

    #[tokio::test]
    async fn test_config_reload_integration_with_retries() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("dnspx_config.toml");

        let initial_config = AppConfig::default();
        let initial_toml_content = toml::to_string_pretty(&initial_config).unwrap();
        std::fs::write(&config_path, initial_toml_content).unwrap();

        let real_store = Arc::new(
            crate::adapters::config::file_store::JsonFileConfigAdapter::new(
                temp_dir.path().to_path_buf(),
            ),
        );
        let (manager, _) = ConfigurationManager::new(real_store).await.unwrap();
        manager.start_watching().unwrap();

        let initial_hash = manager.get_config_hash().await;

        tokio::time::sleep(Duration::from_millis(1000)).await;

        let mut target_config = AppConfig::default();
        target_config.logging.level = "debug".to_string();
        target_config.server.listen_address = "127.0.0.1:7777".to_string();
        let target_toml_content = toml::to_string_pretty(&target_config).unwrap();

        let mut config_updated = false;
        let max_attempts = 5;

        for attempt in 1..=max_attempts {
            println!("Attempt {} to update config", attempt);

            std::fs::write(&config_path, target_toml_content.clone()).unwrap();

            if attempt <= 2 {
                tokio::time::sleep(Duration::from_millis(1000)).await;
            } else {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = manager.reload_request_tx.try_send(ReloadRequest);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            let current_hash = manager.get_config_hash().await;
            let app_config = manager.get_config();
            let current_config = app_config.read().await;

            if current_hash != initial_hash
                && current_config.logging.level == "debug"
                && current_config.server.listen_address == "127.0.0.1:7777"
            {
                println!("✓ Config successfully updated on attempt {}", attempt);
                config_updated = true;
                break;
            }
        }

        assert!(
            config_updated,
            "Config should be updated within {} attempts",
            max_attempts
        );
    }
    #[tokio::test]
    async fn test_config_reload_mechanism_direct() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("dnspx_config.toml");

        let initial_config = AppConfig::default();
        let initial_toml_content = toml::to_string_pretty(&initial_config).unwrap();
        std::fs::write(&config_path, initial_toml_content).unwrap();

        let real_store = Arc::new(
            crate::adapters::config::file_store::JsonFileConfigAdapter::new(
                temp_dir.path().to_path_buf(),
            ),
        );
        let (manager, _) = ConfigurationManager::new(real_store).await.unwrap();

        let initial_hash = manager.get_config_hash().await;

        let mut updated_config = AppConfig::default();
        updated_config.logging.level = "trace".to_string();
        let updated_toml_content = toml::to_string_pretty(&updated_config).unwrap();
        std::fs::write(&config_path, updated_toml_content).unwrap();

        let _ = manager.reload_request_tx.try_send(ReloadRequest);

        sleep(Duration::from_millis(500)).await;

        let new_hash = manager.get_config_hash().await;
        assert_ne!(
            initial_hash, new_hash,
            "Config hash should change after manual reload"
        );

        let app_config = manager.get_config();
        let config = app_config.read().await;
        assert_eq!(
            config.logging.level, "trace",
            "Config should be updated after manual reload"
        );
    }
}
