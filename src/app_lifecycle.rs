use crate::adapters::aws::types::AwsCredentialsCache;
use crate::aws_integration::scanner::DiscoveredAwsNetworkInfo;
use crate::config::models::{AppConfig, AwsAccountConfig, AwsGlobalConfig};
use crate::core::config_manager::ConfigurationManager;
use crate::core::dns_cache::DnsCache;
use crate::core::error::{CliError, ConfigError};
use crate::core::local_hosts_resolver::LocalHostsResolver;
use crate::core::types::{AppStatus, AwsScannerStatus, ConfigStatus, MessageLevel};
use crate::ports::{
    AppLifecycleManagerPort, AwsConfigProvider, StatusReporterPort, UpdateManagerPort,
    UserInteractionPort,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify, RwLock, broadcast};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

pub(crate) struct AppLifecycleManager {
    config_manager: Arc<ConfigurationManager>,
    dns_cache: Arc<DnsCache>,
    local_hosts_resolver: Arc<LocalHostsResolver>,
    status_reporter: Arc<dyn StatusReporterPort>,
    user_interaction: Arc<dyn UserInteractionPort>,
    aws_credentials_cache: AwsCredentialsCache,
    aws_scan_trigger: Arc<Notify>,
    cancellation_token: CancellationToken,
    main_tasks: Mutex<Vec<JoinHandle<()>>>,
    start_time: Instant,
    active_listeners: Arc<Mutex<Vec<String>>>,
    total_queries_processed: Arc<AtomicU64>,
    pub discovered_aws_network_info: Arc<RwLock<DiscoveredAwsNetworkInfo>>,
    pub aws_config_provider: Arc<dyn AwsConfigProvider>,
    update_manager: Arc<Mutex<Option<Arc<dyn UpdateManagerPort>>>>,
}

#[async_trait]
impl AppLifecycleManagerPort for AppLifecycleManager {
    fn get_config(&self) -> Arc<RwLock<AppConfig>> {
        Arc::clone(&self.config_manager.get_config())
    }

    fn get_dns_cache(&self) -> Arc<DnsCache> {
        Arc::clone(&self.dns_cache)
    }

    fn get_status_reporter(&self) -> Arc<dyn StatusReporterPort> {
        Arc::clone(&self.status_reporter)
    }

    fn get_user_interaction_port(&self) -> Arc<dyn UserInteractionPort> {
        Arc::clone(&self.user_interaction)
    }

    fn get_aws_scan_trigger(&self) -> Arc<Notify> {
        Arc::clone(&self.aws_scan_trigger)
    }

    fn get_cancellation_token(&self) -> CancellationToken {
        self.cancellation_token.clone()
    }

    fn get_discovered_aws_network_info_view(&self) -> Arc<RwLock<DiscoveredAwsNetworkInfo>> {
        Arc::clone(&self.discovered_aws_network_info)
    }

    fn get_local_hosts_resolver(&self) -> Arc<LocalHostsResolver> {
        Arc::clone(&self.local_hosts_resolver)
    }

    async fn get_total_queries_processed(&self) -> u64 {
        self.total_queries_processed.load(Ordering::Relaxed)
    }

    async fn get_active_listeners(&self) -> Vec<String> {
        futures::executor::block_on(async { self.active_listeners.lock().await.clone() })
    }

    async fn add_listener_address(&self, addr: String) {
        self.add_listener_address(addr).await;
    }

    async fn remove_listener_address(&self, addr: String) {
        self.remove_listener_address(addr).await;
    }

    async fn start(&self) -> Result<(), String> {
        self.start().await
    }

    async fn stop(&self) {
        self.stop().await
    }

    async fn trigger_config_reload(&self) -> Result<(), CliError> {
        self.trigger_config_reload().await
    }

    async fn trigger_aws_scan_refresh(&self) -> Result<(), CliError> {
        self.trigger_aws_scan_refresh().await
    }

    async fn add_or_update_aws_account_config(
        &self,
        new_account_config: AwsAccountConfig,
        original_dnspx_label_for_edit: Option<String>,
    ) -> Result<(), ConfigError> {
        self.add_or_update_aws_account_config(new_account_config, original_dnspx_label_for_edit)
            .await
    }

    async fn persist_discovered_aws_details(
        &self,
        discovered_ips: Option<Vec<String>>,
        discovered_zones: Option<Vec<String>>,
    ) -> Result<(), ConfigError> {
        self.persist_discovered_aws_details(discovered_ips, discovered_zones)
            .await
    }

    async fn get_app_status(&self) -> AppStatus {
        self.get_app_status().await
    }

    fn get_aws_config_provider(&self) -> Arc<dyn AwsConfigProvider> {
        Arc::clone(&self.aws_config_provider)
    }

    fn get_update_manager(&self) -> Option<Arc<dyn UpdateManagerPort>> {
        match self.update_manager.try_lock() {
            Ok(guard) => guard.clone(),
            Err(_) => None,
        }
    }

    async fn add_task(&self, handle: JoinHandle<()>) {
        self.add_task(handle).await;
    }

    async fn get_config_for_processor(&self) -> Arc<RwLock<AppConfig>> {
        self.config_manager.get_config()
    }

    fn increment_total_queries_processed(&self) {
        self.increment_total_queries_processed_internal();
    }
}

impl AppLifecycleManager {
    pub(crate) async fn new(
        config_manager: Arc<ConfigurationManager>,
        status_reporter: Arc<dyn StatusReporterPort>,
        user_interaction: Arc<dyn UserInteractionPort>,
        aws_config_provider: Arc<dyn AwsConfigProvider>,
    ) -> Arc<Self> {
        let initial_config_arc = config_manager.get_config();
        let dns_cache = {
            let config_guard = initial_config_arc.read().await;
            Arc::new(DnsCache::new(
                config_guard.cache.max_capacity,
                config_guard.cache.min_ttl,
                config_guard.cache.max_ttl,
                config_guard.cache.serve_stale_if_error,
                config_guard.cache.serve_stale_max_ttl,
            ))
        };
        let local_hosts_resolver = LocalHostsResolver::new(Arc::clone(&initial_config_arc)).await;
        let aws_credentials_cache = Arc::new(RwLock::new(HashMap::new()));
        let aws_scan_trigger = Arc::new(Notify::new());

        let app_manager = Arc::new(Self {
            config_manager,
            dns_cache,
            local_hosts_resolver,
            status_reporter,
            user_interaction,
            aws_credentials_cache,
            aws_scan_trigger,
            cancellation_token: CancellationToken::new(),
            main_tasks: Mutex::new(Vec::new()),
            start_time: Instant::now(),
            active_listeners: Arc::new(Mutex::new(Vec::new())),
            total_queries_processed: Arc::new(AtomicU64::new(0)),
            discovered_aws_network_info: Arc::new(RwLock::new(DiscoveredAwsNetworkInfo::default())),
            aws_config_provider,
            update_manager: Arc::new(Mutex::new(None)),
        });

        let app_manager_clone = Arc::clone(&app_manager);
        tokio::spawn(async move {
            app_manager_clone.listen_for_config_updates().await;
        });

        app_manager
    }

    pub(crate) async fn set_update_manager(&self, update_manager: Arc<dyn UpdateManagerPort>) {
        let mut guard = self.update_manager.lock().await;
        *guard = Some(update_manager);
    }

    fn increment_total_queries_processed_internal(&self) {
        self.total_queries_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) async fn get_total_queries_processed(&self) -> u64 {
        self.total_queries_processed.load(Ordering::Relaxed)
    }

    async fn listen_for_config_updates(&self) {
        let mut rx = self.config_manager.subscribe_to_updates();
        let initial_config_hash = self.config_manager.get_config_hash().await;
        let mut last_processed_config_hash = initial_config_hash;
        let mut last_aws_config_snapshot: Option<crate::config::models::AwsGlobalConfig> =
            self.config_manager.get_config().read().await.aws.clone();

        debug!("Config update listener started.");
        loop {
            tokio::select! {
                _ = self.cancellation_token.cancelled() => {
                    info!("Config update listener shutting down due to cancellation token.");
                    break;
                }
                update_result = rx.recv() => {
                    match update_result {
                        Ok(_) => {
                            let current_config_hash = self.config_manager.get_config_hash().await;
                            if current_config_hash == last_processed_config_hash {
                                continue;
                            }

                            info!("AppLifecycleManager: Detected configuration update. New hash: {}", current_config_hash);

                            self.local_hosts_resolver.update_hosts().await;
                            info!("LocalHostsResolver updated due to AppConfig change.");

                            warn!("DnsCache parameters (TTL, stale serving) changed. Existing entries retain old TTLs. Max capacity change requires restart or cache clear for full effect.");
                            let app_config = self.config_manager.get_config();
                            let new_config_guard = app_config.read().await;
                            let new_aws_config = new_config_guard.aws.clone();
                            if new_aws_config != last_aws_config_snapshot {
                                info!("AWS configuration changed. Triggering AWS scan.");
                                self.aws_scan_trigger.notify_one();
                                last_aws_config_snapshot = new_aws_config;
                            }

                            let config_status = ConfigStatus {
                                last_loaded_time: Some(chrono::Utc::now()),
                                is_valid: true,
                                error_message: None,
                                source_file_path: Some(self.config_manager.get_config_file_path().to_string_lossy().into_owned()),
                            };
                            self.status_reporter.report_config_status(config_status).await;
                            last_processed_config_hash = current_config_hash;
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("AppLifecycleManager: Config update channel lagged by {} messages.", n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("AppLifecycleManager: Config update channel closed. Listener stopping.");
                            break;
                        }
                    }
                }
            }
        }
        debug!("Config update listener stopped.");
    }

    pub(crate) async fn add_task(&self, handle: JoinHandle<()>) {
        self.main_tasks.lock().await.push(handle);
    }

    pub(crate) async fn add_listener_address(&self, addr: String) {
        let mut listeners = self.active_listeners.lock().await;
        if !listeners.contains(&addr) {
            listeners.push(addr);
        }
    }

    pub(crate) async fn remove_listener_address(&self, addr: String) {
        let mut listeners = self.active_listeners.lock().await;
        listeners.retain(|x| x != &addr);
    }

    pub(crate) async fn get_active_listeners(&self) -> Vec<String> {
        self.active_listeners.lock().await.clone()
    }

    pub(crate) async fn start(&self) -> Result<(), String> {
        info!("Starting application subsystems...");
        let initial_config_status = ConfigStatus {
            last_loaded_time: Some(chrono::Utc::now()),
            is_valid: true,
            error_message: None,
            source_file_path: Some(
                self.config_manager
                    .get_config_file_path()
                    .to_string_lossy()
                    .into_owned(),
            ),
        };
        self.status_reporter
            .report_config_status(initial_config_status)
            .await;

        if self.config_manager.get_config().read().await.aws.is_some() {
            self.status_reporter
                .report_aws_scanner_status(AwsScannerStatus::default())
                .await;
        }
        info!("Application subsystems (listeners) assumed to be started externally by main.");
        Ok(())
    }

    pub(crate) async fn stop(&self) {
        if self.cancellation_token.is_cancelled() {
            info!(
                "AppLifecycleManager::stop called again or shutdown already in progress. Will proceed to wait for tasks."
            );
        } else {
            info!("AppLifecycleManager::stop initiated.");
            self.user_interaction
                .display_message("Shutting down application...", MessageLevel::Info);

            debug!("AppLifecycleManager: Cancelling main CancellationToken.");
            self.cancellation_token.cancel();

            debug!(
                "AppLifecycleManager: Notifying AWS scan trigger to unblock scanner if waiting."
            );
            self.aws_scan_trigger.notify_waiters();

            info!("AppLifecycleManager: Shutting down components...");

            debug!("AppLifecycleManager: Shutting down LocalHostsResolver...");
            self.local_hosts_resolver.shutdown().await;

            debug!("AppLifecycleManager: Shutting down ConfigurationManager...");
            self.config_manager.shutdown().await;

            info!("AppLifecycleManager: Component shutdown completed.");
        }

        info!("AppLifecycleManager: Waiting for main tasks to complete...");
        let mut tasks_guard = self.main_tasks.lock().await;
        if tasks_guard.is_empty() {
            debug!("AppLifecycleManager: No main tasks to wait for.");
        } else {
            debug!(
                "AppLifecycleManager: Acquired main_tasks lock. Waiting for {} tasks.",
                tasks_guard.len()
            );
            let tasks_to_await: Vec<_> = tasks_guard.drain(..).collect();
            let num_tasks_being_awaited = tasks_to_await.len();
            for (i, handle) in tasks_to_await.into_iter().enumerate() {
                debug!("AppLifecycleManager: Waiting for task #{}...", i);
                match tokio::time::timeout(Duration::from_secs(5), handle).await {
                    Ok(Ok(())) => debug!("AppLifecycleManager: Task #{} completed gracefully.", i),
                    Ok(Err(e)) => {
                        if e.is_cancelled() {
                            debug!(
                                "AppLifecycleManager: Task #{} was cancelled as expected.",
                                i
                            );
                        } else if e.is_panic() {
                            error!("AppLifecycleManager: Task #{} panicked: {:?}", i, e);
                        } else {
                            warn!(
                                "AppLifecycleManager: Task #{} joined with an error: {:?}",
                                i, e
                            );
                        }
                    }
                    Err(_) => warn!(
                        "AppLifecycleManager: Task #{} timed out during shutdown.",
                        i
                    ),
                }
            }
            debug!(
                "AppLifecycleManager: Finished waiting for tasks. {} tasks were processed.",
                tasks_guard.len() + num_tasks_being_awaited
            );
        }

        info!(
            "AppLifecycleManager: Application shutdown sequence complete from AppLifecycleManager perspective."
        );
    }

    pub(crate) fn get_cancellation_token(&self) -> CancellationToken {
        self.cancellation_token.clone()
    }

    pub(crate) fn get_aws_scan_trigger(&self) -> Arc<Notify> {
        Arc::clone(&self.aws_scan_trigger)
    }

    pub(crate) fn get_config(&self) -> Arc<RwLock<AppConfig>> {
        Arc::clone(&self.config_manager.get_config())
    }

    pub(crate) async fn get_config_hash(&self) -> String {
        self.config_manager.get_config_hash().await
    }

    pub(crate) fn get_dns_cache(&self) -> Arc<DnsCache> {
        Arc::clone(&self.dns_cache)
    }

    pub(crate) fn get_local_hosts_resolver(&self) -> Arc<LocalHostsResolver> {
        Arc::clone(&self.local_hosts_resolver)
    }

    pub(crate) fn get_status_reporter(&self) -> Arc<dyn StatusReporterPort> {
        Arc::clone(&self.status_reporter)
    }

    pub(crate) fn get_user_interaction_port(&self) -> Arc<dyn UserInteractionPort> {
        Arc::clone(&self.user_interaction)
    }

    pub(crate) fn get_aws_credentials_cache(&self) -> AwsCredentialsCache {
        Arc::clone(&self.aws_credentials_cache)
    }

    pub(crate) fn get_discovered_aws_network_info_view(
        &self,
    ) -> Arc<RwLock<DiscoveredAwsNetworkInfo>> {
        Arc::clone(&self.discovered_aws_network_info)
    }

    pub(crate) async fn get_app_status(&self) -> AppStatus {
        let uptime_seconds = self.start_time.elapsed().as_secs();
        let active_listeners = self.get_active_listeners().await;
        let config_hash = self.get_config_hash().await;
        let cache_stats = self.dns_cache.get_stats();

        self.status_reporter
            .get_full_app_status(
                uptime_seconds,
                active_listeners,
                config_hash,
                Some(cache_stats),
            )
            .await
    }

    pub(crate) async fn trigger_config_reload(&self) -> Result<(), CliError> {
        info!("Manual configuration reload triggered.");
        self.user_interaction.display_message(
            "Config reload mechanism relies on file system watch. Ensure file is saved.",
            MessageLevel::Info,
        );
        Ok(())
    }

    pub(crate) async fn trigger_aws_scan_refresh(&self) -> Result<(), CliError> {
        info!("Manual AWS scan refresh triggered.");
        if self.get_config().read().await.aws.is_none() {
            self.user_interaction.display_message(
                "AWS configuration not enabled. Scan not triggered.",
                MessageLevel::Warning,
            );
            return Err(CliError::Execution(
                "AWS configuration not enabled.".to_string(),
            ));
        }
        self.aws_scan_trigger.notify_one();
        self.user_interaction
            .display_message("AWS scan refresh triggered.", MessageLevel::Info);
        Ok(())
    }

    pub(crate) async fn add_or_update_aws_account_config(
        &self,
        new_account_config: AwsAccountConfig,
        original_dnspx_label_for_edit: Option<String>,
    ) -> Result<(), ConfigError> {
        info!(
            "Attempting to add/update AWS account config for dnspx label: {}",
            new_account_config.label
        );
        self.config_manager
            .update_app_config(move |app_conf| {
                let aws_global_config = app_conf.aws.get_or_insert_with(AwsGlobalConfig::default);
                let target_label = &new_account_config.label;

                if original_dnspx_label_for_edit.as_ref() != Some(target_label)
                    && aws_global_config
                        .accounts
                        .iter()
                        .any(|acc| &acc.label == target_label)
                {
                    let error_msg = format!("dnspx Label '{target_label}' already exists.");
                    warn!("{}", error_msg);
                    return Err(ConfigError::Validation(error_msg));
                }

                if let Some(label_to_edit) = original_dnspx_label_for_edit {
                    if let Some(existing_account_idx) = aws_global_config
                        .accounts
                        .iter()
                        .position(|acc| acc.label == label_to_edit)
                    {
                        debug!(
                            "Updating existing AWS account config in dnspx: {}",
                            label_to_edit
                        );
                        let mut final_config = new_account_config.clone();
                        final_config.scan_vpc_ids = aws_global_config.accounts
                            [existing_account_idx]
                            .scan_vpc_ids
                            .clone();
                        final_config.roles_to_assume = aws_global_config.accounts
                            [existing_account_idx]
                            .roles_to_assume
                            .clone();
                        final_config.discover_services = aws_global_config.accounts
                            [existing_account_idx]
                            .discover_services
                            .clone();
                        aws_global_config.accounts[existing_account_idx] = final_config;

                        info!(
                            "Updated dnspx AWS account config for (new) label: {}",
                            target_label
                        );
                    } else {
                        warn!(
                            "Original label '{}' for edit not found. Adding as new account '{}'.",
                            label_to_edit, target_label
                        );
                        aws_global_config.accounts.push(new_account_config.clone());
                        info!(
                            "Added new dnspx AWS account config for label: {}",
                            target_label
                        );
                    }
                } else {
                    debug!("Adding new AWS account config to dnspx: {}", target_label);
                    aws_global_config.accounts.push(new_account_config.clone());
                    info!(
                        "Added new dnspx AWS account config for label: {}",
                        target_label
                    );
                }
                Ok(())
            })
            .await
    }

    pub(crate) async fn persist_discovered_aws_details(
        &self,
        discovered_ips: Option<Vec<String>>,
        discovered_zones: Option<Vec<String>>,
    ) -> Result<(), ConfigError> {
        if discovered_ips.is_none() && discovered_zones.is_none() {
            info!("No new AWS network details provided to persist.");
            return Ok(());
        }
        info!("Persisting discovered AWS network details to configuration file...");
        self.config_manager.update_app_config(move |app_conf| {
            let aws_global = app_conf.aws.get_or_insert_with(AwsGlobalConfig::default);

            if let Some(ips) = discovered_ips {
                if aws_global.route53_inbound_endpoint_ips.as_ref().is_none_or(|e_ips| e_ips.is_empty()) {
                    aws_global.route53_inbound_endpoint_ips = Some(ips);
                    info!("Updated route53_inbound_endpoint_ips in config with discovered values.");
                } else {
                    info!("Manual route53_inbound_endpoint_ips exist in config; discovered IPs not automatically overwritten by this call. User can update via TUI.");
                }
            }
            if let Some(zones) = discovered_zones {
                 if aws_global.discovered_private_zones.as_ref().is_none_or(|e_zones| e_zones.is_empty()) {
                    aws_global.discovered_private_zones = Some(zones);
                    info!("Updated discovered_private_zones in config with discovered values.");
                } else {
                     info!("Manual/existing discovered_private_zones exist in config; newly discovered zones not automatically overwritten by this call. User can update via TUI.");
                }
            }
            Ok(())
        }).await
    }
}
