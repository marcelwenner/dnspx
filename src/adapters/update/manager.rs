use crate::adapters::update::release_analyzer::ReleaseAnalyzer;
use crate::adapters::update::security::SecurityValidator;
use crate::adapters::update::transaction::UpdateTransaction;
use crate::config::models::UpdateConfig;
use crate::core::error::UpdateError;
use crate::core::types::{MessageLevel, UpdateInfo, UpdateResult};
use crate::ports::{AppLifecycleManagerPort, UpdateManagerPort};
use async_trait::async_trait;
use reqwest::Client;
use semver::Version;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    name: String,
    body: String,
    assets: Vec<GitHubAsset>,
    prerelease: bool,
    draft: bool,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

pub(crate) struct VerifiedUpdateManager {
    config: Arc<RwLock<UpdateConfig>>,
    http_client: Client,
    security_validator: SecurityValidator,
    release_analyzer: ReleaseAnalyzer,
    current_binary_path: PathBuf,
    backup_dir: PathBuf,
}

impl VerifiedUpdateManager {
    pub(crate) fn new(
        config: UpdateConfig,
        http_client: Client,
        current_binary_path: PathBuf,
        backup_dir: PathBuf,
    ) -> Self {
        let security_validator =
            SecurityValidator::new(config.security.clone(), http_client.clone());
        let release_analyzer = ReleaseAnalyzer::new();

        Self {
            config: Arc::new(RwLock::new(config)),
            http_client,
            security_validator,
            release_analyzer,
            current_binary_path,
            backup_dir,
        }
    }

    pub(crate) async fn update_config(&self, new_config: UpdateConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
    }

    pub(crate) async fn run_background_checker(
        self: Arc<Self>,
        app_lifecycle: Arc<dyn AppLifecycleManagerPort>,
    ) {
        let cancellation_token = app_lifecycle.get_cancellation_token();
        let user_interaction = app_lifecycle.get_user_interaction_port();

        let mut interval = {
            let config = self.config.read().await;
            tokio::time::interval(config.check_interval)
        };

        interval.tick().await;

        info!("Update background checker started");

        debug!("Performing initial update check at startup");
        match self.check_for_updates().await {
            Ok(UpdateResult::UpdateAvailable(update_info)) => {
                user_interaction.display_message(
                    &format!(
                        "Update available: v{} (current: v{})",
                        update_info.version,
                        self.get_current_version()
                    ),
                    MessageLevel::Info,
                );

                if update_info.breaking_changes {
                    user_interaction.display_message(
                        "⚠️  This update contains breaking changes. Review release notes before installing.",
                        MessageLevel::Warning,
                    );
                }
            }
            Ok(UpdateResult::UpToDate) => {
                debug!("Already running latest version");
            }
            Ok(UpdateResult::UpdateInstalled { .. }) => {
                debug!("Unexpected UpdateInstalled result during check");
            }
            Ok(UpdateResult::UpdateFailed { .. }) => {
                debug!("Unexpected UpdateFailed result during check");
            }
            Err(e) => {
                debug!("Initial update check failed: {}", e);
            }
        }

        loop {
            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    info!("Update background checker shutting down");
                    break;
                }
                _ = interval.tick() => {
                    debug!("Performing scheduled update check");

                    match self.check_for_updates().await {
                        Ok(UpdateResult::UpdateAvailable(update_info)) => {
                            user_interaction.display_message(
                                &format!(
                                    "Update available: v{} (current: v{})",
                                    update_info.version,
                                    self.get_current_version()
                                ),
                                MessageLevel::Info,
                            );

                            if update_info.breaking_changes {
                                user_interaction.display_message(
                                    "⚠️  This update contains breaking changes. Review release notes before installing.",
                                    MessageLevel::Warning,
                                );
                            }

                            let config = self.config.read().await;
                            if config.auto_update_policy.update_level != crate::config::models::UpdateLevel::None {
                                info!("Auto-update is enabled, installing update automatically");
                                match self.install_update(&update_info).await {
                                    Ok(UpdateResult::UpdateInstalled { from_version, to_version }) => {
                                        user_interaction.display_message(
                                            &format!("Successfully updated from v{} to v{}", from_version, to_version),
                                            MessageLevel::Info,
                                        );
                                    }
                                    Ok(UpdateResult::UpdateFailed { error, rollback_performed }) => {
                                        user_interaction.display_message(
                                            &format!("Update failed: {}. Rollback performed: {}", error, rollback_performed),
                                            MessageLevel::Error,
                                        );
                                    }
                                    Err(e) => {
                                        error!("Auto-update failed: {}", e);
                                        user_interaction.display_message(
                                            &format!("Auto-update failed: {}", e),
                                            MessageLevel::Error,
                                        );
                                    }
                                    _ => {}
                                }
                            } else {
                                user_interaction.display_message(
                                    "Use 'update install' command to install the update.",
                                    MessageLevel::Info,
                                );
                            }
                        }
                        Ok(UpdateResult::UpToDate) => {
                            debug!("No updates available");
                        }
                        Ok(UpdateResult::UpdateInstalled { from_version, to_version }) => {
                            debug!("Update was already installed from v{} to v{}", from_version, to_version);
                        }
                        Ok(UpdateResult::UpdateFailed { error, rollback_performed }) => {
                            warn!("Previous update failed: {}. Rollback performed: {}", error, rollback_performed);
                        }
                        Err(UpdateError::NotAvailable) => {
                            debug!("No releases available or only draft releases found");
                        }
                        Err(e) => {
                            warn!("Update check failed: {}", e);
                            if matches!(e, UpdateError::Network(_)) {
                                debug!("Network error during update check (will retry): {}", e);
                            }
                        }
                    }

                    let new_interval = {
                        let config = self.config.read().await;
                        config.check_interval
                    };
                    interval = tokio::time::interval(new_interval);
                    interval.tick().await;
                }
            }
        }
    }

    async fn fetch_latest_release(&self) -> Result<GitHubRelease, UpdateError> {
        let config = self.config.read().await;
        let url = format!(
            "https://api.github.com/repos/{}/releases/latest",
            config.github_repo
        );

        debug!("Fetching latest release from: {}", url);

        let response = self
            .http_client
            .get(&url)
            .header("User-Agent", format!("dnspx/{}", env!("CARGO_PKG_VERSION")))
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .map_err(UpdateError::Network)?;

        if !response.status().is_success() {
            return Err(UpdateError::CheckFailed(format!(
                "GitHub API request failed: HTTP {}",
                response.status()
            )));
        }

        let release: GitHubRelease = response.json().await.map_err(|e| {
            UpdateError::CheckFailed(format!("Failed to parse GitHub response: {}", e))
        })?;

        if release.draft {
            return Err(UpdateError::NotAvailable);
        }

        Ok(release)
    }

    fn determine_platform_suffix(&self) -> String {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;

        // Check if we're running on musl (simplified detection)
        let is_musl = cfg!(target_env = "musl");

        let platform_name = match (os, arch, is_musl) {
            ("linux", "x86_64", true) => "linux-musl-x64",
            ("linux", "x86_64", false) => "linux-x64",
            ("linux", "aarch64", _) => "linux-arm64",
            ("windows", "x86_64", _) => "windows-x64",
            ("windows", "aarch64", _) => "windows-arm64",
            ("macos", "x86_64", _) => "macos-intel",
            ("macos", "aarch64", _) => "macos-arm64",
            _ => {
                warn!(
                    "Unknown platform: {}-{} (musl: {}), defaulting to linux-x64",
                    os, arch, is_musl
                );
                "linux-x64"
            }
        };

        let extension = if os == "windows" { "zip" } else { "tar.gz" };

        format!("{}.{}", platform_name, extension)
    }

    fn get_expected_target_names(&self) -> Vec<String> {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        let is_musl = cfg!(target_env = "musl");

        let mut targets = Vec::new();

        // Add Rust target triple names (for fallback compatibility)
        match (os, arch, is_musl) {
            ("linux", "x86_64", true) => {
                targets.push("x86_64-unknown-linux-musl".to_string());
                targets.push("linux-musl-x64".to_string());
            }
            ("linux", "x86_64", false) => {
                targets.push("x86_64-unknown-linux-gnu".to_string());
                targets.push("linux-x64".to_string());
            }
            ("linux", "aarch64", _) => {
                targets.push("aarch64-unknown-linux-gnu".to_string());
                targets.push("linux-arm64".to_string());
            }
            ("windows", "x86_64", _) => {
                targets.push("x86_64-pc-windows-msvc".to_string());
                targets.push("windows-x64".to_string());
            }
            ("windows", "aarch64", _) => {
                targets.push("aarch64-pc-windows-msvc".to_string());
                targets.push("windows-arm64".to_string());
            }
            ("macos", "x86_64", _) => {
                targets.push("x86_64-apple-darwin".to_string());
                targets.push("macos-intel".to_string());
            }
            ("macos", "aarch64", _) => {
                targets.push("aarch64-apple-darwin".to_string());
                targets.push("macos-arm64".to_string());
            }
            _ => {
                warn!(
                    "Unknown platform: {}-{} (musl: {}), defaulting to linux targets",
                    os, arch, is_musl
                );
                targets.push("x86_64-unknown-linux-gnu".to_string());
                targets.push("linux-x64".to_string());
            }
        };

        targets
    }

    async fn find_matching_asset<'a>(
        &self,
        assets: &'a [GitHubAsset],
        release_version: &str,
    ) -> Result<&'a GitHubAsset, UpdateError> {
        let platform_suffix = self.determine_platform_suffix();
        let expected_target_names = self.get_expected_target_names();

        debug!(
            "Looking for asset with platform suffix: {}",
            platform_suffix
        );
        debug!("Expected target names: {:?}", expected_target_names);

        // Try to find asset with version-prefixed names based on release workflow patterns
        // Format: dnspx-v{VERSION}-{platform_name}.{extension}
        // release_version comes without 'v' prefix, so we need to add it
        let expected_name = format!("dnspx-v{}-{}", release_version, platform_suffix);
        debug!("Looking for asset matching: {}", expected_name);

        // First try exact match with version prefix
        for asset in assets {
            if asset.name == expected_name {
                debug!("Found exact matching asset: {}", asset.name);
                return Ok(asset);
            }
        }

        // Fallback: try matching by target name (from release workflow matrix.name)
        for asset in assets {
            for target_name in &expected_target_names {
                if asset.name.contains(target_name) {
                    debug!(
                        "Found asset matching target name '{}': {}",
                        target_name, asset.name
                    );
                    return Ok(asset);
                }
            }
        }

        // Final fallback: try partial match with platform suffix
        let platform_base = platform_suffix
            .split('.')
            .next()
            .unwrap_or(&platform_suffix);
        for asset in assets {
            if asset.name.contains(platform_base) {
                debug!("Found partial matching asset: {}", asset.name);
                return Ok(asset);
            }
        }

        Err(UpdateError::CheckFailed(format!(
            "No compatible binary found for current platform. Looking for: {} (targets: {:?}) among assets: {:?}",
            expected_name,
            expected_target_names,
            assets.iter().map(|a| &a.name).collect::<Vec<_>>()
        )))
    }

    async fn download_and_extract_update(
        &self,
        asset: &GitHubAsset,
        checksum_url: Option<String>,
        signature_url: Option<String>,
    ) -> Result<PathBuf, UpdateError> {
        let temp_dir = std::env::temp_dir();
        let download_path = temp_dir.join(&asset.name);

        info!("Downloading update from: {}", asset.browser_download_url);

        let response = self
            .http_client
            .get(&asset.browser_download_url)
            .send()
            .await
            .map_err(UpdateError::Network)?;

        if !response.status().is_success() {
            return Err(UpdateError::DownloadFailed(format!(
                "Failed to download update: HTTP {}",
                response.status()
            )));
        }

        let bytes = response.bytes().await.map_err(UpdateError::Network)?;
        tokio::fs::write(&download_path, &bytes)
            .await
            .map_err(|e| UpdateError::FileSystem {
                path: download_path.clone(),
                source: e,
            })?;

        self.security_validator
            .validate_download(
                &download_path,
                checksum_url.as_deref(),
                signature_url.as_deref(),
            )
            .await?;

        let extracted_binary = self.extract_binary(&download_path).await?;

        tokio::fs::remove_file(&download_path)
            .await
            .unwrap_or_else(|e| warn!("Failed to cleanup download file: {}", e));

        Ok(extracted_binary)
    }

    async fn extract_binary(&self, archive_path: &Path) -> Result<PathBuf, UpdateError> {
        let temp_dir = std::env::temp_dir();
        let extract_dir = temp_dir.join("dnspx_update");

        tokio::fs::create_dir_all(&extract_dir)
            .await
            .map_err(|e| UpdateError::FileSystem {
                path: extract_dir.clone(),
                source: e,
            })?;

        let archive_path_str = archive_path.to_string_lossy();

        if archive_path_str.ends_with(".tar.gz") {
            self.extract_tar_gz(archive_path, &extract_dir).await?;
        } else if archive_path_str.ends_with(".zip") {
            self.extract_zip(archive_path, &extract_dir).await?;
        } else {
            return Err(UpdateError::InstallationFailed(
                "Unsupported archive format".to_string(),
            ));
        }

        let binary_name = if std::env::consts::OS == "windows" {
            "dnspx.exe"
        } else {
            "dnspx"
        };

        let binary_path = extract_dir.join(binary_name);

        if !binary_path.exists() {
            return Err(UpdateError::InstallationFailed(format!(
                "Binary not found in extracted archive: {}",
                binary_path.display()
            )));
        }

        Ok(binary_path)
    }

    async fn extract_tar_gz(
        &self,
        archive_path: &Path,
        extract_dir: &Path,
    ) -> Result<(), UpdateError> {
        let archive_path = archive_path.to_path_buf();
        let extract_dir = extract_dir.to_path_buf();

        tokio::task::spawn_blocking(move || {
            use std::fs::File;
            use std::io::{BufReader, Read};

            let file = File::open(&archive_path).map_err(|e| UpdateError::FileSystem {
                path: archive_path.clone(),
                source: e,
            })?;

            let mut reader = BufReader::new(file);
            let mut buffer = Vec::new();
            reader.read_to_end(&mut buffer).map_err(|e| {
                UpdateError::InstallationFailed(format!("Failed to read archive: {}", e))
            })?;

            let cursor = std::io::Cursor::new(buffer);
            let tar = flate2::read::GzDecoder::new(cursor);
            let mut archive = tar::Archive::new(tar);

            archive.unpack(&extract_dir).map_err(|e| {
                UpdateError::InstallationFailed(format!("Failed to extract tar.gz: {}", e))
            })?;

            Ok::<(), UpdateError>(())
        })
        .await
        .map_err(|e| UpdateError::InstallationFailed(format!("Extraction task failed: {}", e)))?
    }

    async fn extract_zip(
        &self,
        archive_path: &Path,
        extract_dir: &Path,
    ) -> Result<(), UpdateError> {
        let archive_path = archive_path.to_path_buf();
        let extract_dir = extract_dir.to_path_buf();

        tokio::task::spawn_blocking(move || {
            use std::fs::File;

            let file = File::open(&archive_path).map_err(|e| UpdateError::FileSystem {
                path: archive_path.clone(),
                source: e,
            })?;

            let mut archive = zip::ZipArchive::new(file).map_err(|e| {
                UpdateError::InstallationFailed(format!("Failed to open zip: {}", e))
            })?;

            archive.extract(&extract_dir).map_err(|e| {
                UpdateError::InstallationFailed(format!("Failed to extract zip: {}", e))
            })?;

            Ok::<(), UpdateError>(())
        })
        .await
        .map_err(|e| UpdateError::InstallationFailed(format!("Extraction task failed: {}", e)))?
    }
}

#[async_trait]
impl UpdateManagerPort for VerifiedUpdateManager {
    async fn check_for_updates(&self) -> Result<UpdateResult, UpdateError> {
        let config = self.config.read().await;

        if !config.enabled {
            debug!("Updates are disabled");
            return Ok(UpdateResult::UpToDate);
        }

        drop(config);

        info!("Checking for updates...");

        let release = self.fetch_latest_release().await?;
        let current_version = Version::parse(env!("CARGO_PKG_VERSION"))
            .map_err(|e| UpdateError::InvalidVersion(format!("Invalid current version: {}", e)))?;

        let latest_version = Version::parse(release.tag_name.trim_start_matches('v'))
            .map_err(|e| UpdateError::InvalidVersion(format!("Invalid release version: {}", e)))?;

        if latest_version <= current_version {
            debug!("Already up to date: v{}", current_version);
            return Ok(UpdateResult::UpToDate);
        }

        let metadata = self
            .release_analyzer
            .analyze_release_notes(&release.body, &latest_version.to_string())?;

        let asset = self
            .find_matching_asset(&release.assets, &latest_version.to_string())
            .await?;

        let checksum_url = release
            .assets
            .iter()
            .find(|a| a.name == format!("{}.sha256", asset.name))
            .map(|a| a.browser_download_url.clone());

        let signature_url = release
            .assets
            .iter()
            .find(|a| a.name == format!("{}.asc", asset.name))
            .map(|a| a.browser_download_url.clone());

        let update_info = UpdateInfo {
            version: latest_version.to_string(),
            download_url: asset.browser_download_url.clone(),
            checksum: checksum_url,
            signature_url,
            release_notes: Some(release.body),
            breaking_changes: metadata.has_breaking_changes,
        };

        info!(
            "Update available: v{} -> v{}",
            current_version, latest_version
        );
        Ok(UpdateResult::UpdateAvailable(update_info))
    }

    async fn install_update(&self, update_info: &UpdateInfo) -> Result<UpdateResult, UpdateError> {
        let config = self.config.read().await;

        if !config.enabled {
            return Err(UpdateError::InstallationFailed(
                "Updates are disabled".to_string(),
            ));
        }

        let current_version = Version::parse(env!("CARGO_PKG_VERSION"))
            .map_err(|e| UpdateError::InvalidVersion(format!("Invalid current version: {}", e)))?;

        let new_version = Version::parse(&update_info.version)
            .map_err(|e| UpdateError::InvalidVersion(format!("Invalid update version: {}", e)))?;

        info!(
            "Installing update: v{} -> v{}",
            current_version, new_version
        );

        let mut transaction = UpdateTransaction::new(
            self.current_binary_path.clone(),
            self.backup_dir.clone(),
            new_version.clone(),
            current_version.clone(),
            config.rollback.clone(),
        );

        drop(config);

        transaction.prepare().await?;

        let asset_name = update_info
            .download_url
            .split('/')
            .next_back()
            .unwrap_or("unknown");

        let asset = GitHubAsset {
            name: asset_name.to_string(),
            browser_download_url: update_info.download_url.clone(),
        };

        let new_binary_path = match self
            .download_and_extract_update(
                &asset,
                update_info.checksum.clone(),
                update_info.signature_url.clone(),
            )
            .await
        {
            Ok(path) => path,
            Err(e) => {
                error!("Update download/extraction failed: {}", e);
                transaction.rollback().await.unwrap_or_else(|re| {
                    error!("Rollback also failed: {}", re);
                });
                return Err(e);
            }
        };

        match transaction.commit(&new_binary_path).await {
            Ok(()) => {
                info!(
                    "Update installed successfully: v{} -> v{}",
                    current_version, new_version
                );

                tokio::fs::remove_file(&new_binary_path)
                    .await
                    .unwrap_or_else(|e| warn!("Failed to cleanup extracted binary: {}", e));

                Ok(UpdateResult::UpdateInstalled {
                    from_version: current_version.to_string(),
                    to_version: new_version.to_string(),
                })
            }
            Err(e) => {
                error!("Update installation failed: {}", e);

                let rollback_result = transaction.rollback().await;
                let rollback_performed = rollback_result.is_ok();

                if let Err(re) = rollback_result {
                    error!("Rollback also failed: {}", re);
                }

                Ok(UpdateResult::UpdateFailed {
                    error: e.to_string(),
                    rollback_performed,
                })
            }
        }
    }

    async fn rollback_update(&self) -> Result<UpdateResult, UpdateError> {
        warn!("Manual rollback requested");

        let backup_dir = &self.backup_dir;
        if !backup_dir.exists() {
            return Err(UpdateError::RollbackFailed(
                "No backup directory found. Cannot perform rollback.".to_string(),
            ));
        }

        let mut backup_entries =
            tokio::fs::read_dir(backup_dir)
                .await
                .map_err(|e| UpdateError::FileSystem {
                    path: backup_dir.clone(),
                    source: e,
                })?;

        let mut backup_files = Vec::new();
        while let Some(entry) =
            backup_entries
                .next_entry()
                .await
                .map_err(|e| UpdateError::FileSystem {
                    path: backup_dir.clone(),
                    source: e,
                })?
        {
            let path = entry.path();
            if path.is_file()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.starts_with("dnspx-") && s.ends_with(".backup"))
                    .unwrap_or(false)
            {
                if let Ok(metadata) = entry.metadata().await {
                    backup_files.push((path, metadata.modified().unwrap_or(std::time::UNIX_EPOCH)));
                }
            }
        }

        if backup_files.is_empty() {
            return Err(UpdateError::RollbackFailed(
                "No backup files found. Cannot perform rollback.".to_string(),
            ));
        }

        backup_files.sort_by(|a, b| b.1.cmp(&a.1));
        let (most_recent_backup, _) = &backup_files[0];

        let backup_filename = most_recent_backup
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| UpdateError::RollbackFailed("Invalid backup filename".to_string()))?;

        let backup_version_str = backup_filename
            .strip_prefix("dnspx-")
            .and_then(|s| s.strip_suffix(".backup"))
            .ok_or_else(|| {
                UpdateError::RollbackFailed(format!(
                    "Cannot extract version from backup filename: {}",
                    backup_filename
                ))
            })?;

        let backup_version = Version::parse(backup_version_str).map_err(|e| {
            UpdateError::RollbackFailed(format!(
                "Invalid version in backup filename '{}': {}",
                backup_filename, e
            ))
        })?;

        let current_version = Version::parse(env!("CARGO_PKG_VERSION"))
            .map_err(|e| UpdateError::InvalidVersion(format!("Invalid current version: {}", e)))?;

        info!(
            "Performing manual rollback from v{} to v{}",
            current_version, backup_version
        );

        let backup_path = most_recent_backup.clone();
        let current_binary_path = self.current_binary_path.clone();
        let config = self.config.read().await;
        let health_check_enabled = config.rollback.health_check_enabled;
        drop(config);

        tokio::task::spawn_blocking(move || -> Result<(), UpdateError> {
            use self_update::Move;

            let mut move_op = Move::from_source(&backup_path);

            let temp_path = current_binary_path.with_extension("rollback_temp");
            move_op.replace_using_temp(&temp_path);

            move_op.to_dest(&current_binary_path).map_err(|e| {
                UpdateError::RollbackFailed(format!(
                    "Failed to restore backup using self_update: {}",
                    e
                ))
            })
        })
        .await
        .map_err(|e| UpdateError::RollbackFailed(format!("Rollback task failed: {}", e)))??;

        if health_check_enabled {
            let health_check = async {
                let output = std::process::Command::new(&self.current_binary_path)
                    .arg("--version")
                    .output()
                    .map_err(|e| {
                        UpdateError::RollbackFailed(format!("Health check failed: {}", e))
                    })?;

                if !output.status.success() {
                    return Err(UpdateError::RollbackFailed(
                        "Binary health check failed after rollback: exit code non-zero".to_string(),
                    ));
                }

                let version_output = String::from_utf8_lossy(&output.stdout);
                debug!("Rollback health check output: {}", version_output.trim());

                Ok::<(), UpdateError>(())
            };

            let config = self.config.read().await;
            let timeout_duration = config.rollback.health_check_timeout;
            drop(config);

            tokio::time::timeout(timeout_duration, health_check)
                .await
                .map_err(|_| {
                    UpdateError::RollbackFailed("Health check timed out after rollback".to_string())
                })??;
        }

        info!(
            "Manual rollback completed successfully: v{} -> v{}",
            current_version, backup_version
        );

        Ok(UpdateResult::UpdateInstalled {
            from_version: current_version.to_string(),
            to_version: backup_version.to_string(),
        })
    }

    fn get_current_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    async fn is_rollback_available(&self) -> bool {
        if !self.backup_dir.exists() {
            return false;
        }

        match tokio::fs::read_dir(&self.backup_dir).await {
            Ok(mut entries) => {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.is_file()
                        && path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .map(|s| s.starts_with("dnspx-") && s.ends_with(".backup"))
                            .unwrap_or(false)
                    {
                        return true;
                    }
                }
                false
            }
            Err(_) => false,
        }
    }
}
