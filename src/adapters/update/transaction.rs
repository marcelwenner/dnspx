use crate::config::models::UpdateRollbackConfig;
use crate::core::error::UpdateError;
use semver::Version;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::fs;
use tokio::time::timeout;
use tracing::{debug, info, warn};

pub(crate) struct UpdateTransaction {
    current_binary_path: PathBuf,
    backup_dir: PathBuf,
    new_version: Version,
    old_version: Version,
    config: UpdateRollbackConfig,
    backup_path: Option<PathBuf>,
}

impl UpdateTransaction {
    pub(crate) fn new(
        current_binary_path: PathBuf,
        backup_dir: PathBuf,
        new_version: Version,
        old_version: Version,
        config: UpdateRollbackConfig,
    ) -> Self {
        Self {
            current_binary_path,
            backup_dir,
            new_version,
            old_version,
            config,
            backup_path: None,
        }
    }

    pub(crate) async fn prepare(&mut self) -> Result<(), UpdateError> {
        if !self.config.enabled {
            debug!("Rollback is disabled, skipping backup preparation");
            return Ok(());
        }

        info!(
            "Preparing update transaction for v{} -> v{}",
            self.old_version, self.new_version
        );

        fs::create_dir_all(&self.backup_dir)
            .await
            .map_err(|e| UpdateError::FileSystem {
                path: self.backup_dir.clone(),
                source: e,
            })?;

        let backup_filename = format!("dnspx-{}.backup", self.old_version);
        let backup_path = self.backup_dir.join(backup_filename);

        debug!("Creating backup at: {}", backup_path.display());
        fs::copy(&self.current_binary_path, &backup_path)
            .await
            .map_err(|e| UpdateError::FileSystem {
                path: backup_path.clone(),
                source: e,
            })?;

        self.backup_path = Some(backup_path);

        self.cleanup_old_backups().await?;

        info!("Backup created successfully");
        Ok(())
    }

    pub(crate) async fn commit(&self, new_binary_path: &Path) -> Result<(), UpdateError> {
        info!("Committing update transaction");

        debug!(
            "Replacing binary: {} -> {}",
            new_binary_path.display(),
            self.current_binary_path.display()
        );

        let new_binary_path = new_binary_path.to_path_buf();
        let current_binary_path = self.current_binary_path.clone();
        let health_check_enabled = self.config.health_check_enabled;

        tokio::task::spawn_blocking(move || -> Result<(), UpdateError> {
            use self_update::Move;

            let mut move_op = Move::from_source(&new_binary_path);

            let temp_path = current_binary_path.with_extension("temp");
            move_op.replace_using_temp(&temp_path);

            move_op.to_dest(&current_binary_path).map_err(|e| {
                UpdateError::InstallationFailed(format!(
                    "Failed to replace binary using self_update: {}",
                    e
                ))
            })
        })
        .await
        .map_err(|e| {
            UpdateError::InstallationFailed(format!("Binary replacement task failed: {}", e))
        })??;

        if health_check_enabled {
            self.health_check().await?;
        }

        info!("Update transaction committed successfully");
        Ok(())
    }

    pub(crate) async fn rollback(&self) -> Result<(), UpdateError> {
        if !self.config.enabled {
            return Err(UpdateError::RollbackFailed(
                "Rollback is disabled".to_string(),
            ));
        }

        let backup_path = self.backup_path.as_ref().ok_or_else(|| {
            UpdateError::RollbackFailed("No backup available for rollback".to_string())
        })?;

        warn!(
            "Rolling back update from v{} to v{}",
            self.new_version, self.old_version
        );

        if !backup_path.exists() {
            return Err(UpdateError::RollbackFailed(format!(
                "Backup file not found: {}",
                backup_path.display()
            )));
        }

        fs::copy(backup_path, &self.current_binary_path)
            .await
            .map_err(|e| UpdateError::FileSystem {
                path: self.current_binary_path.clone(),
                source: e,
            })?;

        if self.config.health_check_enabled {
            self.health_check().await.map_err(|e| {
                UpdateError::RollbackFailed(format!("Health check failed after rollback: {}", e))
            })?;
        }

        info!("Rollback completed successfully");
        Ok(())
    }

    async fn health_check(&self) -> Result<(), UpdateError> {
        debug!(
            "Performing health check with timeout: {:?}",
            self.config.health_check_timeout
        );

        let health_check = async {
            let output = Command::new(&self.current_binary_path)
                .arg("--version")
                .output()
                .map_err(|e| {
                    UpdateError::InstallationFailed(format!("Health check failed: {}", e))
                })?;

            if !output.status.success() {
                return Err(UpdateError::InstallationFailed(
                    "Binary health check failed: exit code non-zero".to_string(),
                ));
            }

            let version_output = String::from_utf8_lossy(&output.stdout);
            debug!("Health check output: {}", version_output.trim());

            Ok::<(), UpdateError>(())
        };

        timeout(self.config.health_check_timeout, health_check)
            .await
            .map_err(|_| UpdateError::InstallationFailed("Health check timed out".to_string()))?
    }

    async fn cleanup_old_backups(&self) -> Result<(), UpdateError> {
        if self.config.keep_backups == 0 {
            return Ok(());
        }

        debug!(
            "Cleaning up old backups, keeping {} most recent",
            self.config.keep_backups
        );

        let mut entries =
            fs::read_dir(&self.backup_dir)
                .await
                .map_err(|e| UpdateError::FileSystem {
                    path: self.backup_dir.clone(),
                    source: e,
                })?;

        let mut backup_files = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| UpdateError::FileSystem {
                path: self.backup_dir.clone(),
                source: e,
            })?
        {
            let path = entry.path();
            if path.is_file()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|s| s.ends_with(".backup"))
                    .unwrap_or(false)
            {
                if let Ok(metadata) = entry.metadata().await {
                    backup_files.push((path, metadata.modified().unwrap_or(std::time::UNIX_EPOCH)));
                }
            }
        }

        backup_files.sort_by(|a, b| b.1.cmp(&a.1));

        for (path, _) in backup_files
            .into_iter()
            .skip(self.config.keep_backups as usize)
        {
            debug!("Removing old backup: {}", path.display());
            if let Err(e) = fs::remove_file(&path).await {
                warn!("Failed to remove old backup {}: {}", path.display(), e);
            }
        }

        Ok(())
    }

    pub(crate) fn is_rollback_available(&self) -> bool {
        self.config.enabled
            && self
                .backup_path
                .as_ref()
                .map(|p| p.exists())
                .unwrap_or(false)
    }
}
