use crate::config::models::UpdateSecurityConfig;
use crate::core::error::UpdateError;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs;
use tracing::{debug, error, info, warn};

pub(crate) struct SecurityValidator {
    config: UpdateSecurityConfig,
    http_client: Client,
}

impl SecurityValidator {
    pub(crate) fn new(config: UpdateSecurityConfig, http_client: Client) -> Self {
        Self {
            config,
            http_client,
        }
    }

    pub(crate) async fn validate_download(
        &self,
        file_path: &Path,
        expected_checksum_url: Option<&str>,
        signature_url: Option<&str>,
    ) -> Result<(), UpdateError> {
        if self.config.verify_checksums {
            if let Some(checksum_url) = expected_checksum_url {
                self.verify_checksum(file_path, checksum_url).await?;
            } else {
                warn!("Checksum verification enabled but no checksum URL provided");
            }
        }

        if self.config.verify_signatures {
            if let Some(sig_url) = signature_url {
                self.verify_signature(file_path, sig_url).await?;
            } else if self.config.verify_signatures {
                return Err(UpdateError::SecurityValidation(
                    "Signature verification required but no signature URL provided".to_string(),
                ));
            }
        }

        if self.config.require_attestations {
            warn!("Build attestation verification not yet implemented");
        }

        Ok(())
    }

    async fn verify_checksum(
        &self,
        file_path: &Path,
        checksum_url: &str,
    ) -> Result<(), UpdateError> {
        debug!("Downloading checksum from: {}", checksum_url);

        let response = self
            .http_client
            .get(checksum_url)
            .send()
            .await
            .map_err(UpdateError::Network)?;

        if !response.status().is_success() {
            return Err(UpdateError::SecurityValidation(format!(
                "Failed to download checksum: HTTP {}",
                response.status()
            )));
        }

        let checksum_content = response.text().await.map_err(UpdateError::Network)?;
        let expected_checksum = self.parse_checksum_file(&checksum_content)?;

        debug!("Computing SHA256 checksum for downloaded file");
        let file_content = fs::read(file_path)
            .await
            .map_err(|e| UpdateError::FileSystem {
                path: file_path.to_path_buf(),
                source: e,
            })?;

        let mut hasher = Sha256::new();
        hasher.update(&file_content);
        let computed_checksum = format!("{:x}", hasher.finalize());

        if computed_checksum.to_lowercase() != expected_checksum.to_lowercase() {
            error!(
                "Checksum mismatch: expected {}, computed {}",
                expected_checksum, computed_checksum
            );
            return Err(UpdateError::SecurityValidation(
                "File checksum does not match expected value".to_string(),
            ));
        }

        info!("Checksum verification successful");
        Ok(())
    }

    fn parse_checksum_file(&self, content: &str) -> Result<String, UpdateError> {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(checksum) = line.split_whitespace().next() {
                if checksum.len() == 64 && checksum.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Ok(checksum.to_string());
                }
            }
        }

        Err(UpdateError::SecurityValidation(
            "No valid SHA256 checksum found in checksum file".to_string(),
        ))
    }

    async fn verify_signature(
        &self,
        _file_path: &Path,
        _signature_url: &str,
    ) -> Result<(), UpdateError> {
        warn!("GPG signature verification not yet implemented");

        if self.config.verify_signatures {
            return Err(UpdateError::SecurityValidation(
                "GPG signature verification is not yet implemented".to_string(),
            ));
        }

        Ok(())
    }
}
