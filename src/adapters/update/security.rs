use crate::config::models::UpdateSecurityConfig;
use crate::core::error::UpdateError;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs;
use tracing::{debug, error, info, warn};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct GitHubAttestation {
    bundle: AttestationBundle,
}

#[derive(Debug, Deserialize)]
struct AttestationBundle {
    #[serde(rename = "dsseEnvelope")]
    dsse_envelope: DsseEnvelope,
}

#[derive(Debug, Deserialize)]
struct DsseEnvelope {
    payload: String,
    signatures: Vec<DsseSignature>,
}

#[derive(Debug, Deserialize)]
struct DsseSignature {
    sig: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SlsaProvenance {
    #[serde(rename = "_type")]
    type_: String,
    subject: Vec<SlsaSubject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
    predicate: SlsaPredicate,
}

#[derive(Debug, Deserialize, Serialize)]
struct SlsaSubject {
    name: String,
    digest: SlsaDigest,
}

#[derive(Debug, Deserialize, Serialize)]
struct SlsaDigest {
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SlsaPredicate {
    builder: SlsaBuilder,
    #[serde(rename = "buildDefinition")]
    build_definition: SlsaBuildDefinition,
}

#[derive(Debug, Deserialize, Serialize)]
struct SlsaBuilder {
    id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SlsaBuildDefinition {
    #[serde(rename = "buildType")]
    build_type: String,
    #[serde(rename = "externalParameters")]
    external_parameters: serde_json::Value,
}

pub(crate) struct SecurityValidator {
    pub(crate) config: UpdateSecurityConfig,
    http_client: Client,
}

impl SecurityValidator {
    pub(crate) fn new(config: UpdateSecurityConfig, http_client: Client) -> Self {
        Self {
            config,
            http_client,
        }
    }

    pub(crate) fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            http_client: self.http_client.clone(),
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
                return Err(UpdateError::SecurityValidationFailed(
                    "Signature verification required but no signature URL provided".to_string(),
                ));
            }
        }

        if self.config.require_attestations {
            self.verify_attestation(file_path).await?;
        }

        Ok(())
    }

    async fn verify_attestation(&self, file_path: &Path) -> Result<(), UpdateError> {
        info!("Verifying build attestation for: {}", file_path.display());

        // Compute the SHA256 hash of the file for attestation verification
        let file_content = fs::read(file_path)
            .await
            .map_err(|e| UpdateError::FileSystem {
                path: file_path.to_path_buf(),
                source: e,
            })?;

        let mut hasher = Sha256::new();
        hasher.update(&file_content);
        let file_hash = format!("{:x}", hasher.finalize());

        debug!("File SHA256: {}", file_hash);

        // Extract filename for attestation lookup
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                UpdateError::SecurityValidationFailed("Invalid file path".to_string())
            })?;

        // For GitHub releases, attestations are typically associated with the repository
        // We'll use a heuristic to extract the repository from allowed domains
        let github_repo = self.extract_github_repo()?;

        // Fetch attestations from GitHub API
        let attestations = self.fetch_github_attestations(&github_repo, filename).await?;

        // Verify at least one attestation matches our file
        let mut attestation_verified = false;
        for attestation in attestations {
            match self.verify_single_attestation(&attestation, &file_hash, filename).await {
                Ok(()) => {
                    attestation_verified = true;
                    info!("Build attestation verification successful");
                    break;
                }
                Err(e) => {
                    debug!("Attestation verification failed: {}", e);
                    continue;
                }
            }
        }

        if !attestation_verified {
            return Err(UpdateError::SecurityValidationFailed(
                "No valid build attestation found for the downloaded file".to_string(),
            ));
        }

        Ok(())
    }

    pub(crate) fn extract_github_repo(&self) -> Result<String, UpdateError> {
        // Use the configured attestation repository
        Ok(self.config.attestation_repo.clone())
    }

    async fn fetch_github_attestations(
        &self,
        repo: &str,
        filename: &str,
    ) -> Result<Vec<GitHubAttestation>, UpdateError> {
        debug!("Fetching attestations for {} from repo {}", filename, repo);

        // GitHub's attestations API endpoint
        let url = format!("https://api.github.com/repos/{}/attestations", repo);

        let response = self
            .http_client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", format!("dnspx/{}", env!("CARGO_PKG_VERSION")))
            .send()
            .await
            .map_err(UpdateError::Network)?;

        if !response.status().is_success() {
            if response.status() == 404 {
                return Err(UpdateError::SecurityValidationFailed(
                    "No attestations found for this repository".to_string(),
                ));
            }
            return Err(UpdateError::SecurityValidationFailed(format!(
                "Failed to fetch attestations: HTTP {}",
                response.status()
            )));
        }

        let attestations_response: serde_json::Value = response.json().await.map_err(UpdateError::Network)?;
        
        // GitHub returns attestations in an array under "attestations"
        let attestations_array = attestations_response
            .get("attestations")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                UpdateError::SecurityValidationFailed(
                    "Invalid attestations response format".to_string(),
                )
            })?;

        let mut matching_attestations = Vec::new();
        for attestation_value in attestations_array {
            if let Ok(attestation) = serde_json::from_value::<GitHubAttestation>(attestation_value.clone()) {
                matching_attestations.push(attestation);
            }
        }

        if matching_attestations.is_empty() {
            return Err(UpdateError::SecurityValidationFailed(
                "No valid attestations found in repository".to_string(),
            ));
        }

        Ok(matching_attestations)
    }

    async fn verify_single_attestation(
        &self,
        attestation: &GitHubAttestation,
        expected_hash: &str,
        filename: &str,
    ) -> Result<(), UpdateError> {
        debug!("Verifying individual attestation for {}", filename);

        // Decode the base64 payload
        let payload_bytes = general_purpose::STANDARD
            .decode(&attestation.bundle.dsse_envelope.payload)
            .map_err(|e| {
                UpdateError::SecurityValidationFailed(format!(
                    "Failed to decode attestation payload: {}",
                    e
                ))
            })?;

        let payload_str = String::from_utf8(payload_bytes).map_err(|e| {
            UpdateError::SecurityValidationFailed(format!(
                "Invalid UTF-8 in attestation payload: {}",
                e
            ))
        })?;

        // Parse the SLSA provenance
        let provenance: SlsaProvenance = serde_json::from_str(&payload_str).map_err(|e| {
            UpdateError::SecurityValidationFailed(format!(
                "Failed to parse SLSA provenance: {}",
                e
            ))
        })?;

        debug!("SLSA provenance type: {}", provenance.type_);
        debug!("SLSA predicate type: {}", provenance.predicate_type);

        // Verify this is a valid SLSA provenance
        if !provenance.predicate_type.contains("slsa-provenance") {
            return Err(UpdateError::SecurityValidationFailed(
                "Not a valid SLSA provenance attestation".to_string(),
            ));
        }

        // Find the subject that matches our file
        let mut subject_found = false;
        for subject in &provenance.subject {
            if subject.name.contains(filename) || subject.name.ends_with(filename) {
                if subject.digest.sha256.to_lowercase() == expected_hash.to_lowercase() {
                    subject_found = true;
                    debug!("Found matching subject: {} with hash {}", subject.name, subject.digest.sha256);
                    break;
                } else {
                    return Err(UpdateError::SecurityValidationFailed(format!(
                        "Hash mismatch in attestation: expected {}, found {}",
                        expected_hash,
                        subject.digest.sha256
                    )));
                }
            }
        }

        if !subject_found {
            return Err(UpdateError::SecurityValidationFailed(format!(
                "File {} not found in attestation subjects",
                filename
            )));
        }

        // Verify the builder is in the trusted builders list
        let builder_trusted = self.config.trusted_builders.iter().any(|trusted| {
            provenance.predicate.builder.id.contains(trusted) || 
            provenance.predicate.builder.id.starts_with(trusted)
        });

        if !builder_trusted {
            return Err(UpdateError::SecurityValidationFailed(format!(
                "Untrusted builder '{}'. Trusted builders: {:?}",
                provenance.predicate.builder.id,
                self.config.trusted_builders
            )));
        }

        info!("Attestation verification successful for {}", filename);
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
            return Err(UpdateError::SecurityValidationFailed(format!(
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
            return Err(UpdateError::SecurityValidationFailed(
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

        Err(UpdateError::SecurityValidationFailed(
            "No valid SHA256 checksum found in checksum file".to_string(),
        ))
    }

    pub(crate) fn validate_url(&self, url: &str) -> Result<(), UpdateError> {
        // Parse URL to validate format
        let parsed_url = url::Url::parse(url)
            .map_err(|_| UpdateError::SecurityValidationFailed("Invalid URL format".to_string()))?;

        // Check protocol
        match parsed_url.scheme() {
            "https" => {}, // Always allowed
            "http" => {
                // Only allow HTTP for localhost/test scenarios
                if let Some(host) = parsed_url.host_str() {
                    if !host.starts_with("127.0.0.1") && !host.starts_with("localhost") {
                        return Err(UpdateError::SecurityValidationFailed(
                            "HTTP downloads only allowed from localhost".to_string()
                        ));
                    }
                }
            },
            _ => return Err(UpdateError::SecurityValidationFailed(
                format!("Unsupported protocol: {}", parsed_url.scheme())
            )),
        }

        // Check domain whitelist
        if let Some(host) = parsed_url.host_str() {
            let is_allowed = self.config.allowed_update_domains.iter()
                .any(|domain| host.ends_with(domain) || host == domain);
            
            if !is_allowed {
                return Err(UpdateError::SecurityValidationFailed(
                    format!("Domain not in allowlist: {}", host)
                ));
            }
        }

        Ok(())
    }

    async fn verify_signature(
        &self,
        _file_path: &Path,
        _signature_url: &str,
    ) -> Result<(), UpdateError> {
        warn!("GPG signature verification not yet implemented");

        if self.config.verify_signatures {
            return Err(UpdateError::NotImplemented(
                "GPG signature verification is not yet implemented".to_string(),
            ));
        }

        Ok(())
    }
}
