use crate::config::models::{UpdateAutoPolicy, UpdateLevel};
use crate::core::error::UpdateError;
use semver::Version;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReleaseMetadata {
    pub version: Version,
    pub has_breaking_changes: bool,
    pub security_fixes: bool,
    pub deprecations: Vec<String>,
    pub new_features: Vec<String>,
    pub bug_fixes: Vec<String>,
}

pub(crate) struct ReleaseAnalyzer;

impl ReleaseAnalyzer {
    pub(crate) fn new() -> Self {
        Self
    }

    pub(crate) fn analyze_release_notes(
        &self,
        body: &str,
        version: &str,
    ) -> Result<ReleaseMetadata, UpdateError> {
        let version = Version::parse(version).map_err(|e| {
            UpdateError::InvalidVersion(format!("Invalid version {}: {}", version, e))
        })?;

        let body_lower = body.to_lowercase();

        let has_breaking_changes = self.detect_breaking_changes(&body_lower);
        let security_fixes = self.detect_security_fixes(&body_lower);
        let deprecations = self.extract_deprecations(body);
        let new_features = self.extract_new_features(body);
        let bug_fixes = self.extract_bug_fixes(body);

        debug!(
            "Release analysis for v{}: breaking={}, security={}, features={}, fixes={}",
            version,
            has_breaking_changes,
            security_fixes,
            new_features.len(),
            bug_fixes.len()
        );

        Ok(ReleaseMetadata {
            version,
            has_breaking_changes,
            security_fixes,
            deprecations,
            new_features,
            bug_fixes,
        })
    }

    pub(crate) fn has_breaking_changes(&self, from: &Version, to: &Version) -> bool {
        to.major > from.major
    }

    fn detect_breaking_changes(&self, body: &str) -> bool {
        let breaking_indicators = [
            "breaking change",
            "breaking:",
            "💥",
            "⚠️ breaking",
            "backwards incompatible",
            "breaking api change",
            "[breaking]",
        ];

        breaking_indicators
            .iter()
            .any(|indicator| body.contains(indicator))
    }

    fn detect_security_fixes(&self, body: &str) -> bool {
        let security_indicators = [
            "security fix",
            "security update",
            "vulnerability",
            "cve-",
            "security patch",
            "🔒",
            "[security]",
            "rustsec-",
        ];

        security_indicators
            .iter()
            .any(|indicator| body.contains(indicator))
    }

    fn extract_deprecations(&self, body: &str) -> Vec<String> {
        let mut deprecations = Vec::new();

        for line in body.lines() {
            let line = line.trim().to_lowercase();
            if line.contains("deprecat") || line.contains("⚠️") {
                if let Some(original) = body.lines().find(|l| l.trim().to_lowercase() == line) {
                    deprecations.push(original.trim().to_string());
                }
            }
        }

        deprecations
    }

    fn extract_new_features(&self, body: &str) -> Vec<String> {
        let mut features = Vec::new();

        for line in body.lines() {
            let line = line.trim();
            if line.starts_with("- ")
                && (line.to_lowercase().contains("add")
                    || line.to_lowercase().contains("new")
                    || line.to_lowercase().contains("feature")
                    || line.contains("✨")
                    || line.contains("🎉"))
            {
                features.push(line.trim_start_matches("- ").to_string());
            }
        }

        features
    }

    fn extract_bug_fixes(&self, body: &str) -> Vec<String> {
        let mut fixes = Vec::new();

        for line in body.lines() {
            let line = line.trim();
            if line.starts_with("- ")
                && (line.to_lowercase().contains("fix")
                    || line.to_lowercase().contains("bug")
                    || line.to_lowercase().contains("resolve")
                    || line.contains("🐛"))
            {
                fixes.push(line.trim_start_matches("- ").to_string());
            }
        }

        fixes
    }

    pub(crate) fn should_auto_update(
        &self,
        metadata: &ReleaseMetadata,
        current_version: &Version,
        auto_update_policy: &UpdateAutoPolicy,
    ) -> bool {
        if metadata.has_breaking_changes && !auto_update_policy.allow_breaking_changes {
            debug!("Skipping auto-update due to breaking changes");
            return false;
        }

        match auto_update_policy.update_level {
            UpdateLevel::None => false,
            UpdateLevel::PatchOnly => {
                metadata.version.major == current_version.major
                    && metadata.version.minor == current_version.minor
                    && metadata.version.patch > current_version.patch
            }
            UpdateLevel::MinorAndPatch => {
                metadata.version.major == current_version.major
                    && (metadata.version.minor > current_version.minor
                        || (metadata.version.minor == current_version.minor
                            && metadata.version.patch > current_version.patch))
            }
            UpdateLevel::All => metadata.version > *current_version,
        }
    }
}
