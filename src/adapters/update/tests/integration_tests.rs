use super::test_utils::*;
use crate::adapters::update::release_analyzer::ReleaseAnalyzer;
use crate::adapters::update::security::SecurityValidator;
use crate::adapters::update::transaction::UpdateTransaction;
use crate::config::models::{
    UpdateAutoPolicy, UpdateLevel, UpdateRollbackConfig, UpdateSecurityConfig,
};
use reqwest::Client;
use semver::Version;
use std::time::Duration;

/// Creates a complete test setup for integration testing
async fn create_test_update_components() -> (SecurityValidator, ReleaseAnalyzer, tempfile::TempDir)
{
    let temp_dir = create_test_dir();

    let security_config = UpdateSecurityConfig {
        verify_checksums: false, // Disable for integration testing
        verify_signatures: false,
        require_attestations: false,
        trusted_builders: vec!["https://github.com/actions".to_string()],
        attestation_repo: "mwenner/dnspx".to_string(),
        require_slsa_level: 0,
        allowed_update_domains: vec!["github.com".to_string(), "api.github.com".to_string()],
        max_download_size_mb: 100,
    };

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client");

    let security_validator = SecurityValidator::new(security_config, client);
    let release_analyzer = ReleaseAnalyzer::new();

    (security_validator, release_analyzer, temp_dir)
}

/// Creates a test transaction for integration testing
async fn create_test_transaction(temp_dir: &tempfile::TempDir) -> UpdateTransaction {
    let current_binary_content = create_test_executable_content("1.0.0");
    let current_binary =
        create_test_binary(temp_dir.path(), "dnspx-current", &current_binary_content).await;

    let backup_dir = temp_dir.path().join("backups");

    let config = UpdateRollbackConfig {
        enabled: true,
        keep_backups: 3,
        health_check_timeout: Duration::from_secs(1), // Short timeout for testing
        health_check_enabled: false,                  // Disable to avoid issues with test binaries
    };

    UpdateTransaction::new(
        current_binary,
        backup_dir,
        Version::new(1, 1, 0),
        Version::new(1, 0, 0),
        config,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_update_workflow_analysis() {
        let (security_validator, analyzer, _temp_dir) = create_test_update_components().await;

        // Test URL validation
        let update_url = "https://github.com/owner/repo/releases/download/v1.1.0/dnspx-linux";
        let url_result = security_validator.validate_url(update_url);
        assert!(url_result.is_ok(), "Update URL should be valid");

        // Test release analysis
        let release_notes = "
## What's Changed
- Fix memory leak in DNS resolution
- Add performance improvements
- Update dependencies for security
        ";

        let metadata = analyzer
            .analyze_release_notes(release_notes, "1.1.0")
            .unwrap();
        assert_eq!(metadata.version, Version::new(1, 1, 0));
        assert!(
            !metadata.has_breaking_changes,
            "Should not detect breaking changes"
        );

        // Test auto-update decision
        let policy = UpdateAutoPolicy {
            update_level: UpdateLevel::MinorAndPatch,
            allow_breaking_changes: false,
            require_security_approval: false,
        };

        let current_version = Version::new(1, 0, 0);
        let should_update =
            analyzer.should_auto_update(&policy, &current_version, &metadata.version, &metadata);
        assert!(
            should_update,
            "Should allow minor update with MinorAndPatch policy"
        );
    }

    #[tokio::test]
    async fn test_security_blocks_unsafe_update() {
        let (security_validator, analyzer, _temp_dir) = create_test_update_components().await;

        // Test blocked URL
        let malicious_url = "https://malicious-site.com/fake-update.exe";
        let url_result = security_validator.validate_url(malicious_url);
        assert!(url_result.is_err(), "Malicious URL should be blocked");

        // Test breaking changes detection
        let breaking_notes = "
## Breaking Changes
- 💥 Remove deprecated API
- Change configuration format
        ";

        let metadata = analyzer
            .analyze_release_notes(breaking_notes, "2.0.0")
            .unwrap();
        assert!(
            metadata.has_breaking_changes,
            "Should detect breaking changes"
        );

        // Test auto-update blocks breaking changes
        let policy = UpdateAutoPolicy {
            update_level: UpdateLevel::All,
            allow_breaking_changes: false,
            require_security_approval: false,
        };

        let current_version = Version::new(1, 0, 0);
        let should_update =
            analyzer.should_auto_update(&policy, &current_version, &metadata.version, &metadata);
        assert!(
            !should_update,
            "Should block breaking changes even with All policy"
        );
    }

    #[tokio::test]
    async fn test_security_allows_security_patches() {
        let (_security_validator, analyzer, _temp_dir) = create_test_update_components().await;

        // Test security patch detection and prioritization
        let security_notes = "
## Security Update
- Fix critical vulnerability (CVE-2024-1234)
- Security patch for authentication bypass
        ";

        let metadata = analyzer
            .analyze_release_notes(security_notes, "1.0.1")
            .unwrap();
        assert!(metadata.security_fixes, "Should detect security fixes");

        // Security patches should override restrictive policies
        let restrictive_policy = UpdateAutoPolicy {
            update_level: UpdateLevel::None,
            allow_breaking_changes: false,
            require_security_approval: false,
        };

        let current_version = Version::new(1, 0, 0);
        let should_update = analyzer.should_auto_update(
            &restrictive_policy,
            &current_version,
            &metadata.version,
            &metadata,
        );
        // Note: Current implementation allows security fixes to override policies within same major version
        assert!(
            should_update,
            "Security fixes should override restrictive policies"
        );
    }

    #[tokio::test]
    async fn test_transaction_backup_and_rollback_flow() {
        let (_security_validator, _analyzer, temp_dir) = create_test_update_components().await;
        let mut transaction = create_test_transaction(&temp_dir).await;

        // Test backup preparation
        let prepare_result = transaction.prepare().await;
        assert!(prepare_result.is_ok(), "Transaction prepare should succeed");
        assert!(
            transaction.is_rollback_available(),
            "Rollback should be available after prepare"
        );

        // Create a new binary for commit
        let new_binary_content = create_test_executable_content("1.1.0");
        let new_binary_path =
            create_test_binary(temp_dir.path(), "dnspx-new", &new_binary_content).await;

        // Test commit
        let commit_result = transaction.commit(&new_binary_path).await;
        assert!(commit_result.is_ok(), "Transaction commit should succeed");

        // Test rollback capability
        let rollback_result = transaction.rollback().await;
        assert!(
            rollback_result.is_ok(),
            "Transaction rollback should succeed"
        );
    }

    #[tokio::test]
    async fn test_version_comparison_logic() {
        let (_security_validator, analyzer, _temp_dir) = create_test_update_components().await;

        // Test version breaking change detection
        let v1_0_0 = Version::new(1, 0, 0);
        let v1_0_1 = Version::new(1, 0, 1); // patch
        let v1_1_0 = Version::new(1, 1, 0); // minor
        let v2_0_0 = Version::new(2, 0, 0); // major

        assert!(
            !analyzer.has_breaking_changes(&v1_0_0, &v1_0_1),
            "Patch should not be breaking"
        );
        assert!(
            !analyzer.has_breaking_changes(&v1_0_0, &v1_1_0),
            "Minor should not be breaking"
        );
        assert!(
            analyzer.has_breaking_changes(&v1_0_0, &v2_0_0),
            "Major should be breaking"
        );

        // Test downgrade prevention
        let policy = UpdateAutoPolicy {
            update_level: UpdateLevel::All,
            allow_breaking_changes: true,
            require_security_approval: false,
        };

        let downgrade_metadata = analyzer
            .analyze_release_notes("Rollback release", "0.9.0")
            .unwrap();
        let should_downgrade = analyzer.should_auto_update(
            &policy,
            &v1_0_0,
            &downgrade_metadata.version,
            &downgrade_metadata,
        );
        assert!(!should_downgrade, "Should never allow downgrades");
    }

    #[tokio::test]
    async fn test_comprehensive_validation_workflow() {
        let (security_validator, analyzer, temp_dir) = create_test_update_components().await;

        // Simulate a complete validation workflow

        // Step 1: Validate update source
        let update_url = "https://github.com/mwenner/dnspx/releases/download/v1.1.0/dnspx-linux";
        assert!(security_validator.validate_url(update_url).is_ok());

        // Step 2: Analyze release notes
        let release_notes = "
## DNSPX v1.1.0 Release Notes

### New Features
- Add IPv6 support for DNS resolution
- Implement connection pooling for better performance

### Bug Fixes
- Fix race condition in cache invalidation
- Resolve memory leak in long-running instances

### Security
- Update dependencies to address minor vulnerability
- Improve input validation for DNS queries
        ";

        let metadata = analyzer
            .analyze_release_notes(release_notes, "1.1.0")
            .unwrap();
        assert_eq!(metadata.version, Version::new(1, 1, 0));
        assert!(!metadata.has_breaking_changes);
        assert!(metadata.security_fixes); // Should detect security mentions
        assert!(!metadata.new_features.is_empty());
        assert!(!metadata.bug_fixes.is_empty());

        // Step 3: Check auto-update policy
        let policy = UpdateAutoPolicy {
            update_level: UpdateLevel::MinorAndPatch,
            allow_breaking_changes: false,
            require_security_approval: false,
        };

        let current_version = Version::new(1, 0, 5);
        let should_update =
            analyzer.should_auto_update(&policy, &current_version, &metadata.version, &metadata);
        assert!(
            should_update,
            "Should allow minor update with security fixes"
        );

        // Step 4: Prepare transaction
        let mut transaction = create_test_transaction(&temp_dir).await;
        assert!(transaction.prepare().await.is_ok());

        // Step 5: Validate download (simplified - no actual download)
        let test_binary_content = create_test_executable_content("1.1.0");
        let test_binary_path =
            create_test_binary(temp_dir.path(), "test-download", &test_binary_content).await;

        let validation_result = security_validator
            .validate_download(&test_binary_path, None, None)
            .await;
        assert!(
            validation_result.is_ok(),
            "Validation should succeed with checksum disabled"
        );

        // Step 6: Commit update
        assert!(transaction.commit(&test_binary_path).await.is_ok());

        // Complete workflow should succeed
        // Test passed - all validation steps completed successfully
    }
}
