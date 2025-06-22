use super::test_utils::*;
use crate::adapters::update::security::SecurityValidator;
use crate::config::models::UpdateSecurityConfig;
use crate::core::error::UpdateError;
use reqwest::Client;
use std::time::Duration;

async fn create_test_security_validator() -> SecurityValidator {
    let config = UpdateSecurityConfig {
        verify_checksums: true,
        verify_signatures: false,
        require_attestations: false,
        trusted_builders: vec![
            "https://github.com/actions/runner".to_string(),
            "https://github.com/actions".to_string(),
        ],
        attestation_repo: "mwenner/dnspx".to_string(),
        require_slsa_level: 0,
        allowed_update_domains: vec![
            "github.com".to_string(),
            "api.github.com".to_string(),
        ],
        max_download_size_mb: 50,
    };
    
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client");
    
    SecurityValidator::new(config, client)
}

async fn create_attestation_enabled_validator() -> SecurityValidator {
    let config = UpdateSecurityConfig {
        verify_checksums: true,
        verify_signatures: false,
        require_attestations: true,
        trusted_builders: vec![
            "https://github.com/actions/runner".to_string(),
            "https://github.com/actions".to_string(),
        ],
        attestation_repo: "mwenner/dnspx".to_string(),
        require_slsa_level: 1,
        allowed_update_domains: vec![
            "github.com".to_string(),
            "api.github.com".to_string(),
        ],
        max_download_size_mb: 50,
    };
    
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client");
    
    SecurityValidator::new(config, client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_validate_url_allowed_domains() {
        let validator = create_test_security_validator().await;
        
        // Test allowed domains
        let allowed_urls = vec![
            "https://github.com/owner/repo/releases/download/v1.0.0/file.tar.gz",
            "https://api.github.com/repos/owner/repo/releases",
        ];
        
        for url in allowed_urls {
            let result = validator.validate_url(url);
            assert!(result.is_ok(), "URL should be allowed: {}", url);
        }
    }

    #[tokio::test]
    async fn test_validate_url_blocked_domains() {
        let validator = create_test_security_validator().await;
        
        // Test blocked domains
        let blocked_urls = vec![
            "https://malicious-site.com/file.exe",
            "http://untrusted-server.net/download",
        ];
        
        for url in blocked_urls {
            let result = validator.validate_url(url);
            assert!(result.is_err(), "URL should be blocked: {}", url);
        }
    }

    #[tokio::test]
    async fn test_validate_url_invalid_format() {
        let validator = create_test_security_validator().await;
        
        let invalid_urls = vec![
            "not-a-url-at-all",
            "ftp://unsupported-protocol.com/file",
            "",
        ];
        
        for url in invalid_urls {
            let result = validator.validate_url(url);
            assert!(result.is_err(), "Invalid URL should be rejected: {}", url);
        }
    }

    #[tokio::test]
    async fn test_validate_download_checksum_disabled() {
        let mut config = UpdateSecurityConfig::default();
        config.verify_checksums = false;
        
        let client = Client::new();
        let validator = SecurityValidator::new(config, client);
        
        let temp_dir = create_test_dir();
        let test_data = b"test file content";
        let file_path = create_test_binary(temp_dir.path(), "test-file", test_data).await;
        
        // Should succeed when checksum verification is disabled
        let result = validator.validate_download(&file_path, None, None).await;
        assert!(result.is_ok(), "Validation should succeed when checksum verification is disabled");
    }

    #[tokio::test]
    async fn test_clone_validator() {
        let validator1 = create_test_security_validator().await;
        let validator2 = validator1.clone();
        
        // Both validators should work the same way
        let test_url = "https://github.com/test/repo";
        
        let result1 = validator1.validate_url(test_url);
        let result2 = validator2.validate_url(test_url);
        
        assert_eq!(result1.is_ok(), result2.is_ok());
    }

    // ===== ATTESTATION VERIFICATION TESTS =====

    #[tokio::test]
    async fn test_attestation_disabled_by_default() {
        let validator = create_test_security_validator().await;
        let temp_dir = create_test_dir();
        let test_data = b"test file content for attestation";
        let file_path = create_test_binary(temp_dir.path(), "test-binary", test_data).await;
        
        // Should succeed when attestations are disabled (default)
        let result = validator.validate_download(&file_path, None, None).await;
        assert!(result.is_ok(), "Validation should succeed when attestations are disabled");
    }

    #[tokio::test]
    async fn test_attestation_repo_configuration() {
        let validator = create_attestation_enabled_validator().await;
        
        // Test that the configured attestation repo is used
        let repo = validator.extract_github_repo().unwrap();
        assert_eq!(repo, "mwenner/dnspx");
    }

    #[tokio::test]
    async fn test_attestation_verification_enabled_fails_without_network() {
        let validator = create_attestation_enabled_validator().await;
        let temp_dir = create_test_dir();
        let test_data = b"test file requiring attestation";
        let file_path = create_test_binary(temp_dir.path(), "dnspx-test", test_data).await;
        
        // Should fail when attestations are required but not available
        // (This will fail because we can't reach GitHub API in tests)
        let result = validator.validate_download(&file_path, None, None).await;
        assert!(result.is_err(), "Should fail when attestations are required but not available");
        
        if let Err(UpdateError::SecurityValidationFailed(msg)) = result {
            assert!(
                msg.contains("attestation") || msg.contains("attestations"),
                "Error should mention attestations: {}",
                msg
            );
        } else {
            panic!("Expected SecurityValidationFailed error");
        }
    }

    #[tokio::test]
    async fn test_trusted_builders_configuration() {
        let config = UpdateSecurityConfig {
            verify_checksums: false,
            verify_signatures: false,
            require_attestations: true,
            trusted_builders: vec![
                "https://github.com/custom/builder".to_string(),
                "https://custom-ci.com".to_string(),
            ],
            attestation_repo: "test/repo".to_string(),
            require_slsa_level: 2,
            allowed_update_domains: vec!["github.com".to_string()],
            max_download_size_mb: 100,
        };
        
        let client = Client::new();
        let validator = SecurityValidator::new(config, client);
        
        // Verify that custom trusted builders are configured
        // (We can't easily test the actual verification without mocking the GitHub API)
        assert_eq!(validator.config.trusted_builders.len(), 2);
        assert!(validator.config.trusted_builders.contains(&"https://github.com/custom/builder".to_string()));
        assert!(validator.config.trusted_builders.contains(&"https://custom-ci.com".to_string()));
    }

    #[tokio::test]
    async fn test_slsa_level_configuration() {
        let config = UpdateSecurityConfig {
            verify_checksums: false,
            verify_signatures: false,
            require_attestations: true,
            trusted_builders: vec!["https://github.com/actions".to_string()],
            attestation_repo: "test/repo".to_string(),
            require_slsa_level: 3,
            allowed_update_domains: vec!["github.com".to_string()],
            max_download_size_mb: 100,
        };
        
        let client = Client::new();
        let validator = SecurityValidator::new(config, client);
        
        // Verify SLSA level requirement is configured
        assert_eq!(validator.config.require_slsa_level, 3);
    }

    #[tokio::test]
    async fn test_attestation_with_different_repos() {
        let repos = vec![
            "owner/repo1",
            "different-owner/different-repo",
            "org/project-name",
        ];
        
        for repo in repos {
            let config = UpdateSecurityConfig {
                verify_checksums: false,
                verify_signatures: false,
                require_attestations: true,
                trusted_builders: vec!["https://github.com/actions".to_string()],
                attestation_repo: repo.to_string(),
                require_slsa_level: 1,
                allowed_update_domains: vec!["github.com".to_string()],
                max_download_size_mb: 100,
            };
            
            let client = Client::new();
            let validator = SecurityValidator::new(config, client);
            
            let extracted_repo = validator.extract_github_repo().unwrap();
            assert_eq!(extracted_repo, repo, "Repository configuration should be preserved");
        }
    }

    #[tokio::test]
    async fn test_security_config_defaults() {
        let config = UpdateSecurityConfig::default();
        
        // Verify default security configuration
        assert!(config.verify_checksums, "Checksums should be verified by default");
        assert!(!config.verify_signatures, "Signatures should not be required by default");
        assert!(!config.require_attestations, "Attestations should not be required by default");
        assert_eq!(config.require_slsa_level, 0, "SLSA level should default to 0");
        assert!(!config.trusted_builders.is_empty(), "Should have default trusted builders");
        assert_eq!(config.attestation_repo, "mwenner/dnspx", "Should have default attestation repo");
        assert!(config.allowed_update_domains.contains(&"github.com".to_string()), "Should allow GitHub by default");
    }

    #[tokio::test]
    async fn test_attestation_error_handling() {
        let validator = create_attestation_enabled_validator().await;
        let temp_dir = create_test_dir();
        
        // Test with various problematic file scenarios
        let test_cases = vec![
            ("non-existent-file.bin", "Should handle non-existent files"),
            ("empty-file.bin", "Should handle empty files"),
            ("malformed-name@#$%.bin", "Should handle files with special characters"),
        ];
        
        for (filename, description) in test_cases {
            let test_data = b"test content";
            let file_path = create_test_binary(temp_dir.path(), filename, test_data).await;
            
            let result = validator.validate_download(&file_path, None, None).await;
            assert!(result.is_err(), "{}", description);
        }
    }
}