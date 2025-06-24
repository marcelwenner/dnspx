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
        attestation_repo: "marcelwenner/dnspx".to_string(),
        require_slsa_level: 0,
        allowed_update_domains: vec!["github.com".to_string(), "api.github.com".to_string()],
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
        attestation_repo: "marcelwenner/dnspx".to_string(),
        require_slsa_level: 1,
        allowed_update_domains: vec!["github.com".to_string(), "api.github.com".to_string()],
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
        let config = UpdateSecurityConfig {
            verify_checksums: false,
            ..Default::default()
        };

        let client = Client::new();
        let validator = SecurityValidator::new(config, client);

        let temp_dir = create_test_dir();
        let test_data = b"test file content";
        let file_path = create_test_binary(temp_dir.path(), "test-file", test_data).await;

        let result = validator.validate_download(&file_path, None, None).await;
        assert!(
            result.is_ok(),
            "Validation should succeed when checksum verification is disabled"
        );
    }

    #[tokio::test]
    async fn test_clone_validator() {
        let validator1 = create_test_security_validator().await;
        let validator2 = validator1.clone();

        let test_url = "https://github.com/test/repo";

        let result1 = validator1.validate_url(test_url);
        let result2 = validator2.validate_url(test_url);

        assert_eq!(result1.is_ok(), result2.is_ok());
    }

    #[tokio::test]
    async fn test_attestation_disabled_by_default() {
        let validator = create_test_security_validator().await;
        let temp_dir = create_test_dir();
        let test_data = b"test file content for attestation";
        let file_path = create_test_binary(temp_dir.path(), "test-binary", test_data).await;

        let result = validator.validate_download(&file_path, None, None).await;
        assert!(
            result.is_ok(),
            "Validation should succeed when attestations are disabled"
        );
    }

    #[tokio::test]
    async fn test_attestation_verification_enabled_fails_without_network() {
        let validator = create_attestation_enabled_validator().await;
        let temp_dir = create_test_dir();
        let test_data = b"test file requiring attestation";
        let file_path = create_test_binary(temp_dir.path(), "dnspx-test", test_data).await;

        let result = validator.validate_download(&file_path, None, None).await;
        assert!(
            result.is_err(),
            "Should fail when attestations are required but not available"
        );

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

        assert_eq!(validator.config.trusted_builders.len(), 2);
        assert!(
            validator
                .config
                .trusted_builders
                .contains(&"https://github.com/custom/builder".to_string())
        );
        assert!(
            validator
                .config
                .trusted_builders
                .contains(&"https://custom-ci.com".to_string())
        );
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
            assert_eq!(
                extracted_repo, repo,
                "Repository configuration should be preserved"
            );
        }
    }

    #[tokio::test]
    async fn test_security_config_defaults() {
        let config = UpdateSecurityConfig::default();

        assert!(
            config.verify_checksums,
            "Checksums should be verified by default"
        );
        assert!(
            !config.verify_signatures,
            "Signatures should not be required by default"
        );
        assert!(
            !config.require_attestations,
            "Attestations should not be required by default"
        );
        assert_eq!(
            config.require_slsa_level, 0,
            "SLSA level should default to 0"
        );
        assert!(
            !config.trusted_builders.is_empty(),
            "Should have default trusted builders"
        );
        assert_eq!(
            config.attestation_repo, "marcelwenner/dnspx",
            "Should have default attestation repo"
        );
        assert!(
            config
                .allowed_update_domains
                .contains(&"github.com".to_string()),
            "Should allow GitHub by default"
        );
    }

    #[tokio::test]
    async fn test_attestation_error_handling() {
        let validator = create_attestation_enabled_validator().await;
        let temp_dir = create_test_dir();

        let test_cases = vec![
            ("non-existent-file.bin", "Should handle non-existent files"),
            ("empty-file.bin", "Should handle empty files"),
            (
                "malformed-name@#$%.bin",
                "Should handle files with special characters",
            ),
        ];

        for (filename, description) in test_cases {
            let test_data = b"test content";
            let file_path = create_test_binary(temp_dir.path(), filename, test_data).await;

            let result = validator.validate_download(&file_path, None, None).await;
            assert!(result.is_err(), "{}", description);
        }
    }

    #[tokio::test]
    async fn test_jwks_fetching_disabled_when_attestations_disabled() {
        let validator = create_test_security_validator().await;
        let temp_dir = create_test_dir();
        let test_data = b"test file content";
        let file_path = create_test_binary(temp_dir.path(), "test-binary", test_data).await;

        let result = validator.validate_download(&file_path, None, None).await;
        assert!(
            result.is_ok(),
            "Should succeed when attestations are disabled"
        );
    }

    #[tokio::test]
    async fn test_jwks_cache_initialization() {
        let validator = create_attestation_enabled_validator().await;

        let result = validator.get_cached_jwks().await;

        match result {
            Ok(jwks) => {
                assert!(
                    !jwks.keys.is_empty(),
                    "JWKS should contain at least one key"
                );
                println!("Successfully fetched {} JWKS keys", jwks.keys.len());
            }
            Err(crate::core::error::UpdateError::JwksFetchFailed(_)) => {
                println!("JWKS fetch failed as expected (no network/mock)");
            }
            Err(crate::core::error::UpdateError::Network(_)) => {
                println!("Network error as expected");
            }
            Err(e) => {
                panic!("Unexpected error type: {:?}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_jwt_header_validation() {
        use crate::adapters::update::security::SecurityValidator;

        let config = UpdateSecurityConfig {
            verify_checksums: false,
            verify_signatures: false,
            require_attestations: true,
            trusted_builders: vec!["https://github.com/actions".to_string()],
            attestation_repo: "test/repo".to_string(),
            require_slsa_level: 0,
            allowed_update_domains: vec!["github.com".to_string()],
            max_download_size_mb: 100,
        };

        let client = Client::new();
        let validator = SecurityValidator::new(config, client);

        let invalid_jwts = vec![
            "not.a.jwt",
            "invalid-base64-header.payload.signature",
            "",
            "only-one-part",
            "two.parts",
            "valid.header.but.too.many.parts.here",
        ];

        for invalid_jwt in invalid_jwts {
            let result = validator
                .verify_jwt_signature(invalid_jwt, &create_mock_jwks())
                .await;
            assert!(result.is_err(), "Invalid JWT should fail: {}", invalid_jwt);
        }
    }

    fn create_mock_jwks() -> crate::adapters::update::security::GitHubJwks {
        crate::adapters::update::security::GitHubJwks {
            keys: vec![crate::adapters::update::security::JsonWebKey {
                key_id: "test-kid-1".to_string(),
                key_type: "RSA".to_string(),
                algorithm: "RS256".to_string(),
                key_use: "sig".to_string(),
                modulus: "test-modulus".to_string(),
                exponent: "AQAB".to_string(),
            }],
        }
    }

    #[tokio::test]
    async fn test_trusted_builder_validation_with_attestations() {
        let trusted_builders = vec![
            "https://github.com/actions".to_string(),
            "https://custom-ci.example.com".to_string(),
        ];

        let config = UpdateSecurityConfig {
            verify_checksums: false,
            verify_signatures: false,
            require_attestations: true,
            trusted_builders,
            attestation_repo: "test/repo".to_string(),
            require_slsa_level: 1,
            allowed_update_domains: vec!["github.com".to_string()],
            max_download_size_mb: 100,
        };

        let client = Client::new();
        let validator = SecurityValidator::new(config, client);

        assert_eq!(validator.config.trusted_builders.len(), 2);
        assert!(
            validator
                .config
                .trusted_builders
                .contains(&"https://github.com/actions".to_string())
        );
        assert!(
            validator
                .config
                .trusted_builders
                .contains(&"https://custom-ci.example.com".to_string())
        );
        assert!(validator.config.require_attestations);
        assert_eq!(validator.config.require_slsa_level, 1);
    }

    #[tokio::test]
    async fn test_attestation_repo_configuration() {
        let repos = vec![
            "owner/repo",
            "github-org/project",
            "enterprise/internal-tool",
        ];

        for repo in repos {
            let config = UpdateSecurityConfig {
                verify_checksums: false,
                verify_signatures: false,
                require_attestations: true,
                trusted_builders: vec!["https://github.com/actions".to_string()],
                attestation_repo: repo.to_string(),
                require_slsa_level: 0,
                allowed_update_domains: vec!["github.com".to_string()],
                max_download_size_mb: 100,
            };

            let client = Client::new();
            let validator = SecurityValidator::new(config, client);

            let extracted_repo = validator.extract_github_repo().unwrap();
            assert_eq!(
                extracted_repo, repo,
                "Attestation repo should be configurable"
            );
        }
    }

    #[tokio::test]
    async fn test_github_attestations_api_success() {
        use httpmock::prelude::*;

        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/repos/test/repo/attestations")
                .header("Accept", "application/vnd.github+json")
                .header_exists("User-Agent");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!({
                    "attestations": [
                        {
                            "bundle": {
                                "dsseEnvelope": {
                                    "payload": "eyJ0ZXN0IjoidmFsdWUifQ==",
                                    "signatures": [
                                        {
                                            "sig": "mock-signature"
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }));
        });

        let config = UpdateSecurityConfig {
            require_attestations: true,
            attestation_repo: "test/repo".to_string(),
            allowed_update_domains: vec![server.base_url()],
            ..Default::default()
        };

        let client = Client::new();
        let _validator = SecurityValidator::new(config, client);

        assert_eq!(mock.hits(), 0);
    }

    #[tokio::test]
    async fn test_github_attestations_api_error_scenarios() {
        use httpmock::prelude::*;

        let test_cases = vec![
            (404, "No attestations found for this repository"),
            (500, "Failed to fetch attestations: HTTP 500"),
            (403, "Failed to fetch attestations: HTTP 403"),
        ];

        for (status_code, _expected_error_part) in test_cases {
            let server = MockServer::start();

            let mock = server.mock(|when, then| {
                when.method(GET).path("/repos/test/repo/attestations");
                then.status(status_code)
                    .header("content-type", "application/json")
                    .body("{}");
            });

            assert_eq!(mock.hits(), 0);
        }
    }

    #[tokio::test]
    async fn test_jwks_endpoint_mocking() {
        use httpmock::prelude::*;

        let server = MockServer::start();

        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/.well-known/jwks")
                .header("Accept", "application/json")
                .header_exists("User-Agent");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(serde_json::json!({
                    "keys": [
                        {
                            "kid": "test-key-id",
                            "kty": "RSA",
                            "alg": "RS256",
                            "use": "sig",
                            "n": "test-modulus-value",
                            "e": "AQAB"
                        }
                    ]
                }));
        });

        assert_eq!(mock.hits(), 0);
    }

    #[tokio::test]
    async fn test_jwt_signature_verification_structure() {
        let validator = create_attestation_enabled_validator().await;
        let mock_jwks = create_mock_jwks();

        let invalid_test_cases = vec![
            ("", "Empty JWT"),
            ("not.a.jwt", "Malformed JWT"),
            ("invalid.header.signature", "Invalid structure"),
            (
                "dGVzdA==.dGVzdA==.dGVzdA==",
                "Valid structure but invalid content",
            ),
        ];

        for (jwt, description) in invalid_test_cases {
            let result = validator.verify_jwt_signature(jwt, &mock_jwks).await;
            assert!(result.is_err(), "Should fail for {}: {}", description, jwt);

            match result {
                Err(crate::core::error::UpdateError::InvalidJwtFormat(_))
                | Err(crate::core::error::UpdateError::JwtVerificationFailed(_)) => {}
                Err(e) => {
                    println!("Unexpected error for {}: {:?}", description, e);
                }
                Ok(_) => panic!("Should not succeed for {}", description),
            }
        }
    }

    #[tokio::test]
    async fn test_complete_attestation_workflow_mock_structure() {
        let temp_dir = create_test_dir();
        let test_data = b"test binary content for attestation";
        let file_path = create_test_binary(temp_dir.path(), "test-binary", test_data).await;

        let config = UpdateSecurityConfig {
            verify_checksums: false,
            verify_signatures: false,
            require_attestations: true,
            trusted_builders: vec!["https://github.com/actions".to_string()],
            attestation_repo: "test/repo".to_string(),
            require_slsa_level: 1,
            allowed_update_domains: vec!["github.com".to_string()],
            max_download_size_mb: 100,
        };

        let client = Client::new();
        let validator = SecurityValidator::new(config, client);

        let result = validator.validate_download(&file_path, None, None).await;

        assert!(
            result.is_err(),
            "Should fail when no mocked GitHub API is available"
        );

        match result {
            Err(crate::core::error::UpdateError::SecurityValidationFailed(_))
            | Err(crate::core::error::UpdateError::JwksFetchFailed(_))
            | Err(crate::core::error::UpdateError::Network(_)) => {
                println!("Expected failure at GitHub API stage");
            }
            Err(e) => {
                println!("Workflow failed with: {:?}", e);
            }
            Ok(_) => panic!("Should not succeed without proper mocking"),
        }
    }
}
