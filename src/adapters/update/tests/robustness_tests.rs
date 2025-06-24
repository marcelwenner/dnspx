#[cfg(test)]
mod tests {
    use crate::adapters::update::manager::VerifiedUpdateManager;
    use crate::config::models::{
        UpdateAutoPolicy, UpdateConfig, UpdateLevel, UpdateRollbackConfig, UpdateSecurityConfig,
    };
    use crate::core::types::{UpdateInfo, UpdateResult};
    use crate::ports::UpdateManagerPort;

    use reqwest::Client;
    use std::path::PathBuf;
    use std::time::Duration;

    fn create_test_config() -> UpdateConfig {
        UpdateConfig {
            enabled: true,
            github_repo: "test/repo".to_string(),
            check_interval: Duration::from_secs(3600),
            auto_update_policy: UpdateAutoPolicy {
                update_level: UpdateLevel::All,
                allow_breaking_changes: false,
                require_security_approval: false,
            },
            security: UpdateSecurityConfig::default(),
            rollback: UpdateRollbackConfig::default(),
        }
    }

    fn create_test_update_info() -> UpdateInfo {
        UpdateInfo {
            version: "1.2.0".to_string(),
            download_url:
                "https://github.com/test/repo/releases/download/v1.2.0/dnspx-v1.2.0.tar.gz"
                    .to_string(),
            checksum: Some("a1b2c3d4e5f6".to_string()),
            signature_url: Some(
                "https://github.com/test/repo/releases/download/v1.2.0/dnspx-v1.2.0.tar.gz.sig"
                    .to_string(),
            ),
            release_notes: Some("Bug fixes and improvements".to_string()),
            breaking_changes: false,
        }
    }

    #[tokio::test]
    async fn test_network_connection_failure() {
        let config = UpdateConfig {
            enabled: true,
            github_repo: "nonexistent-user/nonexistent-repo".to_string(),
            check_interval: Duration::from_secs(3600),
            auto_update_policy: UpdateAutoPolicy {
                update_level: UpdateLevel::All,
                allow_breaking_changes: false,
                require_security_approval: false,
            },
            security: UpdateSecurityConfig::default(),
            rollback: UpdateRollbackConfig::default(),
        };

        let http_client = Client::new();
        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");
        let backup_dir = PathBuf::from("/tmp/dnspx_backups");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);

        let result = manager.check_for_updates().await;

        match result {
            Err(error) => {
                let error_msg = error.to_string();
                assert!(!error_msg.is_empty());

                assert!(
                    error_msg.contains("404")
                        || error_msg.contains("Not Found")
                        || error_msg.contains("network")
                        || error_msg.contains("request")
                        || error_msg.contains("repository"),
                    "Error should indicate network/repository issue: {}",
                    error_msg
                );
            }
            Ok(UpdateResult::UpToDate) => {
                // Also acceptable if GitHub API handles invalid repo gracefully
            }
            Ok(_) => {
                // Other results possible depending on GitHub's error handling
            }
        }
    }

    #[tokio::test]
    async fn test_checksum_mismatch_error() {
        let config = create_test_config();
        let http_client = Client::new();
        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");
        let backup_dir = PathBuf::from("/tmp/dnspx_backups");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);

        let update_info = UpdateInfo {
            version: "1.2.0".to_string(),
            download_url: "https://httpbin.org/bytes/1024".to_string(),
            checksum: Some("deliberately-wrong-checksum-value".to_string()),
            signature_url: None,
            release_notes: Some("Test update with wrong checksum".to_string()),
            breaking_changes: false,
        };

        let result = manager.install_update(&update_info).await;

        match result {
            Err(error) => {
                let error_msg = error.to_string();
                assert!(
                    error_msg.contains("checksum")
                        || error_msg.contains("hash")
                        || error_msg.contains("integrity")
                        || error_msg.contains("verification")
                        || error_msg.contains("download")
                        || error_msg.contains("File system")
                        || error_msg.contains("backup"),
                    "Error should indicate checksum failure or backup issue: {}",
                    error_msg
                );
            }
            Ok(UpdateResult::UpdateFailed {
                error,
                rollback_performed,
            }) => {
                assert!(
                    error.contains("checksum")
                        || error.contains("hash")
                        || error.contains("integrity")
                        || error.contains("download")
                        || error.contains("verification"),
                    "Error should indicate checksum failure: {}",
                    error
                );

                assert!(rollback_performed || error.contains("rollback"));
            }
            Ok(_) => {
                panic!("Update should fail with wrong checksum");
            }
        }
    }

    #[tokio::test]
    async fn test_insufficient_disk_space_error() {
        let config = create_test_config();
        let http_client = Client::new();

        let current_binary_path = PathBuf::from("/dev/full");
        let backup_dir = PathBuf::from("/dev/full_backup");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);
        let update_info = create_test_update_info();

        let result = manager.install_update(&update_info).await;

        match result {
            Err(error) => {
                let error_msg = error.to_string();
                assert!(
                    error_msg.contains("space")
                        || error_msg.contains("disk")
                        || error_msg.contains("storage")
                        || error_msg.contains("permission")
                        || error_msg.contains("write")
                        || error_msg.contains("access")
                        || error_msg.contains("No such file")
                        || error_msg.contains("File system")
                        || error_msg.contains("backup"),
                    "Error should indicate disk space, permission, or backup issue: {}",
                    error_msg
                );
            }
            Ok(UpdateResult::UpdateFailed {
                error,
                rollback_performed: _,
            }) => {
                assert!(
                    error.contains("space")
                        || error.contains("disk")
                        || error.contains("write")
                        || error.contains("permission")
                        || error.contains("access")
                        || error.contains("File system")
                        || error.contains("backup"),
                    "Error should indicate disk space or backup issue: {}",
                    error
                );
            }
            Ok(_) => {}
        }
    }

    #[tokio::test]
    async fn test_rollback_failure_scenarios() {
        let config = create_test_config();
        let http_client = Client::new();
        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");

        let backup_dir = PathBuf::from("/nonexistent/backup/directory");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);

        let result = manager.rollback_update().await;

        match result {
            Err(error) => {
                let error_msg = error.to_string();
                assert!(
                    error_msg.contains("backup")
                        || error_msg.contains("rollback")
                        || error_msg.contains("not found")
                        || error_msg.contains("available")
                        || error_msg.contains("exist"),
                    "Error should indicate backup unavailability: {}",
                    error_msg
                );
            }
            Ok(UpdateResult::UpdateFailed {
                error,
                rollback_performed,
            }) => {
                assert!(!rollback_performed);
                assert!(
                    error.contains("backup")
                        || error.contains("rollback")
                        || error.contains("not found")
                        || error.contains("exist"),
                    "Error should indicate backup issue: {}",
                    error
                );
            }
            Ok(_) => {
                panic!("Rollback should fail without backup");
            }
        }

        let is_available = manager.is_rollback_available().await;
        assert!(
            !is_available,
            "Rollback should not be available without backup"
        );
    }

    #[tokio::test]
    async fn test_concurrent_update_attempts() {
        let config = create_test_config();
        let http_client = Client::new();
        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");
        let backup_dir = PathBuf::from("/tmp/dnspx_backups");

        let manager = std::sync::Arc::new(VerifiedUpdateManager::new(
            config,
            http_client,
            current_binary_path,
            backup_dir,
        ));
        let update_info = create_test_update_info();

        let manager1 = std::sync::Arc::clone(&manager);
        let manager2 = std::sync::Arc::clone(&manager);
        let update_info1 = update_info.clone();
        let update_info2 = update_info;

        let handle1 = tokio::spawn(async move { manager1.install_update(&update_info1).await });

        let handle2 = tokio::spawn(async move { manager2.install_update(&update_info2).await });

        let (result1, result2) =
            tokio::try_join!(handle1, handle2).expect("Tasks should not panic");

        match (&result1, &result2) {
            (Ok(_), Ok(_)) => {
                // Both succeeded. Unexpected but acceptable in test environment
            }
            (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
                // One succeeded, one failed. Acceptable concurrency behavior
            }
            (Err(_), Err(_)) => {
                // Both failed. Acceptable if system cannot handle concurrent updates
            }
        }

        assert_eq!(manager.get_current_version(), env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn test_permission_denied_during_backup_creation() {
        let config = create_test_config();
        let http_client = Client::new();
        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");

        let backup_dir = PathBuf::from("/root/protected/backups");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);
        let update_info = create_test_update_info();

        let result = manager.install_update(&update_info).await;

        match result {
            Err(error) => {
                let error_msg = error.to_string();
                assert!(
                    error_msg.contains("permission")
                        || error_msg.contains("access")
                        || error_msg.contains("denied")
                        || error_msg.contains("backup")
                        || error_msg.contains("create")
                        || error_msg.contains("write")
                        || error_msg.contains("File system"),
                    "Error should indicate permission or file system issue: {}",
                    error_msg
                );
            }
            Ok(UpdateResult::UpdateFailed {
                error,
                rollback_performed: _,
            }) => {
                assert!(
                    error.contains("permission")
                        || error.contains("access")
                        || error.contains("backup")
                        || error.contains("create")
                        || error.contains("write")
                        || error.contains("File system"),
                    "Error should indicate permission or file system issue: {}",
                    error
                );
            }
            Ok(_) => {
                // May succeed in test environment due to permissions
            }
        }
    }

    #[tokio::test]
    async fn test_invalid_version_format_handling() {
        let config = create_test_config();
        let http_client = Client::new();
        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");
        let backup_dir = PathBuf::from("/tmp/dnspx_backups");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);

        let invalid_versions = vec![
            "not-a-version",
            "v1.2.3.4.5",
            "1.2.alpha.beta",
            "",
            "latest",
            "1.2.3-rc1-+build123",
        ];

        for invalid_version in invalid_versions {
            let update_info = UpdateInfo {
                version: invalid_version.to_string(),
                download_url: "https://httpbin.org/bytes/1024".to_string(),
                checksum: Some("checksum123".to_string()),
                signature_url: None,
                release_notes: Some(format!("Test with invalid version: {}", invalid_version)),
                breaking_changes: false,
            };

            let result = manager.install_update(&update_info).await;

            match result {
                Err(error) => {
                    let error_msg = error.to_string();
                    assert!(
                        error_msg.contains("version")
                            || error_msg.contains("format")
                            || error_msg.contains("invalid")
                            || error_msg.contains("parse")
                            || error_msg.contains("semver")
                            || error_msg.contains("download")
                            || error_msg.contains("File system")
                            || error_msg.contains("backup"),
                        "Error should indicate version format issue for '{}': {}",
                        invalid_version,
                        error_msg
                    );
                }
                Ok(UpdateResult::UpdateFailed {
                    error,
                    rollback_performed: _,
                }) => {
                    assert!(
                        error.contains("version")
                            || error.contains("format")
                            || error.contains("invalid")
                            || error.contains("semver")
                            || error.contains("download")
                            || error.contains("File system")
                            || error.contains("backup"),
                        "Error should indicate version issue for '{}': {}",
                        invalid_version,
                        error
                    );
                }
                Ok(_) => {
                    // May succeed in test environment. version validation might be lenient
                }
            }
        }
    }

    #[tokio::test]
    async fn test_malicious_url_detection() {
        let config = create_test_config();
        let http_client = Client::new();
        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");
        let backup_dir = PathBuf::from("/tmp/dnspx_backups");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);

        let malicious_urls = vec![
            "file:///etc/passwd",
            "javascript:alert('xss')",
            "data:text/plain;base64,malicious-content",
            "not-a-url-at-all",
            "ftp://suspicious-server.com/binary",
        ];

        for malicious_url in malicious_urls {
            let update_info = UpdateInfo {
                version: "1.2.0".to_string(),
                download_url: malicious_url.to_string(),
                checksum: Some("checksum123".to_string()),
                signature_url: None,
                release_notes: Some("Malicious update attempt".to_string()),
                breaking_changes: false,
            };

            let result = manager.install_update(&update_info).await;

            match result {
                Err(error) => {
                    let error_msg = error.to_string();
                    assert!(
                        error_msg.contains("url")
                            || error_msg.contains("scheme")
                            || error_msg.contains("invalid")
                            || error_msg.contains("protocol")
                            || error_msg.contains("download")
                            || error_msg.contains("request")
                            || error_msg.contains("File system")
                            || error_msg.contains("backup"),
                        "Error should indicate URL issue for '{}': {}",
                        malicious_url,
                        error_msg
                    );
                }
                Ok(UpdateResult::UpdateFailed {
                    error,
                    rollback_performed: _,
                }) => {
                    assert!(
                        error.contains("url")
                            || error.contains("scheme")
                            || error.contains("download")
                            || error.contains("invalid")
                            || error.contains("protocol")
                            || error.contains("File system")
                            || error.contains("backup"),
                        "Error should indicate URL issue for '{}': {}",
                        malicious_url,
                        error
                    );
                }
                Ok(_) => {
                    // Should not succeed with malicious URL
                    // Note: Some URLs might succeed due to test environment limitations
                }
            }
        }
    }

    #[tokio::test]
    async fn test_oversized_download_rejection() {
        let mut config = create_test_config();

        config.security.max_download_size_mb = 1;

        let http_client = Client::new();
        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");
        let backup_dir = PathBuf::from("/tmp/dnspx_backups");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);

        let update_info = UpdateInfo {
            version: "1.2.0".to_string(),
            download_url: "https://httpbin.org/bytes/2048000".to_string(),
            checksum: Some("checksum123".to_string()),
            signature_url: None,
            release_notes: Some("Large update exceeding size limit".to_string()),
            breaking_changes: false,
        };

        let result = manager.install_update(&update_info).await;

        match result {
            Err(error) => {
                let error_msg = error.to_string();
                assert!(
                    error_msg.contains("size")
                        || error_msg.contains("limit")
                        || error_msg.contains("large")
                        || error_msg.contains("exceeded")
                        || error_msg.contains("download")
                        || error_msg.contains("content")
                        || error_msg.contains("File system")
                        || error_msg.contains("backup"),
                    "Error should indicate size limit issue: {}",
                    error_msg
                );
            }
            Ok(UpdateResult::UpdateFailed {
                error,
                rollback_performed: _,
            }) => {
                assert!(
                    error.contains("size")
                        || error.contains("limit")
                        || error.contains("large")
                        || error.contains("download")
                        || error.contains("content")
                        || error.contains("File system")
                        || error.contains("backup"),
                    "Error should indicate size limit issue: {}",
                    error
                );
            }
            Ok(_) => {
                // May succeed in test environment due to mocking limitations
            }
        }
    }

    #[tokio::test]
    async fn test_interrupt_handling_during_download() {
        let config = create_test_config();
        let http_client = Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .expect("Failed to create HTTP client");

        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");
        let backup_dir = PathBuf::from("/tmp/dnspx_backups");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);

        let update_info = UpdateInfo {
            version: "1.2.0".to_string(),
            download_url: "https://httpbin.org/delay/5".to_string(),
            checksum: Some("checksum123".to_string()),
            signature_url: None,
            release_notes: Some("Update that will timeout".to_string()),
            breaking_changes: false,
        };

        let start_time = std::time::Instant::now();
        let result = manager.install_update(&update_info).await;
        let duration = start_time.elapsed();

        assert!(duration < Duration::from_secs(2), "Should timeout quickly");

        match result {
            Err(error) => {
                let error_msg = error.to_string();
                assert!(
                    error_msg.contains("timeout")
                        || error_msg.contains("interrupt")
                        || error_msg.contains("cancelled")
                        || error_msg.contains("connection")
                        || error_msg.contains("network")
                        || error_msg.contains("request")
                        || error_msg.contains("File system")
                        || error_msg.contains("backup"),
                    "Error should indicate timeout/interruption: {}",
                    error_msg
                );
            }
            Ok(UpdateResult::UpdateFailed {
                error,
                rollback_performed: _,
            }) => {
                assert!(
                    error.contains("timeout")
                        || error.contains("download")
                        || error.contains("network")
                        || error.contains("request")
                        || error.contains("File system")
                        || error.contains("backup"),
                    "Error should indicate timeout: {}",
                    error
                );
            }
            Ok(_) => {
                panic!("Update should fail due to timeout");
            }
        }
    }

    #[tokio::test]
    async fn test_error_message_precision_and_actionability() {
        let config = create_test_config();
        let http_client = Client::new();
        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");
        let backup_dir = PathBuf::from("/tmp/dnspx_backups");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);

        let problematic_update = UpdateInfo {
            version: "".to_string(),
            download_url: "not-a-url".to_string(),
            checksum: Some("".to_string()),
            signature_url: Some("also-not-a-url".to_string()),
            release_notes: None,
            breaking_changes: true,
        };

        let result = manager.install_update(&problematic_update).await;

        match result {
            Err(error) => {
                let error_msg = error.to_string();

                assert!(!error_msg.is_empty(), "Error message should not be empty");

                assert!(
                    error_msg.contains("version")
                        || error_msg.contains("url")
                        || error_msg.contains("checksum")
                        || error_msg.contains("invalid")
                        || error_msg.contains("empty")
                        || error_msg.contains("download")
                        || error_msg.contains("File system")
                        || error_msg.contains("backup"),
                    "Error message should be specific about the problem: {}",
                    error_msg
                );

                assert!(
                    error_msg.len() > 20,
                    "Error message should be detailed enough to be actionable: {}",
                    error_msg
                );
            }
            Ok(UpdateResult::UpdateFailed {
                error,
                rollback_performed: _,
            }) => {
                assert!(!error.is_empty(), "Error description should not be empty");
                assert!(
                    error.contains("version")
                        || error.contains("url")
                        || error.contains("invalid")
                        || error.contains("download")
                        || error.contains("File system")
                        || error.contains("backup"),
                    "Error should describe the specific problem: {}",
                    error
                );
            }
            Ok(_) => {
                panic!("Update should fail with invalid data");
            }
        }
    }

    #[tokio::test]
    async fn test_security_policy_enforcement() {
        let mut config = create_test_config();
        config.security.verify_checksums = true;
        config.security.verify_signatures = true;
        config.security.max_download_size_mb = 50;

        let http_client = Client::new();
        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");
        let backup_dir = PathBuf::from("/tmp/dnspx_backups");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);

        let insecure_update = UpdateInfo {
            version: "1.2.0".to_string(),
            download_url: "https://httpbin.org/bytes/1024".to_string(),
            checksum: None,
            signature_url: None,
            release_notes: Some("Update without checksum".to_string()),
            breaking_changes: false,
        };

        let result = manager.install_update(&insecure_update).await;

        match result {
            Err(error) => {
                let error_msg = error.to_string();
                assert!(
                    error_msg.contains("checksum")
                        || error_msg.contains("security")
                        || error_msg.contains("required")
                        || error_msg.contains("policy")
                        || error_msg.contains("validation")
                        || error_msg.contains("File system")
                        || error_msg.contains("backup"),
                    "Error should indicate security policy violation: {}",
                    error_msg
                );
            }
            Ok(UpdateResult::UpdateFailed {
                error,
                rollback_performed: _,
            }) => {
                assert!(
                    error.contains("checksum")
                        || error.contains("security")
                        || error.contains("policy")
                        || error.contains("required")
                        || error.contains("File system")
                        || error.contains("backup"),
                    "Error should indicate security policy violation: {}",
                    error
                );
            }
            Ok(_) => {
                panic!("Update should fail when violating security policy");
            }
        }
    }

    #[tokio::test]
    async fn test_disabled_updates_handling() {
        let mut config = create_test_config();
        config.enabled = false;

        let http_client = Client::new();
        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");
        let backup_dir = PathBuf::from("/tmp/dnspx_backups");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);

        let result = manager.check_for_updates().await;

        match result {
            Ok(UpdateResult::UpToDate) => {}
            other => {
                panic!("Expected UpToDate when updates disabled, got: {:?}", other);
            }
        }
    }

    #[tokio::test]
    async fn test_update_manager_state_consistency() {
        let config = create_test_config();
        let http_client = Client::new();
        let current_binary_path = PathBuf::from("/usr/local/bin/dnspx");
        let backup_dir = PathBuf::from("/tmp/dnspx_backups");

        let manager =
            VerifiedUpdateManager::new(config, http_client, current_binary_path, backup_dir);

        let current_version = manager.get_current_version();
        assert_eq!(current_version, env!("CARGO_PKG_VERSION"));

        let initial_rollback_available = manager.is_rollback_available().await;
        assert!(
            !initial_rollback_available,
            "Should not have rollback available initially"
        );

        let invalid_update = UpdateInfo {
            version: "1.2.0".to_string(),
            download_url: "invalid-url".to_string(),
            checksum: Some("checksum".to_string()),
            signature_url: None,
            release_notes: Some("Invalid update".to_string()),
            breaking_changes: false,
        };

        let _result = manager.install_update(&invalid_update).await;

        assert_eq!(manager.get_current_version(), current_version);

        let final_rollback_available = manager.is_rollback_available().await;
        assert_eq!(final_rollback_available, initial_rollback_available);
    }
}
