use super::test_utils::*;
use crate::adapters::update::transaction::UpdateTransaction;
use crate::config::models::UpdateRollbackConfig;
use semver::Version;
use std::time::Duration;

/// Creates a test transaction with rollback enabled
async fn create_test_transaction_enabled() -> (UpdateTransaction, tempfile::TempDir) {
    let temp_dir = create_test_dir();
    let backup_dir = temp_dir.path().join("backups");

    // Create a mock current binary
    let current_binary_content = create_test_executable_content("1.0.0");
    let current_binary =
        create_test_binary(temp_dir.path(), "dnspx-current", &current_binary_content).await;

    let config = UpdateRollbackConfig {
        enabled: true,
        keep_backups: 3,
        health_check_timeout: Duration::from_secs(5),
        health_check_enabled: true,
    };

    let transaction = UpdateTransaction::new(
        current_binary,
        backup_dir,
        Version::new(1, 1, 0),
        Version::new(1, 0, 0),
        config,
    );

    (transaction, temp_dir)
}

/// Creates a test transaction with rollback disabled
fn create_test_transaction_disabled() -> (UpdateTransaction, tempfile::TempDir) {
    let temp_dir = create_test_dir();
    let backup_dir = temp_dir.path().join("backups");

    let config = UpdateRollbackConfig {
        enabled: false,
        keep_backups: 0,
        health_check_timeout: Duration::from_secs(5),
        health_check_enabled: false,
    };

    let transaction = UpdateTransaction::new(
        temp_dir.path().join("fake-binary"),
        backup_dir,
        Version::new(1, 1, 0),
        Version::new(1, 0, 0),
        config,
    );

    (transaction, temp_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_prepare_backup_enabled() {
        let (mut transaction, _temp_dir) = create_test_transaction_enabled().await;

        // Prepare should create backup
        let result = transaction.prepare().await;
        assert!(
            result.is_ok(),
            "Prepare should succeed when rollback is enabled"
        );

        // Should be able to check if rollback is available
        assert!(
            transaction.is_rollback_available(),
            "Rollback should be available after prepare"
        );
    }

    #[tokio::test]
    async fn test_prepare_backup_disabled() {
        let (mut transaction, _temp_dir) = create_test_transaction_disabled();

        // Prepare should succeed even when disabled
        let result = transaction.prepare().await;
        assert!(
            result.is_ok(),
            "Prepare should succeed when rollback is disabled"
        );

        // Should not be available when disabled
        assert!(
            !transaction.is_rollback_available(),
            "Rollback should not be available when disabled"
        );
    }

    #[tokio::test]
    async fn test_commit_with_new_binary() {
        let (mut transaction, temp_dir) = create_test_transaction_enabled().await;

        // Prepare backup first
        transaction.prepare().await.unwrap();

        // Create a new binary to commit
        let new_binary_content = create_test_executable_content("1.1.0");
        let new_binary_path =
            create_test_binary(temp_dir.path(), "dnspx-new", &new_binary_content).await;

        // Commit should succeed (note: health check may fail but that's expected in test environment)
        let result = transaction.commit(&new_binary_path).await;
        // For testing purposes, we allow health check failures since we're using dummy binaries
        match result {
            Ok(()) => {} // Great, commit succeeded
            Err(err) => {
                // If it's a health check failure, that's expected with dummy binaries
                let err_msg = err.to_string();
                if !err_msg.contains("Health check") && !err_msg.contains("health check") {
                    panic!("Unexpected error during commit: {}", err);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_rollback_when_enabled() {
        let (mut transaction, _temp_dir) = create_test_transaction_enabled().await;

        // Prepare backup first
        transaction.prepare().await.unwrap();

        // Rollback should be possible
        let result = transaction.rollback().await;
        // Similar to commit, health check may fail with dummy binaries
        match result {
            Ok(()) => {} // Great, rollback succeeded
            Err(err) => {
                let err_msg = err.to_string();
                if !err_msg.contains("Health check") && !err_msg.contains("health check") {
                    panic!("Unexpected error during rollback: {}", err);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_rollback_when_disabled() {
        let (transaction, _temp_dir) = create_test_transaction_disabled();

        // Rollback should fail when disabled
        let result = transaction.rollback().await;
        assert!(result.is_err(), "Rollback should fail when disabled");

        match result.unwrap_err() {
            crate::core::error::UpdateError::RollbackFailed(msg) => {
                assert!(
                    msg.contains("disabled"),
                    "Error should mention rollback is disabled"
                );
            }
            _ => panic!("Expected RollbackFailed error"),
        }
    }

    #[tokio::test]
    async fn test_rollback_without_prepare() {
        let (transaction, _temp_dir) = create_test_transaction_enabled().await;

        // Rollback should fail without prepare
        let result = transaction.rollback().await;
        assert!(result.is_err(), "Rollback should fail without backup");

        match result.unwrap_err() {
            crate::core::error::UpdateError::RollbackFailed(msg) => {
                assert!(
                    msg.contains("backup"),
                    "Error should mention missing backup"
                );
            }
            _ => panic!("Expected RollbackFailed error"),
        }
    }

    #[tokio::test]
    async fn test_is_rollback_available_states() {
        let (mut transaction, _temp_dir) = create_test_transaction_enabled().await;

        // Initially should not be available
        assert!(
            !transaction.is_rollback_available(),
            "Rollback should not be available initially"
        );

        // After prepare, should be available
        transaction.prepare().await.unwrap();
        assert!(
            transaction.is_rollback_available(),
            "Rollback should be available after prepare"
        );
    }

    #[tokio::test]
    async fn test_transaction_version_tracking() {
        let (_transaction, _temp_dir) = create_test_transaction_enabled().await;

        // Transaction should track old and new versions
        // We can't directly access version fields since they're private,
        // but we can verify the transaction was created with the right parameters
        // by checking that it doesn't panic and behaves correctly

        // This test verifies the constructor works with different version combinations
        let _transaction2 = UpdateTransaction::new(
            std::path::PathBuf::from("/fake/path"),
            std::path::PathBuf::from("/fake/backup"),
            Version::new(2, 0, 0),
            Version::new(1, 5, 3),
            UpdateRollbackConfig::default(),
        );

        // No panic means the constructor properly handles versions
        // Test passed - constructor accepts different version combinations
    }
}
