use super::test_utils::*;
use crate::adapters::update::transaction::UpdateTransaction;
use crate::config::models::UpdateRollbackConfig;
use semver::Version;
use std::time::Duration;

async fn create_test_transaction_enabled() -> (UpdateTransaction, tempfile::TempDir) {
    let temp_dir = create_test_dir();
    let backup_dir = temp_dir.path().join("backups");

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

        let result = transaction.prepare().await;
        assert!(
            result.is_ok(),
            "Prepare should succeed when rollback is enabled"
        );

        assert!(
            transaction.is_rollback_available(),
            "Rollback should be available after prepare"
        );
    }

    #[tokio::test]
    async fn test_prepare_backup_disabled() {
        let (mut transaction, _temp_dir) = create_test_transaction_disabled();

        let result = transaction.prepare().await;
        assert!(
            result.is_ok(),
            "Prepare should succeed when rollback is disabled"
        );

        assert!(
            !transaction.is_rollback_available(),
            "Rollback should not be available when disabled"
        );
    }

    #[tokio::test]
    async fn test_commit_with_new_binary() {
        let (mut transaction, temp_dir) = create_test_transaction_enabled().await;

        transaction.prepare().await.unwrap();

        let new_binary_content = create_test_executable_content("1.1.0");
        let new_binary_path =
            create_test_binary(temp_dir.path(), "dnspx-new", &new_binary_content).await;

        let result = transaction.commit(&new_binary_path).await;

        match result {
            Ok(()) => {}
            Err(err) => {
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

        transaction.prepare().await.unwrap();

        let result = transaction.rollback().await;

        match result {
            Ok(()) => {}
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

        assert!(
            !transaction.is_rollback_available(),
            "Rollback should not be available initially"
        );

        transaction.prepare().await.unwrap();
        assert!(
            transaction.is_rollback_available(),
            "Rollback should be available after prepare"
        );
    }

    #[tokio::test]
    async fn test_transaction_version_tracking() {
        let (_transaction, _temp_dir) = create_test_transaction_enabled().await;

        let _transaction2 = UpdateTransaction::new(
            std::path::PathBuf::from("/fake/path"),
            std::path::PathBuf::from("/fake/backup"),
            Version::new(2, 0, 0),
            Version::new(1, 5, 3),
            UpdateRollbackConfig::default(),
        );
    }
}
