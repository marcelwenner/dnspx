#[cfg(test)]
mod tests {
    use crate::adapters::status::memory_status_store::InMemoryStatusStoreAdapter;
    use crate::app_lifecycle::AppLifecycleManager;
    use crate::config::models::{
        AppConfig, CacheConfig, CliConfig, DefaultResolverConfig, LoggingConfig, ServerConfig,
    };
    use crate::core::config_manager::ConfigurationManager;
    use crate::core::error::UserInputError;
    use crate::core::types::{AppStatus, MessageLevel};
    use crate::ports::{
        AppLifecycleManagerPort, AwsConfigProvider, StatusReporterPort, UserInteractionPort,
    };

    use async_trait::async_trait;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;

    struct MockUserInteraction;

    #[async_trait]
    impl UserInteractionPort for MockUserInteraction {
        async fn prompt_for_mfa_token(
            &self,
            _user_identity: &str,
            _attempt: u32,
        ) -> Result<String, UserInputError> {
            Ok("mock-mfa-token".to_string())
        }

        async fn prompt_for_aws_keys(
            &self,
            _account_label: &str,
        ) -> Result<(String, String), UserInputError> {
            Ok(("mock-access-key".to_string(), "mock-secret-key".to_string()))
        }

        fn display_message(&self, _message: &str, _level: MessageLevel) {
            // No-op for tests
        }

        fn display_status(&self, _status_info: &AppStatus) {
            // No-op for tests
        }

        fn display_error(&self, _error: &dyn std::error::Error) {
            // No-op for tests
        }

        fn display_table(&self, _headers: Vec<String>, _rows: Vec<Vec<String>>) {
            // No-op for tests
        }

        fn display_prompt(&self, _prompt_text: &str) {
            // No-op for tests
        }
    }

    struct MockAwsConfigProvider;

    #[async_trait]
    impl AwsConfigProvider for MockAwsConfigProvider {
        async fn get_credentials_for_account(
            &self,
            _account_config: &crate::config::models::AwsAccountConfig,
            _mfa_provider: Arc<dyn UserInteractionPort>,
        ) -> Result<crate::core::types::AwsCredentials, crate::core::error::AwsAuthError> {
            use aws_credential_types::Credentials;
            Ok(Credentials::new(
                "mock-access-key",
                "mock-secret-key",
                None,
                None,
                "MockCredentialsProvider",
            ))
        }

        async fn get_credentials_for_role(
            &self,
            _base_credentials: &crate::core::types::AwsCredentials,
            _role_config: &crate::config::models::AwsRoleConfig,
            _account_config_for_mfa_serial: &crate::config::models::AwsAccountConfig,
            _mfa_provider: Arc<dyn UserInteractionPort>,
        ) -> Result<crate::core::types::AwsCredentials, crate::core::error::AwsAuthError> {
            use aws_credential_types::Credentials;
            Ok(Credentials::new(
                "mock-role-access-key",
                "mock-role-secret-key",
                Some("mock-session-token".to_string()),
                None,
                "MockRoleCredentialsProvider",
            ))
        }

        async fn validate_credentials(
            &self,
            _credentials: &crate::core::types::AwsCredentials,
        ) -> Result<String, crate::core::error::AwsAuthError> {
            Ok("arn:aws:sts::123456789012:assumed-role/MockRole/MockSession".to_string())
        }
    }

    fn create_test_app_config() -> AppConfig {
        AppConfig {
            server: ServerConfig::default(),
            default_resolver: DefaultResolverConfig::default(),
            routing_rules: vec![],
            local_hosts: None,
            cache: CacheConfig::default(),
            http_proxy: None,
            aws: None,
            logging: LoggingConfig::default(),
            cli: CliConfig::default(),
            update: None,
        }
    }

    async fn create_test_lifecycle_manager() -> (Arc<AppLifecycleManager>, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config_base_path = temp_dir.path().to_path_buf();

        let config_store_adapter: Arc<dyn crate::ports::ConfigurationStore> = Arc::new(
            crate::adapters::config::file_store::JsonFileConfigAdapter::new(config_base_path),
        );

        let (config_manager, _initial_config_result) =
            ConfigurationManager::new(Arc::clone(&config_store_adapter))
                .await
                .expect("Failed to create configuration manager");
        let config_manager = Arc::new(config_manager);

        let status_reporter: Arc<dyn StatusReporterPort> =
            Arc::new(InMemoryStatusStoreAdapter::new());
        let user_interaction: Arc<dyn UserInteractionPort> = Arc::new(MockUserInteraction);
        let aws_config_provider: Arc<dyn AwsConfigProvider> = Arc::new(MockAwsConfigProvider);

        let lifecycle_manager = AppLifecycleManager::new(
            config_manager,
            status_reporter,
            user_interaction,
            aws_config_provider,
        )
        .await;

        (lifecycle_manager, temp_dir)
    }

    #[tokio::test]
    async fn test_lifecycle_manager_creation() {
        let (lifecycle_manager, _temp_dir) = create_test_lifecycle_manager().await;

        let initial_query_count = lifecycle_manager.get_total_queries_processed().await;
        assert_eq!(initial_query_count, 0);

        let active_listeners = lifecycle_manager.get_active_listeners().await;
        assert!(active_listeners.is_empty());

        let config = lifecycle_manager.get_config();
        let config_guard = config.read().await;
        assert!(config_guard.routing_rules.is_empty());
    }

    #[tokio::test]
    async fn test_lifecycle_start_and_stop() {
        let (lifecycle_manager, _temp_dir) = create_test_lifecycle_manager().await;

        let start_result = lifecycle_manager.start().await;
        assert!(
            start_result.is_ok(),
            "Lifecycle manager should start successfully"
        );

        lifecycle_manager.stop().await;
    }

    #[tokio::test]
    async fn test_query_counter_increment() {
        let (lifecycle_manager, _temp_dir) = create_test_lifecycle_manager().await;

        let initial_count = lifecycle_manager.get_total_queries_processed().await;

        for i in 1..=5 {
            lifecycle_manager.increment_total_queries_processed();
            let current_count = lifecycle_manager.get_total_queries_processed().await;
            assert_eq!(current_count, initial_count + i);
        }
    }

    #[tokio::test]
    async fn test_listener_management() {
        let (lifecycle_manager, _temp_dir) = create_test_lifecycle_manager().await;

        let listeners = lifecycle_manager.get_active_listeners().await;
        assert!(listeners.is_empty());

        lifecycle_manager
            .add_listener_address("127.0.0.1:53".to_string())
            .await;
        lifecycle_manager
            .add_listener_address("[::1]:53".to_string())
            .await;

        let listeners = lifecycle_manager.get_active_listeners().await;
        assert_eq!(listeners.len(), 2);
        assert!(listeners.contains(&"127.0.0.1:53".to_string()));
        assert!(listeners.contains(&"[::1]:53".to_string()));

        lifecycle_manager
            .remove_listener_address("127.0.0.1:53".to_string())
            .await;

        let listeners = lifecycle_manager.get_active_listeners().await;
        assert_eq!(listeners.len(), 1);
        assert!(listeners.contains(&"[::1]:53".to_string()));
        assert!(!listeners.contains(&"127.0.0.1:53".to_string()));
    }

    #[tokio::test]
    async fn test_config_reload_trigger() {
        let (lifecycle_manager, _temp_dir) = create_test_lifecycle_manager().await;

        let reload_result = lifecycle_manager.trigger_config_reload().await;
        assert!(reload_result.is_ok(), "Config reload should succeed");
    }

    #[tokio::test]
    async fn test_aws_scan_trigger() {
        let (lifecycle_manager, _temp_dir) = create_test_lifecycle_manager().await;

        let scan_result = lifecycle_manager.trigger_aws_scan_refresh().await;
        assert!(
            scan_result.is_err(),
            "AWS scan trigger should fail without AWS config"
        );
    }

    #[tokio::test]
    async fn test_cancellation_token_functionality() {
        let (lifecycle_manager, _temp_dir) = create_test_lifecycle_manager().await;

        let cancellation_token = lifecycle_manager.get_cancellation_token();
        assert!(!cancellation_token.is_cancelled());

        cancellation_token.cancel();
        assert!(cancellation_token.is_cancelled());
    }

    #[tokio::test]
    async fn test_aws_scan_trigger_notification() {
        let (lifecycle_manager, _temp_dir) = create_test_lifecycle_manager().await;

        let aws_scan_trigger = lifecycle_manager.get_aws_scan_trigger();

        aws_scan_trigger.notify_one();
        aws_scan_trigger.notify_waiters();
    }

    #[tokio::test]
    async fn test_component_access_methods() {
        let (lifecycle_manager, _temp_dir) = create_test_lifecycle_manager().await;

        let dns_cache = lifecycle_manager.get_dns_cache();
        let cache_stats = dns_cache.get_stats();
        assert_eq!(cache_stats.size, 0);

        let local_hosts = lifecycle_manager.get_local_hosts_resolver();

        drop(local_hosts);

        let status_reporter = lifecycle_manager.get_status_reporter();
        drop(status_reporter);

        let user_interaction = lifecycle_manager.get_user_interaction_port();
        drop(user_interaction);

        let aws_provider = lifecycle_manager.get_aws_config_provider();
        drop(aws_provider);
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let (lifecycle_manager, _temp_dir) = create_test_lifecycle_manager().await;

        let mut handles = vec![];
        for _ in 0..10 {
            let lm = Arc::clone(&lifecycle_manager);
            let handle = tokio::spawn(async move {
                for _ in 0..100 {
                    lm.increment_total_queries_processed();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.expect("Task should complete successfully");
        }

        let final_count = lifecycle_manager.get_total_queries_processed().await;
        assert_eq!(final_count, 1000, "All increments should be counted");
    }

    #[tokio::test]
    async fn test_graceful_shutdown_with_tasks() {
        let (lifecycle_manager, _temp_dir) = create_test_lifecycle_manager().await;

        let task1 = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let task2 = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        lifecycle_manager.add_task(task1).await;
        lifecycle_manager.add_task(task2).await;

        let shutdown_start = std::time::Instant::now();
        lifecycle_manager.stop().await;
        let shutdown_duration = shutdown_start.elapsed();

        assert!(
            shutdown_duration < Duration::from_secs(1),
            "Shutdown should complete quickly"
        );
    }

    #[tokio::test]
    async fn test_config_hot_reload_infrastructure() {
        let (lifecycle_manager, _temp_dir) = create_test_lifecycle_manager().await;

        let config = lifecycle_manager.get_config();
        let initial_config = config.read().await.clone();

        let reload_result = lifecycle_manager.trigger_config_reload().await;
        assert!(reload_result.is_ok());

        assert_eq!(initial_config.server.listen_address, "0.0.0.0:53");
    }
}
