use super::mock_providers::{
    MockAwsApiResponse, MockAwsConfigProvider, MockAwsError, MockAwsVpcInfoProvider,
    MockStatusReporter, MockUserInteraction,
};
use crate::adapters::aws::types::AwsDiscoveredEndpoint;
use crate::aws_integration::scanner::AwsVpcScannerTask;
use crate::config::models::{
    AppConfig, AwsAccountConfig, AwsGlobalConfig, AwsRoleConfig, AwsServiceDiscoveryConfig,
};
use crate::core::dns_cache::DnsCache;
use crate::core::types::{AwsCredentials, AwsScannerStatus};
use crate::ports::{
    AppLifecycleManagerPort, AwsConfigProvider, AwsVpcInfoProvider, StatusReporterPort,
    UpstreamResolver, UserInteractionPort,
};
use aws_credential_types::Credentials;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{Notify, RwLock};
use tokio_util::sync::CancellationToken;

pub(crate) struct AwsScannerTestHarness {
    pub mock_vpc_provider: Arc<MockAwsVpcInfoProvider>,
    pub mock_config_provider: Arc<MockAwsConfigProvider>,
    pub mock_status_reporter: Arc<MockStatusReporter>,
    pub mock_user_interaction: Arc<MockUserInteraction>,
    pub mock_upstream_resolver: Arc<MockUpstreamResolver>,
    pub app_config: Arc<RwLock<AppConfig>>,
    pub dns_cache: Arc<DnsCache>,
    pub cancellation_token: CancellationToken,
    pub scan_trigger: Arc<Notify>,
    pub network_info: Arc<RwLock<crate::aws_integration::scanner::DiscoveredAwsNetworkInfo>>,
}

impl AwsScannerTestHarness {
    pub(crate) fn new() -> Self {
        let app_config = Arc::new(RwLock::new(Self::create_test_aws_config()));
        let dns_cache = Arc::new(DnsCache::new(
            100,
            Duration::from_secs(1),
            Duration::from_secs(300),
            false,
            Duration::from_secs(600),
        ));

        Self {
            mock_vpc_provider: Arc::new(MockAwsVpcInfoProvider::new()),
            mock_config_provider: Arc::new(MockAwsConfigProvider::new()),
            mock_status_reporter: Arc::new(MockStatusReporter::new()),
            mock_user_interaction: Arc::new(MockUserInteraction::new()),
            mock_upstream_resolver: Arc::new(MockUpstreamResolver::new()),
            app_config,
            dns_cache,
            cancellation_token: CancellationToken::new(),
            scan_trigger: Arc::new(Notify::new()),
            network_info: Arc::new(RwLock::new(
                crate::aws_integration::scanner::DiscoveredAwsNetworkInfo::default(),
            )),
        }
    }

    pub(crate) fn new_single_account() -> Self {
        let config = AppConfig {
            aws: Some(AwsGlobalConfig {
                default_region: Some("us-east-1".to_string()),
                output_file_name: None,
                scan_interval: Duration::from_secs(60),
                credentials_cache_enabled: true,
                credential_cache_ttl: Duration::from_secs(3600),
                accounts: vec![AwsAccountConfig {
                    label: "test-account-1".to_string(),
                    account_id: Some("123456789012".to_string()),
                    profile_name: Some("test-profile-1".to_string()),
                    scan_vpc_ids: vec!["vpc-test123".to_string()],
                    scan_regions: Some(vec!["us-east-1".to_string(), "eu-west-1".to_string()]),
                    roles_to_assume: vec![],
                    discover_services: AwsServiceDiscoveryConfig {
                        vpc_endpoints: true,
                        ec2_instances: true,
                        rds_instances: true,
                        elasticache_clusters: false,
                        docdb_clusters: false,
                        api_gateways_private: false,
                    },
                }],
                route53_inbound_endpoint_ips: None,
                private_aws_suffixes: Some(vec![
                    ".rds.amazonaws.com".to_string(),
                    ".cache.amazonaws.com".to_string(),
                ]),
                discovered_private_zones: None,
            }),
            ..Default::default()
        };

        let app_config = Arc::new(RwLock::new(config));
        let dns_cache = Arc::new(DnsCache::new(
            100,
            Duration::from_secs(1),
            Duration::from_secs(300),
            false,
            Duration::from_secs(600),
        ));

        Self {
            mock_vpc_provider: Arc::new(MockAwsVpcInfoProvider::new()),
            mock_config_provider: Arc::new(MockAwsConfigProvider::new()),
            mock_status_reporter: Arc::new(MockStatusReporter::new()),
            mock_user_interaction: Arc::new(MockUserInteraction::new()),
            mock_upstream_resolver: Arc::new(MockUpstreamResolver::new()),
            app_config,
            dns_cache,
            cancellation_token: CancellationToken::new(),
            scan_trigger: Arc::new(Notify::new()),
            network_info: Arc::new(RwLock::new(
                crate::aws_integration::scanner::DiscoveredAwsNetworkInfo::default(),
            )),
        }
    }

    pub(crate) fn create_test_aws_config() -> AppConfig {
        AppConfig {
            aws: Some(AwsGlobalConfig {
                default_region: Some("us-east-1".to_string()),
                output_file_name: None,
                scan_interval: Duration::from_secs(60),
                credentials_cache_enabled: true,
                credential_cache_ttl: Duration::from_secs(3600),
                accounts: vec![
                    AwsAccountConfig {
                        label: "test-account-1".to_string(),
                        account_id: Some("123456789012".to_string()),
                        profile_name: Some("test-profile-1".to_string()),
                        scan_vpc_ids: vec!["vpc-test123".to_string()],
                        scan_regions: Some(vec!["us-east-1".to_string(), "eu-west-1".to_string()]),
                        roles_to_assume: vec![],
                        discover_services: AwsServiceDiscoveryConfig {
                            vpc_endpoints: true,
                            ec2_instances: true,
                            rds_instances: true,
                            elasticache_clusters: false,
                            docdb_clusters: false,
                            api_gateways_private: false,
                        },
                    },
                    AwsAccountConfig {
                        label: "test-account-2".to_string(),
                        account_id: Some("234567890123".to_string()),
                        profile_name: Some("test-profile-2".to_string()),
                        scan_vpc_ids: vec!["vpc-test456".to_string()],
                        scan_regions: Some(vec!["us-west-2".to_string()]),
                        roles_to_assume: vec![AwsRoleConfig {
                            role_arn: "arn:aws:iam::234567890123:role/CrossAccountRole".to_string(),
                            label: Some("CrossAccountRole".to_string()),
                            scan_vpc_ids: vec![],
                            scan_regions: Some(vec!["ap-southeast-1".to_string()]),
                            discover_services: AwsServiceDiscoveryConfig::default(),
                        }],
                        discover_services: AwsServiceDiscoveryConfig {
                            vpc_endpoints: true,
                            ec2_instances: false,
                            rds_instances: true,
                            elasticache_clusters: true,
                            docdb_clusters: false,
                            api_gateways_private: true,
                        },
                    },
                ],
                route53_inbound_endpoint_ips: None,
                private_aws_suffixes: Some(vec![
                    ".rds.amazonaws.com".to_string(),
                    ".cache.amazonaws.com".to_string(),
                ]),
                discovered_private_zones: None,
            }),
            ..Default::default()
        }
    }

    pub(crate) fn create_mock_lifecycle_manager(&self) -> Arc<MockAppLifecycleManager> {
        let status_reporter: Arc<dyn StatusReporterPort> = self.mock_status_reporter.clone();
        let user_interaction: Arc<dyn UserInteractionPort> = self.mock_user_interaction.clone();
        let aws_config_provider: Arc<dyn AwsConfigProvider> = self.mock_config_provider.clone();

        Arc::new(MockAppLifecycleManager {
            config: self.app_config.clone(),
            dns_cache: self.dns_cache.clone(),
            status_reporter,
            user_interaction,
            aws_config_provider,
            scan_trigger: self.scan_trigger.clone(),
            cancellation_token: self.cancellation_token.clone(),
            network_info: self.network_info.clone(),
        })
    }

    pub(crate) fn create_scanner(&self) -> Arc<AwsVpcScannerTask> {
        let lifecycle_manager = self.create_mock_lifecycle_manager();
        let lifecycle_manager_port: Arc<dyn AppLifecycleManagerPort> = lifecycle_manager;
        let config_provider: Arc<dyn AwsConfigProvider> = self.mock_config_provider.clone();
        let vpc_provider: Arc<dyn AwsVpcInfoProvider> = self.mock_vpc_provider.clone();
        let upstream_resolver: Arc<dyn UpstreamResolver> = self.mock_upstream_resolver.clone();

        Arc::new(AwsVpcScannerTask::new(
            lifecycle_manager_port,
            config_provider,
            vpc_provider,
            upstream_resolver,
        ))
    }

    pub(crate) fn start_scanner(&self) -> Arc<AwsVpcScannerTask> {
        let scanner = self.create_scanner();
        let scanner_clone = Arc::clone(&scanner);

        tokio::spawn(async move {
            scanner_clone.run().await;
        });

        scanner
    }

    pub(crate) async fn trigger_scan_and_wait(&self) -> AwsScannerStatus {
        let _scanner = self.start_scanner();

        let mut attempts = 0;
        while attempts < 60 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let status = self
                .mock_status_reporter
                .get_current_aws_status()
                .unwrap_or_default();
            if status.is_scanning || status.accounts_scanned > 0 || status.accounts_failed > 0 {
                break;
            }
            attempts += 1;
        }

        if attempts >= 60 {
            self.scan_trigger.notify_one();
        }

        self.wait_for_scan_completion().await
    }

    pub(crate) fn setup_successful_scan_scenario(&self) {
        self.mock_config_provider.set_credentials_response(
            "test-profile-1",
            Ok(Self::create_mock_credentials("ACCOUNT1")),
        );
        self.mock_config_provider.set_credentials_response(
            "test-profile-2",
            Ok(Self::create_mock_credentials("ACCOUNT2")),
        );
        self.mock_config_provider.set_role_response(
            "arn:aws:iam::234567890123:role/CrossAccountRole",
            Ok(Self::create_mock_credentials("ROLE1")),
        );

        self.mock_vpc_provider.set_discover_vpc_endpoints_response(
            "us-east-1",
            MockAwsApiResponse {
                endpoints: vec![
                    Self::create_test_endpoint("ec2", "10.0.1.100", "us-east-1", "EC2"),
                    Self::create_test_endpoint("rds-instance-1", "10.0.1.101", "us-east-1", "RDS"),
                ],
                should_fail: false,
                error_type: None,
                delay_ms: None,
            },
        );
        self.mock_vpc_provider.set_discover_vpc_endpoints_response(
            "eu-west-1",
            MockAwsApiResponse {
                endpoints: vec![Self::create_test_endpoint(
                    "s3",
                    "10.0.2.100",
                    "eu-west-1",
                    "S3",
                )],
                should_fail: false,
                error_type: None,
                delay_ms: None,
            },
        );
        self.mock_vpc_provider.set_discover_vpc_endpoints_response(
            "us-west-2",
            MockAwsApiResponse {
                endpoints: vec![Self::create_test_endpoint(
                    "elasticache-cluster",
                    "10.0.3.100",
                    "us-west-2",
                    "ElastiCache-Node",
                )],
                should_fail: false,
                error_type: None,
                delay_ms: None,
            },
        );

        self.mock_vpc_provider.set_route53_response(
            "us-east-1",
            vec![IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 169, 253))],
        );

        let mut zones = HashSet::new();
        zones.insert("test.vpc-test123.local".to_string());
        self.mock_vpc_provider
            .set_private_zones_response("us-east-1", "vpc-test123", zones);
    }

    pub(crate) fn setup_credential_failure_scenario(&self) {
        self.mock_config_provider.set_credentials_response(
            "test-profile-1",
            Err(crate::core::error::AwsAuthError::Config(
                "Access denied".to_string(),
            )),
        );

        self.mock_config_provider.set_credentials_response(
            "test-profile-2",
            Ok(Self::create_mock_credentials("ACCOUNT2")),
        );

        self.mock_vpc_provider.set_discover_vpc_endpoints_response(
            "us-west-2",
            MockAwsApiResponse {
                endpoints: vec![Self::create_test_endpoint(
                    "working-service",
                    "10.0.1.200",
                    "us-west-2",
                    "EC2",
                )],
                should_fail: false,
                error_type: None,
                delay_ms: None,
            },
        );
    }

    pub(crate) fn setup_api_failure_scenario(&self) {
        self.mock_config_provider.set_credentials_response(
            "test-profile-1",
            Ok(Self::create_mock_credentials("ACCOUNT1")),
        );

        self.mock_vpc_provider.set_discover_vpc_endpoints_response(
            "us-east-1",
            MockAwsApiResponse {
                endpoints: vec![],
                should_fail: true,
                error_type: Some(MockAwsError::ServiceUnavailable),
                delay_ms: None,
            },
        );
    }

    pub(crate) fn setup_mfa_required_scenario(&self) {
        self.mock_config_provider.set_credentials_response(
            "test-profile-2",
            Ok(Self::create_mock_credentials("ACCOUNT2")),
        );
        self.mock_config_provider.set_role_response(
            "arn:aws:iam::234567890123:role/CrossAccountRole",
            Err(crate::core::error::AwsAuthError::MfaRequired {
                user_identity: "234567890123".to_string(),
            }),
        );

        self.mock_user_interaction.set_mfa_response("123456");
    }

    pub(crate) async fn wait_for_scan_completion(&self) -> AwsScannerStatus {
        let timeout = Duration::from_secs(10);
        let poll_interval = Duration::from_millis(50);
        let start_time = tokio::time::Instant::now();

        loop {
            let status = self
                .mock_status_reporter
                .get_current_aws_status()
                .unwrap_or_default();

            if !status.is_scanning && (status.accounts_scanned > 0 || status.accounts_failed > 0) {
                println!(
                    "Scan completed: accounts_scanned={}, accounts_failed={}, discovered_entries_count={}",
                    status.accounts_scanned,
                    status.accounts_failed,
                    status.discovered_entries_count
                );
                return status;
            }

            if start_time.elapsed() > timeout {
                println!(
                    "Scan timeout reached: is_scanning={}, accounts_scanned={}, accounts_failed={}, discovered_entries_count={}",
                    status.is_scanning,
                    status.accounts_scanned,
                    status.accounts_failed,
                    status.discovered_entries_count
                );
                return status;
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    pub(crate) fn get_call_logs(&self) -> (Vec<(String, String, String)>, Vec<String>) {
        (
            self.mock_vpc_provider.get_call_log(),
            self.mock_config_provider.get_call_log(),
        )
    }

    pub(crate) fn clear_all_mocks(&self) {
        self.mock_vpc_provider.clear_responses();
        self.mock_config_provider.clear_responses();
        self.mock_status_reporter.clear_status();
        self.mock_user_interaction.clear_messages();
    }

    fn create_mock_credentials(prefix: &str) -> AwsCredentials {
        Credentials::new(
            format!("MOCK_{}_ACCESS_KEY", prefix),
            format!("MOCK_{}_SECRET_KEY", prefix),
            Some(format!("MOCK_{}_SESSION_TOKEN", prefix)),
            Some(SystemTime::now() + Duration::from_secs(3600)),
            "MockProvider",
        )
    }

    fn create_test_endpoint(
        service_name: &str,
        private_ip: &str,
        region: &str,
        service_type: &str,
    ) -> AwsDiscoveredEndpoint {
        AwsDiscoveredEndpoint {
            service_dns_name: format!("{}.{}.amazonaws.com", service_name, region),
            vpc_endpoint_dns_name: Some(format!(
                "vpce-{}.{}.vpce.amazonaws.com",
                service_name, region
            )),
            private_ips: vec![private_ip.parse().unwrap()],
            service_type: service_type.to_string(),
            region: region.to_string(),
            vpc_id: Some("vpc-test123".to_string()),
            comment: Some(format!("Test {} endpoint in {}", service_type, region)),
        }
    }
}

pub(crate) struct MockAppLifecycleManager {
    pub config: Arc<RwLock<AppConfig>>,
    pub dns_cache: Arc<DnsCache>,
    pub status_reporter: Arc<dyn StatusReporterPort>,
    pub user_interaction: Arc<dyn UserInteractionPort>,
    pub aws_config_provider: Arc<dyn AwsConfigProvider>,
    pub scan_trigger: Arc<Notify>,
    pub cancellation_token: CancellationToken,
    pub network_info: Arc<RwLock<crate::aws_integration::scanner::DiscoveredAwsNetworkInfo>>,
}

#[async_trait::async_trait]
impl AppLifecycleManagerPort for MockAppLifecycleManager {
    fn get_config(&self) -> Arc<RwLock<AppConfig>> {
        Arc::clone(&self.config)
    }

    fn get_dns_cache(&self) -> Arc<DnsCache> {
        Arc::clone(&self.dns_cache)
    }

    fn get_status_reporter(&self) -> Arc<dyn StatusReporterPort> {
        Arc::clone(&self.status_reporter)
    }

    fn get_user_interaction_port(&self) -> Arc<dyn UserInteractionPort> {
        Arc::clone(&self.user_interaction)
    }

    fn get_aws_scan_trigger(&self) -> Arc<Notify> {
        Arc::clone(&self.scan_trigger)
    }

    fn get_cancellation_token(&self) -> CancellationToken {
        self.cancellation_token.clone()
    }

    fn get_discovered_aws_network_info_view(
        &self,
    ) -> Arc<RwLock<crate::aws_integration::scanner::DiscoveredAwsNetworkInfo>> {
        Arc::clone(&self.network_info)
    }

    fn get_local_hosts_resolver(
        &self,
    ) -> Arc<crate::core::local_hosts_resolver::LocalHostsResolver> {
        panic!("LocalHostsResolver not implemented in test mock - AWS tests shouldn't need this")
    }

    async fn add_task(&self, _handle: tokio::task::JoinHandle<()>) {}

    async fn get_total_queries_processed(&self) -> u64 {
        0
    }

    async fn get_active_listeners(&self) -> Vec<String> {
        vec![]
    }

    async fn add_listener_address(&self, _addr: String) {}

    async fn remove_listener_address(&self, _addr: String) {}

    async fn start(&self) -> Result<(), String> {
        Ok(())
    }

    async fn stop(&self) {}

    async fn trigger_config_reload(&self) -> Result<(), crate::core::error::CliError> {
        Ok(())
    }

    async fn trigger_aws_scan_refresh(&self) -> Result<(), crate::core::error::CliError> {
        self.scan_trigger.notify_one();
        Ok(())
    }

    async fn add_or_update_aws_account_config(
        &self,
        _new_account_config: crate::config::models::AwsAccountConfig,
        _original_dnspx_label_for_edit: Option<String>,
    ) -> Result<(), crate::core::error::ConfigError> {
        Ok(())
    }

    async fn persist_discovered_aws_details(
        &self,
        _discovered_ips: Option<Vec<String>>,
        _discovered_zones: Option<Vec<String>>,
    ) -> Result<(), crate::core::error::ConfigError> {
        Ok(())
    }

    async fn get_app_status(&self) -> crate::core::types::AppStatus {
        crate::core::types::AppStatus {
            config_status: crate::core::types::ConfigStatus::default(),
            aws_scanner_status: None,
            uptime_seconds: 0,
            active_listeners: vec![],
            cache_stats: None,
            active_config_hash: String::new(),
            update_status: None,
        }
    }

    fn get_aws_config_provider(&self) -> Arc<dyn AwsConfigProvider> {
        Arc::clone(&self.aws_config_provider)
    }

    fn get_update_manager(&self) -> Option<Arc<dyn crate::ports::UpdateManagerPort>> {
        None
    }

    async fn get_config_for_processor(&self) -> Arc<RwLock<AppConfig>> {
        Arc::clone(&self.config)
    }

    fn increment_total_queries_processed(&self) {}
}

pub(crate) struct MockUpstreamResolver {
    responses: std::sync::Arc<
        std::sync::Mutex<
            std::collections::HashMap<
                String,
                Result<crate::dns_protocol::DnsMessage, crate::core::error::ResolveError>,
            >,
        >,
    >,
}

impl MockUpstreamResolver {
    pub(crate) fn new() -> Self {
        Self {
            responses: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub(crate) fn set_response(
        &self,
        dns_name: &str,
        response: Result<crate::dns_protocol::DnsMessage, crate::core::error::ResolveError>,
    ) {
        self.responses
            .lock()
            .unwrap()
            .insert(dns_name.to_string(), response);
    }
}

#[async_trait::async_trait]
impl UpstreamResolver for MockUpstreamResolver {
    async fn resolve_dns(
        &self,
        question: &crate::dns_protocol::DnsQuestion,
        _upstream_servers: &[String],
        _timeout: Duration,
    ) -> Result<crate::dns_protocol::DnsMessage, crate::core::error::ResolveError> {
        if let Some(response) = self.responses.lock().unwrap().get(&question.name) {
            match response {
                Ok(msg) => Ok(msg.clone()),
                Err(_err) => {
                    use crate::core::error::ResolveError;
                    Err(ResolveError::Network("Mock error".to_string()))
                }
            }
        } else {
            use crate::dns_protocol::DnsMessage;
            use hickory_proto::op::ResponseCode;
            let dummy_query =
                DnsMessage::new_query(0, "dummy.local", hickory_proto::rr::RecordType::A).unwrap();
            Ok(DnsMessage::new_response(
                &dummy_query,
                ResponseCode::NoError,
            ))
        }
    }

    async fn resolve_doh(
        &self,
        question: &crate::dns_protocol::DnsQuestion,
        _upstream_urls: &[url::Url],
        _timeout: Duration,
        _http_proxy_config: Option<&crate::config::models::HttpProxyConfig>,
    ) -> Result<crate::dns_protocol::DnsMessage, crate::core::error::ResolveError> {
        self.resolve_dns(question, &[], _timeout).await
    }
}
