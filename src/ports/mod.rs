use crate::adapters::aws::types::AwsDiscoveredEndpoint;
use crate::aws_integration::scanner::DiscoveredAwsNetworkInfo;
use crate::config::models::{
    AppConfig, AwsAccountConfig, AwsRoleConfig, DotNetLegacyConfig, HttpProxyConfig,
};
use crate::core::dns_cache::DnsCache;
use crate::core::error::{
    AwsApiError, AwsAuthError, CliError, ConfigError, DnsProcessingError, ResolveError,
    UpdateError, UserInputError,
};
use crate::core::local_hosts_resolver::LocalHostsResolver;
use crate::core::types::{
    AppStatus, AwsCredentials, AwsScannerStatus, CacheStats, CliCommand, CliOutput, ConfigStatus,
    MessageLevel, ProtocolType, UpdateInfo, UpdateResult, UpdateStatus,
};
use crate::dns_protocol::{DnsMessage, DnsQuestion};
use async_trait::async_trait;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

#[async_trait]
pub(crate) trait AppLifecycleManagerPort: Send + Sync {
    fn get_config(&self) -> Arc<RwLock<AppConfig>>;
    fn get_dns_cache(&self) -> Arc<DnsCache>;
    fn get_status_reporter(&self) -> Arc<dyn StatusReporterPort>;
    fn get_user_interaction_port(&self) -> Arc<dyn UserInteractionPort>;
    fn get_aws_scan_trigger(&self) -> Arc<Notify>;
    fn get_cancellation_token(&self) -> CancellationToken;
    fn get_discovered_aws_network_info_view(&self) -> Arc<RwLock<DiscoveredAwsNetworkInfo>>;
    fn get_local_hosts_resolver(&self) -> Arc<LocalHostsResolver>;
    async fn add_task(&self, handle: JoinHandle<()>);
    async fn get_total_queries_processed(&self) -> u64;
    async fn get_active_listeners(&self) -> Vec<String>;
    async fn add_listener_address(&self, addr: String);
    async fn remove_listener_address(&self, addr: String);

    async fn start(&self) -> Result<(), String>;
    async fn stop(&self);
    async fn trigger_config_reload(&self) -> Result<(), CliError>;
    async fn trigger_aws_scan_refresh(&self) -> Result<(), CliError>;
    async fn add_or_update_aws_account_config(
        &self,
        new_account_config: AwsAccountConfig,
        original_dnspx_label_for_edit: Option<String>,
    ) -> Result<(), ConfigError>;
    async fn persist_discovered_aws_details(
        &self,
        discovered_ips: Option<Vec<String>>,
        discovered_zones: Option<Vec<String>>,
    ) -> Result<(), ConfigError>;
    async fn get_app_status(&self) -> AppStatus;
    fn get_aws_config_provider(&self) -> Arc<dyn AwsConfigProvider>;
    fn get_update_manager(&self) -> Option<Arc<dyn UpdateManagerPort>>;

    async fn get_config_for_processor(&self) -> Arc<RwLock<AppConfig>>;
    fn increment_total_queries_processed(&self);
}

#[async_trait]
pub(crate) trait DnsQueryService: Send + Sync {
    async fn process_query(
        &self,
        query_bytes: Vec<u8>,
        client_addr: SocketAddr,
        protocol: ProtocolType,
    ) -> Result<Vec<u8>, DnsProcessingError>;
}

#[async_trait]
pub(crate) trait InteractiveCliPort: Send + Sync {
    async fn handle_cli_command(
        &self,
        command: CliCommand,
        app_lifecycle: Arc<dyn AppLifecycleManagerPort>,
    ) -> Result<CliOutput, CliError>;
}

#[async_trait]
pub(crate) trait UpstreamResolver: Send + Sync {
    async fn resolve_dns(
        &self,
        question: &DnsQuestion,
        upstream_servers: &[String],
        timeout: Duration,
    ) -> Result<DnsMessage, ResolveError>;

    async fn resolve_doh(
        &self,
        question: &DnsQuestion,
        upstream_urls: &[Url],
        timeout: Duration,
        http_proxy_config: Option<&HttpProxyConfig>,
    ) -> Result<DnsMessage, ResolveError>;
}

#[async_trait]
pub(crate) trait AwsConfigProvider: Send + Sync {
    async fn get_credentials_for_account(
        &self,
        account_config: &AwsAccountConfig,
        mfa_provider: Arc<dyn UserInteractionPort>,
    ) -> Result<AwsCredentials, AwsAuthError>;

    async fn get_credentials_for_role(
        &self,
        base_credentials: &AwsCredentials,
        role_config: &AwsRoleConfig,
        account_config_for_mfa_serial: &AwsAccountConfig,
        mfa_provider: Arc<dyn UserInteractionPort>,
    ) -> Result<AwsCredentials, AwsAuthError>;

    async fn validate_credentials(
        &self,
        credentials: &AwsCredentials,
    ) -> Result<String, AwsAuthError>;
}

#[async_trait]
pub(crate) trait AwsVpcInfoProvider: Send + Sync {
    async fn discover_vpc_endpoints(
        &self,
        credentials: &AwsCredentials,
        account_config: &AwsAccountConfig,
        region: &str,
    ) -> Result<Vec<AwsDiscoveredEndpoint>, AwsApiError>;
    async fn discover_route53_inbound_endpoint_ips(
        &self,
        credentials: &AwsCredentials,
        region: &str,
    ) -> Result<Vec<IpAddr>, AwsApiError>;

    async fn discover_private_hosted_zones_for_vpc(
        &self,
        credentials: &AwsCredentials,
        vpc_id: &str,
        vpc_region: &str,
    ) -> Result<HashSet<String>, AwsApiError>;
}

pub(crate) trait ConfigurationStore: Send + Sync {
    fn load_dotnet_legacy_config_files(
        &self,
        main_path_opt: Option<&Path>,
        rules_path_opt: Option<&Path>,
        hosts_path_opt: Option<&Path>,
    ) -> Result<DotNetLegacyConfig, ConfigError>;

    fn load_app_config_file(&self, path: &Path) -> Result<AppConfig, ConfigError>;
    fn save_app_config_file(&self, config: &AppConfig, path: &Path) -> Result<(), ConfigError>;
    fn backup_dotnet_legacy_config_files(
        &self,
        legacy_config: &DotNetLegacyConfig,
    ) -> Result<(), ConfigError>;
    fn get_default_config_path(&self) -> Result<PathBuf, ConfigError>;
}

#[async_trait]
pub(crate) trait UserInteractionPort: Send + Sync {
    async fn prompt_for_mfa_token(
        &self,
        user_identity: &str,
        attempt: u32,
    ) -> Result<String, UserInputError>;
    async fn prompt_for_aws_keys(
        &self,
        account_label: &str,
    ) -> Result<(String, String), UserInputError>;
    fn display_message(&self, message: &str, level: MessageLevel);
    fn display_status(&self, status_info: &AppStatus);
    fn display_error(&self, error: &dyn std::error::Error);
    fn display_table(&self, headers: Vec<String>, rows: Vec<Vec<String>>);
    fn display_prompt(&self, prompt_text: &str);
}

#[async_trait]
pub(crate) trait StatusReporterPort: Send + Sync {
    async fn report_aws_scanner_status(&self, status: AwsScannerStatus);
    async fn get_aws_scanner_status(&self) -> AwsScannerStatus;
    async fn report_config_status(&self, status: ConfigStatus);
    async fn get_config_status(&self) -> ConfigStatus;
    async fn report_update_status(&self, status: UpdateStatus);
    async fn get_update_status(&self) -> UpdateStatus;
    async fn get_full_app_status(
        &self,
        uptime_seconds: u64,
        active_listeners: Vec<String>,
        config_hash: String,
        cache_stats: Option<CacheStats>,
    ) -> AppStatus;
}

#[async_trait]
pub(crate) trait UpdateManagerPort: Send + Sync {
    async fn check_for_updates(&self) -> Result<UpdateResult, UpdateError>;
    async fn install_update(&self, update_info: &UpdateInfo) -> Result<UpdateResult, UpdateError>;
    async fn rollback_update(&self) -> Result<UpdateResult, UpdateError>;
    fn get_current_version(&self) -> String;
    async fn is_rollback_available(&self) -> bool;
}
