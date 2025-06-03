use crate::core::types::ProtocolType;
use ipnetwork::IpNetwork;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use url::Url;

#[derive(Debug, Default, Clone, serde::Deserialize)]
pub struct DotNetLegacyConfig {
    pub main_config: DotNetMainConfig,
    pub rules_config: Option<DotNetRulesConfig>,
    pub hosts_config: Option<DotNetHostsConfig>,
    pub main_config_path: Option<PathBuf>,
    pub rules_config_path: Option<PathBuf>,
    pub hosts_config_path: Option<PathBuf>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetMainConfig {
    pub dns_host_config: Option<DotNetDnsHostConfig>,
    pub dns_default_server: Option<DotNetDnsDefaultServer>,
    pub http_proxy_config: Option<DotNetHttpProxyConfig>,
    pub aws_settings: Option<DotNetAwsSettings>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetDnsHostConfig {
    pub listener_port: Option<u16>,
    pub network_whitelist: Option<Vec<String>>,
    pub default_query_timeout: Option<u64>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetDnsDefaultServer {
    pub servers: Option<DotNetServers>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetServers {
    pub name_server: Option<Vec<String>>,
    pub strategy: Option<String>,
    pub compression_mutation: Option<bool>,
    pub query_timeout: Option<u64>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetHttpProxyConfig {
    pub authentication_type: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub domain: Option<String>,
    pub bypass_addresses: Option<String>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetAwsSettings {
    pub region: Option<String>,
    pub user_accounts: Option<Vec<DotNetUserAccount>>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetUserAccount {
    pub user_account_id: Option<String>,
    pub user_name: Option<String>,
    pub user_access_key: Option<String>,
    pub user_secret_key: Option<String>,
    pub do_scan: Option<bool>,
    pub scan_vpc_ids: Option<Vec<String>>,
    pub roles: Option<Vec<DotNetRole>>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetRole {
    pub aws_account_label: Option<String>,
    pub aws_account_id: Option<String>,
    pub role: Option<String>,
    pub do_scan: Option<bool>,
    pub scan_vpc_ids: Option<Vec<String>>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetRulesConfig {
    pub rules_config: Option<DotNetRules>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetRules {
    pub rules: Option<Vec<DotNetRule>>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetRule {
    pub domain_name_pattern: Option<String>,
    pub domain_name: Option<String>,
    pub name_server: Option<Vec<String>>,
    pub strategy: Option<String>,
    pub is_enabled: Option<bool>,
    pub compression_mutation: Option<bool>,
    pub query_timeout: Option<u64>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetHostsConfig {
    pub hosts_config: Option<DotNetHosts>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetHosts {
    pub rule: Option<DotNetHostRule>,
    pub hosts: Option<Vec<DotNetHost>>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetHostRule {
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DotNetHost {
    pub ip_addresses: Option<Vec<String>>,
    pub domain_names: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct HashableRegex(pub Regex);

impl PartialEq for HashableRegex {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}
impl Eq for HashableRegex {}

impl Hash for HashableRegex {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state);
    }
}

impl Serialize for HashableRegex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HashableRegex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Regex::new(&s)
            .map(HashableRegex)
            .map_err(serde::de::Error::custom)
    }
}

impl Default for HashableRegex {
    fn default() -> Self {
        HashableRegex(Regex::new("(?!)").unwrap())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub default_resolver: DefaultResolverConfig,
    #[serde(default)]
    pub routing_rules: Vec<RuleConfig>,
    pub local_hosts: Option<LocalHostsConfig>,
    #[serde(default)]
    pub cache: CacheConfig,
    pub http_proxy: Option<HttpProxyConfig>,
    pub aws: Option<AwsGlobalConfig>,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub cli: CliConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            default_resolver: DefaultResolverConfig::default(),
            routing_rules: Vec::new(),
            local_hosts: None,
            cache: CacheConfig::default(),
            http_proxy: None,
            aws: None,
            logging: LoggingConfig::default(),
            cli: CliConfig::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerConfig {
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    #[serde(default = "default_protocols")]
    pub protocols: Vec<ProtocolType>,
    pub network_whitelist: Option<Vec<IpNetwork>>,
    #[serde(with = "humantime_serde", default = "default_query_timeout")]
    pub default_query_timeout: Duration,
}

fn default_listen_address() -> String {
    "0.0.0.0:53".to_string()
}
fn default_protocols() -> Vec<ProtocolType> {
    vec![ProtocolType::Udp, ProtocolType::Tcp]
}
fn default_query_timeout() -> Duration {
    Duration::from_millis(500)
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_address: default_listen_address(),
            protocols: default_protocols(),
            network_whitelist: None,
            default_query_timeout: default_query_timeout(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResolverStrategy {
    First,
    Random,
    Rotate,
    Fastest,
}
impl Default for ResolverStrategy {
    fn default() -> Self {
        ResolverStrategy::First
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct DefaultResolverConfig {
    pub nameservers: Vec<String>,
    #[serde(default)]
    pub strategy: ResolverStrategy,
    #[serde(with = "humantime_serde", default = "default_resolver_timeout")]
    pub timeout: Duration,
    #[serde(default = "default_doh_compression_mutation")]
    pub doh_compression_mutation: bool,
}
fn default_resolver_timeout() -> Duration {
    Duration::from_millis(500)
}
fn default_doh_compression_mutation() -> bool {
    false
}
impl Default for DefaultResolverConfig {
    fn default() -> Self {
        Self {
            nameservers: vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()],
            strategy: ResolverStrategy::default(),
            timeout: default_resolver_timeout(),
            doh_compression_mutation: default_doh_compression_mutation(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuleAction {
    Forward,
    Block,
    Allow,
    ResolveLocal,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleConfig {
    pub name: String,
    #[serde(default)]
    pub domain_pattern: HashableRegex,
    pub action: RuleAction,
    pub nameservers: Option<Vec<String>>,
    #[serde(default)]
    pub strategy: ResolverStrategy,
    #[serde(with = "humantime_serde", default = "default_resolver_timeout")]
    pub timeout: Duration,
    #[serde(default = "default_doh_compression_mutation")]
    pub doh_compression_mutation: bool,
    pub source_list_url: Option<Url>,
    #[serde(default)]
    pub invert_match: bool,
}

fn default_hosts_ttl() -> u32 {
    300
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostsLoadBalancing {
    All,
    Random,
    First,
}

impl Default for HostsLoadBalancing {
    fn default() -> Self {
        HostsLoadBalancing::All
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocalHostsConfig {
    pub entries: BTreeMap<String, Vec<IpAddr>>,
    pub file_path: Option<PathBuf>,
    #[serde(default)]
    pub watch_file: bool,
    #[serde(default = "default_hosts_ttl")]
    pub ttl: u32,
    #[serde(default)]
    pub load_balancing: HostsLoadBalancing,
}

impl Default for LocalHostsConfig {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            file_path: None,
            watch_file: false,
            ttl: default_hosts_ttl(),
            load_balancing: HostsLoadBalancing::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheConfig {
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_capacity")]
    pub max_capacity: u64,
    #[serde(with = "humantime_serde", default = "default_min_ttl")]
    pub min_ttl: Duration,
    #[serde(with = "humantime_serde", default = "default_max_ttl")]
    pub max_ttl: Duration,
    #[serde(default = "default_serve_stale_enabled")]
    pub serve_stale_if_error: bool,
    #[serde(with = "humantime_serde", default = "default_stale_max_ttl")]
    pub serve_stale_max_ttl: Duration,
}
fn default_cache_enabled() -> bool {
    true
}
fn default_max_capacity() -> u64 {
    10_000
}
fn default_min_ttl() -> Duration {
    Duration::from_secs(60)
}
fn default_max_ttl() -> Duration {
    Duration::from_secs(24 * 60 * 60)
}
fn default_serve_stale_enabled() -> bool {
    true
}
fn default_stale_max_ttl() -> Duration {
    Duration::from_secs(60 * 60)
}
impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_enabled(),
            max_capacity: default_max_capacity(),
            min_ttl: default_min_ttl(),
            max_ttl: default_max_ttl(),
            serve_stale_if_error: default_serve_stale_enabled(),
            serve_stale_max_ttl: default_stale_max_ttl(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpProxyConfig {
    pub url: Url,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AwsGlobalConfig {
    pub default_region: Option<String>,
    pub output_file_name: Option<PathBuf>,
    #[serde(with = "humantime_serde", default = "default_scan_interval")]
    pub scan_interval: Duration,
    #[serde(default = "default_true")]
    pub credentials_cache_enabled: bool,
    #[serde(with = "humantime_serde", default = "default_credential_cache_ttl")]
    pub credential_cache_ttl: Duration,
    #[serde(default)]
    pub accounts: Vec<AwsAccountConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route53_inbound_endpoint_ips: Option<Vec<String>>,
    #[serde(
        default = "default_private_aws_suffixes",
        skip_serializing_if = "Option::is_none"
    )]
    pub private_aws_suffixes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovered_private_zones: Option<Vec<String>>,
}
fn default_scan_interval() -> Duration {
    Duration::from_secs(15 * 60)
}
fn default_credential_cache_ttl() -> Duration {
    Duration::from_secs(50 * 60)
}
fn default_true() -> bool {
    true
}
fn default_private_aws_suffixes() -> Option<Vec<String>> {
    Some(vec![
        ".rds.amazonaws.com".to_string(),
        ".cache.amazonaws.com".to_string(),
        ".docdb.amazonaws.com".to_string(),
        ".vpce.amazonaws.com".to_string(),
        ".execute-api.amazonaws.com".to_string(),
    ])
}
impl Default for AwsGlobalConfig {
    fn default() -> Self {
        Self {
            default_region: Some("us-east-1".to_string()),
            output_file_name: None,
            scan_interval: default_scan_interval(),
            credentials_cache_enabled: default_true(),
            credential_cache_ttl: default_credential_cache_ttl(),
            accounts: Vec::new(),
            route53_inbound_endpoint_ips: None,
            private_aws_suffixes: default_private_aws_suffixes(),
            discovered_private_zones: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AwsAccountConfig {
    pub label: String,
    pub account_id: Option<String>,
    pub profile_name: Option<String>,
    #[serde(default)]
    pub scan_vpc_ids: Vec<String>,
    #[serde(default)]
    pub scan_regions: Option<Vec<String>>,
    #[serde(default)]
    pub roles_to_assume: Vec<AwsRoleConfig>,
    #[serde(default)]
    pub discover_services: AwsServiceDiscoveryConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct AwsServiceDiscoveryConfig {
    #[serde(default = "default_true")]
    pub vpc_endpoints: bool,
    #[serde(default)]
    pub ec2_instances: bool,
    #[serde(default)]
    pub rds_instances: bool,
    #[serde(default)]
    pub elasticache_clusters: bool,
    #[serde(default)]
    pub docdb_clusters: bool,
    #[serde(default)]
    pub api_gateways_private: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct AwsRoleConfig {
    pub role_arn: String,
    pub label: Option<String>,
    #[serde(default)]
    pub scan_vpc_ids: Vec<String>,
    #[serde(default)]
    pub scan_regions: Option<Vec<String>>,
    #[serde(default)]
    pub discover_services: AwsServiceDiscoveryConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum LogFormat {
    Pretty,
    Json,
    Compact,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: LogFormat,
    #[serde(default = "default_query_log_enabled")]
    pub query_log_enabled: bool,
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> LogFormat {
    LogFormat::Pretty
}
fn default_query_log_enabled() -> bool {
    false
}
impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            query_log_enabled: default_query_log_enabled(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct CliConfig {
    #[serde(default = "default_true")]
    pub enable_colors: bool,
    #[serde(default = "default_status_refresh_interval_secs")]
    pub status_refresh_interval_secs: u64,
}
fn default_status_refresh_interval_secs() -> u64 {
    5
}
impl Default for CliConfig {
    fn default() -> Self {
        Self {
            enable_colors: default_true(),
            status_refresh_interval_secs: default_status_refresh_interval_secs(),
        }
    }
}
