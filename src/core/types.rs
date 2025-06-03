use crate::config::models::AppConfig;
use aws_credential_types::Credentials as AwsCredentialsExternal;
use chrono::{DateTime, Utc};

use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum ProtocolType {
    Udp,
    Tcp,
}

pub type AwsCredentials = AwsCredentialsExternal;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountScanError {
    pub label_or_arn: String,
    pub region: Option<String>,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AwsScannerStatus {
    pub is_scanning: bool,
    pub last_scan_time: Option<DateTime<Utc>>,
    pub discovered_entries_count: usize,
    pub error_message: Option<String>,
    pub accounts_scanned: u32,
    pub accounts_failed: u32,
    #[serde(default)]
    pub detailed_errors: Vec<AccountScanError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigStatus {
    pub last_loaded_time: Option<DateTime<Utc>>,
    pub is_valid: bool,
    pub error_message: Option<String>,
    pub source_file_path: Option<String>,
}

impl Default for ConfigStatus {
    fn default() -> Self {
        Self {
            last_loaded_time: None,
            is_valid: false,
            error_message: Some("Configuration not yet loaded.".to_string()),
            source_file_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub size: u64,
    pub estimated_memory_usage_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStatus {
    pub config_status: ConfigStatus,
    pub aws_scanner_status: Option<AwsScannerStatus>,
    pub uptime_seconds: u64,
    pub active_listeners: Vec<String>,
    pub cache_stats: Option<CacheStats>,
    pub active_config_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum MessageLevel {
    Info,
    Warning,
    Error,
    Debug,
    Trace,
}

#[derive(Debug, Clone)]
pub enum CliCommand {
    Status,
    ReloadConfig,
    TriggerAwsScan,
    GetConfig(Option<String>),
    Exit,
}

#[derive(Debug, Clone)]
pub enum CliOutput {
    Message(String),
    Table(Vec<Vec<String>>),
    Json(serde_json::Value),
    Status(Box<AppStatus>),
    Config(Arc<RwLock<AppConfig>>),
    None,
}

#[derive(PartialEq, Eq, Clone, Debug, Copy, Hash, Default)]
pub enum AwsAuthMethod {
    #[default]
    AwsProfile,
    AccessKeys,
    IamRole,
}

impl AwsAuthMethod {
    pub fn next(&self) -> Self {
        match self {
            AwsAuthMethod::AwsProfile => AwsAuthMethod::AccessKeys,
            AwsAuthMethod::AccessKeys => AwsAuthMethod::IamRole,
            AwsAuthMethod::IamRole => AwsAuthMethod::AwsProfile,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            AwsAuthMethod::AwsProfile => AwsAuthMethod::IamRole,
            AwsAuthMethod::AccessKeys => AwsAuthMethod::AwsProfile,
            AwsAuthMethod::IamRole => AwsAuthMethod::AccessKeys,
        }
    }
}
