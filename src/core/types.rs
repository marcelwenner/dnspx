use crate::config::models::AppConfig;
use aws_credential_types::Credentials as AwsCredentialsExternal;
use chrono::{DateTime, Utc};

use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub(crate) enum ProtocolType {
    Udp,
    Tcp,
}

pub(crate) type AwsCredentials = AwsCredentialsExternal;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct AccountScanError {
    pub label_or_arn: String,
    pub region: Option<String>,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct AwsScannerStatus {
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
pub(crate) struct ConfigStatus {
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
pub(crate) struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub size: u64,
    pub estimated_memory_usage_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AppStatus {
    pub config_status: ConfigStatus,
    pub aws_scanner_status: Option<AwsScannerStatus>,
    pub uptime_seconds: u64,
    pub active_listeners: Vec<String>,
    pub cache_stats: Option<CacheStats>,
    pub active_config_hash: String,
    pub update_status: Option<UpdateStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub(crate) enum MessageLevel {
    Info,
    Warning,
    Error,
    Debug,
    Trace,
}

#[derive(Debug, Clone)]
pub(crate) enum CliCommand {
    Status,
    ReloadConfig,
    TriggerAwsScan,
    GetConfig(Option<String>),
    UpdateCheck,
    UpdateInstall,
    UpdateStatus,
    UpdateRollback,
    Help,
    UpdateHelp,
    Exit,
}

#[derive(Debug, Clone)]
pub(crate) enum CliOutput {
    Message(String),
    Table(Vec<Vec<String>>),
    Json(serde_json::Value),
    Status(Box<AppStatus>),
    Config(Arc<RwLock<AppConfig>>),
    None,
}

#[derive(PartialEq, Eq, Clone, Debug, Copy, Hash, Default)]
pub(crate) enum AwsAuthMethod {
    #[default]
    AwsProfile,
    AccessKeys,
    IamRole,
}

impl AwsAuthMethod {
    pub(crate) fn next(&self) -> Self {
        match self {
            AwsAuthMethod::AwsProfile => AwsAuthMethod::AccessKeys,
            AwsAuthMethod::AccessKeys => AwsAuthMethod::IamRole,
            AwsAuthMethod::IamRole => AwsAuthMethod::AwsProfile,
        }
    }

    pub(crate) fn prev(&self) -> Self {
        match self {
            AwsAuthMethod::AwsProfile => AwsAuthMethod::IamRole,
            AwsAuthMethod::AccessKeys => AwsAuthMethod::AwsProfile,
            AwsAuthMethod::IamRole => AwsAuthMethod::AccessKeys,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UpdateStatus {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub last_check_time: Option<DateTime<Utc>>,
    pub update_available: bool,
    pub checking_for_updates: bool,
    pub installing_update: bool,
    pub last_error: Option<String>,
    pub rollback_available: bool,
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self {
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            latest_version: None,
            last_check_time: None,
            update_available: false,
            checking_for_updates: false,
            installing_update: false,
            last_error: None,
            rollback_available: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UpdateInfo {
    pub version: String,
    pub download_url: String,
    pub checksum: Option<String>,
    pub signature_url: Option<String>,
    pub release_notes: Option<String>,
    pub breaking_changes: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum UpdateResult {
    UpToDate,
    UpdateAvailable(UpdateInfo),
    UpdateInstalled {
        from_version: String,
        to_version: String,
    },
    UpdateFailed {
        error: String,
        rollback_performed: bool,
    },
}
