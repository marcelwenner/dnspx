use crate::core::types::AwsCredentials as CoreAwsCredentials;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub type CredentialCacheKey = String;

#[derive(Debug, Clone)]
pub struct CachedAwsCredentials {
    pub credentials: CoreAwsCredentials,
    pub expiry_time: Option<DateTime<Utc>>,
}

pub type AwsCredentialsCache = Arc<RwLock<HashMap<CredentialCacheKey, CachedAwsCredentials>>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct AwsDiscoveredEndpoint {
    pub service_dns_name: String,
    pub vpc_endpoint_dns_name: Option<String>,
    pub private_ips: Vec<std::net::IpAddr>,
    pub service_type: String,
    pub region: String,
    pub vpc_id: Option<String>,
    pub comment: Option<String>,
}
