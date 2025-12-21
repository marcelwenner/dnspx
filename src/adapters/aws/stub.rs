use crate::config::models::{AwsAccountConfig, AwsRoleConfig};
use crate::core::error::AwsAuthError;
use crate::core::types::AwsCredentials;
use crate::ports::UserInteractionPort;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub(crate) type AwsCredentialsCache = Arc<RwLock<HashMap<String, ()>>>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub(crate) struct AwsDiscoveredEndpoint {
    pub service_dns_name: String,
    pub vpc_endpoint_dns_name: Option<String>,
    pub private_ips: Vec<std::net::IpAddr>,
    pub service_type: String,
    pub region: String,
    pub vpc_id: Option<String>,
    pub comment: Option<String>,
}

pub(crate) struct StubAwsConfigProvider;

impl StubAwsConfigProvider {
    pub(crate) fn new() -> Self {
        Self
    }
}

#[async_trait]
impl crate::ports::AwsConfigProvider for StubAwsConfigProvider {
    async fn get_credentials_for_account(
        &self,
        _account_config: &AwsAccountConfig,
        _mfa_provider: Arc<dyn UserInteractionPort>,
    ) -> Result<AwsCredentials, AwsAuthError> {
        Err(AwsAuthError::Config(
            "AWS feature is not enabled in this build".to_string(),
        ))
    }

    async fn get_credentials_for_role(
        &self,
        _base_credentials: &AwsCredentials,
        _role_config: &AwsRoleConfig,
        _account_config_for_mfa_serial: &AwsAccountConfig,
        _mfa_provider: Arc<dyn UserInteractionPort>,
    ) -> Result<AwsCredentials, AwsAuthError> {
        Err(AwsAuthError::Config(
            "AWS feature is not enabled in this build".to_string(),
        ))
    }

    async fn validate_credentials(
        &self,
        _credentials: &AwsCredentials,
    ) -> Result<String, AwsAuthError> {
        Err(AwsAuthError::Config(
            "AWS feature is not enabled in this build".to_string(),
        ))
    }
}

pub(crate) mod profile_utils {
    use crate::config::models::AwsAccountConfig;

    #[derive(Debug, Clone, Default)]
    pub(crate) struct AwsConfigParams<'a> {
        pub profile_name: Option<&'a str>,
        pub access_key_id: Option<&'a str>,
        pub secret_access_key: Option<&'a str>,
        pub regions: Vec<&'a str>,
    }

    impl<'a> AwsConfigParams<'a> {
        pub(crate) fn parse_regions(_regions_str: &str) -> Vec<&str> {
            vec![]
        }
    }

    pub(crate) fn read_aws_profiles_from_files() -> Vec<String> {
        vec![]
    }

    pub(crate) fn create_aws_account_config_from_params(
        _params: &AwsConfigParams<'_>,
        label: &str,
    ) -> AwsAccountConfig {
        AwsAccountConfig {
            label: label.to_string(),
            account_id: None,
            profile_name: None,
            scan_vpc_ids: vec![],
            scan_regions: None,
            roles_to_assume: vec![],
            discover_services: Default::default(),
        }
    }
}
