use crate::adapters::aws::types::AwsDiscoveredEndpoint;
use crate::config::models::{AwsAccountConfig, AwsRoleConfig};
use crate::core::error::{AwsApiError, AwsAuthError};
use crate::core::types::{AwsCredentials, AwsScannerStatus};
use crate::ports::{
    AwsConfigProvider, AwsVpcInfoProvider, StatusReporterPort, UserInteractionPort,
};
use async_trait::async_trait;
use aws_credential_types::Credentials;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub(crate) struct MockAwsApiResponse {
    pub endpoints: Vec<AwsDiscoveredEndpoint>,
    pub should_fail: bool,
    pub error_type: Option<MockAwsError>,
    pub delay_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) enum MockAwsError {
    AccessDenied,
    ServiceUnavailable,
    Timeout,
    InvalidCredentials,
    MfaRequired,
    RoleAssumptionFailed,
}

impl MockAwsError {
    pub(crate) fn to_aws_api_error(&self) -> AwsApiError {
        match self {
            MockAwsError::AccessDenied => AwsApiError::Permissions {
                operation: "DescribeInstances".to_string(),
            },
            MockAwsError::ServiceUnavailable => AwsApiError::Discovery {
                region: "mock-region".to_string(),
                details: "Service temporarily unavailable".to_string(),
            },
            MockAwsError::Timeout => AwsApiError::Discovery {
                region: "mock-region".to_string(),
                details: "Request timed out".to_string(),
            },
            MockAwsError::InvalidCredentials => AwsApiError::Permissions {
                operation: "GetCallerIdentity".to_string(),
            },
            MockAwsError::MfaRequired => AwsApiError::Discovery {
                region: "mock-region".to_string(),
                details: "MultiFactorAuthentication required".to_string(),
            },
            MockAwsError::RoleAssumptionFailed => AwsApiError::Permissions {
                operation: "AssumeRole".to_string(),
            },
        }
    }

    pub(crate) fn to_aws_auth_error(&self) -> AwsAuthError {
        match self {
            MockAwsError::AccessDenied => AwsAuthError::Config("AccessDenied".to_string()),
            MockAwsError::InvalidCredentials => {
                AwsAuthError::Config("Invalid credentials".to_string())
            }
            MockAwsError::MfaRequired => AwsAuthError::MfaRequired {
                user_identity: "123456789012".to_string(),
            },
            MockAwsError::RoleAssumptionFailed => AwsAuthError::AssumeRole {
                role_arn: "arn:aws:iam::123456789012:role/test".to_string(),
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Role assumption failed",
                )),
            },
            _ => AwsAuthError::Config("Unknown error".to_string()),
        }
    }
}

pub(crate) struct MockAwsVpcInfoProvider {
    responses: Arc<Mutex<HashMap<String, MockAwsApiResponse>>>,
    route53_responses: Arc<Mutex<HashMap<String, Vec<IpAddr>>>>,
    private_zones_responses: Arc<Mutex<HashMap<String, HashSet<String>>>>,
    call_log: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl MockAwsVpcInfoProvider {
    pub(crate) fn new() -> Self {
        Self {
            responses: Arc::new(Mutex::new(HashMap::new())),
            route53_responses: Arc::new(Mutex::new(HashMap::new())),
            private_zones_responses: Arc::new(Mutex::new(HashMap::new())),
            call_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn set_response(&self, region: &str, operation: &str, response: MockAwsApiResponse) {
        let key = format!("{}:{}", region, operation);
        self.responses.lock().unwrap().insert(key, response);
    }

    pub(crate) fn set_discover_vpc_endpoints_response(
        &self,
        region: &str,
        response: MockAwsApiResponse,
    ) {
        self.set_response(region, "discover_vpc_endpoints", response);
    }

    pub(crate) fn set_route53_response(&self, region: &str, ips: Vec<IpAddr>) {
        self.route53_responses
            .lock()
            .unwrap()
            .insert(region.to_string(), ips);
    }

    pub(crate) fn set_private_zones_response(
        &self,
        region: &str,
        vpc_id: &str,
        zones: HashSet<String>,
    ) {
        let key = format!("{}:{}", region, vpc_id);
        self.private_zones_responses
            .lock()
            .unwrap()
            .insert(key, zones);
    }

    pub(crate) fn get_call_log(&self) -> Vec<(String, String, String)> {
        self.call_log.lock().unwrap().clone()
    }

    pub(crate) fn clear_responses(&self) {
        self.responses.lock().unwrap().clear();
        self.route53_responses.lock().unwrap().clear();
        self.private_zones_responses.lock().unwrap().clear();
        self.call_log.lock().unwrap().clear();
    }

    fn log_call(&self, account: &str, region: &str, operation: &str) {
        self.call_log.lock().unwrap().push((
            account.to_string(),
            region.to_string(),
            operation.to_string(),
        ));
    }

    async fn simulate_delay(&self, delay_ms: Option<u64>) {
        if let Some(ms) = delay_ms {
            tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
        }
    }
}

#[async_trait]
impl AwsVpcInfoProvider for MockAwsVpcInfoProvider {
    async fn discover_vpc_endpoints(
        &self,
        _credentials: &AwsCredentials,
        account_config: &AwsAccountConfig,
        region: &str,
    ) -> Result<Vec<AwsDiscoveredEndpoint>, AwsApiError> {
        self.log_call(&account_config.label, region, "discover_vpc_endpoints");

        let key = format!("{}:discover_vpc_endpoints", region);
        let response_opt = self.responses.lock().unwrap().get(&key).cloned();
        if let Some(response) = response_opt {
            self.simulate_delay(response.delay_ms).await;

            if response.should_fail {
                if let Some(error_type) = &response.error_type {
                    return Err(error_type.to_aws_api_error());
                }
                return Err(AwsApiError::Discovery {
                    region: region.to_string(),
                    details: "Mock API error".to_string(),
                });
            }

            return Ok(response.endpoints.clone());
        }

        Ok(vec![])
    }

    async fn discover_route53_inbound_endpoint_ips(
        &self,
        _credentials: &AwsCredentials,
        region: &str,
    ) -> Result<Vec<IpAddr>, AwsApiError> {
        self.log_call("system", region, "discover_route53_inbound_endpoint_ips");

        if let Some(ips) = self.route53_responses.lock().unwrap().get(region) {
            Ok(ips.clone())
        } else {
            // Default fallback
            Ok(vec![IpAddr::V4(std::net::Ipv4Addr::new(
                169, 254, 169, 253,
            ))])
        }
    }

    async fn discover_private_hosted_zones_for_vpc(
        &self,
        _credentials: &AwsCredentials,
        vpc_id: &str,
        vpc_region: &str,
    ) -> Result<HashSet<String>, AwsApiError> {
        self.log_call(
            "system",
            vpc_region,
            "discover_private_hosted_zones_for_vpc",
        );

        let key = format!("{}:{}", vpc_region, vpc_id);
        if let Some(zones) = self.private_zones_responses.lock().unwrap().get(&key) {
            Ok(zones.clone())
        } else {
            // Default fallback
            let mut zones = HashSet::new();
            zones.insert(format!("test.{}.local", vpc_id));
            Ok(zones)
        }
    }
}

pub(crate) struct MockAwsConfigProvider {
    credential_responses: Arc<Mutex<HashMap<String, Result<AwsCredentials, AwsAuthError>>>>,
    role_responses: Arc<Mutex<HashMap<String, Result<AwsCredentials, AwsAuthError>>>>,
    validation_responses: Arc<Mutex<HashMap<String, Result<String, AwsAuthError>>>>,
    call_log: Arc<Mutex<Vec<String>>>,
}

impl MockAwsConfigProvider {
    pub(crate) fn new() -> Self {
        Self {
            credential_responses: Arc::new(Mutex::new(HashMap::new())),
            role_responses: Arc::new(Mutex::new(HashMap::new())),
            validation_responses: Arc::new(Mutex::new(HashMap::new())),
            call_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn set_credentials_response(
        &self,
        profile_name: &str,
        result: Result<AwsCredentials, AwsAuthError>,
    ) {
        self.credential_responses
            .lock()
            .unwrap()
            .insert(profile_name.to_string(), result);
    }

    pub(crate) fn set_role_response(
        &self,
        role_arn: &str,
        result: Result<AwsCredentials, AwsAuthError>,
    ) {
        self.role_responses
            .lock()
            .unwrap()
            .insert(role_arn.to_string(), result);
    }

    pub(crate) fn set_validation_response(
        &self,
        credentials_key: &str,
        result: Result<String, AwsAuthError>,
    ) {
        self.validation_responses
            .lock()
            .unwrap()
            .insert(credentials_key.to_string(), result);
    }

    pub(crate) fn get_call_log(&self) -> Vec<String> {
        self.call_log.lock().unwrap().clone()
    }

    pub(crate) fn clear_responses(&self) {
        self.credential_responses.lock().unwrap().clear();
        self.role_responses.lock().unwrap().clear();
        self.validation_responses.lock().unwrap().clear();
        self.call_log.lock().unwrap().clear();
    }

    fn create_mock_credentials(prefix: &str) -> AwsCredentials {
        Credentials::new(
            format!("MOCK_{}_ACCESS_KEY", prefix),
            format!("MOCK_{}_SECRET_KEY", prefix),
            Some(format!("MOCK_{}_SESSION_TOKEN", prefix)),
            Some(SystemTime::now() + std::time::Duration::from_secs(3600)),
            "MockProvider",
        )
    }
}

#[async_trait]
impl AwsConfigProvider for MockAwsConfigProvider {
    async fn get_credentials_for_account(
        &self,
        account_config: &AwsAccountConfig,
        _mfa_provider: Arc<dyn UserInteractionPort>,
    ) -> Result<AwsCredentials, AwsAuthError> {
        let default_profile = "default".to_string();
        let profile_name = account_config
            .profile_name
            .as_ref()
            .unwrap_or(&default_profile);

        self.call_log
            .lock()
            .unwrap()
            .push(format!("get_credentials_for_account:{}", profile_name));

        {
            let responses = self.credential_responses.lock().unwrap();
            if let Some(result) = responses.get(profile_name) {
                match result {
                    Ok(creds) => return Ok(creds.clone()),
                    Err(AwsAuthError::Config(msg)) => {
                        return Err(AwsAuthError::Config(msg.clone()));
                    }
                    Err(AwsAuthError::MfaRequired { user_identity }) => {
                        return Err(AwsAuthError::MfaRequired {
                            user_identity: user_identity.clone(),
                        });
                    }
                    Err(_) => return Err(AwsAuthError::Config("Mock error".to_string())),
                }
            }
        }

        Ok(Self::create_mock_credentials("ACCOUNT"))
    }

    async fn get_credentials_for_role(
        &self,
        _base_credentials: &AwsCredentials,
        role_config: &AwsRoleConfig,
        _account_config_for_mfa_serial: &AwsAccountConfig,
        _mfa_provider: Arc<dyn UserInteractionPort>,
    ) -> Result<AwsCredentials, AwsAuthError> {
        self.call_log
            .lock()
            .unwrap()
            .push(format!("get_credentials_for_role:{}", role_config.role_arn));

        {
            let responses = self.role_responses.lock().unwrap();
            if let Some(result) = responses.get(&role_config.role_arn) {
                match result {
                    Ok(creds) => return Ok(creds.clone()),
                    Err(AwsAuthError::Config(msg)) => {
                        return Err(AwsAuthError::Config(msg.clone()));
                    }
                    Err(AwsAuthError::MfaRequired { user_identity }) => {
                        return Err(AwsAuthError::MfaRequired {
                            user_identity: user_identity.clone(),
                        });
                    }
                    Err(_) => {
                        return Err(AwsAuthError::AssumeRole {
                            role_arn: role_config.role_arn.clone(),
                            source: Box::new(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                "Mock role assumption failed",
                            )),
                        });
                    }
                }
            }
        }

        Ok(Self::create_mock_credentials("ROLE"))
    }

    async fn validate_credentials(
        &self,
        credentials: &AwsCredentials,
    ) -> Result<String, AwsAuthError> {
        let key = credentials.access_key_id().to_string();
        self.call_log
            .lock()
            .unwrap()
            .push(format!("validate_credentials:{}", key));

        {
            let responses = self.validation_responses.lock().unwrap();
            if let Some(result) = responses.get(&key) {
                match result {
                    Ok(value) => return Ok(value.clone()),
                    Err(AwsAuthError::Config(msg)) => {
                        return Err(AwsAuthError::Config(msg.clone()));
                    }
                    Err(_) => {
                        return Err(AwsAuthError::Config("Mock validation error".to_string()));
                    }
                }
            }
        }

        Ok("123456789012".to_string())
    }
}

pub(crate) struct MockStatusReporter {
    aws_status: Arc<Mutex<Option<AwsScannerStatus>>>,
    status_updates: Arc<Mutex<Vec<AwsScannerStatus>>>,
}

impl MockStatusReporter {
    pub(crate) fn new() -> Self {
        Self {
            aws_status: Arc::new(Mutex::new(None)),
            status_updates: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn get_current_aws_status(&self) -> Option<AwsScannerStatus> {
        self.aws_status.lock().unwrap().clone()
    }

    pub(crate) fn get_status_updates(&self) -> Vec<AwsScannerStatus> {
        self.status_updates.lock().unwrap().clone()
    }

    pub(crate) fn clear_status(&self) {
        *self.aws_status.lock().unwrap() = None;
        self.status_updates.lock().unwrap().clear();
    }
}

#[async_trait]
impl StatusReporterPort for MockStatusReporter {
    async fn report_aws_scanner_status(&self, status: AwsScannerStatus) {
        *self.aws_status.lock().unwrap() = Some(status.clone());
        self.status_updates.lock().unwrap().push(status);
    }

    async fn get_aws_scanner_status(&self) -> AwsScannerStatus {
        self.aws_status.lock().unwrap().clone().unwrap_or_default()
    }

    async fn report_config_status(&self, _status: crate::core::types::ConfigStatus) {
        // No-op for tests
    }

    async fn get_config_status(&self) -> crate::core::types::ConfigStatus {
        crate::core::types::ConfigStatus::default()
    }

    async fn report_update_status(&self, _status: crate::core::types::UpdateStatus) {
        // No-op for tests
    }

    async fn get_update_status(&self) -> crate::core::types::UpdateStatus {
        crate::core::types::UpdateStatus::default()
    }

    async fn get_full_app_status(
        &self,
        _uptime_seconds: u64,
        _active_listeners: Vec<String>,
        _config_hash: String,
        _cache_stats: Option<crate::core::types::CacheStats>,
    ) -> crate::core::types::AppStatus {
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
}

pub(crate) struct MockUserInteraction {
    messages: Arc<Mutex<Vec<(String, crate::core::types::MessageLevel)>>>,
    mfa_responses: Arc<Mutex<Vec<String>>>,
    aws_key_responses: Arc<Mutex<Vec<(String, String)>>>,
}

impl MockUserInteraction {
    pub(crate) fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(Vec::new())),
            mfa_responses: Arc::new(Mutex::new(vec!["123456".to_string()])),
            aws_key_responses: Arc::new(Mutex::new(vec![(
                "test-access-key".to_string(),
                "test-secret-key".to_string(),
            )])),
        }
    }

    pub(crate) fn get_messages(&self) -> Vec<(String, crate::core::types::MessageLevel)> {
        self.messages.lock().unwrap().clone()
    }

    pub(crate) fn set_mfa_response(&self, token: &str) {
        self.mfa_responses.lock().unwrap().clear();
        self.mfa_responses.lock().unwrap().push(token.to_string());
    }

    pub(crate) fn set_aws_key_response(&self, access_key: &str, secret_key: &str) {
        self.aws_key_responses.lock().unwrap().clear();
        self.aws_key_responses
            .lock()
            .unwrap()
            .push((access_key.to_string(), secret_key.to_string()));
    }

    pub(crate) fn clear_messages(&self) {
        self.messages.lock().unwrap().clear();
    }
}

#[async_trait]
impl UserInteractionPort for MockUserInteraction {
    async fn prompt_for_mfa_token(
        &self,
        _user_identity: &str,
        _attempt: u32,
    ) -> Result<String, crate::core::error::UserInputError> {
        if let Some(token) = self.mfa_responses.lock().unwrap().pop() {
            Ok(token)
        } else {
            Err(crate::core::error::UserInputError::InvalidFormat(
                "No MFA token configured".to_string(),
            ))
        }
    }

    async fn prompt_for_aws_keys(
        &self,
        _account_label: &str,
    ) -> Result<(String, String), crate::core::error::UserInputError> {
        if let Some((access_key, secret_key)) = self.aws_key_responses.lock().unwrap().pop() {
            Ok((access_key, secret_key))
        } else {
            Err(crate::core::error::UserInputError::InvalidFormat(
                "No AWS keys configured".to_string(),
            ))
        }
    }

    fn display_message(&self, message: &str, level: crate::core::types::MessageLevel) {
        self.messages
            .lock()
            .unwrap()
            .push((message.to_string(), level));
    }

    fn display_status(&self, _status_info: &crate::core::types::AppStatus) {
        // No-op for tests
    }

    fn display_error(&self, error: &dyn std::error::Error) {
        self.display_message(&error.to_string(), crate::core::types::MessageLevel::Error);
    }

    fn display_table(&self, _headers: Vec<String>, _rows: Vec<Vec<String>>) {
        // No-op for tests
    }

    fn display_prompt(&self, _prompt_text: &str) {
        // No-op for tests
    }
}
