use crate::adapters::aws::profile_utils::read_aws_profiles_from_files;
use crate::adapters::aws::types::{AwsCredentialsCache, CachedAwsCredentials, CredentialCacheKey};
use crate::config::models::{AppConfig, AwsAccountConfig, AwsRoleConfig};
use crate::core::error::AwsAuthError;
use crate::core::types::AwsCredentials as CoreAwsCredentials;
use crate::ports::{AwsConfigProvider, UserInteractionPort};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_credential_types::provider::ProvideCredentials;
use aws_sdk_sts::config::Region as StsRegion;
use aws_sdk_sts::error::ProvideErrorMetadata;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

pub struct AwsSdkConfigProvider {
    app_config: Arc<RwLock<AppConfig>>,
    user_interaction: Arc<dyn UserInteractionPort>,
    credentials_cache: AwsCredentialsCache,
}

impl AwsSdkConfigProvider {
    pub fn new(
        app_config: Arc<RwLock<AppConfig>>,
        user_interaction: Arc<dyn UserInteractionPort>,
        credentials_cache: AwsCredentialsCache,
    ) -> Self {
        Self {
            app_config,
            user_interaction,
            credentials_cache,
        }
    }

    fn generate_profile_cache_key(profile_name: &str) -> CredentialCacheKey {
        format!("aws_profile_{}", profile_name)
    }

    fn generate_role_cache_key(role_config: &AwsRoleConfig) -> CredentialCacheKey {
        format!("role_{}", role_config.role_arn)
    }

    async fn get_from_cache(&self, key: &CredentialCacheKey) -> Option<CoreAwsCredentials> {
        let app_config_guard = self.app_config.read().await;
        let cache_enabled = app_config_guard
            .aws
            .as_ref()
            .is_none_or(|c| c.credentials_cache_enabled);
        if !cache_enabled {
            return None;
        }

        let cache_guard = self.credentials_cache.read().await;
        if let Some(cached_creds_entry) = cache_guard.get(key) {
            if let Some(expiry_system_time) = cached_creds_entry.credentials.expiry() {
                if expiry_system_time > std::time::SystemTime::now() {
                    debug!(
                        "Credentials for key '{}' found in cache and are valid.",
                        key
                    );
                    return Some(cached_creds_entry.credentials.clone());
                } else {
                    debug!("Credentials for key '{}' found in cache but expired.", key);
                }
            } else {
                debug!("Static credentials for key '{}' found in cache.", key);
                return Some(cached_creds_entry.credentials.clone());
            }
        }
        None
    }

    async fn store_in_cache(
        &self,
        key: CredentialCacheKey,
        credentials: CoreAwsCredentials,
        expiry_time_chrono: Option<DateTime<Utc>>,
    ) {
        let app_config_guard = self.app_config.read().await;
        if !app_config_guard
            .aws
            .as_ref()
            .is_none_or(|c| c.credentials_cache_enabled)
        {
            return;
        }
        let mut cache_guard = self.credentials_cache.write().await;
        let cached_entry = CachedAwsCredentials {
            credentials,
            expiry_time: expiry_time_chrono,
        };
        debug!(
            "Storing credentials for key '{}' in cache. Expiry: {:?}",
            key, expiry_time_chrono
        );
        cache_guard.insert(key, cached_entry);
    }

    async fn get_sts_client_with_creds(
        &self,
        current_credentials: &CoreAwsCredentials,
    ) -> aws_sdk_sts::Client {
        let app_config_guard = self.app_config.read().await;
        let default_region = app_config_guard
            .aws
            .as_ref()
            .and_then(|c| c.default_region.clone())
            .unwrap_or_else(|| "us-east-1".to_string());

        let provider = aws_credential_types::provider::SharedCredentialsProvider::new(
            current_credentials.clone(),
        );

        let mut config_builder = aws_sdk_sts::Config::builder()
            .credentials_provider(provider)
            .region(StsRegion::new(default_region))
            .behavior_version(BehaviorVersion::latest());

        #[cfg(test)]
        {
            if let Ok(endpoint_url) = std::env::var("AWS_ENDPOINT_URL_STS") {
                config_builder = config_builder.endpoint_url(endpoint_url);
            }
        }

        let sts_config = config_builder.build();
        aws_sdk_sts::Client::from_conf(sts_config)
    }

    pub async fn get_available_profiles(&self) -> Vec<String> {
        match read_aws_profiles_from_files() {
            Ok(profiles) => {
                debug!("Found {} AWS CLI profiles", profiles.len());
                profiles
            }
            Err(e) => {
                warn!(
                    "Failed to read AWS CLI profiles: {}. Using 'default' only.",
                    e
                );
                vec!["default".to_string()]
            }
        }
    }

    pub async fn validate_profile(&self, profile_name: &str) -> Result<String, AwsAuthError> {
        info!("Validating AWS CLI profile: {}", profile_name);

        let sdk_config = aws_config::defaults(BehaviorVersion::latest())
            .profile_name(profile_name)
            .load()
            .await;

        let provider =
            sdk_config
                .credentials_provider()
                .ok_or_else(|| AwsAuthError::CredentialRetrieval {
                    account_label: format!("profile-{}", profile_name),
                    source: "No credentials provider found for profile".into(),
                })?;

        let credentials = provider.provide_credentials().await.map_err(|e| {
            AwsAuthError::CredentialRetrieval {
                account_label: format!("profile-{}", profile_name),
                source: Box::new(e),
            }
        })?;

        self.validate_credentials_impl(&credentials).await
    }

    async fn validate_credentials_impl(
        &self,
        credentials: &CoreAwsCredentials,
    ) -> Result<String, AwsAuthError> {
        debug!("Validating AWS credentials by calling GetCallerIdentity...");
        let sts_client = self.get_sts_client_with_creds(credentials).await;
        match sts_client.get_caller_identity().send().await {
            Ok(output) => {
                let arn = output.arn().unwrap_or("Unknown ARN").to_string();
                info!("Credentials validated successfully. Caller ARN: {}", arn);
                Ok(arn)
            }
            Err(e) => {
                let service_error = e.into_service_error();
                warn!(
                    "Credential validation failed (GetCallerIdentity): {}",
                    service_error
                );
                Err(AwsAuthError::CredentialRetrieval {
                    account_label: "ValidationCheck".to_string(),
                    source: Box::new(service_error),
                })
            }
        }
    }

    pub async fn get_profile_info(
        &self,
        profile_name: &str,
    ) -> Result<(Option<String>, Option<String>), AwsAuthError> {
        info!("Getting profile info for: {}", profile_name);

        let cache_key = Self::generate_profile_cache_key(profile_name);

        if let Some(cached_creds) = self.get_from_cache(&cache_key).await {
            match self.validate_credentials_impl(&cached_creds).await {
                Ok(arn) => {
                    let account_id = extract_account_id_from_arn(&arn);

                    return Ok((account_id, None));
                }
                Err(e) => {
                    debug!("Cached credentials invalid: {}", e);
                }
            }
        }

        let sdk_config = aws_config::defaults(BehaviorVersion::latest())
            .profile_name(profile_name)
            .load()
            .await;

        let provider =
            sdk_config
                .credentials_provider()
                .ok_or_else(|| AwsAuthError::CredentialRetrieval {
                    account_label: format!("profile-{}", profile_name),
                    source: "No credentials provider found for profile".into(),
                })?;

        let credentials = provider.provide_credentials().await.map_err(|e| {
            AwsAuthError::CredentialRetrieval {
                account_label: format!("profile-{}", profile_name),
                source: Box::new(e),
            }
        })?;

        let expiry_chrono = credentials.expiry().map(|st| {
            let dur = st.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            DateTime::from_timestamp(dur.as_secs() as i64, dur.subsec_nanos())
                .unwrap_or_else(Utc::now)
        });
        self.store_in_cache(cache_key, credentials.clone(), expiry_chrono)
            .await;

        match self.validate_credentials_impl(&credentials).await {
            Ok(arn) => {
                let account_id = extract_account_id_from_arn(&arn);
                let region = sdk_config.region().map(|r| r.to_string());
                Ok((account_id, region))
            }
            Err(e) => Err(e),
        }
    }

    async fn verify_account_id(
        &self,
        credentials: &CoreAwsCredentials,
        expected_account_id: &str,
        account_label: &str,
    ) -> Result<(), AwsAuthError> {
        match self.validate_credentials_impl(credentials).await {
            Ok(arn) => {
                if let Some(actual_account_id) = extract_account_id_from_arn(&arn) {
                    if actual_account_id != expected_account_id {
                        error!(
                            "Account ID mismatch for {}: expected '{}', got '{}'",
                            account_label, expected_account_id, actual_account_id
                        );
                        return Err(AwsAuthError::CredentialRetrieval {
                            account_label: account_label.to_string(),
                            source: format!(
                                "Account ID mismatch: expected '{}', but credentials belong to account '{}'",
                                expected_account_id, actual_account_id
                            ).into(),
                        });
                    }
                    debug!(
                        "Account ID verification successful for {}: {}",
                        account_label, actual_account_id
                    );
                    Ok(())
                } else {
                    warn!(
                        "Could not extract account ID from ARN '{}' for verification",
                        arn
                    );
                    Ok(())
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn load_profile_credentials(
        &self,
        profile_name: &str,
        account_config: &AwsAccountConfig,
    ) -> Result<CoreAwsCredentials, AwsAuthError> {
        let sdk_config = aws_config::defaults(BehaviorVersion::latest())
            .profile_name(profile_name)
            .load()
            .await;

        let provider =
            sdk_config
                .credentials_provider()
                .ok_or_else(|| AwsAuthError::CredentialRetrieval {
                    account_label: account_config.label.clone(),
                    source: format!(
                        "No credentials provider found for profile '{}'",
                        profile_name
                    )
                    .into(),
                })?;

        let credentials = provider.provide_credentials().await.map_err(|e| {
            AwsAuthError::CredentialRetrieval {
                account_label: account_config.label.clone(),
                source: Box::new(e),
            }
        })?;

        if let Some(expected_account_id) = &account_config.account_id {
            self.verify_account_id(&credentials, expected_account_id, &account_config.label)
                .await?;
        }

        info!(
            "Successfully loaded credentials for profile: {}",
            profile_name
        );
        Ok(credentials)
    }

    async fn authenticate_with_mfa(
        &self,
        profile_name: &str,
        account_config: &AwsAccountConfig,
        mfa_provider: Arc<dyn UserInteractionPort>,
    ) -> Result<CoreAwsCredentials, AwsAuthError> {
        let sdk_config = aws_config::defaults(BehaviorVersion::latest())
            .profile_name(profile_name)
            .load()
            .await;

        let provider =
            sdk_config
                .credentials_provider()
                .ok_or_else(|| AwsAuthError::CredentialRetrieval {
                    account_label: account_config.label.clone(),
                    source: format!(
                        "No credentials provider found for profile '{}'",
                        profile_name
                    )
                    .into(),
                })?;

        let base_credentials = provider.provide_credentials().await.map_err(|e| {
            AwsAuthError::CredentialRetrieval {
                account_label: account_config.label.clone(),
                source: Box::new(e),
            }
        })?;

        let sts_client = self.get_sts_client_with_creds(&base_credentials).await;

        let caller_identity = sts_client.get_caller_identity().send().await.map_err(|e| {
            AwsAuthError::CredentialRetrieval {
                account_label: account_config.label.clone(),
                source: format!("Failed to get caller identity: {}", e).into(),
            }
        })?;

        let user_arn = caller_identity.arn().unwrap_or("");
        let mfa_serial = self
            .derive_mfa_serial_from_user_arn(user_arn)
            .map_err(|e| AwsAuthError::CredentialRetrieval {
                account_label: account_config.label.clone(),
                source: format!("Could not derive MFA serial: {}", e).into(),
            })?;

        let token_code = mfa_provider
            .prompt_for_mfa_token(
                &format!("Profile: {} (MFA Device: {})", profile_name, mfa_serial),
                1,
            )
            .await?;

        let get_session_token = sts_client
            .get_session_token()
            .serial_number(mfa_serial)
            .token_code(token_code)
            .duration_seconds(3600);

        match get_session_token.send().await {
            Ok(output) => {
                if let Some(sts_creds) = output.credentials {
                    let core_creds = self.create_core_credentials_from_sts(sts_creds)?;

                    if let Some(expected_account_id) = &account_config.account_id {
                        self.verify_account_id(
                            &core_creds,
                            expected_account_id,
                            &account_config.label,
                        )
                        .await?;
                    }

                    info!(
                        "Successfully authenticated with MFA for profile: {}",
                        profile_name
                    );
                    Ok(core_creds)
                } else {
                    Err(AwsAuthError::CredentialRetrieval {
                        account_label: account_config.label.clone(),
                        source: "No credentials in GetSessionToken output".into(),
                    })
                }
            }
            Err(e) => {
                let sdk_error = e.into_service_error();
                error!(
                    "GetSessionToken with MFA failed for {}: {}",
                    profile_name, sdk_error
                );
                Err(AwsAuthError::CredentialRetrieval {
                    account_label: account_config.label.clone(),
                    source: Box::new(sdk_error),
                })
            }
        }
    }

    async fn assume_role_with_mfa_retry(
        &self,
        sts_client: &aws_sdk_sts::Client,
        role_config: &AwsRoleConfig,
        token_code: &str,
        cache_key: &CredentialCacheKey,
    ) -> Result<CoreAwsCredentials, AwsAuthError> {
        let caller_identity = sts_client.get_caller_identity().send().await.map_err(|e| {
            AwsAuthError::AssumeRole {
                role_arn: role_config.role_arn.clone(),
                source: format!("Failed to get caller identity for MFA serial: {}", e).into(),
            }
        })?;

        let user_arn = caller_identity.arn().unwrap_or("");
        let mfa_serial = self.derive_mfa_serial_from_user_arn(user_arn)?;

        info!("Retrying assume role with MFA. Serial: {}", mfa_serial);

        let assume_role_with_mfa = sts_client
            .assume_role()
            .role_arn(role_config.role_arn.clone())
            .role_session_name(format!("mfa-session-{}", Utc::now().timestamp_millis()))
            .serial_number(mfa_serial)
            .token_code(token_code);

        match assume_role_with_mfa.send().await {
            Ok(output) => {
                if let Some(sts_creds_sdk) = output.credentials {
                    let core_creds = self.create_core_credentials_from_sts(sts_creds_sdk)?;
                    let expiry_chrono = self.extract_expiry_time(&core_creds);
                    self.store_in_cache(cache_key.clone(), core_creds.clone(), expiry_chrono)
                        .await;
                    info!(
                        "Successfully assumed role with MFA: {}",
                        role_config.role_arn
                    );
                    Ok(core_creds)
                } else {
                    Err(AwsAuthError::AssumeRole {
                        role_arn: role_config.role_arn.clone(),
                        source: "No credentials in AssumeRole MFA retry output".into(),
                    })
                }
            }
            Err(e) => {
                let sdk_error = e.into_service_error();
                error!(
                    "AssumeRole with MFA failed for {}: {}",
                    role_config.role_arn, sdk_error
                );
                Err(AwsAuthError::AssumeRole {
                    role_arn: role_config.role_arn.clone(),
                    source: Box::new(sdk_error),
                })
            }
        }
    }

    fn derive_mfa_serial_from_user_arn(&self, user_arn: &str) -> Result<String, AwsAuthError> {
        if user_arn.contains(":user/") {
            let mfa_serial = user_arn.replace(":user/", ":mfa/");
            Ok(mfa_serial)
        } else {
            Err(AwsAuthError::AssumeRole {
                role_arn: "unknown".to_string(),
                source: format!("Cannot derive MFA serial from ARN: {}", user_arn).into(),
            })
        }
    }

    fn create_core_credentials_from_sts(
        &self,
        sts_creds: aws_sdk_sts::types::Credentials,
    ) -> Result<CoreAwsCredentials, AwsAuthError> {
        let expiry_smithy_dt = sts_creds.expiration;
        let expiry_system_time = Some(
            std::time::UNIX_EPOCH
                + std::time::Duration::from_secs_f64(expiry_smithy_dt.as_secs_f64()),
        );

        Ok(CoreAwsCredentials::new(
            sts_creds.access_key_id,
            sts_creds.secret_access_key,
            Some(sts_creds.session_token),
            expiry_system_time,
            "AssumeRoleProvider",
        ))
    }

    fn extract_expiry_time(&self, credentials: &CoreAwsCredentials) -> Option<DateTime<Utc>> {
        credentials.expiry().map(|st| {
            let dur = st.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            DateTime::from_timestamp(dur.as_secs() as i64, dur.subsec_nanos())
                .unwrap_or_else(Utc::now)
        })
    }
}

fn extract_account_id_from_arn(arn: &str) -> Option<String> {
    arn.split(':')
        .nth(4)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

#[async_trait]
impl AwsConfigProvider for AwsSdkConfigProvider {
    async fn get_credentials_for_account(
        &self,
        account_config: &AwsAccountConfig,
        mfa_provider: Arc<dyn UserInteractionPort>,
    ) -> Result<CoreAwsCredentials, AwsAuthError> {
        let profile_name = account_config.profile_name.as_ref().ok_or_else(|| {
            AwsAuthError::CredentialRetrieval {
                account_label: account_config.label.clone(),
                source: "No AWS CLI profile specified in account config".into(),
            }
        })?;

        let cache_key = Self::generate_profile_cache_key(profile_name);

        if let Some(cached_creds) = self.get_from_cache(&cache_key).await {
            debug!("Using cached credentials for profile: {}", profile_name);

            if let Some(expected_account_id) = &account_config.account_id {
                if let Err(e) = self
                    .verify_account_id(&cached_creds, expected_account_id, &account_config.label)
                    .await
                {
                    warn!("Cached credentials failed account ID verification: {}", e);

                    let mut cache_guard = self.credentials_cache.write().await;
                    cache_guard.remove(&cache_key);
                } else {
                    return Ok(cached_creds);
                }
            } else {
                return Ok(cached_creds);
            }
        }

        info!("Loading credentials for AWS CLI profile: {}", profile_name);

        match self
            .load_profile_credentials(profile_name, account_config)
            .await
        {
            Ok(credentials) => {
                let expiry_chrono = self.extract_expiry_time(&credentials);
                self.store_in_cache(cache_key, credentials.clone(), expiry_chrono)
                    .await;
                return Ok(credentials);
            }
            Err(e) => {
                let error_msg = format!("{}", e);
                if error_msg.to_lowercase().contains("mfa")
                    || error_msg.to_lowercase().contains("multifactor")
                    || error_msg.to_lowercase().contains("token")
                {
                    info!(
                        "Profile {} requires MFA. Attempting MFA authentication...",
                        profile_name
                    );

                    return self
                        .authenticate_with_mfa(profile_name, account_config, mfa_provider)
                        .await;
                } else {
                    return Err(e);
                }
            }
        }
    }

    async fn get_credentials_for_role(
        &self,
        base_credentials: &CoreAwsCredentials,
        role_config: &AwsRoleConfig,
        account_config: &AwsAccountConfig,
        mfa_provider: Arc<dyn UserInteractionPort>,
    ) -> Result<CoreAwsCredentials, AwsAuthError> {
        let cache_key = Self::generate_role_cache_key(role_config);

        if let Some(cached_creds) = self.get_from_cache(&cache_key).await {
            debug!(
                "Using cached credentials for role: {}",
                role_config.role_arn
            );
            return Ok(cached_creds);
        }

        debug!("Attempting to assume role: {}", role_config.role_arn);
        let sts_client = self.get_sts_client_with_creds(base_credentials).await;

        let assume_role_builder = sts_client
            .assume_role()
            .role_arn(role_config.role_arn.clone())
            .role_session_name(
                role_config
                    .label
                    .clone()
                    .unwrap_or_else(|| format!("session-{}", Utc::now().timestamp_millis())),
            );

        match assume_role_builder.send().await {
            Ok(output) => {
                if let Some(sts_creds_sdk) = output.credentials {
                    let core_creds = self.create_core_credentials_from_sts(sts_creds_sdk)?;
                    let expiry_chrono = self.extract_expiry_time(&core_creds);
                    self.store_in_cache(cache_key, core_creds.clone(), expiry_chrono)
                        .await;
                    info!("Successfully assumed role: {}", role_config.role_arn);
                    return Ok(core_creds);
                } else {
                    return Err(AwsAuthError::AssumeRole {
                        role_arn: role_config.role_arn.clone(),
                        source: "No credentials in AssumeRole output".into(),
                    });
                }
            }
            Err(e) => {
                let sdk_error = e.into_service_error();

                let is_access_denied = sdk_error.code() == Some("AccessDenied");
                let has_mfa_error = sdk_error
                    .message()
                    .unwrap_or_default()
                    .to_lowercase()
                    .contains("multifactorauthentication");

                if is_access_denied && has_mfa_error {
                    info!(
                        "Role {} requires MFA. Prompting for MFA token...",
                        role_config.role_arn
                    );

                    let token_code = mfa_provider
                        .prompt_for_mfa_token(&format!("Role: {}", role_config.role_arn), 1)
                        .await?;

                    return self
                        .assume_role_with_mfa_retry(
                            &sts_client,
                            role_config,
                            &token_code,
                            &cache_key,
                        )
                        .await;
                }

                error!(
                    "AssumeRole failed for {}: {}",
                    role_config.role_arn, sdk_error
                );
                Err(AwsAuthError::AssumeRole {
                    role_arn: role_config.role_arn.clone(),
                    source: Box::new(sdk_error),
                })
            }
        }
    }

    async fn validate_credentials(
        &self,
        credentials: &CoreAwsCredentials,
    ) -> Result<String, AwsAuthError> {
        self.validate_credentials_impl(credentials).await
    }
}
