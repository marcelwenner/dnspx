// Remove the duplicate cfg attribute since it's already in mod.rs
use std::sync::Arc;
use tokio::sync::RwLock;

use sspi::{
    AuthData, AuthDataType, DataRepresentation, Negotiate, NegotiateConfig, SecurityBuffer,
    SecurityStatus, Sspi, Username,
};
use tracing::{debug, error, warn};

use crate::errors::ResolveError;

#[derive(Debug, Clone)]
pub enum SspiAuthState {
    Initial,
    NegotiateSent,
    Authenticated,
    Failed(String),
}

#[derive(Debug)]
pub struct SspiAuthManager {
    target_spn: String,
    username: Option<String>,
    password: Option<String>,
    domain: Option<String>,
    sspi_client: Arc<Negotiate>,
    auth_state: Arc<RwLock<SspiAuthState>>,
    credentials_handle: Arc<RwLock<Option<sspi::CredentialsBuffers>>>,
}

impl SspiAuthManager {
    pub fn new(
        target_spn: String,
        username: Option<String>,
        password: Option<String>,
        domain: Option<String>,
    ) -> Result<Self, ResolveError> {
        let config = NegotiateConfig::default();
        let sspi_client = Negotiate::new(config).map_err(|e| {
            ResolveError::AuthenticationFailed(format!("Failed to create SSPI client: {}", e))
        })?;

        Ok(Self {
            target_spn,
            username,
            password,
            domain,
            sspi_client: Arc::new(sspi_client),
            auth_state: Arc::new(RwLock::new(SspiAuthState::Initial)),
            credentials_handle: Arc::new(RwLock::new(None)),
        })
    }

    pub fn new_for_current_user(target_spn: String) -> Result<Self, ResolveError> {
        let config = NegotiateConfig::default();
        let sspi_client = Negotiate::new(config).map_err(|e| {
            ResolveError::AuthenticationFailed(format!("Failed to create SSPI client: {}", e))
        })?;

        Ok(Self {
            target_spn,
            username: None,
            password: None,
            domain: None,
            sspi_client: Arc::new(sspi_client),
            auth_state: Arc::new(RwLock::new(SspiAuthState::Initial)),
            credentials_handle: Arc::new(RwLock::new(None)),
        })
    }

    // Public method to access auth state
    pub async fn get_auth_state(&self) -> SspiAuthState {
        self.auth_state.read().await.clone()
    }

    // Public method to set auth state
    pub async fn set_auth_state(&self, state: SspiAuthState) {
        *self.auth_state.write().await = state;
    }

    fn create_auth_data(&self) -> Option<AuthData> {
        match (&self.username, &self.password) {
            (Some(username), Some(password)) => {
                let mut auth_data = AuthData::new();

                if let Some(domain) = &self.domain {
                    auth_data = auth_data.with_domain_as_str(domain);
                }

                Some(
                    auth_data
                        .with_username_as_str(username)
                        .with_password_as_str(password),
                )
            }
            _ => None,
        }
    }

    pub async fn acquire_credentials_handle_with_auth_data(
        &self,
    ) -> Result<sspi::CredentialsBuffers, ResolveError> {
        if let Some(auth_data) = self.create_auth_data() {
            let mut builder = self.sspi_client.acquire_credentials_handle();
            builder = builder.with_auth_data(&auth_data);

            let mut sspi_impl = self.sspi_client.as_ref().clone();
            let handle = builder.execute(&mut sspi_impl).map_err(|e| {
                ResolveError::AuthenticationFailed(format!(
                    "Failed to acquire credentials handle: {}",
                    e
                ))
            })?;

            match handle {
                Some(creds) => Ok(creds),
                None => Err(ResolveError::AuthenticationFailed(
                    "No credentials handle returned".to_string(),
                )),
            }
        } else {
            Err(ResolveError::AuthenticationFailed(
                "No authentication data available".to_string(),
            ))
        }
    }

    pub async fn acquire_credentials_handle_current_user(
        &self,
    ) -> Result<sspi::CredentialsBuffers, ResolveError> {
        let builder = self.sspi_client.acquire_credentials_handle();

        let mut sspi_impl = self.sspi_client.as_ref().clone();
        let handle = builder.execute(&mut sspi_impl).map_err(|e| {
            ResolveError::AuthenticationFailed(format!(
                "Failed to acquire credentials handle for current user: {}",
                e
            ))
        })?;

        match handle {
            Some(creds) => Ok(creds),
            None => Err(ResolveError::AuthenticationFailed(
                "No credentials handle returned for current user".to_string(),
            )),
        }
    }

    pub async fn generate_negotiate_token(
        &self,
        creds_handle: &sspi::CredentialsBuffers,
    ) -> Result<Vec<u8>, ResolveError> {
        let mut sspi_client = self.sspi_client.as_ref().clone();

        let sspi_context_client = sspi_client
            .initialize_security_context()
            .with_target_name(&self.target_spn)
            .with_context_requirements(
                sspi::ClientRequestFlags::MUTUAL_AUTH
                    | sspi::ClientRequestFlags::CONFIDENTIALITY
                    | sspi::ClientRequestFlags::INTEGRITY
                    | sspi::ClientRequestFlags::ALLOCATE_MEMORY,
            )
            .with_credentials_handle(creds_handle)
            .with_target_data_representation(DataRepresentation::Network);

        let result = sspi_context_client.execute(&mut sspi_client).map_err(|e| {
            ResolveError::AuthenticationFailed(format!(
                "Failed to initialize security context: {}",
                e
            ))
        })?;

        match result.status {
            SecurityStatus::ContinueNeeded | SecurityStatus::Ok => {
                if let Some(output_buffer) = result.output_buffers.first() {
                    Ok(output_buffer.buffer().to_vec())
                } else {
                    Err(ResolveError::AuthenticationFailed(
                        "No output token generated".to_string(),
                    ))
                }
            }
            _ => Err(ResolveError::AuthenticationFailed(format!(
                "Security context initialization failed with status: {:?}",
                result.status
            ))),
        }
    }

    pub async fn continue_authentication(
        &self,
        server_challenge: &[u8],
    ) -> Result<Vec<u8>, ResolveError> {
        let creds_handle_guard = self.credentials_handle.read().await;
        let creds_handle = creds_handle_guard.as_ref().ok_or_else(|| {
            ResolveError::AuthenticationFailed("No credentials handle available".to_string())
        })?;

        let mut sspi_client = self.sspi_client.as_ref().clone();

        let input_buffer =
            SecurityBuffer::new(server_challenge.to_vec(), sspi::SecurityBufferType::Token);

        let sspi_context_client = sspi_client
            .initialize_security_context()
            .with_target_name(&self.target_spn)
            .with_context_requirements(
                sspi::ClientRequestFlags::MUTUAL_AUTH
                    | sspi::ClientRequestFlags::CONFIDENTIALITY
                    | sspi::ClientRequestFlags::INTEGRITY
                    | sspi::ClientRequestFlags::ALLOCATE_MEMORY,
            )
            .with_credentials_handle(creds_handle)
            .with_target_data_representation(DataRepresentation::Network)
            .with_input(&[input_buffer]);

        let result = sspi_context_client.execute(&mut sspi_client).map_err(|e| {
            ResolveError::AuthenticationFailed(format!("Failed to continue authentication: {}", e))
        })?;

        match result.status {
            SecurityStatus::ContinueNeeded | SecurityStatus::Ok => {
                if let Some(output_buffer) = result.output_buffers.first() {
                    Ok(output_buffer.buffer().to_vec())
                } else {
                    Ok(Vec::new()) // Some auth flows don't require response token
                }
            }
            _ => Err(ResolveError::AuthenticationFailed(format!(
                "Authentication continuation failed with status: {:?}",
                result.status
            ))),
        }
    }

    pub async fn get_negotiate_token(&self) -> Result<String, ResolveError> {
        let current_state = self.get_auth_state().await;

        match current_state {
            SspiAuthState::Initial => {
                debug!("Starting SSPI authentication for SPN: {}", self.target_spn);

                let creds_handle = if self.username.is_some() && self.password.is_some() {
                    self.acquire_credentials_handle_with_auth_data().await?
                } else {
                    self.acquire_credentials_handle_current_user().await?
                };

                // Store credentials handle for future use
                *self.credentials_handle.write().await = Some(creds_handle.clone());

                let token = self.generate_negotiate_token(&creds_handle).await?;
                let b64_token = base64::encode(&token);

                self.set_auth_state(SspiAuthState::NegotiateSent).await;

                debug!("Generated initial NTLM negotiate token");
                Ok(format!("Negotiate {}", b64_token))
            }
            SspiAuthState::Failed(msg) => {
                warn!("SSPI authentication is in failed state: {}", msg);
                Err(ResolveError::AuthenticationFailed(msg))
            }
            _ => {
                debug!("SSPI authentication already in progress or completed");
                Err(ResolveError::AuthenticationFailed(
                    "Authentication already in progress".to_string(),
                ))
            }
        }
    }

    pub async fn handle_challenge(&self, challenge_header: &str) -> Result<String, ResolveError> {
        let current_state = self.get_auth_state().await;

        match current_state {
            SspiAuthState::NegotiateSent => {
                if let Some(challenge_data) = challenge_header.strip_prefix("Negotiate ") {
                    let challenge_bytes = base64::decode(challenge_data).map_err(|e| {
                        ResolveError::AuthenticationFailed(format!(
                            "Failed to decode challenge: {}",
                            e
                        ))
                    })?;

                    let response_token = self.continue_authentication(&challenge_bytes).await?;

                    if response_token.is_empty() {
                        self.set_auth_state(SspiAuthState::Authenticated).await;
                        Ok(String::new()) // No additional token needed
                    } else {
                        let b64_response = base64::encode(&response_token);
                        self.set_auth_state(SspiAuthState::Authenticated).await;
                        Ok(format!("Negotiate {}", b64_response))
                    }
                } else {
                    let error_msg = "Invalid challenge format".to_string();
                    self.set_auth_state(SspiAuthState::Failed(error_msg.clone()))
                        .await;
                    Err(ResolveError::AuthenticationFailed(error_msg))
                }
            }
            _ => {
                let error_msg = format!(
                    "Unexpected state for challenge handling: {:?}",
                    current_state
                );
                self.set_auth_state(SspiAuthState::Failed(error_msg.clone()))
                    .await;
                Err(ResolveError::AuthenticationFailed(error_msg))
            }
        }
    }

    pub async fn reset(&self) {
        debug!("Resetting SSPI authentication state");
        *self.auth_state.write().await = SspiAuthState::Initial;
        *self.credentials_handle.write().await = None;
    }
}

// Mock implementation for non-Windows platforms
#[cfg(not(windows))]
pub mod mock {
    use super::*;

    impl SspiAuthManager {
        pub fn new(
            _target_spn: String,
            _username: Option<String>,
            _password: Option<String>,
            _domain: Option<String>,
        ) -> Result<Self, ResolveError> {
            Err(ResolveError::AuthenticationFailed(
                "SSPI authentication not supported on this platform".to_string(),
            ))
        }

        pub fn new_for_current_user(_target_spn: String) -> Result<Self, ResolveError> {
            Err(ResolveError::AuthenticationFailed(
                "SSPI authentication not supported on this platform".to_string(),
            ))
        }

        pub async fn get_negotiate_token(&self) -> Result<String, ResolveError> {
            Err(ResolveError::AuthenticationFailed(
                "SSPI authentication not supported on this platform".to_string(),
            ))
        }

        pub async fn handle_challenge(
            &self,
            _challenge_header: &str,
        ) -> Result<String, ResolveError> {
            Err(ResolveError::AuthenticationFailed(
                "SSPI authentication not supported on this platform".to_string(),
            ))
        }

        pub async fn reset(&self) {}

        pub async fn get_auth_state(&self) -> SspiAuthState {
            SspiAuthState::Failed("Not supported on this platform".to_string())
        }
    }
}
