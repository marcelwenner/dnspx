use crate::core::error::ResolveError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sspi::{
    BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, Ntlm, SecurityBuffer,
    SecurityStatus, Sspi, SspiImpl, Username,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SspiAuthState {
    Initial,
    NegotiateSent,
    ChallengeReceived,
    Authenticated,
    Failed(String),
}

#[derive(Debug)]
pub struct SspiAuthManager {
    target_spn: String,
    username: Option<String>,
    password: Option<String>,
    domain: Option<String>,
    sspi_client: Arc<tokio::sync::Mutex<Ntlm>>,
    auth_state: Arc<RwLock<SspiAuthState>>,
    credentials_handle: Arc<RwLock<Option<<Ntlm as SspiImpl>::CredentialsHandle>>>,
}

impl SspiAuthManager {
    pub fn new(
        target_spn: String,
        username: Option<String>,
        password: Option<String>,
        domain: Option<String>,
    ) -> Result<Self, ResolveError> {
        let sspi_client = Ntlm::new();
        debug!(target: "sspi_auth", spn = %target_spn, user = ?username, domain = ?domain, "Creating NTLM SSPI auth manager with explicit credentials");
        Ok(Self {
            target_spn,
            username,
            password,
            domain,
            sspi_client: Arc::new(tokio::sync::Mutex::new(sspi_client)),
            auth_state: Arc::new(RwLock::new(SspiAuthState::Initial)),
            credentials_handle: Arc::new(RwLock::new(None)),
        })
    }

    pub fn new_for_current_user(target_spn: String) -> Result<Self, ResolveError> {
        let sspi_client = Ntlm::new();
        debug!(target: "sspi_auth", spn = %target_spn, "Creating NTLM SSPI auth manager for current user");
        Ok(Self {
            target_spn,
            username: None,
            password: None,
            domain: None,
            sspi_client: Arc::new(tokio::sync::Mutex::new(sspi_client)),
            auth_state: Arc::new(RwLock::new(SspiAuthState::Initial)),
            credentials_handle: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn get_auth_state(&self) -> SspiAuthState {
        self.auth_state.read().await.clone()
    }

    pub async fn set_auth_state(&self, state: SspiAuthState) {
        *self.auth_state.write().await = state;
    }

    pub async fn is_authenticated(&self) -> bool {
        matches!(self.get_auth_state().await, SspiAuthState::Authenticated)
    }

    pub async fn mark_failed(&self, message: String) {
        warn!(target: "sspi_auth", spn = %self.target_spn, "SSPI authentication marked as failed: {}", message);
        self.set_auth_state(SspiAuthState::Failed(message)).await;
    }

    fn create_auth_identity(&self) -> Option<sspi::AuthIdentity> {
        match (&self.username, &self.password) {
            (Some(username), Some(password)) => {
                let username_str = if let Some(domain) = &self.domain {
                    format!("{}\\{}", domain, username)
                } else {
                    username.clone()
                };
                Username::parse(&username_str)
                    .ok()
                    .map(|uname| sspi::AuthIdentity {
                        username: uname,
                        password: password.clone().into(),
                    })
            }
            _ => None,
        }
    }

    async fn acquire_credentials_handle_internal(
        &self,
    ) -> Result<<Ntlm as SspiImpl>::CredentialsHandle, ResolveError> {
        let mut creds_handle_guard = self.credentials_handle.write().await;
        if creds_handle_guard.is_none() {
            let mut sspi_client_locked = self.sspi_client.lock().await;

            let builder = sspi_client_locked
                .acquire_credentials_handle()
                .with_credential_use(CredentialUse::Outbound);

            let final_builder = if let Some(identity) = self.create_auth_identity() {
                debug!(target: "sspi_auth", spn = %self.target_spn, "Acquiring NTLM credentials with explicit identity");
                builder.with_auth_data(&identity)
            } else {
                debug!(target: "sspi_auth", spn = %self.target_spn, "Acquiring NTLM credentials for current user");
                builder
            };

            let acq_result = final_builder.resolve(&mut *sspi_client_locked).map_err(|e| {
                error!(target: "sspi_auth", spn = %self.target_spn, error = %e, "Failed to acquire NTLM credentials");
                ResolveError::HttpProxy(format!("Failed to acquire NTLM credentials handle: {}", e))
            })?;

            debug!(target: "sspi_auth", spn = %self.target_spn, "Successfully acquired NTLM credentials handle");
            *creds_handle_guard = Some(acq_result.credentials_handle);
        }
        Ok(creds_handle_guard.as_ref().unwrap().clone())
    }

    pub async fn get_initial_token(&self) -> Result<String, ResolveError> {
        self.reset().await;
        self.set_auth_state(SspiAuthState::Initial).await;

        debug!(target: "sspi_auth", spn = %self.target_spn, "Attempting to get initial NTLM token");
        let mut creds_handle = self.acquire_credentials_handle_internal().await?;

        *self.credentials_handle.write().await = Some(creds_handle.clone());

        let mut sspi_client_locked = self.sspi_client.lock().await;
        let mut output_buffers = [SecurityBuffer::new(Vec::new(), BufferType::Token)];

        let mut init_builder = sspi_client_locked
            .initialize_security_context()
            .with_credentials_handle(&mut creds_handle)
            .with_context_requirements(
                ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(&self.target_spn)
            .with_output(&mut output_buffers);

        let result = init_builder
            .resolve(&mut *sspi_client_locked)
            .map_err(|e| {
                ResolveError::HttpProxy(format!(
                    "Failed to initialize NTLM security context: {}",
                    e
                ))
            })?;

        let token = output_buffers[0].buffer.to_vec();

        match result.status {
            SecurityStatus::ContinueNeeded | SecurityStatus::Ok => {
                let b64_token = BASE64_STANDARD.encode(&token);
                self.set_auth_state(SspiAuthState::NegotiateSent).await;
                debug!(target: "sspi_auth", spn = %self.target_spn, "Generated initial NTLM token ({} bytes), state: NegotiateSent", token.len());
                Ok(format!("Negotiate {}", b64_token))
            }
            _ => {
                let err_msg = format!(
                    "NTLM initial token generation failed with status: {:?}",
                    result.status
                );
                warn!(target: "sspi_auth", spn = %self.target_spn, "{}", err_msg);
                self.mark_failed(err_msg.clone()).await;
                Err(ResolveError::HttpProxy(err_msg))
            }
        }
    }

    pub async fn get_challenge_response_token(
        &self,
        challenge_header: &str,
    ) -> Result<String, ResolveError> {
        let current_state = self.get_auth_state().await;
        debug!(target: "sspi_auth", spn = %self.target_spn, "Handling NTLM challenge, current state: {:?}", current_state);

        match current_state {
            SspiAuthState::NegotiateSent | SspiAuthState::ChallengeReceived => {
                let challenge_data = challenge_header
                    .strip_prefix("Negotiate ")
                    .or_else(|| challenge_header.strip_prefix("NTLM "))
                    .ok_or_else(|| {
                        let msg = format!("Invalid challenge header format: {}", challenge_header);
                        warn!(target: "sspi_auth", "{}", msg);
                        ResolveError::HttpProxy(msg)
                    })?;

                let challenge_bytes =
                    BASE64_STANDARD.decode(challenge_data.trim()).map_err(|e| {
                        let msg = format!("Failed to decode NTLM challenge: {}", e);
                        warn!(target: "sspi_auth", "{}", msg);
                        ResolveError::HttpProxy(msg)
                    })?;

                debug!(target: "sspi_auth", spn = %self.target_spn, challenge_size = challenge_bytes.len(), "Decoded NTLM challenge");

                let mut creds_handle_guard = self.credentials_handle.write().await;
                let mut creds_handle = match creds_handle_guard.as_mut() {
                    Some(ch) => ch,
                    None => {
                        let msg = "No NTLM credentials handle available for challenge response"
                            .to_string();
                        warn!(target: "sspi_auth", "{}", msg);
                        return Err(ResolveError::HttpProxy(msg));
                    }
                };

                let mut sspi_client_locked = self.sspi_client.lock().await;
                let mut input_buffers = [SecurityBuffer::new(challenge_bytes, BufferType::Token)];
                let mut output_buffers = [SecurityBuffer::new(Vec::new(), BufferType::Token)];

                let mut builder = sspi_client_locked
                    .initialize_security_context()
                    .with_credentials_handle(&mut creds_handle)
                    .with_input(&mut input_buffers)
                    .with_output(&mut output_buffers)
                    .with_context_requirements(
                        ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY,
                    )
                    .with_target_data_representation(DataRepresentation::Native)
                    .with_target_name(&self.target_spn);

                let result = builder.resolve(&mut *sspi_client_locked).map_err(|e| {
                    ResolveError::HttpProxy(format!("NTLM challenge response failed: {}", e))
                })?;

                let response_token_bytes = output_buffers[0].buffer.to_vec();

                match result.status {
                    SecurityStatus::Ok => {
                        self.set_auth_state(SspiAuthState::Authenticated).await;
                        debug!(target: "sspi_auth", spn = %self.target_spn, "NTLM authentication successful after challenge.");
                        if !response_token_bytes.is_empty() {
                            let b64_response = BASE64_STANDARD.encode(&response_token_bytes);
                            Ok(format!("Negotiate {}", b64_response))
                        } else {
                            Ok(String::new())
                        }
                    }
                    SecurityStatus::ContinueNeeded => {
                        self.set_auth_state(SspiAuthState::ChallengeReceived).await;
                        debug!(target: "sspi_auth", spn = %self.target_spn, "NTLM authentication ContinueNeeded after challenge.");
                        if response_token_bytes.is_empty() {
                            let err_msg = "NTLM: ContinueNeeded but empty token after challenge";
                            self.mark_failed(err_msg.to_string()).await;
                            Err(ResolveError::HttpProxy(err_msg.to_string()))
                        } else {
                            let b64_response = BASE64_STANDARD.encode(&response_token_bytes);
                            Ok(format!("Negotiate {}", b64_response))
                        }
                    }
                    _ => {
                        let err_msg = format!(
                            "NTLM authentication failed after challenge with status: {:?}",
                            result.status
                        );
                        warn!(target: "sspi_auth", spn = %self.target_spn, "{}", err_msg);
                        self.mark_failed(err_msg.clone()).await;
                        Err(ResolveError::HttpProxy(err_msg))
                    }
                }
            }
            _ => {
                let err_msg = format!(
                    "Unexpected state for NTLM challenge handling: {:?}",
                    current_state
                );
                self.mark_failed(err_msg.clone()).await;
                Err(ResolveError::HttpProxy(err_msg))
            }
        }
    }

    pub async fn reset(&self) {
        debug!(target: "sspi_auth", spn = %self.target_spn, "Resetting NTLM SSPI authentication state");
        *self.auth_state.write().await = SspiAuthState::Initial;
        *self.credentials_handle.write().await = None;
    }
}

#[cfg(not(windows))]
mod mock_sspi {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SspiAuthState {
        Initial,
        NegotiateSent,
        ChallengeReceived,
        Authenticated,
        Failed(String),
    }

    #[derive(Debug)]
    pub struct SspiAuthManager;

    impl SspiAuthManager {
        pub fn new(
            _target_spn: String,
            _username: Option<String>,
            _password: Option<String>,
            _domain: Option<String>,
        ) -> Result<Self, ResolveError> {
            Err(ResolveError::HttpProxy(
                "SSPI NTLM authentication not supported on this platform".to_string(),
            ))
        }

        pub fn new_for_current_user(_target_spn: String) -> Result<Self, ResolveError> {
            Err(ResolveError::HttpProxy(
                "SSPI NTLM authentication not supported on this platform".to_string(),
            ))
        }

        pub async fn get_initial_token(&self) -> Result<String, ResolveError> {
            Err(ResolveError::HttpProxy(
                "SSPI NTLM authentication not supported on this platform".to_string(),
            ))
        }

        pub async fn get_challenge_response_token(
            &self,
            _challenge_header: &str,
        ) -> Result<String, ResolveError> {
            Err(ResolveError::HttpProxy(
                "SSPI NTLM authentication not supported on this platform".to_string(),
            ))
        }

        pub async fn reset(&self) {}

        pub async fn get_auth_state(&self) -> SspiAuthState {
            SspiAuthState::Failed("Not supported on this platform".to_string())
        }

        pub async fn is_authenticated(&self) -> bool {
            false
        }

        pub async fn mark_failed(&self, _message: String) {}

        pub async fn set_auth_state(&self, _state: SspiAuthState) {}
    }
}

#[cfg(not(windows))]
pub use mock_sspi::{SspiAuthManager, SspiAuthState};
