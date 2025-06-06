#![cfg(windows)]

use crate::core::error::ResolveError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, Ntlm,
    SecurityBuffer, SecurityStatus, SspiImpl, Username,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, warn}; // error hinzugefügt

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
    // 1. Security Context Handle Management
    security_context: Arc<RwLock<Option<<Ntlm as SspiImpl>::SecurityContextHandle>>>,
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
            security_context: Arc::new(RwLock::new(None)), // Initialisieren
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
            security_context: Arc::new(RwLock::new(None)), // Initialisieren
        })
    }

    pub async fn get_auth_state(&self) -> SspiAuthState {
        self.auth_state.read().await.clone()
    }

    async fn set_auth_state(&self, state: SspiAuthState) {
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
    // 2. Credentials Handle Caching-Verbesserung
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

            let acq_result = final_builder.execute(&mut *sspi_client_locked).map_err(|e| {
                // Verbesserte Error-Behandlung
                error!(target: "sspi_auth", spn = %self.target_spn, error = %e, "Failed to acquire NTLM credentials");
                ResolveError::HttpProxy(format!("Failed to acquire NTLM credentials handle: {}", e))
            })?;

            debug!(target: "sspi_auth", spn = %self.target_spn, "Successfully acquired NTLM credentials handle");
            *creds_handle_guard = Some(acq_result.credentials_handle);
        }
        Ok(creds_handle_guard.as_ref().unwrap().clone())
    }

    async fn generate_negotiate_token_internal(
        &self,
        creds_handle: &mut <Ntlm as SspiImpl>::CredentialsHandle,
    ) -> Result<
        (
            Vec<u8>,
            SecurityStatus,
            <Ntlm as SspiImpl>::SecurityContextHandle,
        ),
        ResolveError,
    > {
        let mut sspi_client_locked = self.sspi_client.lock().await;
        let mut output_buffers = [SecurityBuffer::new(Vec::new(), BufferType::Token)];

        let mut init_builder = sspi_client_locked
            .initialize_security_context()
            .with_credentials_handle(creds_handle)
            .with_context_requirements(
                ClientRequestFlags::CONFIDENTIALITY
                    | ClientRequestFlags::ALLOCATE_MEMORY
                    | ClientRequestFlags::MUTUAL_AUTH
                    | ClientRequestFlags::DELEGATE,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(&self.target_spn)
            .with_output(&mut output_buffers);

        let result = init_builder
            .execute(&mut *sspi_client_locked)
            .map_err(|e| {
                ResolveError::HttpProxy(format!(
                    "Failed to initialize NTLM security context: {}",
                    e
                ))
            })?;

        let token = output_buffers[0].buffer().to_vec();
        Ok((token, result.status, result.context_handle))
    }

    async fn continue_authentication_internal(
        &self,
        server_challenge: &[u8],
        creds_handle: &mut <Ntlm as SspiImpl>::CredentialsHandle,
        sec_context_handle: &mut <Ntlm as SspiImpl>::SecurityContextHandle,
    ) -> Result<(Vec<u8>, SecurityStatus), ResolveError> {
        let mut sspi_client_locked = self.sspi_client.lock().await;

        let mut input_buffers = [SecurityBuffer::new(
            server_challenge.to_vec(),
            BufferType::Token,
        )];
        let mut output_buffers = [SecurityBuffer::new(Vec::new(), BufferType::Token)];

        let mut builder = sspi_client_locked
            .initialize_security_context()
            .with_credentials_handle(creds_handle)
            .with_security_context(sec_context_handle)
            .with_context_requirements(
                ClientRequestFlags::CONFIDENTIALITY
                    | ClientRequestFlags::ALLOCATE_MEMORY
                    | ClientRequestFlags::MUTUAL_AUTH
                    | ClientRequestFlags::DELEGATE,
            )
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(&self.target_spn)
            .with_input(&mut input_buffers)
            .with_output(&mut output_buffers);

        let result = builder.execute(&mut *sspi_client_locked).map_err(|e| {
            ResolveError::HttpProxy(format!("Failed to continue NTLM authentication: {}", e))
        })?;

        let token = output_buffers[0].buffer().to_vec();
        Ok((token, result.status))
    }

    pub async fn get_initial_token(&self) -> Result<String, ResolveError> {
        self.reset().await; // Reset state before attempting
        self.set_auth_state(SspiAuthState::Initial).await;

        debug!(target: "sspi_auth", spn = %self.target_spn, "Attempting to get initial NTLM token");
        let mut creds_handle = self.acquire_credentials_handle_internal().await?;
        *self.credentials_handle.write().await = Some(creds_handle.clone()); // Store for later

        let (token_bytes, status, sec_context_handle) = self
            .generate_negotiate_token_internal(&mut creds_handle)
            .await?;

        // Store the security context handle
        *self.security_context.write().await = Some(sec_context_handle);

        match status {
            SecurityStatus::ContinueNeeded => {
                let b64_token = BASE64_STANDARD.encode(&token_bytes);
                self.set_auth_state(SspiAuthState::NegotiateSent).await;
                debug!(target: "sspi_auth", spn = %self.target_spn, "Generated initial NTLM token (ContinueNeeded), state: NegotiateSent");
                Ok(format!("Negotiate {}", b64_token))
            }
            SecurityStatus::Ok => {
                // Kann bei Kerberos direkt Ok sein
                let b64_token = BASE64_STANDARD.encode(&token_bytes);
                self.set_auth_state(SspiAuthState::Authenticated).await;
                debug!(target: "sspi_auth", spn = %self.target_spn, "NTLM authentication successful in initial step.");
                Ok(format!("Negotiate {}", b64_token))
            }
            _ => {
                let err_msg = format!(
                    "NTLM initial token generation failed with status: {:?}",
                    status
                );
                self.mark_failed(err_msg.clone()).await;
                Err(ResolveError::HttpProxy(err_msg))
            }
        }
    }
    // 3. Challenge Response mit SecurityContext-Tracking
    pub async fn get_challenge_response_token(
        &self,
        challenge_header: &str,
    ) -> Result<String, ResolveError> {
        let current_state = self.get_auth_state().await;
        debug!(target: "sspi_auth", spn = %self.target_spn, state = ?current_state, "Processing NTLM challenge");

        match current_state {
            SspiAuthState::NegotiateSent | SspiAuthState::ChallengeReceived => {
                let challenge_data = challenge_header
                    .strip_prefix("Negotiate ")
                    .or_else(|| challenge_header.strip_prefix("NTLM "))
                    .ok_or_else(|| {
                        let msg = format!(
                            "Invalid challenge header format (expected 'Negotiate' or 'NTLM'): {}",
                            challenge_header
                        );
                        warn!(target: "sspi_auth", spn = %self.target_spn, "{}", msg);
                        ResolveError::HttpProxy(msg)
                    })?;

                let challenge_bytes =
                    BASE64_STANDARD.decode(challenge_data.trim()).map_err(|e| {
                        let msg =
                            format!("Failed to decode NTLM challenge (invalid base64): {}", e);
                        warn!(target: "sspi_auth", spn = %self.target_spn, "{}", msg);
                        ResolveError::HttpProxy(msg)
                    })?;

                debug!(target: "sspi_auth", spn = %self.target_spn, challenge_size = challenge_bytes.len(), "Decoded NTLM challenge from server");

                let mut creds_handle_guard = self.credentials_handle.write().await;
                let mut sec_context_guard = self.security_context.write().await;

                let creds_handle = match creds_handle_guard.as_mut() {
                    Some(ch) => ch,
                    None => {
                        let msg = "No NTLM credentials handle available for challenge response"
                            .to_string();
                        return Err(ResolveError::HttpProxy(msg));
                    }
                };
                let sec_context = match sec_context_guard.as_mut() {
                    Some(sc) => sc,
                    None => {
                        let msg =
                            "No NTLM security context available for challenge response".to_string();
                        return Err(ResolveError::HttpProxy(msg));
                    }
                };

                let (response_token_bytes, status) = self
                    .continue_authentication_internal(&challenge_bytes, creds_handle, sec_context)
                    .await?;

                match status {
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
                            status
                        );
                        self.mark_failed(err_msg.clone()).await;
                        Err(ResolveError::HttpProxy(err_msg))
                    }
                }
            }
            _ => {
                let err_msg = format!(
                    "Cannot handle challenge in state {:?} (expected NegotiateSent or ChallengeReceived)",
                    current_state
                );
                warn!(target: "sspi_auth", spn = %self.target_spn, "{}", err_msg);
                self.mark_failed(err_msg.clone()).await;
                Err(ResolveError::HttpProxy(err_msg))
            }
        }
    }

    // 4. Verbesserte Reset-Implementierung
    pub async fn reset(&self) {
        debug!(target: "sspi_auth", spn = %self.target_spn, "Resetting NTLM SSPI authentication state");
        *self.auth_state.write().await = SspiAuthState::Initial;
        *self.credentials_handle.write().await = None;
        *self.security_context.write().await = None; // Reset security context
        debug!(target: "sspi_auth", spn = %self.target_spn, "NTLM SSPI authentication state reset complete");
    }

    // 6. Zusätzliche Hilfsmethoden für bessere Diagnostik
    /// Returns detailed state information for logging/debugging
    pub async fn get_state_info(&self) -> String {
        // Renamed from get_auth_state_debug_info
        let state = self.get_auth_state().await;
        let has_creds = self.credentials_handle.read().await.is_some();
        let has_sec_context = self.security_context.read().await.is_some();
        format!(
            "SSPI State: {:?}, Has Credentials: {}, Has SecurityContext: {}, SPN: {}",
            state, has_creds, has_sec_context, self.target_spn
        )
    }

    /// Check if we can attempt authentication
    pub async fn can_authenticate(&self) -> bool {
        matches!(
            self.get_auth_state().await,
            SspiAuthState::Initial
                | SspiAuthState::NegotiateSent
                | SspiAuthState::ChallengeReceived
        )
    }
}

// 5. Mock-Implementation Verbesserungen für bessere Tests
#[cfg(not(windows))]
mod sspi_auth_mock_impl {
    // Renamed to avoid conflict if used directly
    use super::*;
    impl SspiAuthManager {
        // Die new-Methoden müssen public sein, wenn sie von außerhalb des Moduls verwendet werden
        pub fn new(
            // `pub` hinzugefügt
            target_spn: String,
            _username: Option<String>,
            _password: Option<String>,
            _domain: Option<String>,
        ) -> Result<Self, ResolveError> {
            debug!(target: "sspi_auth", spn = %target_spn, "Creating mock SSPI manager (non-Windows platform)");
            Ok(Self::mock_instance(target_spn))
        }

        pub fn new_for_current_user(target_spn: String) -> Result<Self, ResolveError> {
            // `pub` hinzugefügt
            debug!(target: "sspi_auth", spn = %target_spn, "Creating mock SSPI manager for current user (non-Windows platform)");
            Ok(Self::mock_instance(target_spn))
        }

        fn mock_instance(target_spn: String) -> Self {
            Self {
                target_spn,
                username: None,
                password: None,
                domain: None,
                sspi_client: Arc::new(tokio::sync::Mutex::new(Ntlm::new())), // Mock Ntlm
                auth_state: Arc::new(RwLock::new(SspiAuthState::Initial)),
                credentials_handle: Arc::new(RwLock::new(None)),
                security_context: Arc::new(RwLock::new(None)),
            }
        }

        pub async fn get_initial_token(&self) -> Result<String, ResolveError> {
            warn!(target: "sspi_auth", spn = %self.target_spn, "SSPI authentication (get_initial_token) attempted on non-Windows platform (mock)");
            Err(ResolveError::HttpProxy(
                "SSPI NTLM authentication not supported on this platform".to_string(),
            ))
        }

        pub async fn get_challenge_response_token(
            &self,
            _challenge_header: &str,
        ) -> Result<String, ResolveError> {
            warn!(target: "sspi_auth", spn = %self.target_spn, "SSPI authentication (get_challenge_response_token) attempted on non-Windows platform (mock)");
            Err(ResolveError::HttpProxy(
                "SSPI NTLM authentication not supported on this platform".to_string(),
            ))
        }
        // Weitere Mock-Methoden aus deinem Original bleiben
        pub async fn reset(&self) {
            debug!(target: "sspi_auth", spn = %self.target_spn, "Reset called on mock SSPI manager");
        }
        pub async fn get_auth_state(&self) -> SspiAuthState {
            SspiAuthState::Initial
        } // Oder Failed
        pub async fn is_authenticated(&self) -> bool {
            false
        }
        pub async fn mark_failed(&self, message: String) {
            warn!(target: "sspi_auth", spn = %self.target_spn, "mark_failed called on mock SSPI manager: {}", message);
        }
        pub async fn get_state_info(&self) -> String {
            format!("Mock SSPI State for SPN: {}", self.target_spn)
        }
        pub async fn can_authenticate(&self) -> bool {
            false
        }
    }
}
