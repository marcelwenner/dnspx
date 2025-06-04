#![cfg(windows)]

use crate::core::error::ResolveError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, Negotiate,
    SecurityBuffer, SecurityContext, SecurityStatus, Sspi, Username,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SspiAuthState {
    Initial,
    NegotiateSent,
    ChallengeReceived,
    Authenticated,
    Failed(String),
}

pub struct SspiAuthManager {
    sspi_client: Arc<Negotiate>,
    auth_state: Arc<RwLock<SspiAuthState>>,
    target_spn: String,
    credentials_handle: Arc<RwLock<Option<sspi::CredentialsHandle>>>,
    security_context: Arc<RwLock<Option<SecurityContext>>>,
    owned_username: Option<String>,
    owned_domain: Option<String>,
    owned_password_utf16: Option<Vec<u16>>,
}

impl SspiAuthManager {
    pub fn new_current_user(proxy_host: &str) -> Result<Self, ResolveError> {
        let sspi_client = Negotiate::new();
        let target_spn = format!("HTTP/{}", proxy_host);
        debug!(
            target: "sspi_auth",
            spn = %target_spn,
            auth_mode = "current_user",
            "Creating SSPI auth manager with Negotiate protocol"
        );

        Ok(Self {
            sspi_client: Arc::new(sspi_client),
            auth_state: Arc::new(RwLock::new(SspiAuthState::Initial)),
            target_spn,
            credentials_handle: Arc::new(RwLock::new(None)),
            security_context: Arc::new(RwLock::new(None)),
            owned_username: None,
            owned_domain: None,
            owned_password_utf16: None,
        })
    }

    fn validate_credentials(username: &str, domain: Option<&str>) -> Result<(), ResolveError> {
        Username::new(username, domain).map_err(|e| {
            ResolveError::Configuration(format!(
                "Invalid SSPI username/domain combination: '{}', domain '{:?}': {}",
                username, domain, e
            ))
        })?;
        Ok(())
    }

    pub fn new_with_credentials(
        username: &str,
        password: &str,
        domain: Option<&str>,
        proxy_host: &str,
    ) -> Result<Self, ResolveError> {
        Self::validate_credentials(username, domain)?;

        let sspi_client = Negotiate::new();
        let target_spn = format!("HTTP/{}", proxy_host);

        debug!(
            target: "sspi_auth",
            spn = %target_spn,
            user = %username,
            domain = ?domain,
            auth_mode = "explicit_credentials",
            "Creating SSPI auth manager with Negotiate protocol"
        );

        Ok(Self {
            sspi_client: Arc::new(sspi_client),
            auth_state: Arc::new(RwLock::new(SspiAuthState::Initial)),
            target_spn,
            credentials_handle: Arc::new(RwLock::new(None)),
            security_context: Arc::new(RwLock::new(None)),
            owned_username: Some(username.to_string()),
            owned_domain: domain.map(|d| d.to_string()),
            owned_password_utf16: Some(password.encode_utf16().collect()),
        })
    }

    fn create_auth_identity_borrowed(&self) -> Option<AuthIdentity<'_>> {
        if let (Some(username), Some(password_utf16)) = (
            self.owned_username.as_ref(),
            self.owned_password_utf16.as_ref(),
        ) {
            Username::new(username.as_str(), self.owned_domain.as_deref())
                .map_err(|e| {
                    error!(target: "sspi_auth", "Internal error creating sspi::Username for {}: {}", username, e);
                    e
                })
                .ok()
                .map(|un| AuthIdentity::new(un, password_utf16.clone()))
        } else {
            None
        }
    }

    async fn ensure_credentials_handle_internal(
        &self,
    ) -> Result<sspi::CredentialsHandle, ResolveError> {
        let mut creds_handle_guard = self.credentials_handle.write().await;
        if creds_handle_guard.is_none() {
            let mut builder = self
                .sspi_client
                .acquire_credentials_handle()
                .with_credential_use(CredentialUse::Outbound);

            let temp_auth_identity = self.create_auth_identity_borrowed();

            if let Some(ref identity) = temp_auth_identity {
                builder = builder.with_auth_data(identity);
                self.log_sspi_operation_internal(
                    "ensure_credentials_handle",
                    0,
                    "Using explicit credentials",
                );
            } else {
                self.log_sspi_operation_internal(
                    "ensure_credentials_handle",
                    0,
                    "Using current user credentials",
                );
            }

            let handle = builder.execute().map_err(|e| {
                let err_msg = format!(
                    "SSPI credential acquisition failed for SPN {}: {}",
                    self.target_spn, e
                );
                error!(target: "sspi_auth", "{}", err_msg);
                ResolveError::HttpProxy(err_msg)
            })?;

            *creds_handle_guard = Some(handle);
            self.log_sspi_operation_internal(
                "ensure_credentials_handle",
                0,
                "Acquired credentials handle successfully",
            );
        }
        Ok(creds_handle_guard.as_ref().unwrap().clone())
    }

    async fn ensure_credentials_handle_with_timeout(
        &self,
    ) -> Result<sspi::CredentialsHandle, ResolveError> {
        tokio::time::timeout(
            Duration::from_secs(30),
            self.ensure_credentials_handle_internal(),
        )
        .await
        .map_err(|_| {
            let err_msg = format!(
                "SSPI credential acquisition timed out for SPN: {}",
                self.target_spn
            );
            error!(target: "sspi_auth", "{}", err_msg);
            ResolveError::HttpProxy(err_msg)
        })?
    }

    async fn get_or_init_security_context(
        &self,
        creds_handle: &sspi::CredentialsHandle,
    ) -> Result<SecurityContext, ResolveError> {
        let mut sec_context_guard = self.security_context.write().await;
        if sec_context_guard.is_none() {
            let sspi_context_client = self
                .sspi_client
                .initialize_security_context(creds_handle)
                .with_target_name(&self.target_spn)
                .with_context_requirements(
                    ClientRequestFlags::CONFIDENTIALITY
                        | ClientRequestFlags::INTEGRITY
                        | ClientRequestFlags::MUTUAL_AUTH
                        | ClientRequestFlags::DELEGATE
                        | ClientRequestFlags::SEQUENCE_DETECT
                        | ClientRequestFlags::REPLAY_DETECT,
                )
                .with_target_data_representation(DataRepresentation::Network)
                .initially_empty();
            *sec_context_guard = Some(sspi_context_client);
            self.log_sspi_operation_internal(
                "get_or_init_security_context",
                0,
                "Initialized new security context",
            );
        }
        Ok(sec_context_guard.as_ref().unwrap().clone())
    }

    pub async fn get_initial_token(&self) -> Result<String, ResolveError> {
        let mut auth_state_guard = self.auth_state.write().await;
        if *auth_state_guard != SspiAuthState::Initial {
            self.log_sspi_operation_internal(
                "get_initial_token",
                0,
                "State was not Initial, resetting.",
            );
            self.reset_internal(&mut auth_state_guard).await;
        }

        let creds_handle = self.ensure_credentials_handle_with_timeout().await?;

        let mut sec_context_opt_guard = self.security_context.write().await;
        let mut sspi_context = sec_context_opt_guard.take().unwrap_or_else(|| {
            self.log_sspi_operation_internal(
                "get_initial_token",
                0,
                "No existing security context, creating new one.",
            );
            self.sspi_client
                .initialize_security_context(&creds_handle)
                .with_target_name(&self.target_spn)
                .with_context_requirements(
                    ClientRequestFlags::MUTUAL_AUTH
                        | ClientRequestFlags::CONFIDENTIALITY
                        | ClientRequestFlags::INTEGRITY
                        | ClientRequestFlags::DELEGATE
                        | ClientRequestFlags::SEQUENCE_DETECT
                        | ClientRequestFlags::REPLAY_DETECT,
                )
                .with_target_data_representation(DataRepresentation::Network)
                .initially_empty()
        });

        let mut output_buffers = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

        let sspi_result = sspi_context
            .next_token(None, &mut output_buffers)
            .map_err(|e| {
                ResolveError::HttpProxy(format!(
                    "SSPI initial next_token failed for SPN {}: {}",
                    self.target_spn, e
                ))
            })?;

        *sec_context_opt_guard = Some(sspi_context);

        match sspi_result.status {
            SecurityStatus::ContinueNeeded => {
                let token_bytes = &output_buffers[0].buffer;
                if token_bytes.is_empty() {
                    let err_msg = "SSPI: No initial token generated despite ContinueNeeded";
                    self.log_sspi_operation_internal(
                        "get_initial_token",
                        0,
                        &format!("Error: {}", err_msg),
                    );
                    *auth_state_guard = SspiAuthState::Failed(err_msg.to_string());
                    return Err(ResolveError::HttpProxy(err_msg.to_string()));
                }
                let token_base64 = BASE64_STANDARD.encode(token_bytes);
                *auth_state_guard = SspiAuthState::NegotiateSent;
                self.log_sspi_operation_internal(
                    "get_initial_token",
                    0,
                    &format!(
                        "Generated initial Negotiate token ({} bytes)",
                        token_bytes.len()
                    ),
                );
                Ok(format!("Negotiate {}", token_base64))
            }
            SecurityStatus::Ok => {
                *auth_state_guard = SspiAuthState::Authenticated;
                self.log_sspi_operation_internal(
                    "get_initial_token",
                    0,
                    "Authentication completed on initial step (Ok status).",
                );
                let token_bytes = &output_buffers[0].buffer;
                if !token_bytes.is_empty() {
                    let token_base64 = BASE64_STANDARD.encode(token_bytes);
                    Ok(format!("Negotiate {}", token_base64))
                } else {
                    Ok(String::new())
                }
            }
            _ => {
                let err_msg = format!(
                    "SSPI initial token generation failed with status {:?} for SPN {}",
                    sspi_result.status, self.target_spn
                );
                self.log_sspi_operation_internal(
                    "get_initial_token",
                    0,
                    &format!("Error: {}", err_msg),
                );
                *auth_state_guard = SspiAuthState::Failed(err_msg.clone());
                Err(ResolveError::HttpProxy(err_msg))
            }
        }
    }

    pub async fn get_challenge_response_token(
        &self,
        challenge_header: &str,
    ) -> Result<String, ResolveError> {
        let mut auth_state_guard = self.auth_state.write().await;
        let creds_handle_read_guard = self.credentials_handle.read().await;
        let creds_handle = creds_handle_read_guard.as_ref().ok_or_else(|| {
            ResolveError::HttpProxy(
                "SSPI: Credentials handle not available for challenge response".to_string(),
            )
        })?;

        let mut sec_context_opt_guard = self.security_context.write().await;

        match &*auth_state_guard {
            SspiAuthState::NegotiateSent | SspiAuthState::ChallengeReceived => {}
            _ => {
                let err_msg = format!(
                    "SSPI: get_challenge_response_token called in unexpected state {:?} for SPN {}",
                    *auth_state_guard, self.target_spn
                );
                self.log_sspi_operation_internal(
                    "get_challenge_response_token",
                    0,
                    &format!("Error: {}", err_msg),
                );
                *auth_state_guard = SspiAuthState::Failed(err_msg.clone());
                return Err(ResolveError::HttpProxy(err_msg));
            }
        }

        let challenge_bytes = if let Some(challenge_data) = challenge_header
            .strip_prefix("Negotiate ")
            .or_else(|| challenge_header.strip_prefix("NTLM "))
        {
            BASE64_STANDARD.decode(challenge_data.trim()).map_err(|e| {
                ResolveError::HttpProxy(format!(
                    "SSPI: Invalid base64 in challenge token: {}. Header: '{}'",
                    e, challenge_header
                ))
            })?
        } else {
            return Err(ResolveError::HttpProxy(format!(
                "SSPI: Unexpected proxy challenge header format: '{}'",
                challenge_header
            )));
        };

        self.log_sspi_operation_internal(
            "get_challenge_response_token",
            0,
            &format!("Processing challenge ({} bytes)", challenge_bytes.len()),
        );

        let mut sspi_context = sec_context_opt_guard.take().ok_or_else(|| {
            ResolveError::HttpProxy(
                "SSPI: Security context not initialized for challenge response".to_string(),
            )
        })?;

        let input_buffers = vec![SecurityBuffer::new(challenge_bytes, BufferType::Token)];
        let mut output_buffers = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

        let sspi_result = sspi_context
            .next_token(Some(&input_buffers), &mut output_buffers)
            .map_err(|e| {
                ResolveError::HttpProxy(format!(
                    "SSPI challenge response (next_token) failed for SPN {}: {}",
                    self.target_spn, e
                ))
            })?;

        *sec_context_opt_guard = Some(sspi_context);

        match sspi_result.status {
            SecurityStatus::Ok => {
                *auth_state_guard = SspiAuthState::Authenticated;
                self.log_sspi_operation_internal(
                    "get_challenge_response_token",
                    0,
                    "Authentication completed successfully after challenge.",
                );
                let token_bytes = &output_buffers[0].buffer;
                if !token_bytes.is_empty() {
                    let token_base64 = BASE64_STANDARD.encode(token_bytes);
                    Ok(format!("Negotiate {}", token_base64))
                } else {
                    Ok(String::new())
                }
            }
            SecurityStatus::ContinueNeeded => {
                *auth_state_guard = SspiAuthState::ChallengeReceived;
                let token_bytes = &output_buffers[0].buffer;
                if token_bytes.is_empty() {
                    let err_msg = "SSPI: ContinueNeeded but empty token after challenge";
                    self.log_sspi_operation_internal(
                        "get_challenge_response_token",
                        0,
                        &format!("Error: {}", err_msg),
                    );
                    *auth_state_guard = SspiAuthState::Failed(err_msg.to_string());
                    return Err(ResolveError::HttpProxy(err_msg.to_string()));
                }
                let token_base64 = BASE64_STANDARD.encode(token_bytes);
                self.log_sspi_operation_internal(
                    "get_challenge_response_token",
                    0,
                    &format!(
                        "Continuing authentication, token generated ({} bytes)",
                        token_bytes.len()
                    ),
                );
                Ok(format!("Negotiate {}", token_base64))
            }
            _ => {
                let err_msg = format!(
                    "SSPI authentication failed with status {:?} after challenge for SPN {}",
                    sspi_result.status, self.target_spn
                );
                self.log_sspi_operation_internal(
                    "get_challenge_response_token",
                    0,
                    &format!("Error: {}", err_msg),
                );
                *auth_state_guard = SspiAuthState::Failed(err_msg.clone());
                Err(ResolveError::HttpProxy(err_msg))
            }
        }
    }

    async fn reset_internal(
        &self,
        auth_state_guard: &mut tokio::sync::RwLockWriteGuard<'_, SspiAuthState>,
    ) {
        let mut sec_context_guard = self.security_context.write().await;

        *auth_state_guard = SspiAuthState::Initial;
        *sec_context_guard = None;
        self.log_sspi_operation_internal("reset_internal", 0, "State reset.");
    }

    pub async fn reset(&self) {
        let mut auth_state_guard = self.auth_state.write().await;
        self.reset_internal(&mut auth_state_guard).await;
    }

    pub async fn mark_failed(&self, reason: String) {
        let mut auth_state_guard = self.auth_state.write().await;
        match &*auth_state_guard {
            SspiAuthState::Failed(existing_reason) => {
                let combined_reason = format!("{} | {}", existing_reason, reason);
                warn!(target: "sspi_auth", "SSPI: Additional failure for SPN {}: {} (was: {})", self.target_spn, reason, existing_reason);
                *auth_state_guard = SspiAuthState::Failed(combined_reason);
            }
            _ => {
                warn!(target: "sspi_auth", "SSPI: Marking authentication as failed for SPN {}. Reason: {}", self.target_spn, reason);
                *auth_state_guard = SspiAuthState::Failed(reason);
            }
        }
    }

    pub async fn is_authenticated(&self) -> bool {
        matches!(*self.auth_state.read().await, SspiAuthState::Authenticated)
    }

    pub fn is_using_current_user(&self) -> bool {
        self.owned_username.is_none()
    }

    fn log_sspi_operation_internal(&self, operation: &str, attempt: u8, additional_info: &str) {
        debug!(
            target: "sspi_auth",
            spn = %self.target_spn,
            operation = %operation,
            attempt = %attempt,
            current_user = %self.is_using_current_user(),
            info = %additional_info,
            "SSPI operation"
        );
    }

    #[allow(dead_code)]
    pub async fn get_auth_state_debug_info(&self) -> String {
        let state = self.auth_state.read().await;
        let has_creds = self.credentials_handle.read().await.is_some();
        let has_context = self.security_context.read().await.is_some();

        format!(
            "SSPI Debug - SPN: {}, State: {:?}, HasCreds: {}, HasContext: {}, CurrentUser: {}",
            self.target_spn,
            *state,
            has_creds,
            has_context,
            self.is_using_current_user()
        )
    }
}

impl Drop for SspiAuthManager {
    fn drop(&mut self) {
        debug!(target: "sspi_auth", "SSPI: Dropping auth manager for SPN: {}", self.target_spn);
    }
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_current_user_manager_creation() {
        let manager = SspiAuthManager::new_current_user("proxy.example.com")
            .expect("Should create current user manager");

        assert!(manager.is_using_current_user());
        assert_eq!(manager.target_spn, "HTTP/proxy.example.com");
        assert!(matches!(
            *manager.auth_state.read().await,
            SspiAuthState::Initial
        ));
    }

    #[tokio::test]
    async fn test_explicit_credentials_manager_creation() {
        let manager = SspiAuthManager::new_with_credentials(
            "testuser",
            "testpass",
            Some("DOMAIN"),
            "proxy.example.com",
        )
        .expect("Should create credentials manager");

        assert!(!manager.is_using_current_user());
        assert_eq!(manager.target_spn, "HTTP/proxy.example.com");
        assert_eq!(manager.owned_username.as_deref(), Some("testuser"));
        assert_eq!(manager.owned_domain.as_deref(), Some("DOMAIN"));
        assert!(manager.owned_password_utf16.is_some());
    }

    #[tokio::test]
    async fn test_create_auth_identity_with_credentials() {
        let manager = SspiAuthManager::new_with_credentials(
            "testuser",
            "testpass",
            Some("DOMAIN"),
            "proxy.example.com",
        )
        .expect("Should create manager");

        let auth_identity = manager.create_auth_identity_borrowed();
        assert!(
            auth_identity.is_some(),
            "Should create AuthIdentity for explicit credentials"
        );
    }

    #[tokio::test]
    async fn test_create_auth_identity_current_user() {
        let manager =
            SspiAuthManager::new_current_user("proxy.example.com").expect("Should create manager");

        let auth_identity = manager.create_auth_identity_borrowed();
        assert!(
            auth_identity.is_none(),
            "Should not create AuthIdentity for current user"
        );
    }

    #[tokio::test]
    async fn test_reset_functionality() {
        let manager =
            SspiAuthManager::new_current_user("proxy.example.com").expect("Should create manager");

        {
            let mut state = manager.auth_state.write().await;
            *state = SspiAuthState::Authenticated;
        }

        manager.reset().await;

        assert!(matches!(
            *manager.auth_state.read().await,
            SspiAuthState::Initial
        ));

        assert!(manager.security_context.read().await.is_none());
    }

    #[tokio::test]
    async fn test_mark_failed_logic() {
        let manager =
            SspiAuthManager::new_current_user("proxy.example.com").expect("Should create manager");

        let reason1 = "Test failure 1".to_string();
        manager.mark_failed(reason1.clone()).await;
        let state1 = manager.auth_state.read().await;
        assert!(matches!(*state1, SspiAuthState::Failed(ref msg) if msg == &reason1));

        let reason2 = "Test failure 2".to_string();
        manager.mark_failed(reason2.clone()).await;
        let state2 = manager.auth_state.read().await;
        let expected_combined = format!("{} | {}", reason1, reason2);
        assert!(matches!(*state2, SspiAuthState::Failed(ref msg) if msg == &expected_combined));
    }

    #[tokio::test]
    async fn test_is_authenticated() {
        let manager =
            SspiAuthManager::new_current_user("proxy.example.com").expect("Should create manager");

        assert!(!manager.is_authenticated().await);

        {
            let mut state = manager.auth_state.write().await;
            *state = SspiAuthState::Authenticated;
        }
        assert!(manager.is_authenticated().await);
    }

    #[tokio::test]
    fn test_credential_validation_logic() {
        assert!(SspiAuthManager::validate_credentials("user", Some("DOMAIN")).is_ok());
        assert!(SspiAuthManager::validate_credentials("user", None).is_ok());
    }

    #[tokio::test]
    async fn test_concurrent_sspi_state_access() {
        let manager = Arc::new(
            SspiAuthManager::new_current_user("concurrent.example.com")
                .expect("Should create manager"),
        );

        let mut handles = vec![];
        for _ in 0..10 {
            let mgr_clone = Arc::clone(&manager);
            handles.push(tokio::spawn(async move {
                let _ = mgr_clone.is_authenticated().await;
                let _ = mgr_clone.is_using_current_user();
                if mgr_clone.auth_state.read().await.clone() == SspiAuthState::Initial {
                    mgr_clone.mark_failed("concurrent test".to_string()).await;
                }
            }));
        }

        for handle in handles {
            handle.await.expect("Concurrent task failed");
        }

        assert!(matches!(
            *manager.auth_state.read().await,
            SspiAuthState::Failed(_)
        ));
    }

    #[tokio::test]
    async fn test_performance_baseline_sspi_manager() {
        let manager =
            SspiAuthManager::new_current_user("perf.example.com").expect("Should create manager");

        let start = Instant::now();

        let _ = manager.is_authenticated().await;
        let _ = manager.is_using_current_user();
        manager.reset().await;

        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(150),
            "Basic SSPI manager operations should be fast: {:?}",
            elapsed
        );
    }
}
