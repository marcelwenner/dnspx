#![cfg(not(windows))]

//! Mock SSPI implementation for non-Windows platforms
//! This allows the code to compile and basic tests to run on macOS/Linux

use crate::core::error::ResolveError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SspiAuthState {
    Initial,
    NegotiateSent,
    ChallengeReceived,
    Authenticated,
    Failed(String),
}

#[derive(Debug)]
pub(super) struct SspiAuthManager;

impl SspiAuthManager {
    pub(super) fn new_current_user(_proxy_host: &str) -> Result<Self, ResolveError> {
        Err(ResolveError::Configuration(
            "SSPI authentication is only available on Windows".to_string(),
        ))
    }

    pub(super) fn new_with_credentials(
        _username: &str,
        _password: &str,
        _domain: Option<&str>,
        _proxy_host: &str,
    ) -> Result<Self, ResolveError> {
        Err(ResolveError::Configuration(
            "SSPI authentication is only available on Windows".to_string(),
        ))
    }

    pub(super) async fn get_initial_token(&self) -> Result<String, ResolveError> {
        Err(ResolveError::Configuration(
            "SSPI authentication is only available on Windows".to_string(),
        ))
    }

    pub(super) async fn get_challenge_response_token(
        &self,
        _challenge_header: &str,
    ) -> Result<String, ResolveError> {
        Err(ResolveError::Configuration(
            "SSPI authentication is only available on Windows".to_string(),
        ))
    }

    pub(super) async fn reset(&self) {}

    pub(super) async fn mark_failed(&self, _reason: String) {}

    pub(super) async fn is_authenticated(&self) -> bool {
        false
    }

    pub(super) fn is_using_current_user(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_sspi_creation_fails() {
        let result = SspiAuthManager::new_current_user("proxy.example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Windows"));
    }

    #[tokio::test]
    async fn test_mock_sspi_with_credentials_fails() {
        let result = SspiAuthManager::new_with_credentials(
            "testuser",
            "testpass",
            Some("DOMAIN"),
            "proxy.example.com",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Windows"));
    }
}
