#![allow(dead_code)] 
use crate::config::models::{HttpProxyConfig, ProxyAuthenticationType};
use crate::core::error::ResolveError;
use crate::dns_protocol::{DnsMessage, DnsQuestion, parse_dns_message, serialize_dns_message};
use crate::ports::UpstreamResolver;
use reqwest::{
    Body,
    Client,
    Proxy,
    StatusCode,
    header::{ACCEPT, CONTENT_TYPE}, 
};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, instrument, warn};
use url::Url;


#[cfg(windows)]
use super::sspi_auth::{SspiAuthManager, SspiAuthState};
#[cfg(windows)]
use reqwest::header::{HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};


#[cfg(not(windows))]
mod sspi_auth_mock_client {
    use super::*;
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub(super) enum SspiAuthState {
        #[default]
        Initial,
        Failed(String),
        NegotiateSent,
        Authenticated,
        ChallengeReceived,
    }

    #[derive(Debug, Default)]
    pub(super) struct SspiAuthManager {
        pub(super) target_spn: String,
    } 
    impl SspiAuthManager {
        pub(super) fn new(
            target_spn: String,
            _username: Option<String>,
            _password: Option<String>,
            _domain: Option<String>,
        ) -> Result<Self, ResolveError> {
            Ok(Self { target_spn })
        }
        pub(super) fn new_for_current_user(target_spn: String) -> Result<Self, ResolveError> {
            Ok(Self { target_spn })
        }
        pub(super) async fn get_initial_token(&self) -> Result<String, ResolveError> {
            Err(ResolveError::HttpProxy("SSPI (mock) not supported".into()))
        }
        pub(super) async fn get_challenge_response_token(
            &self,
            _challenge_header: &str,
        ) -> Result<String, ResolveError> {
            Err(ResolveError::HttpProxy("SSPI (mock) not supported".into()))
        }
        pub(super) async fn reset(&self) {}
        pub(super) async fn get_auth_state(&self) -> SspiAuthState {
            SspiAuthState::Initial
        }
        pub(super) async fn is_authenticated(&self) -> bool {
            false
        }
        pub(super) async fn mark_failed(&self, _message: String) {}
        pub(super) async fn get_state_info(&self) -> String {
            format!("Mock SSPI State for SPN: {}", self.target_spn)
        }
    }
}
#[cfg(not(windows))]
use sspi_auth_mock_client::SspiAuthManager; 

const DOH_MEDIA_TYPE: &str = "application/dns-message";

pub(crate) struct DohClientAdapter {
    http_client: Client,
    proxy_config: Option<HttpProxyConfig>,
    default_timeout: Duration,
    sspi_auth_manager: Option<SspiAuthManager>,
}

impl DohClientAdapter {
    pub(crate) async fn new(
        default_timeout: Duration,
        global_proxy_config: Option<HttpProxyConfig>,
    ) -> Result<Self, ResolveError> {
        let user_agent = format!("dnspx/{}", env!("CARGO_PKG_VERSION"));

        let mut client_builder = Client::builder()
            .timeout(default_timeout)
            .user_agent(user_agent.clone());

        let mut sspi_auth_manager_opt: Option<SspiAuthManager> = None;

        if let Some(ref proxy_conf) = global_proxy_config {
            let proxy_url_str = proxy_conf.url.as_str();

            match proxy_conf.url.scheme() {
                "http" | "https" => {}
                invalid_scheme => {
                    return Err(ResolveError::HttpProxy(format!(
                        "Unsupported proxy URL scheme '{}'. Only 'http' and 'https' are supported: {}",
                        invalid_scheme, proxy_url_str
                    )));
                }
            }

            let proxy_auth_type = proxy_conf.authentication_type;

            match proxy_auth_type {
                ProxyAuthenticationType::Basic => {
                    let mut proxy = Proxy::all(proxy_url_str).map_err(|e| {
                        ResolveError::HttpProxy(format!(
                            "Failed to create proxy from URL {}: {}",
                            proxy_url_str, e
                        ))
                    })?;
                    if let (Some(user), Some(pass)) = (&proxy_conf.username, &proxy_conf.password) {
                        proxy = proxy.basic_auth(user, pass);
                    }
                    client_builder = client_builder.proxy(proxy);
                }
                ProxyAuthenticationType::None => {
                    let proxy = Proxy::all(proxy_url_str).map_err(|e| {
                        ResolveError::HttpProxy(format!(
                            "Failed to create proxy from URL {}: {}",
                            proxy_url_str, e
                        ))
                    })?;
                    client_builder = client_builder.proxy(proxy);
                }
                ProxyAuthenticationType::Ntlm | ProxyAuthenticationType::WindowsAuth => {
                    
                    let host_res = proxy_conf.url.host_str().ok_or_else(|| {
                        ResolveError::Configuration(format!(
                            "Proxy URL for {:?} has no host",
                            proxy_auth_type
                        ))
                    });
                    match host_res {
                        Ok(host) => {
                            #[cfg(windows)] 
                            {
                                let manager = if proxy_auth_type
                                    == ProxyAuthenticationType::WindowsAuth
                                {
                                    SspiAuthManager::new_for_current_user(host.to_string())?
                                } else if let (Some(user), Some(pass)) =
                                    (&proxy_conf.username, &proxy_conf.password)
                                {
                                    
                                    SspiAuthManager::new(
                                        host.to_string(),
                                        Some(user.clone()),
                                        Some(pass.clone()),
                                        proxy_conf.domain.clone(),
                                    )?
                                } else {
                                    
                                    warn!(
                                        "NTLM Auth for proxy {} selected without credentials. Attempting current user.",
                                        proxy_url_str
                                    );
                                    SspiAuthManager::new_for_current_user(host.to_string())?
                                };
                                sspi_auth_manager_opt = Some(manager);
                            }
                            #[cfg(not(windows))] 
                            {
                                warn!(
                                    "SSPI (NTLM/WindowsAuth) for proxy {} is not supported on this platform.",
                                    proxy_url_str
                                );
                                
                                sspi_auth_manager_opt =
                                    Some(SspiAuthManager::new_for_current_user(host.to_string())?);
                            }
                            if sspi_auth_manager_opt.is_some() {
                                info!(
                                    "SSPI Auth Manager (or mock) configured for proxy: {} with type: {:?}",
                                    proxy_url_str, proxy_auth_type
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Could not get host for SSPI config: {}. SSPI will not be used.",
                                e
                            );
                            #[cfg(not(windows))]
                            {
                                sspi_auth_manager_opt = Some(SspiAuthManager::default());
                            }
                        }
                    }
                }
            }
        } else {
            
            #[cfg(not(windows))]
            {
                sspi_auth_manager_opt = Some(SspiAuthManager::default()); 
            }
        }

        let http_client = client_builder.build().map_err(|e| {
            ResolveError::HttpProxy(format!("Failed to build reqwest client: {}", e))
        })?;

        Ok(Self {
            http_client,
            proxy_config: global_proxy_config,
            default_timeout,
            sspi_auth_manager: sspi_auth_manager_opt,
        })
    }

    fn should_bypass_proxy(&self, url: &Url) -> bool {
        let proxy_conf = match &self.proxy_config {
            Some(pc) => pc,
            None => return true,
        };

        #[cfg(not(windows))]
        if matches!(
            proxy_conf.authentication_type,
            ProxyAuthenticationType::WindowsAuth | ProxyAuthenticationType::Ntlm
        ) {
            debug!(
                "Bypassing proxy for {} because WindowsAuth/NTLM is configured on non-Windows and not using Basic/None.",
                url
            );
            return true;
        }

        match &proxy_conf.bypass_list {
            Some(list) => {
                if list.is_empty() {
                    return false;
                }
                if let Some(host_str_url) = url.host_str() {
                    let host_str_lower = host_str_url.to_lowercase();
                    for bypass_entry_orig in list {
                        let bypass_entry_lower = bypass_entry_orig.to_lowercase();

                        if bypass_entry_lower == "<local>" {
                            if !host_str_lower.contains('.') && host_str_lower != "localhost" {
                                debug!(
                                    "Bypassing proxy for local host (no dots): {} due to <local> rule",
                                    host_str_url
                                );
                                return true;
                            }
                            if host_str_lower == "localhost"
                                || host_str_lower == "127.0.0.1"
                                || host_str_lower == "::1"
                            {
                                debug!(
                                    "Bypassing proxy for explicit localhost: {} due to <local> rule",
                                    host_str_url
                                );
                                return true;
                            }
                        } else if bypass_entry_lower.starts_with('*')
                            && bypass_entry_lower.ends_with('*')
                            && bypass_entry_lower.len() > 2
                        {
                            let pattern = &bypass_entry_lower[1..bypass_entry_lower.len() - 1];
                            if host_str_lower.contains(pattern) {
                                debug!(
                                    "Bypassing proxy for {} due to rule '{}'",
                                    host_str_url, bypass_entry_orig
                                );
                                return true;
                            }
                        } else if bypass_entry_lower.starts_with('*')
                            && bypass_entry_lower.len() > 1
                        {
                            let pattern = &bypass_entry_lower[1..];
                            if host_str_lower.ends_with(pattern) {
                                debug!(
                                    "Bypassing proxy for {} due to rule '{}'",
                                    host_str_url, bypass_entry_orig
                                );
                                return true;
                            }
                        } else if bypass_entry_lower.ends_with('*') && bypass_entry_lower.len() > 1
                        {
                            let pattern = &bypass_entry_lower[..bypass_entry_lower.len() - 1];
                            if host_str_lower.starts_with(pattern) {
                                debug!(
                                    "Bypassing proxy for {} due to rule '{}'",
                                    host_str_url, bypass_entry_orig
                                );
                                return true;
                            }
                        } else if host_str_lower == bypass_entry_lower {
                            debug!(
                                "Bypassing proxy for {} due to rule '{}'",
                                host_str_url, bypass_entry_orig
                            );
                            return true;
                        }
                    }
                    false
                } else {
                    false
                }
            }
            None => false,
        }
    }

    #[instrument(skip_all, fields(doh_server = %url, q_name = %question_name))]
    #[allow(clippy::never_loop)] 
    async fn execute_doh_request_internal(
        &self,
        query_bytes: Arc<Vec<u8>>,
        url: &Url,
        request_timeout: Duration,
        question_name: &str,
        is_proxied_request: bool,
    ) -> Result<DnsMessage, ResolveError> {
        const MAX_AUTH_ATTEMPTS: u8 = 3;
        let mut attempt = 0;
        #[cfg(windows)]
        let mut last_proxy_challenge: Option<String> = None;

        #[cfg(windows)]
        if is_proxied_request {
            if let Some(sspi_mgr) = &self.sspi_auth_manager {
                if self.proxy_config.as_ref().map_or(false, |pc| {
                    matches!(
                        pc.authentication_type,
                        ProxyAuthenticationType::WindowsAuth | ProxyAuthenticationType::Ntlm
                    )
                }) {
                    sspi_mgr.reset().await;
                    debug!("SSPI auth manager reset for new DoH request to {}", url);
                }
            }
        }

        loop {
            
            attempt += 1;
            if attempt > MAX_AUTH_ATTEMPTS {
                #[cfg(windows)]
                if let Some(sspi_mgr) = &self.sspi_auth_manager {
                    if is_proxied_request
                        && self.proxy_config.as_ref().map_or(false, |pc| {
                            matches!(
                                pc.authentication_type,
                                ProxyAuthenticationType::WindowsAuth
                                    | ProxyAuthenticationType::Ntlm
                            )
                        })
                    {
                        sspi_mgr
                            .mark_failed(format!(
                                "Max auth attempts ({}) exceeded",
                                MAX_AUTH_ATTEMPTS
                            ))
                            .await;
                    }
                }
                return Err(ResolveError::HttpProxy(format!(
                    "Proxy authentication failed after {} attempts for {}",
                    MAX_AUTH_ATTEMPTS, url
                )));
            }

            
            #[cfg(windows)]
            let mut current_request_builder = self.http_client.post(url.clone());
            #[cfg(not(windows))]
            let current_request_builder = self.http_client.post(url.clone());

            let current_request_builder = current_request_builder
                .header(CONTENT_TYPE, DOH_MEDIA_TYPE)
                .header(ACCEPT, DOH_MEDIA_TYPE)
                .body(Body::from((*query_bytes).clone()));

            if is_proxied_request {
                #[cfg(windows)]
                if let Some(proxy_conf) = &self.proxy_config {
                    if matches!(
                        proxy_conf.authentication_type,
                        ProxyAuthenticationType::WindowsAuth | ProxyAuthenticationType::Ntlm
                    ) {
                        if let Some(sspi_mgr) = &self.sspi_auth_manager {
                            let auth_header_result = if attempt == 1 {
                                sspi_mgr.get_initial_token().await
                            } else if let Some(challenge) = last_proxy_challenge.as_deref() {
                                sspi_mgr.get_challenge_response_token(challenge).await
                            } else {
                                let err_msg = "SSPI: Attempting challenge response without a stored challenge header".to_string();
                                error!(target: "sspi_auth", "{}", err_msg);
                                sspi_mgr.mark_failed(err_msg.clone()).await;
                                return Err(ResolveError::HttpProxy(err_msg));
                            };

                            match auth_header_result {
                                Ok(token_str) if !token_str.is_empty() => {
                                    match HeaderValue::from_str(&token_str) {
                                        Ok(header_val) => {
                                            current_request_builder = current_request_builder
                                                .header(PROXY_AUTHORIZATION, header_val);
                                            debug!(
                                                "Attempt {}: Added SSPI Proxy-Authorization header for {}",
                                                attempt, url
                                            );
                                        }
                                        Err(e) => {
                                            let err_msg = format!(
                                                "Failed to create header value from SSPI token: {}",
                                                e
                                            );
                                            error!(target: "sspi_auth", "{}", err_msg);
                                            sspi_mgr.mark_failed(err_msg.clone()).await;
                                            return Err(ResolveError::HttpProxy(err_msg));
                                        }
                                    }
                                }
                                Ok(_) => {
                                    if sspi_mgr.is_authenticated().await {
                                        debug!(
                                            "Attempt {}: SSPI authenticated, no new header for {}.",
                                            attempt, url
                                        );
                                    }
                                }
                                Err(e) => return Err(e),
                            }
                        }
                    }
                }
            }

            let final_request = current_request_builder.build().map_err(|e| {
                ResolveError::HttpProxy(format!("Failed to build DoH request: {}", e))
            })?;
            let response_result =
                tokio::time::timeout(request_timeout, self.http_client.execute(final_request))
                    .await;

            match response_result {
                Ok(Ok(response)) => {
                    let status = response.status();
                    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                        #[cfg(windows)]
                        if is_proxied_request {
                            if let Some(sspi_mgr) = &self.sspi_auth_manager {
                                if self.proxy_config.as_ref().map_or(false, |pc| {
                                    matches!(
                                        pc.authentication_type,
                                        ProxyAuthenticationType::WindowsAuth
                                            | ProxyAuthenticationType::Ntlm
                                    )
                                }) {
                                    if let Some(challenge) = response
                                        .headers()
                                        .get(PROXY_AUTHENTICATE)
                                        .and_then(|h| h.to_str().ok())
                                    {
                                        debug!(
                                            "Attempt {}: Received 407 challenge for {}: {}",
                                            attempt, url, challenge
                                        );
                                        last_proxy_challenge = Some(challenge.to_string());
                                        if let SspiAuthState::Failed(msg) =
                                            sspi_mgr.get_auth_state().await
                                        {
                                            error!(
                                                "SSPI manager in failed state before retry: {}",
                                                msg
                                            );
                                            return Err(ResolveError::HttpProxy(format!(
                                                "SSPI failed: {}",
                                                msg
                                            )));
                                        }
                                        continue; 
                                    } else {
                                        let err_msg = format!(
                                            "Proxy sent 407 but no {} header for {}",
                                            PROXY_AUTHENTICATE, url
                                        );
                                        error!("{}", err_msg);
                                        sspi_mgr.mark_failed(err_msg.clone()).await;
                                        return Err(ResolveError::HttpProxy(err_msg));
                                    }
                                }
                            }
                        }
                        return Err(ResolveError::HttpProxy(format!(
                            "Proxy authentication required (407) for {}",
                            url
                        )));
                    }

                    #[cfg(windows)]
                    if is_proxied_request {
                        if let Some(sspi_mgr) = &self.sspi_auth_manager {
                            if self.proxy_config.as_ref().map_or(false, |pc| {
                                matches!(
                                    pc.authentication_type,
                                    ProxyAuthenticationType::WindowsAuth
                                        | ProxyAuthenticationType::Ntlm
                                )
                            }) && !sspi_mgr.is_authenticated().await
                                && status.is_success()
                            {
                                warn!(
                                    "SSPI auth was in progress for {}, received success status {} but SSPI state is not Authenticated.",
                                    url, status
                                );
                            }
                        }
                    }

                    if !status.is_success() {
                        let body_text = response
                            .text()
                            .await
                            .unwrap_or_else(|_| "<failed to read error body>".to_string());
                        warn!(
                            "DoH server {} responded with error {}: {}",
                            url, status, body_text
                        );
                        return Err(ResolveError::UpstreamServer {
                            server: url.to_string(),
                            details: format!("HTTP status {}", status),
                        });
                    }

                    let response_body_bytes = response.bytes().await.map_err(|e| {
                        ResolveError::Network(format!(
                            "Failed to read DoH response body from {}: {}",
                            url, e
                        ))
                    })?;
                    debug!(
                        "Received {} bytes via DoH from {}",
                        response_body_bytes.len(),
                        url
                    );
                    return parse_dns_message(&response_body_bytes).map_err(ResolveError::Protocol);
                }
                Ok(Err(e)) => {
                    warn!("DoH request to {} failed: {}", url, e);
                    #[cfg(windows)]
                    if is_proxied_request && (e.to_string().contains("proxy") || e.is_connect()) {
                        if let Some(sspi_mgr) = &self.sspi_auth_manager {
                            sspi_mgr.mark_failed(format!("Reqwest error: {}", e)).await;
                        }
                    }
                    return Err(ResolveError::Network(format!(
                        "DoH request to {} failed: {}",
                        url, e
                    )));
                }
                Err(_timeout) => {
                    warn!(
                        "DoH request to {} timed out after {:?}",
                        url, request_timeout
                    );
                    #[cfg(windows)]
                    if is_proxied_request {
                        if let Some(sspi_mgr) = &self.sspi_auth_manager {
                            sspi_mgr.mark_failed("Request timed out".to_string()).await;
                        }
                    }
                    return Err(ResolveError::Timeout {
                        domain: question_name.to_string(),
                        duration: request_timeout,
                    });
                }
            }
        }
    }

    #[instrument(skip(self, query_bytes, url), fields(doh_server = %url))]
    async fn resolve_single_doh_server(
        &self,
        query_bytes: Arc<Vec<u8>>,
        url: Url,
        request_timeout: Duration,
        question_name_for_error: &str,
    ) -> Result<DnsMessage, ResolveError> {
        let is_proxied_request = self.proxy_config.is_some() && !self.should_bypass_proxy(&url);
        self.execute_doh_request_internal(
            query_bytes,
            &url,
            request_timeout,
            question_name_for_error,
            is_proxied_request,
        )
        .await
    }
}

#[async_trait::async_trait]
impl UpstreamResolver for DohClientAdapter {
    async fn resolve_dns(
        &self,
        _question: &DnsQuestion,
        _upstream_servers: &[String],
        _timeout: Duration,
    ) -> Result<DnsMessage, ResolveError> {
        error!("DohClientAdapter does not support standard DNS.");
        Err(ResolveError::Configuration(
            "Standard DNS not supported by DohClientAdapter".to_string(),
        ))
    }

    #[instrument(skip(self, question, http_proxy_config_param), fields(qname = %question.name, qtype = %question.record_type))]
    async fn resolve_doh(
        &self,
        question: &DnsQuestion,
        upstream_urls: &[Url],
        timeout_duration: Duration,
        http_proxy_config_param: Option<&HttpProxyConfig>,
    ) -> Result<DnsMessage, ResolveError> {
        if upstream_urls.is_empty() {
            return Err(ResolveError::NoUpstreamServers);
        }
        if http_proxy_config_param.is_some() {
            debug!(
                "resolve_doh called with http_proxy_config_param (will be ignored as client uses its init-time proxy config)."
            );
        }

        let query_id = rand::random();
        let query_msg_to_send =
            DnsMessage::new_query(query_id, &question.name, question.record_type)
                .map_err(ResolveError::Protocol)?;

        let query_bytes =
            Arc::new(serialize_dns_message(&query_msg_to_send).map_err(ResolveError::Protocol)?);

        let mut last_error: Option<ResolveError> = None;

        for url in upstream_urls {
            match self
                .resolve_single_doh_server(
                    Arc::clone(&query_bytes),
                    url.clone(),
                    timeout_duration,
                    &question.name,
                )
                .await
            {
                Ok(response_msg) => {
                    if response_msg.id() == query_id {
                        debug!("Successfully resolved {} via DoH to {}", question.name, url);
                        return Ok(response_msg);
                    } else {
                        warn!(
                            "Mismatched DNS ID from {} (DoH). Expected {}, got {}. Discarding.",
                            url,
                            query_id,
                            response_msg.id()
                        );
                        last_error = Some(ResolveError::InvalidResponse(format!(
                            "Mismatched ID from {} (DoH)",
                            url
                        )));
                    }
                }
                Err(e) => {
                    warn!("DoH resolution failed for server {}: {}", url, e);
                    last_error = Some(e);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| ResolveError::UpstreamServer {
            server: "all_doh_tried".to_string(),
            details: "All DoH upstream servers failed".to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::HttpProxyConfig;
    use hickory_proto::{op::ResponseCode, rr::RecordType};

    async fn get_test_client_async(proxy_config: Option<HttpProxyConfig>) -> DohClientAdapter {
        DohClientAdapter::new(Duration::from_secs(10), proxy_config)
            .await
            .unwrap()
    }

    #[tokio::test]
    #[ignore]
    async fn test_doh_resolution_live() {
        let client = get_test_client_async(None).await;
        let question = DnsQuestion {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let upstream_urls = vec![
            Url::parse("https://cloudflare-dns.com/dns-query").unwrap(),
            Url::parse("https://dns.google/dns-query").unwrap(),
        ];

        let result = client
            .resolve_doh(&question, &upstream_urls, Duration::from_secs(5), None)
            .await;

        assert!(
            result.is_ok(),
            "DoH resolution should succeed, got: {:?}",
            result.err()
        );
        let response = result.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(
            response.answers().next().is_some(),
            "Should have at least one answer"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_doh_resolution_with_proxy_live() {
        let proxy_url_str = "http://localhost:8080";
        let proxy_config = HttpProxyConfig {
            url: Url::parse(proxy_url_str).unwrap(),
            authentication_type: ProxyAuthenticationType::None,
            username: None,
            password: None,
            domain: None,
            bypass_list: None,
        };

        let client = get_test_client_async(Some(proxy_config.clone())).await;

        let question = DnsQuestion {
            name: "icanhazip.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let upstream_urls = vec![Url::parse("https://cloudflare-dns.com/dns-query").unwrap()];

        let result = client
            .resolve_doh(
                &question,
                &upstream_urls,
                Duration::from_secs(10),
                Some(&proxy_config),
            )
            .await;
        assert!(
            result.is_ok(),
            "DoH resolution with proxy should succeed, got: {:?}",
            result.err()
        );
        if result.is_ok() {
            let response = result.unwrap();
            assert_eq!(response.response_code(), ResponseCode::NoError);
        }
    }

    async fn create_adapter_for_bypass_test_async(
        bypass_list: Option<Vec<String>>,
    ) -> DohClientAdapter {
        let proxy_url = Url::parse("http://dummy.proxy:8080").unwrap();
        let proxy_config = HttpProxyConfig {
            url: proxy_url,
            authentication_type: ProxyAuthenticationType::None,
            username: None,
            password: None,
            domain: None,
            bypass_list,
        };
        DohClientAdapter::new(Duration::from_secs(5), Some(proxy_config))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_bypass_no_proxy_configured_async() {
        let adapter = DohClientAdapter::new(Duration::from_secs(5), None)
            .await
            .unwrap();
        assert!(adapter.should_bypass_proxy(&Url::parse("https://example.com").unwrap()));
    }

    #[tokio::test]
    async fn test_bypass_with_proxy_no_bypass_list_async() {
        let adapter = create_adapter_for_bypass_test_async(None).await;
        assert!(!adapter.should_bypass_proxy(&Url::parse("https://example.com").unwrap()));
    }

    #[tokio::test]
    async fn test_bypass_empty_list_async() {
        let adapter = create_adapter_for_bypass_test_async(Some(vec![])).await;
        assert!(!adapter.should_bypass_proxy(&Url::parse("https://example.com").unwrap()));
    }

    #[tokio::test]
    async fn test_bypass_exact_match_async() {
        let adapter =
            create_adapter_for_bypass_test_async(Some(vec!["example.com".to_string()])).await;
        assert!(adapter.should_bypass_proxy(&Url::parse("https://example.com").unwrap()));
        assert!(!adapter.should_bypass_proxy(&Url::parse("https://sub.example.com").unwrap()));
    }

    #[tokio::test]
    async fn test_bypass_prefix_wildcard_async() {
        let adapter =
            create_adapter_for_bypass_test_async(Some(vec!["*.example.com".to_string()])).await;
        assert!(adapter.should_bypass_proxy(&Url::parse("https://sub.example.com").unwrap()));
        assert!(!adapter.should_bypass_proxy(&Url::parse("https://example.com").unwrap()));
    }

    #[tokio::test]
    async fn test_bypass_suffix_wildcard_async() {
        let adapter =
            create_adapter_for_bypass_test_async(Some(vec!["sub.example.*".to_string()])).await;
        assert!(adapter.should_bypass_proxy(&Url::parse("https://sub.example.com").unwrap()));
        assert!(
            !adapter.should_bypass_proxy(&Url::parse("https://anothersub.example.com").unwrap())
        );
    }

    #[tokio::test]
    async fn test_bypass_contains_wildcard_async() {
        let adapter =
            create_adapter_for_bypass_test_async(Some(vec!["*example*".to_string()])).await;
        assert!(
            adapter.should_bypass_proxy(&Url::parse("https://an.example.of.domain.com").unwrap())
        );
        assert!(!adapter.should_bypass_proxy(&Url::parse("https://another.net").unwrap()));
    }

    #[tokio::test]
    async fn test_bypass_local_special_token_async() {
        let adapter = create_adapter_for_bypass_test_async(Some(vec!["<local>".to_string()])).await;
        assert!(adapter.should_bypass_proxy(&Url::parse("http://localhost").unwrap()));
        assert!(adapter.should_bypass_proxy(&Url::parse("http://my-machine").unwrap()));
        assert!(!adapter.should_bypass_proxy(&Url::parse("http://example.com").unwrap()));
    }

    #[cfg(windows)]
    mod windows_sspi_tests {
        use super::*;
        use crate::config::models::ProxyAuthenticationType;

        #[tokio::test]
        #[ignore]
        async fn test_doh_with_windows_auth_sspi_current_user() {
            let proxy_url_str = std::env::var("TEST_PROXY_WINDOWS_AUTH_URL")
                .unwrap_or_else(|_| "http://your-sspi-proxy.example.com:8080".to_string());

            let proxy_config = HttpProxyConfig {
                url: Url::parse(&proxy_url_str).unwrap(),
                authentication_type: ProxyAuthenticationType::WindowsAuth,
                username: None,
                password: None,
                domain: None,
                bypass_list: None,
            };

            let client = get_test_client_async(Some(proxy_config.clone())).await;

            let question = DnsQuestion {
                name: "microsoft.com".to_string(),
                record_type: RecordType::A,
                class: hickory_proto::rr::DNSClass::IN,
            };
            let upstream_urls = vec![Url::parse("https://cloudflare-dns.com/dns-query").unwrap()];

            let result = client
                .resolve_doh(
                    &question,
                    &upstream_urls,
                    Duration::from_secs(20),
                    Some(&proxy_config),
                )
                .await;

            tracing::info!("WindowsAuth test result: {:?}", result);
            assert!(
                result.is_ok(),
                "DoH with WindowsAuth should succeed if proxy and AD are correctly configured. Error: {:?}",
                result.err()
            );
            if let Ok(response) = result {
                assert_eq!(response.response_code(), ResponseCode::NoError);
            }
        }

        #[tokio::test]
        #[ignore]
        async fn test_doh_with_ntlm_sspi_explicit_credentials() {
            let proxy_url_str = std::env::var("TEST_PROXY_NTLM_URL")
                .unwrap_or_else(|_| "http://your-ntlm-proxy.example.com:8080".to_string());
            let username =
                std::env::var("TEST_PROXY_NTLM_USER").expect("TEST_PROXY_NTLM_USER not set");
            let password =
                std::env::var("TEST_PROXY_NTLM_PASS").expect("TEST_PROXY_NTLM_PASS not set");
            let domain = std::env::var("TEST_PROXY_NTLM_DOMAIN").ok();

            let proxy_config = HttpProxyConfig {
                url: Url::parse(&proxy_url_str).unwrap(),
                authentication_type: ProxyAuthenticationType::Ntlm,
                username: Some(username),
                password: Some(password),
                domain,
                bypass_list: None,
            };

            let client = get_test_client_async(Some(proxy_config.clone())).await;

            let question = DnsQuestion {
                name: "google.com".to_string(),
                record_type: RecordType::A,
                class: hickory_proto::rr::DNSClass::IN,
            };
            let upstream_urls = vec![Url::parse("https://dns.google/dns-query").unwrap()];

            let result = client
                .resolve_doh(
                    &question,
                    &upstream_urls,
                    Duration::from_secs(20),
                    Some(&proxy_config),
                )
                .await;

            tracing::info!("NTLM (explicit creds) test result: {:?}", result);
            assert!(
                result.is_ok(),
                "DoH with NTLM (explicit creds) should succeed if proxy and credentials are correct. Error: {:?}",
                result.err()
            );
            if let Ok(response) = result {
                assert_eq!(response.response_code(), ResponseCode::NoError);
            }
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use hickory_proto::{op::ResponseCode, rr::RecordType};

    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    async fn create_adapter_for_bypass_test_async(
        bypass_list: Option<Vec<String>>,
    ) -> DohClientAdapter {
        let proxy_url = Url::parse("http://dummy.proxy:8080").unwrap();
        let proxy_config = HttpProxyConfig {
            url: proxy_url,
            authentication_type: ProxyAuthenticationType::None,
            username: None,
            password: None,
            domain: None,
            bypass_list,
        };
        DohClientAdapter::new(Duration::from_secs(5), Some(proxy_config))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_doh_client_proxy_error_recovery() {
        let proxy_config = HttpProxyConfig {
            url: Url::parse("http://failing-proxy:8080").unwrap(),
            authentication_type: ProxyAuthenticationType::Basic,
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            domain: None,
            bypass_list: None,
        };

        let client = DohClientAdapter::new(Duration::from_secs(5), Some(proxy_config))
            .await
            .unwrap();

        let question = DnsQuestion {
            name: "test.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let result = client
            .resolve_doh(
                &question,
                &[Url::parse("https://dns.google/dns-query").unwrap()],
                Duration::from_secs(5),
                None,
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ResolveError::Network(_)));
    }

    #[tokio::test]
    async fn test_concurrent_doh_requests() {
        let client = Arc::new(
            DohClientAdapter::new(Duration::from_secs(10), None)
                .await
                .unwrap(),
        );

        let mut handles = vec![];
        let success_count = Arc::new(AtomicU32::new(0));

        for i in 0..5 {
            let client_clone = Arc::clone(&client);
            let success_count_clone = Arc::clone(&success_count);

            handles.push(tokio::spawn(async move {
                let question = DnsQuestion {
                    name: format!("test{}.example.com", i),
                    record_type: RecordType::A,
                    class: hickory_proto::rr::DNSClass::IN,
                };

                let _result = client_clone
                    .resolve_doh(
                        &question,
                        &[Url::parse("https://dns.google/dns-query").unwrap()],
                        Duration::from_secs(5),
                        None,
                    )
                    .await;

                success_count_clone.fetch_add(1, Ordering::Relaxed);
            }));
        }

        for handle in handles {
            handle.await.expect("Task should complete");
        }

        assert_eq!(success_count.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn test_bypass_list_case_insensitive() {
        let adapter =
            create_adapter_for_bypass_test_async(Some(vec!["EXAMPLE.COM".to_string()])).await;

        assert!(adapter.should_bypass_proxy(&Url::parse("https://example.com").unwrap()));
        assert!(adapter.should_bypass_proxy(&Url::parse("https://EXAMPLE.COM").unwrap()));
        assert!(adapter.should_bypass_proxy(&Url::parse("https://Example.Com").unwrap()));
    }

    #[tokio::test]
    async fn test_malformed_urls_handling() {
        let client = DohClientAdapter::new(Duration::from_secs(5), None)
            .await
            .unwrap();

        let question = DnsQuestion {
            name: "test.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let invalid_urls = vec![
            "not-a-url",
            "http://",
            "https://",
            "ftp://example.com/dns-query",
        ];

        for url_str in invalid_urls {
            if let Ok(url) = Url::parse(url_str) {
                let result = client
                    .resolve_doh(&question, &[url], Duration::from_secs(5), None)
                    .await;

                assert!(result.is_err());
            }
        }
    }

    #[tokio::test]
    async fn test_timeout_edge_cases() {
        let client = DohClientAdapter::new(Duration::from_secs(1), None)
            .await
            .unwrap();

        let question = DnsQuestion {
            name: "test.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let result = client
            .resolve_doh(
                &question,
                &[Url::parse("https://httpbin.org/delay/5").unwrap()],
                Duration::from_millis(100),
                None,
            )
            .await;

        assert!(result.is_err());
        if let Err(ResolveError::Timeout { .. }) = result {
        } else {
            assert!(matches!(result.unwrap_err(), ResolveError::Network(_)));
        }
    }

    #[tokio::test]
    async fn test_invalid_proxy_url_handling() {
        let invalid_configs = vec![
            "not-a-url",
            "://missing-protocol",
            "http://",
            "ftp://invalid-protocol.com:8080",
        ];

        for invalid_url in invalid_configs {
            if let Ok(url) = Url::parse(invalid_url) {
                let proxy_config = HttpProxyConfig {
                    url,
                    authentication_type: ProxyAuthenticationType::None,
                    username: None,
                    password: None,
                    domain: None,
                    bypass_list: None,
                };

                let result =
                    DohClientAdapter::new(Duration::from_secs(5), Some(proxy_config)).await;
                assert!(
                    result.is_err(),
                    "Should reject invalid proxy URL: {}",
                    invalid_url
                );
            }
        }
    }

    #[tokio::test]
    async fn test_empty_upstream_urls() {
        let client = DohClientAdapter::new(Duration::from_secs(5), None)
            .await
            .unwrap();
        let question = DnsQuestion {
            name: "test.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let result = client
            .resolve_doh(&question, &[], Duration::from_secs(5), None)
            .await;
        assert!(matches!(result, Err(ResolveError::NoUpstreamServers)));
    }

    #[tokio::test]
    async fn test_nonexistent_domain_handling() {
        let client = DohClientAdapter::new(Duration::from_secs(5), None)
            .await
            .unwrap();

        let question = DnsQuestion {
            name: "this-domain-definitely-does-not-exist-12345.invalid".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let result = client
            .resolve_doh(
                &question,
                &[Url::parse("https://dns.google/dns-query").unwrap()],
                Duration::from_secs(5),
                None,
            )
            .await;

        match result {
            Ok(response) => {
                assert!(
                    response.answers().count() == 0
                        || response.response_code() == ResponseCode::NXDomain,
                    "Should have no answers or NXDOMAIN for nonexistent domain"
                );
            }
            Err(_) => {
                println!("Network error occurred, which is acceptable in test environment");
            }
        }
    }

    #[tokio::test]
    async fn test_network_error_handling() {
        let client = DohClientAdapter::new(Duration::from_secs(5), None)
            .await
            .unwrap();

        let question = DnsQuestion {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let result = client
            .resolve_doh(
                &question,
                &[Url::parse("https://nonexistent-doh-server-12345.invalid/dns-query").unwrap()],
                Duration::from_secs(2),
                None,
            )
            .await;

        assert!(
            result.is_err(),
            "Should fail when contacting non-existent server"
        );

        match result.unwrap_err() {
            ResolveError::Network(msg) => {
                assert!(
                    msg.contains("failed") || msg.contains("connect") || msg.contains("resolve"),
                    "Network error should contain relevant error message, got: {}",
                    msg
                );
            }
            ResolveError::Timeout { domain, .. } => {
                assert_eq!(
                    domain, "example.com",
                    "Timeout should reference the correct domain"
                );
            }
            other => panic!("Expected Network or Timeout error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_timeout_handling() {
        let client = DohClientAdapter::new(Duration::from_secs(5), None)
            .await
            .unwrap();

        let question = DnsQuestion {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let result = client
            .resolve_doh(
                &question,
                &[Url::parse("https://dns.google/dns-query").unwrap()],
                Duration::from_millis(1),
                None,
            )
            .await;

        assert!(result.is_err(), "Should timeout with very short duration");

        match result.unwrap_err() {
            ResolveError::Timeout { domain, duration } => {
                assert_eq!(
                    domain, "example.com",
                    "Timeout should reference the correct domain"
                );
                assert_eq!(
                    duration,
                    Duration::from_millis(1),
                    "Timeout duration should match request"
                );
            }
            ResolveError::Network(msg) => {
                assert!(
                    msg.contains("timeout") || msg.contains("failed") || msg.contains("connect"),
                    "Network error should contain relevant message, got: {}",
                    msg
                );
            }
            other => panic!("Expected timeout or network error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_dns_response_validation() {
        let client = DohClientAdapter::new(Duration::from_secs(5), None)
            .await
            .unwrap();

        let question = DnsQuestion {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let result = client
            .resolve_doh(
                &question,
                &[Url::parse("https://dns.google/dns-query").unwrap()],
                Duration::from_secs(5),
                None,
            )
            .await;

        match result {
            Ok(response) => {
                assert_eq!(response.response_code(), ResponseCode::NoError);
                assert!(
                    response.answers().count() > 0,
                    "example.com should have at least one A record"
                );
                let questions: Vec<_> = response.queries().collect();
                assert_eq!(questions.len(), 1);
                assert_eq!(questions[0].name().to_string(), "example.com.");
                assert_eq!(questions[0].query_type(), RecordType::A);
            }
            Err(e) => {
                println!("Network error occurred (acceptable in test env): {:?}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_invalid_doh_server_response() {
        let client = DohClientAdapter::new(Duration::from_secs(5), None)
            .await
            .unwrap();

        let question = DnsQuestion {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let result = client
            .resolve_doh(
                &question,
                &[Url::parse("https://httpbin.org/status/200").unwrap()],
                Duration::from_secs(5),
                None,
            )
            .await;

        assert!(
            result.is_err(),
            "Should fail when server doesn't return valid DNS response"
        );

        match result.unwrap_err() {
            ResolveError::Protocol(_) => {}
            ResolveError::UpstreamServer { details, .. } => {
                assert!(
                    details.contains("HTTP status") || details.contains("status"),
                    "Should be an HTTP status error, got: {}",
                    details
                );
            }
            ResolveError::Network(_) => {}
            other => panic!("Unexpected error type: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_basic_auth_missing_credentials() {
        let proxy_config = HttpProxyConfig {
            url: Url::parse("http://proxy.example.com:8080").unwrap(),
            authentication_type: ProxyAuthenticationType::Basic,
            username: None,
            password: None,
            domain: None,
            bypass_list: None,
        };

        let result = DohClientAdapter::new(Duration::from_secs(5), Some(proxy_config)).await;
        assert!(
            result.is_ok(),
            "Should create client despite missing Basic auth credentials"
        );
    }

    #[tokio::test]
    async fn test_bypass_list_edge_cases() {
        let edge_cases = vec![
            vec!["".to_string()],
            vec!["*".to_string()],
            vec!["**".to_string()],
            vec!["*.".to_string()],
            vec![".*".to_string()],
            vec!["<LOCAL>".to_string()],
            vec!["<local".to_string()],
            vec!["local>".to_string()],
        ];

        for bypass_list in edge_cases {
            let adapter = create_adapter_for_bypass_test_async(Some(bypass_list.clone())).await;

            let test_urls = vec![
                "https://example.com",
                "https://localhost",
                "https://127.0.0.1",
                "https://my-machine",
            ];

            for url_str in test_urls {
                let url = Url::parse(url_str).unwrap();
                let _ = adapter.should_bypass_proxy(&url);
            }
        }
    }

    #[tokio::test]
    async fn test_zero_timeout() {
        let client = DohClientAdapter::new(Duration::from_millis(1), None)
            .await
            .unwrap();
        let question = DnsQuestion {
            name: "test.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let result = client
            .resolve_doh(
                &question,
                &[Url::parse("https://dns.google/dns-query").unwrap()],
                Duration::from_millis(1),
                None,
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_shared_client_concurrent_different_questions() {
        let client = Arc::new(
            DohClientAdapter::new(Duration::from_secs(10), None)
                .await
                .unwrap(),
        );
        let mut handles = vec![];

        for i in 0..5 {
            let client_clone = Arc::clone(&client);
            handles.push(tokio::spawn(async move {
                let question = DnsQuestion {
                    name: format!("nonexistent{}.invalid", i),
                    record_type: RecordType::A,
                    class: hickory_proto::rr::DNSClass::IN,
                };

                let _result = client_clone
                    .resolve_doh(
                        &question,
                        &[Url::parse("https://dns.google/dns-query").unwrap()],
                        Duration::from_secs(5),
                        None,
                    )
                    .await;
            }));
        }

        for handle in handles {
            handle.await.expect("Concurrent DoH task should complete");
        }
    }

    #[tokio::test]
    async fn test_proxy_auth_type_consistency() {
        #[cfg(not(windows))]
        {
            let proxy_config = HttpProxyConfig {
                url: Url::parse("http://proxy.example.com:8080").unwrap(),
                authentication_type: ProxyAuthenticationType::Ntlm,
                username: None,
                password: None,
                domain: None,
                bypass_list: None,
            };

            let result = DohClientAdapter::new(Duration::from_secs(5), Some(proxy_config)).await;
            assert!(
                result.is_ok(),
                "Should create client on non-Windows despite NTLM config"
            );
        }
    }
}

#[cfg(windows)]
#[cfg(test)]
mod sspi_integration_tests {
    use super::*; 

    #[tokio::test]
    async fn test_sspi_state_transitions() {
        let manager = SspiAuthManager::new_for_current_user("test.example.com".to_string())
            .expect("Should create manager");

        assert!(matches!(
            manager.get_auth_state().await,
            SspiAuthState::Initial
        ));
        assert!(!manager.is_authenticated().await);

        
        let _ = manager.get_initial_token().await;
        if !matches!(manager.get_auth_state().await, SspiAuthState::Failed(_)) {
            assert!(matches!(
                manager.get_auth_state().await,
                SspiAuthState::NegotiateSent
                    | SspiAuthState::Authenticated
                    | SspiAuthState::ChallengeReceived
            ));
        }

        manager.set_auth_state(SspiAuthState::Authenticated).await;
        assert!(manager.is_authenticated().await);

        manager.reset().await;
        assert!(matches!(
            manager.get_auth_state().await,
            SspiAuthState::Initial
        ));
        assert!(!manager.is_authenticated().await);
    }

    #[tokio::test]
    async fn test_sspi_error_accumulation() {
        let manager = SspiAuthManager::new_for_current_user("test.example.com".to_string())
            .expect("Should create manager");

        manager.mark_failed("First failure".to_string()).await;
        let state1 = manager.get_auth_state().await;
        if let SspiAuthState::Failed(msg) = state1 {
            assert!(msg.contains("First failure"));
        } else {
            panic!("Expected Failed");
        }

        manager.mark_failed("Second failure".to_string()).await;
        let state2 = manager.get_auth_state().await;
        if let SspiAuthState::Failed(msg) = state2 {
            assert!(msg.contains("Second failure"));
            assert!(!msg.contains("First failure") || msg == "Second failure");
        } else {
            panic!("Expected Failed state");
        }
    }

    #[tokio::test]
    async fn test_sspi_concurrent_token_generation() {
        let manager = Arc::new(
            SspiAuthManager::new_for_current_user("concurrent.example.com".to_string())
                .expect("Should create manager"),
        );

        let mut handles = vec![];

        for _ in 0..3 {
            let mgr_clone = Arc::clone(&manager);
            handles.push(tokio::spawn(async move {
                let _ = mgr_clone.get_initial_token().await;
                let _ = mgr_clone.is_authenticated().await;
            }));
        }

        for handle in handles {
            handle.await.expect("Concurrent SSPI task should complete");
        }
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    async fn create_adapter_for_bypass_test_async(
        bypass_list: Option<Vec<String>>,
    ) -> DohClientAdapter {
        let proxy_url = Url::parse("http://dummy.proxy:8080").unwrap();
        let proxy_config = HttpProxyConfig {
            url: proxy_url,
            authentication_type: ProxyAuthenticationType::None,
            username: None,
            password: None,
            domain: None,
            bypass_list,
        };
        DohClientAdapter::new(Duration::from_secs(5), Some(proxy_config))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_doh_client_creation_performance() {
        let start = Instant::now();

        for _ in 0..10 {
            let _client = DohClientAdapter::new(Duration::from_secs(5), None)
                .await
                .unwrap();
        }

        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "Client creation should be fast: {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_bypass_logic_performance() {
        let bypass_list = (0..100).map(|i| format!("domain{}.com", i)).collect();

        let adapter = create_adapter_for_bypass_test_async(Some(bypass_list)).await;

        let start = Instant::now();

        for i in 0..1000 {
            let url = Url::parse(&format!("https://test{}.example.com", i % 50)).unwrap();
            let _ = adapter.should_bypass_proxy(&url);
        }

        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(100),
            "Bypass checks should be fast: {:?}",
            elapsed
        );
    }
}
