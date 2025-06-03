use crate::config::models::HttpProxyConfig;
use crate::core::error::ResolveError;
use crate::dns_protocol::{DnsMessage, DnsQuestion, parse_dns_message, serialize_dns_message};
use crate::ports::UpstreamResolver;
use reqwest::{
    Body, Client, Proxy,
    header::{ACCEPT, CONTENT_TYPE},
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, instrument, warn};
use url::Url;

const DOH_MEDIA_TYPE: &str = "application/dns-message";

pub struct DohClientAdapter {
    http_client: Client,
}

impl DohClientAdapter {
    pub fn new(
        default_timeout: Duration,
        global_proxy_config: Option<&HttpProxyConfig>,
    ) -> Result<Self, ResolveError> {
        let mut client_builder = Client::builder()
            .timeout(default_timeout)
            .user_agent(format!("dnspx/{}", env!("CARGO_PKG_VERSION")));

        if let Some(proxy_conf) = global_proxy_config {
            let proxy_url_str = proxy_conf.url.as_str();
            let mut proxy = Proxy::all(proxy_url_str).map_err(|e| {
                ResolveError::HttpProxy(format!("Invalid proxy URL '{}': {}", proxy_url_str, e))
            })?;

            if let (Some(user), Some(pass)) = (&proxy_conf.username, &proxy_conf.password) {
                proxy = proxy.basic_auth(user, pass);
            }
            client_builder = client_builder.proxy(proxy);
            debug!("DoH client configured with proxy: {}", proxy_url_str);
        } else {
            debug!("DoH client configured without proxy.");
        }

        let http_client = client_builder.build().map_err(|e| {
            ResolveError::HttpProxy(format!("Failed to build reqwest client: {}", e))
        })?;

        Ok(Self { http_client })
    }

    #[instrument(skip(self, query_bytes, url), fields(doh_server = %url))]
    async fn resolve_single_doh_server(
        &self,
        query_bytes: Arc<Vec<u8>>,
        url: Url,
        request_timeout: Duration,
        question_name_for_error: &str,
    ) -> Result<DnsMessage, ResolveError> {
        debug!("Resolving via DoH to {}", url);

        let request_body = Body::from((*query_bytes).clone());

        let http_response_result = timeout(
            request_timeout,
            self.http_client
                .post(url.clone())
                .header(CONTENT_TYPE, DOH_MEDIA_TYPE)
                .header(ACCEPT, DOH_MEDIA_TYPE)
                .body(request_body)
                .send(),
        )
        .await;

        let http_response = match http_response_result {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                warn!("DoH request to {} failed: {}", url, e);
                return Err(ResolveError::Network(format!(
                    "DoH request to {} failed: {}",
                    url, e
                )));
            }
            Err(_) => {
                warn!(
                    "DoH request to {} timed out after {:?}",
                    url, request_timeout
                );
                return Err(ResolveError::Timeout {
                    domain: question_name_for_error.to_string(),
                    duration: request_timeout,
                });
            }
        };

        if !http_response.status().is_success() {
            let status = http_response.status();
            let body_text = match http_response.text().await {
                Ok(text) => text,
                Err(e) => {
                    warn!("Failed to read DoH error response body from {}: {}", url, e);
                    String::from("<failed to read error response body>")
                }
            };
            warn!(
                "DoH server {} responded with error {}: {}",
                url, status, body_text
            );
            return Err(ResolveError::UpstreamServer {
                server: url.to_string(),
                details: format!("HTTP status {}", status),
            });
        }

        let response_body_bytes = http_response.bytes().await.map_err(|e| {
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

        parse_dns_message(&response_body_bytes).map_err(ResolveError::Protocol)
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
        error!(
            "DohClientAdapter does not support standard DNS. This method should not be called directly on it."
        );
        Err(ResolveError::Configuration(
            "Standard DNS not supported by DohClientAdapter".to_string(),
        ))
    }

    #[instrument(skip(self, question, _http_proxy_config_param), fields(qname = %question.name, qtype = %question.record_type))]
    async fn resolve_doh(
        &self,
        question: &DnsQuestion,
        upstream_urls: &[Url],
        timeout_duration: Duration,
        _http_proxy_config_param: Option<&HttpProxyConfig>,
    ) -> Result<DnsMessage, ResolveError> {
        if upstream_urls.is_empty() {
            return Err(ResolveError::NoUpstreamServers);
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
    use hickory_proto::{op::ResponseCode, rr::RecordType};

    fn get_test_client() -> DohClientAdapter {
        DohClientAdapter::new(Duration::from_secs(10), None).unwrap()
    }

    #[tokio::test]
    #[ignore]
    async fn test_doh_resolution_live() {
        let client = get_test_client();
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
            !response.answers().next().is_none(),
            "Should have at least one answer"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_doh_resolution_with_proxy_live() {
        let proxy_url_str = "http://localhost:8080";
        let proxy_config = HttpProxyConfig {
            url: Url::parse(proxy_url_str).unwrap(),
            username: None,
            password: None,
        };

        let client = DohClientAdapter::new(Duration::from_secs(10), Some(&proxy_config)).unwrap();

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
        let response = result.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }
}
