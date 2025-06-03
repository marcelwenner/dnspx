use crate::adapters::resolver::doh_client::DohClientAdapter;
use crate::adapters::resolver::standard_dns_client::StandardDnsClient;
use crate::config::models::HttpProxyConfig;
use crate::core::error::ResolveError;
use crate::dns_protocol::{DnsMessage, DnsQuestion};
use crate::ports::UpstreamResolver;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

pub struct CompositeUpstreamResolver {
    std_dns_client: Arc<StandardDnsClient>,
    doh_client: Arc<DohClientAdapter>,
}

impl CompositeUpstreamResolver {
    pub fn new(std_dns_client: Arc<StandardDnsClient>, doh_client: Arc<DohClientAdapter>) -> Self {
        Self {
            std_dns_client,
            doh_client,
        }
    }
}

#[async_trait]
impl UpstreamResolver for CompositeUpstreamResolver {
    async fn resolve_dns(
        &self,
        question: &DnsQuestion,
        upstream_servers: &[String],
        timeout: Duration,
    ) -> Result<DnsMessage, ResolveError> {
        self.std_dns_client
            .resolve_dns(question, upstream_servers, timeout)
            .await
    }

    async fn resolve_doh(
        &self,
        question: &DnsQuestion,
        upstream_urls: &[Url],
        timeout: Duration,
        http_proxy_config: Option<&HttpProxyConfig>,
    ) -> Result<DnsMessage, ResolveError> {
        self.doh_client
            .resolve_doh(question, upstream_urls, timeout, http_proxy_config)
            .await
    }
}
