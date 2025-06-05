use crate::core::types::ProtocolType;
use crate::dns_protocol::{DnsMessage, DnsQuestion as AppDnsQuestion};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::Span;

#[derive(Debug)]
pub(crate) struct RequestContext {
    pub id: u16,
    pub query_message: Arc<DnsMessage>,
    pub client_addr: SocketAddr,
    pub protocol: ProtocolType,
    pub span: Span,
    pub timestamp: std::time::Instant,
}

impl RequestContext {
    pub(crate) fn new(
        query_message: Arc<DnsMessage>,
        client_addr: SocketAddr,
        protocol: ProtocolType,
    ) -> Self {
        let id = query_message.id();
        let query_name = query_message.queries().next().map_or_else(
            || "<no_query>".to_string(),
            |q| q.name().to_utf8().to_string(),
        );
        let query_type = query_message
            .queries()
            .next()
            .map_or_else(|| RecordType::NULL, |q| q.query_type());

        let span = tracing::info_span!(
            "dns_request",
            id,
            client = %client_addr,
            protocol = ?protocol,
            qname = %query_name,
            qtype = %query_type,
        );

        Self {
            id,
            query_message,
            client_addr,
            protocol,
            span,
            timestamp: std::time::Instant::now(),
        }
    }

    pub(crate) fn queries(&self) -> Vec<AppDnsQuestion> {
        self.query_message
            .queries()
            .map(AppDnsQuestion::from_hickory_query)
            .collect()
    }

    pub(crate) fn create_response(&self, response_code: ResponseCode) -> DnsMessage {
        DnsMessage::new_response(&self.query_message, response_code)
    }

    pub(crate) fn elapsed(&self) -> std::time::Duration {
        self.timestamp.elapsed()
    }
}
