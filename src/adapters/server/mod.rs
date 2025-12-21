pub(crate) mod tcp_listener;
pub(crate) mod udp_listener;

use crate::config::models::AppConfig;
use crate::dns_protocol::{DnsMessage as AppDnsMessage, parse_dns_message, serialize_dns_message};
use hickory_proto::op::ResponseCode;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Check if a client IP is whitelisted according to the server configuration.
/// Returns true if no whitelist is configured (all clients allowed) or if the IP is in the whitelist.
pub(crate) async fn is_client_whitelisted(config: &Arc<RwLock<AppConfig>>, client_ip: IpAddr) -> bool {
    let guard = config.read().await;
    match &guard.server.network_whitelist {
        Some(list) => list.iter().any(|net| net.contains(client_ip)),
        None => true,
    }
}

/// Create an error DNS response from raw query bytes.
/// Returns None if the query cannot be parsed.
pub(crate) fn create_error_response(query_bytes: &[u8], response_code: ResponseCode) -> Option<Vec<u8>> {
    let query_msg = parse_dns_message(query_bytes).ok()?;
    let err_response = AppDnsMessage::new_response(&query_msg, response_code);
    serialize_dns_message(&err_response).ok()
}
