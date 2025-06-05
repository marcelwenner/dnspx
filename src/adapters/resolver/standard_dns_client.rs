use crate::config::models::HttpProxyConfig;
use crate::core::error::ResolveError;
use crate::dns_protocol::{DnsMessage, DnsQuestion, parse_dns_message, serialize_dns_message};
use crate::ports::UpstreamResolver;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::time::timeout;
use tracing::{debug, error, field, instrument, warn};
use url::Url;

pub(crate) struct StandardDnsClient;

impl StandardDnsClient {
    pub(crate) fn new() -> Self {
        Self
    }

    fn ensure_port(server_str: &str) -> String {
        if server_str.contains(':') {
            server_str.to_string()
        } else {
            format!("{server_str}:53")
        }
    }

    #[instrument(skip(self, query_bytes, server_str_with_port), fields(server = %server_str_with_port, operation_time_ms = field::Empty))]
    async fn resolve_udp_internal(
        &self,
        query_bytes: &[u8],
        server_str_with_port: &str,
        timeout_duration: Duration,
        question_name_for_error: &str,
    ) -> Result<Vec<u8>, ResolveError> {
        let overall_start = Instant::now();
        let span = tracing::Span::current();

        let lookup_start = Instant::now();
        let mut resolved_addrs = lookup_host(server_str_with_port).await.map_err(|e| {
            ResolveError::Network(format!(
                "DNS lookup failed for upstream server '{server_str_with_port}': {e}"
            ))
        })?;
        debug!(server = %server_str_with_port, elapsed_ms = lookup_start.elapsed().as_millis(), "Upstream server name lookup_host completed");

        let socket_addr = resolved_addrs.next().ok_or_else(|| {
            ResolveError::Configuration(format!(
                "Could not resolve server address to an IP: {server_str_with_port}"
            ))
        })?;
        debug!(server = %server_str_with_port, "Resolved upstream to IP: {}", socket_addr);

        let bind_start = Instant::now();
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| ResolveError::Network(format!("UDP bind failed: {e}")))?;
        debug!(server = %server_str_with_port, local_addr = ?socket.local_addr().ok(), elapsed_ms = bind_start.elapsed().as_millis(), "UDP socket bound");

        let send_start = Instant::now();
        timeout(timeout_duration, socket.send_to(query_bytes, socket_addr)).await
            .map_err(|_| {
                warn!(server = %server_str_with_port, timeout_ms = timeout_duration.as_millis(), "UDP send_to timed out");
                ResolveError::Timeout{ domain: question_name_for_error.to_string(), duration: timeout_duration}
            })?
            .map_err(|e| ResolveError::Network(format!("UDP send_to failed for {socket_addr}: {e}")))?;
        debug!(server = %server_str_with_port, target_addr = %socket_addr, bytes_sent = query_bytes.len(), elapsed_ms = send_start.elapsed().as_millis(), "UDP query sent");

        let mut buffer = vec![0u8; 4096];
        let recv_start = Instant::now();
        let (size, src_addr) = timeout(timeout_duration, socket.recv_from(&mut buffer)).await
            .map_err(|_| {
                warn!(server = %server_str_with_port, timeout_ms = timeout_duration.as_millis(), "UDP recv_from timed out");
                ResolveError::Timeout{ domain: question_name_for_error.to_string(), duration: timeout_duration}
            })?
            .map_err(|e| ResolveError::Network(format!("UDP recv_from failed for {socket_addr}: {e}")))?;
        debug!(server = %server_str_with_port, source_addr = %src_addr, bytes_received = size, elapsed_ms = recv_start.elapsed().as_millis(), "UDP response received");

        buffer.truncate(size);

        let parse_start = Instant::now();
        if let Ok(parsed_msg) = parse_dns_message(&buffer) {
            debug!(server = %server_str_with_port, elapsed_ms = parse_start.elapsed().as_millis(), "UDP response parsed");
            if parsed_msg.inner().truncated() {
                warn!(server = %server_str_with_port, "UDP response from {} was truncated. Falling back to TCP.", socket_addr);
                span.record("operation_time_ms", overall_start.elapsed().as_millis());
                return self
                    .resolve_tcp_internal(
                        query_bytes,
                        server_str_with_port,
                        timeout_duration,
                        question_name_for_error,
                    )
                    .await;
            }
        } else {
            debug!(server = %server_str_with_port, elapsed_ms = parse_start.elapsed().as_millis(), "UDP response parsing failed (or not attempted for this log)");
        }
        span.record("operation_time_ms", overall_start.elapsed().as_millis());
        Ok(buffer)
    }

    #[instrument(skip(self, query_bytes, server_str_with_port), fields(server = %server_str_with_port, operation_time_ms = field::Empty))]
    async fn resolve_tcp_internal(
        &self,
        query_bytes: &[u8],
        server_str_with_port: &str,
        timeout_duration: Duration,
        question_name_for_error: &str,
    ) -> Result<Vec<u8>, ResolveError> {
        let overall_start = Instant::now();
        let span = tracing::Span::current();

        let lookup_start = Instant::now();
        let mut resolved_addrs = lookup_host(server_str_with_port).await.map_err(|e| {
            ResolveError::Network(format!(
                "DNS lookup failed for upstream server '{server_str_with_port}': {e}"
            ))
        })?;
        debug!(server = %server_str_with_port, elapsed_ms = lookup_start.elapsed().as_millis(), "Upstream server name lookup_host completed (TCP)");

        let socket_addr = resolved_addrs.next().ok_or_else(|| {
            ResolveError::Configuration(format!(
                "Could not resolve server address to an IP: {server_str_with_port}"
            ))
        })?;
        debug!(server = %server_str_with_port, "Resolved upstream to IP for TCP: {}", socket_addr);

        let connect_start = Instant::now();
        let mut stream = timeout(timeout_duration, TcpStream::connect(socket_addr)).await
            .map_err(|_| {
                warn!(server = %server_str_with_port, timeout_ms = timeout_duration.as_millis(), "TCP connect timed out");
                ResolveError::Timeout{ domain: question_name_for_error.to_string(), duration: timeout_duration}
            })?
            .map_err(|e| ResolveError::Network(format!("TCP connect failed for {socket_addr}: {e}")))?;
        debug!(server = %server_str_with_port, target_addr = %socket_addr, elapsed_ms = connect_start.elapsed().as_millis(), "TCP stream connected");

        let len_prefix = (query_bytes.len() as u16).to_be_bytes();

        let write_len_start = Instant::now();
        timeout(timeout_duration, stream.write_all(&len_prefix)).await
            .map_err(|_| {
                warn!(server = %server_str_with_port, timeout_ms = timeout_duration.as_millis(), "TCP write length prefix timed out");
                ResolveError::Timeout{ domain: question_name_for_error.to_string(), duration: timeout_duration}
            })?
            .map_err(|e| ResolveError::Network(format!("TCP write length prefix failed for {socket_addr}: {e}")))?;
        debug!(server = %server_str_with_port, target_addr = %socket_addr, elapsed_ms = write_len_start.elapsed().as_millis(), "TCP length prefix sent");

        let write_query_start = Instant::now();
        timeout(timeout_duration, stream.write_all(query_bytes)).await
            .map_err(|_| {
                warn!(server = %server_str_with_port, timeout_ms = timeout_duration.as_millis(), "TCP write query timed out");
                ResolveError::Timeout{ domain: question_name_for_error.to_string(), duration: timeout_duration}
            })?
            .map_err(|e| ResolveError::Network(format!("TCP write query failed for {socket_addr}: {e}")))?;
        debug!(server = %server_str_with_port, target_addr = %socket_addr, bytes_sent = query_bytes.len(), elapsed_ms = write_query_start.elapsed().as_millis(), "TCP query sent");

        let mut response_len_buf = [0u8; 2];
        let read_len_start = Instant::now();
        timeout(timeout_duration, stream.read_exact(&mut response_len_buf)).await
            .map_err(|_| {
                warn!(server = %server_str_with_port, timeout_ms = timeout_duration.as_millis(), "TCP read response length timed out");
                ResolveError::Timeout{ domain: question_name_for_error.to_string(), duration: timeout_duration}
            })?
            .map_err(|e| ResolveError::Network(format!("TCP read response length failed for {socket_addr}: {e}")))?;
        debug!(server = %server_str_with_port, target_addr = %socket_addr, elapsed_ms = read_len_start.elapsed().as_millis(), "TCP response length received");

        let response_len = u16::from_be_bytes(response_len_buf) as usize;
        if response_len == 0 {
            warn!(server = %server_str_with_port, "TCP response length was 0");
            return Err(ResolveError::InvalidResponse(
                "TCP response length was 0".to_string(),
            ));
        }
        if response_len > 65535 {
            warn!(server = %server_str_with_port, "TCP response length too large: {}", response_len);
            return Err(ResolveError::InvalidResponse(format!(
                "TCP response length too large: {response_len}"
            )));
        }
        debug!(server = %server_str_with_port, "Expected TCP response body length: {}", response_len);

        let mut response_buffer = vec![0u8; response_len];
        let read_body_start = Instant::now();
        timeout(timeout_duration, stream.read_exact(&mut response_buffer)).await
            .map_err(|_| {
                warn!(server = %server_str_with_port, timeout_ms = timeout_duration.as_millis(), "TCP read response body timed out");
                ResolveError::Timeout{ domain: question_name_for_error.to_string(), duration: timeout_duration}
            })?
            .map_err(|e| ResolveError::Network(format!("TCP read response body failed for {socket_addr}: {e}")))?;
        debug!(server = %server_str_with_port, target_addr = %socket_addr, bytes_received = response_len, elapsed_ms = read_body_start.elapsed().as_millis(), "TCP response body received");

        span.record("operation_time_ms", overall_start.elapsed().as_millis());
        Ok(response_buffer)
    }
}

#[async_trait::async_trait]
impl UpstreamResolver for StandardDnsClient {
    #[instrument(skip(self, question), fields(qname = %question.name, qtype = %question.record_type, total_resolve_time_ms = field::Empty))]
    async fn resolve_dns(
        &self,
        question: &DnsQuestion,
        upstream_servers: &[String],
        timeout_duration: Duration,
    ) -> Result<DnsMessage, ResolveError> {
        let overall_start_resolve_dns = Instant::now();
        let span_resolve_dns = tracing::Span::current();

        if upstream_servers.is_empty() {
            warn!("No upstream servers provided for DNS resolution.");
            return Err(ResolveError::NoUpstreamServers);
        }

        let query_id = rand::random();
        let query_msg_to_send_start = Instant::now();
        let query_msg_to_send =
            DnsMessage::new_query(query_id, &question.name, question.record_type)
                .map_err(ResolveError::Protocol)?;
        debug!(
            elapsed_ms = query_msg_to_send_start.elapsed().as_millis(),
            "DNS query message created"
        );

        let serialize_start = Instant::now();
        let query_bytes =
            serialize_dns_message(&query_msg_to_send).map_err(ResolveError::Protocol)?;
        debug!(
            bytes_len = query_bytes.len(),
            elapsed_ms = serialize_start.elapsed().as_millis(),
            "DNS query message serialized"
        );

        let mut last_error: Option<ResolveError> = None;

        for server_str_orig in upstream_servers {
            let server_processing_start = Instant::now();
            let server_str_with_port = Self::ensure_port(server_str_orig);
            debug!(server = %server_str_with_port, "Attempting DNS resolution via UDP");

            match self
                .resolve_udp_internal(
                    &query_bytes,
                    &server_str_with_port,
                    timeout_duration,
                    &question.name,
                )
                .await
            {
                Ok(response_bytes) => {
                    let parse_start = Instant::now();
                    match parse_dns_message(&response_bytes) {
                        Ok(response_msg) => {
                            debug!(server = %server_str_with_port, elapsed_ms = parse_start.elapsed().as_millis(), "UDP response parsed successfully");
                            if response_msg.id() == query_id {
                                debug!(server = %server_str_with_port, elapsed_ms = server_processing_start.elapsed().as_millis(), "Successfully resolved {} via UDP to {}", question.name, server_str_with_port);
                                span_resolve_dns.record(
                                    "total_resolve_time_ms",
                                    overall_start_resolve_dns.elapsed().as_millis(),
                                );
                                return Ok(response_msg);
                            } else {
                                warn!(server = %server_str_with_port, expected_id = query_id, got_id = response_msg.id(), "Mismatched DNS ID from {} (UDP). Discarding.", server_str_with_port);
                                last_error = Some(ResolveError::InvalidResponse(format!(
                                    "Mismatched ID from {server_str_with_port} (UDP)"
                                )));
                            }
                        }
                        Err(e) => {
                            warn!(server = %server_str_with_port, error = %e, elapsed_ms = parse_start.elapsed().as_millis(), "Failed to parse UDP response from {}", server_str_with_port);
                            last_error = Some(ResolveError::Protocol(e));
                        }
                    }
                }
                Err(e @ ResolveError::Timeout { .. }) | Err(e @ ResolveError::Network(_))
                    if e.to_string().contains("truncated") =>
                {
                    warn!(server = %server_str_with_port, error = %e, "UDP attempt to {} failed or was truncated. Trying TCP.", server_str_with_port);
                    let tcp_attempt_start = Instant::now();
                    match self
                        .resolve_tcp_internal(
                            &query_bytes,
                            &server_str_with_port,
                            timeout_duration,
                            &question.name,
                        )
                        .await
                    {
                        Ok(response_bytes_tcp) => {
                            let parse_tcp_start = Instant::now();
                            match parse_dns_message(&response_bytes_tcp) {
                                Ok(response_msg_tcp) => {
                                    debug!(server = %server_str_with_port, elapsed_ms = parse_tcp_start.elapsed().as_millis(), "TCP response parsed successfully");
                                    if response_msg_tcp.id() == query_id {
                                        debug!(server = %server_str_with_port, elapsed_ms = tcp_attempt_start.elapsed().as_millis(), "Successfully resolved {} via TCP to {}", question.name, server_str_with_port);
                                        span_resolve_dns.record(
                                            "total_resolve_time_ms",
                                            overall_start_resolve_dns.elapsed().as_millis(),
                                        );
                                        return Ok(response_msg_tcp);
                                    } else {
                                        warn!(server = %server_str_with_port, expected_id = query_id, got_id = response_msg_tcp.id(), "Mismatched DNS ID from {} (TCP). Discarding.", server_str_with_port);
                                        last_error = Some(ResolveError::InvalidResponse(format!(
                                            "Mismatched ID from {server_str_with_port} (TCP)"
                                        )));
                                    }
                                }
                                Err(e_tcp_parse) => {
                                    warn!(server = %server_str_with_port, error = %e_tcp_parse, elapsed_ms = parse_tcp_start.elapsed().as_millis(), "Failed to parse TCP response from {}", server_str_with_port);
                                    last_error = Some(ResolveError::Protocol(e_tcp_parse));
                                }
                            }
                        }
                        Err(e_tcp) => {
                            warn!(server = %server_str_with_port, error = %e_tcp, elapsed_ms = tcp_attempt_start.elapsed().as_millis(), "TCP attempt to {} also failed", server_str_with_port);
                            last_error = Some(e_tcp);
                        }
                    }
                }
                Err(e) => {
                    warn!(server = %server_str_with_port, error = %e, elapsed_ms = server_processing_start.elapsed().as_millis(), "Upstream DNS resolution failed for server {} (UDP)", server_str_with_port);
                    last_error = Some(e);
                }
            }
        }
        span_resolve_dns.record(
            "total_resolve_time_ms",
            overall_start_resolve_dns.elapsed().as_millis(),
        );
        Err(last_error.unwrap_or_else(|| ResolveError::UpstreamServer {
            server: "all_tried".to_string(),
            details: "All upstream servers failed".to_string(),
        }))
    }

    async fn resolve_doh(
        &self,
        _question: &DnsQuestion,
        _upstream_urls: &[Url],
        _timeout: Duration,
        _http_proxy_config: Option<&HttpProxyConfig>,
    ) -> Result<DnsMessage, ResolveError> {
        error!(
            "StandardDnsClient does not support DoH. This method should not be called directly on it."
        );
        Err(ResolveError::Configuration(
            "DoH not supported by StandardDnsClient".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{op::ResponseCode, rr::RecordType};
    #[tokio::test]
    #[ignore]
    async fn test_standard_dns_resolution_live_a_record() {
        let client = StandardDnsClient::new();
        let question = DnsQuestion {
            name: "google.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };
        let upstream_servers = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
        let timeout = Duration::from_secs(5);

        let result = client
            .resolve_dns(&question, &upstream_servers, timeout)
            .await;
        assert!(
            result.is_ok(),
            "Standard DNS resolution failed: {:?}",
            result.err()
        );
        let response = result.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(
            response.answers().next().is_some(),
            "Should have at least one A record for google.com"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_standard_dns_udp_truncation_fallback_to_tcp() {
        let client = StandardDnsClient::new();
        let question = DnsQuestion {
            name: "dnssec-failed.org".to_string(),
            record_type: RecordType::ANY,
            class: hickory_proto::rr::DNSClass::IN,
        };

        let upstream_servers = vec!["8.8.8.8:53".to_string()];
        let timeout = Duration::from_secs(5);

        let result = client
            .resolve_dns(&question, &upstream_servers, timeout)
            .await;
        assert!(
            result.is_ok(),
            "Resolution (potentially via TCP fallback) failed: {:?}",
            result.err()
        );
        let response = result.unwrap();
        assert!(
            matches!(
                response.response_code(),
                ResponseCode::NoError | ResponseCode::Refused | ResponseCode::NotImp
            ),
            "Unexpected response code: {:?}",
            response.response_code()
        );
        let _ = response.response_code() == ResponseCode::NoError;
        tracing::info!(
            "Test for truncation fallback completed. Result: {:?}",
            response.response_code()
        );
    }
}
