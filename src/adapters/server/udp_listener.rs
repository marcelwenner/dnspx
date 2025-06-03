use crate::core::types::ProtocolType;
use crate::dns_protocol::{DnsMessage as AppDnsMessage, parse_dns_message, serialize_dns_message};
use crate::ports::{AppLifecycleManagerPort, DnsQueryService};
use hickory_proto::op::ResponseCode;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{Instrument, error, info, warn};

pub async fn run_udp_listener(
    app_lifecycle: Arc<dyn AppLifecycleManagerPort>,
    dns_query_service: Arc<dyn DnsQueryService>,
) -> Result<(), std::io::Error> {
    let config_guard = app_lifecycle.get_config();
    let listen_address = {
        let guard = config_guard.read().await;
        guard.server.listen_address.clone()
    };

    let socket = Arc::new(UdpSocket::bind(&listen_address).await?);
    info!("UDP listener started on {}", listen_address);
    app_lifecycle
        .add_listener_address(format!("UDP:{}", listen_address))
        .await;

    let cancellation_token = app_lifecycle.get_cancellation_token();

    loop {
        let mut buf = vec![0; 512];
        tokio::select! {
            _ = cancellation_token.cancelled() => {
                info!("UDP listener shutting down.");
                break;
            }
            recv_result = socket.recv_from(&mut buf) => {
                match recv_result {
                    Ok((len, client_addr)) => {
                        let data = buf[..len].to_vec();
                        let service_clone = Arc::clone(&dns_query_service);
                        let socket_clone = Arc::clone(&socket);
                        let app_config_clone = Arc::clone(&config_guard);

                        tokio::spawn(
                            async move {
                                let whitelisted = {
                                    let guard = app_config_clone.read().await;
                                    match &guard.server.network_whitelist {
                                        Some(list) => list.iter().any(|net| net.contains(client_addr.ip())),
                                        None => true,
                                    }
                                };

                                if !whitelisted {
                                    warn!(client = %client_addr, "Client IP not in whitelist, dropping UDP packet.");
                                    return;
                                }

                                match service_clone.process_query(data.clone(), client_addr, ProtocolType::Udp).await {
                                    Ok(response_bytes) => {
                                        if let Err(e) = socket_clone.send_to(&response_bytes, client_addr).await {
                                            error!(client = %client_addr, "Failed to send UDP response: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        error!(client = %client_addr, "Error processing UDP DNS query: {}", e);
                                        if let Ok(query_msg) = parse_dns_message(&data) {
                                            let err_response = AppDnsMessage::new_response(&query_msg, ResponseCode::FormErr);
                                            if let Ok(response_bytes) = serialize_dns_message(&err_response) {
                                                if let Err(e_send) = socket_clone.send_to(&response_bytes, client_addr).await {
                                                    error!(client = %client_addr, "Failed to send FormErr UDP response: {}", e_send);
                                                }
                                            }
                                        }
                                    }
                                }
                            }.instrument(tracing::info_span!("handle_udp_request", client = %client_addr)),
                        );
                    }
                    Err(e) => {
                        error!("Error receiving UDP packet: {}", e);
                        if e.kind() == std::io::ErrorKind::ConnectionReset {
                             tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
    }
    app_lifecycle
        .remove_listener_address(format!("UDP:{}", listen_address))
        .await;
    Ok(())
}
