use crate::core::types::ProtocolType;
use crate::dns_protocol::{DnsMessage as AppDnsMessage, parse_dns_message, serialize_dns_message};
use crate::ports::{AppLifecycleManagerPort, DnsQueryService};
use hickory_proto::op::ResponseCode;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, warn};

async fn handle_tcp_connection(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    dns_query_service: Arc<dyn DnsQueryService>,
    app_config: Arc<tokio::sync::RwLock<crate::config::models::AppConfig>>,
    conn_cancellation_token: CancellationToken,
) {
    debug!(client = %client_addr, "New TCP connection established");

    let whitelisted = {
        let guard = app_config.read().await;
        match &guard.server.network_whitelist {
            Some(list) => list.iter().any(|net| net.contains(client_addr.ip())),
            None => true,
        }
    };

    if !whitelisted {
        warn!(client = %client_addr, "Client IP not in whitelist, closing TCP connection.");
        let _ = stream.shutdown().await;
        return;
    }

    loop {
        let mut len_buf = [0u8; 2];
        tokio::select! {
            _ = conn_cancellation_token.cancelled() => {
                debug!(client = %client_addr, "TCP connection handler cancelled.");
                break;
            }
            read_result = stream.read_exact(&mut len_buf) => {
                match read_result {
                    Ok(_) => {
                        let query_len = u16::from_be_bytes(len_buf) as usize;
                        if query_len == 0 {
                            debug!(client = %client_addr, "TCP client sent 0 length query, closing connection.");
                            break;
                        }
                        if query_len > 4096 {
                             error!(client = %client_addr, "TCP query length too large: {}", query_len);
                             break;
                        }

                        let mut query_buf = vec![0u8; query_len];
                        if let Err(e) = stream.read_exact(&mut query_buf).await {
                            error!(client = %client_addr, "Failed to read TCP query body: {}", e);
                            break;
                        }

                        match dns_query_service.process_query(query_buf.clone(), client_addr, ProtocolType::Tcp).await {
                            Ok(response_bytes) => {
                                let response_len = response_bytes.len() as u16;

                                if let Err(e) = stream.write_all(&response_len.to_be_bytes()).await {
                                    error!(client = %client_addr, "Failed to send TCP response length: {}", e);
                                    break;
                                }

                                if let Err(e) = stream.write_all(&response_bytes).await {
                                    error!(client = %client_addr, "Failed to send TCP response body: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                error!(client = %client_addr, "Error processing TCP DNS query: {}", e);
                                if let Ok(query_msg) = parse_dns_message(&query_buf) {
                                    let err_response = AppDnsMessage::new_response(&query_msg, ResponseCode::FormErr);
                                    if let Ok(response_bytes) = serialize_dns_message(&err_response) {
                                        let response_len = response_bytes.len() as u16;

                                        if let Err(e_send) = stream.write_all(&response_len.to_be_bytes()).await {
                                            error!(client = %client_addr, "Failed to send FormErr TCP response length: {}", e_send);
                                            break;
                                        }


                                        if let Err(e_send) = stream.write_all(&response_bytes).await {
                                            error!(client = %client_addr, "Failed to send FormErr TCP response body: {}", e_send);
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        debug!(client = %client_addr, "TCP client closed connection.");
                        break;
                    }
                    Err(e) => {
                        error!(client = %client_addr, "Failed to read TCP query length: {}", e);
                        break;
                    }
                }
            }
        }
    }
    debug!(client = %client_addr, "TCP connection closed.");
}

pub(crate) async fn run_tcp_listener(
    app_lifecycle: Arc<dyn AppLifecycleManagerPort>,
    dns_query_service: Arc<dyn DnsQueryService>,
) -> Result<(), std::io::Error> {
    let config_guard = app_lifecycle.get_config();
    let listen_address = {
        let guard = config_guard.read().await;
        guard.server.listen_address.clone()
    };

    let listener = TcpListener::bind(&listen_address).await?;
    info!("TCP listener started on {}", listen_address);
    app_lifecycle
        .add_listener_address(format!("TCP:{listen_address}"))
        .await;

    let cancellation_token = app_lifecycle.get_cancellation_token();

    loop {
        tokio::select! {
            _ = cancellation_token.cancelled() => {
                info!("TCP listener shutting down.");
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, client_addr)) => {
                        let service_clone = Arc::clone(&dns_query_service);
                        let app_config_clone = Arc::clone(&config_guard);
                        let conn_token = cancellation_token.clone();
                        tokio::spawn(
                            async move {
                                handle_tcp_connection(stream, client_addr, service_clone, app_config_clone, conn_token).await;
                            }
                            .instrument(tracing::info_span!("handle_tcp_connection", client = %client_addr)),
                        );
                    }
                    Err(e) => {
                        error!("Error accepting TCP connection: {}", e);
                        if e.kind() == std::io::ErrorKind::ResourceBusy {
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    }
    app_lifecycle
        .remove_listener_address(format!("TCP:{listen_address}"))
        .await;
    Ok(())
}
