use crate::adapters::aws::types::AwsDiscoveredEndpoint;
use crate::config::models::{AppConfig, AwsAccountConfig, AwsGlobalConfig, AwsRoleConfig};
use crate::core::dns_cache::{CacheKey, DnsCache};
use crate::core::error::{AwsApiError, ResolveError};
use crate::core::local_hosts_resolver::LocalHostsResolver;
use crate::core::types::{AccountScanError, AwsCredentials, AwsScannerStatus};
use crate::dns_protocol::DnsQuestion;
use crate::ports::{AppLifecycleManagerPort, AwsVpcInfoProvider};
use crate::ports::{AwsConfigProvider, StatusReporterPort, UpstreamResolver, UserInteractionPort};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::sync::{Notify, RwLock};
use tokio::time;
use tracing::{Instrument, debug, error, info, warn};
const VPC_DNS_RESOLVER_IP: &str = "169.254.169.253";
const VPC_DNS_TIMEOUT: StdDuration = StdDuration::from_secs(2);

#[derive(Debug, Clone, Default)]
pub struct DiscoveredAwsNetworkInfo {
    pub inbound_endpoint_ips: Vec<IpAddr>,
    pub private_hosted_zone_names: HashSet<String>,
    pub last_discovery_error: Option<String>,
}

pub struct AwsVpcScannerTask {
    app_lifecycle: Arc<dyn AppLifecycleManagerPort>,
    config_manager_config: Arc<RwLock<AppConfig>>,
    aws_config_provider: Arc<dyn AwsConfigProvider>,
    aws_vpc_info_provider: Arc<dyn AwsVpcInfoProvider>,
    dns_cache: Arc<DnsCache>,
    status_reporter: Arc<dyn StatusReporterPort>,
    user_interaction: Arc<dyn UserInteractionPort>,
    scan_trigger: Arc<Notify>,
    vpc_internal_resolver: Arc<dyn UpstreamResolver>,
}

impl AwsVpcScannerTask {
    pub fn new(
        app_lifecycle: Arc<dyn AppLifecycleManagerPort>,
        aws_config_provider: Arc<dyn AwsConfigProvider>,
        aws_vpc_info_provider: Arc<dyn AwsVpcInfoProvider>,
        vpc_internal_resolver: Arc<dyn UpstreamResolver>,
    ) -> Self {
        let user_interaction_port = app_lifecycle.get_user_interaction_port();
        let scan_trigger = app_lifecycle.get_aws_scan_trigger();
        Self {
            config_manager_config: app_lifecycle.get_config(),
            dns_cache: app_lifecycle.get_dns_cache(),
            status_reporter: app_lifecycle.get_status_reporter(),
            user_interaction: user_interaction_port,
            scan_trigger,
            app_lifecycle,
            aws_config_provider,
            aws_vpc_info_provider,
            vpc_internal_resolver,
        }
    }

    pub async fn run(self: Arc<Self>) {
        info!("AWS VPC Scanner Task started.");

        if self.config_manager_config.read().await.aws.is_some() {
            info!("Performing initial AWS scan on startup.");
            time::sleep(StdDuration::from_secs(5)).await;
            if self.app_lifecycle.get_cancellation_token().is_cancelled() {
                return;
            }
            self.perform_scan().await;
        }

        let cancellation_token = self.app_lifecycle.get_cancellation_token();

        loop {
            let scan_interval_duration = {
                let config_guard = self.config_manager_config.read().await;
                config_guard
                    .aws
                    .as_ref()
                    .map_or(StdDuration::from_secs(15 * 60), |ac| ac.scan_interval)
            };

            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    info!("AWS VPC Scanner Task shutting down.");
                    break;
                }
                _ = time::sleep(scan_interval_duration) => {
                    if self.config_manager_config.read().await.aws.is_some() {
                        info!("AWS scan triggered by interval.");
                        self.perform_scan().await;
                    } else {
                        debug!("AWS scan interval elapsed, but AWS not configured. Skipping.");
                    }
                }
                _ = self.scan_trigger.notified() => {
                     if self.config_manager_config.read().await.aws.is_some() {
                        info!("AWS scan triggered by notification (CLI or config change).");
                        self.perform_scan().await;
                    } else {
                        info!("AWS scan trigger received, but AWS not configured. Skipping.");
                    }
                }
            }
        }
        info!("AWS VPC Scanner Task finished.");
    }

    async fn perform_scan(&self) {
        let config_guard = self.config_manager_config.read().await;
        let aws_global_config = match &config_guard.aws {
            Some(conf) => conf,
            None => {
                debug!("AWS scanning skipped: AWS configuration not present.");
                let mut current_status = self.status_reporter.get_aws_scanner_status().await;
                current_status.is_scanning = false;
                self.status_reporter
                    .report_aws_scanner_status(current_status)
                    .await;
                return;
            }
        };

        let mut initial_status = self.status_reporter.get_aws_scanner_status().await;
        initial_status.is_scanning = true;
        initial_status.error_message = None;
        initial_status.detailed_errors.clear();
        self.status_reporter
            .report_aws_scanner_status(initial_status)
            .await;

        let mut overall_discovered_endpoints_count = 0;
        let mut accounts_scanned = 0u32;
        let mut accounts_failed = 0u32;
        let mut accumulated_general_errors: Vec<String> = Vec::new();
        let mut detailed_scan_errors: Vec<AccountScanError> = Vec::new();
        let mut proxy_bypass_list_domains: HashSet<String> = HashSet::new();

        let mut discovered_inbound_ips_all_accounts: HashSet<IpAddr> = HashSet::new();
        let mut discovered_private_zones_all_accounts: HashSet<String> = HashSet::new();

        for account_config in &aws_global_config.accounts {
            if self.app_lifecycle.get_cancellation_token().is_cancelled() {
                break;
            }
            let span = tracing::info_span!("scan_account", account_label = %account_config.label);
            let span_for_role = span.clone();
            async {
            accounts_scanned += 1;
            info!("Starting scan for account: {}", account_config.label);

            let base_credentials = match self.aws_config_provider
                .get_credentials_for_account(account_config, Arc::clone(&self.user_interaction))
                .await
            {
                Ok(creds) => creds,
                Err(e) => {
                    let err_msg = format!("Failed to get base credentials for account {}: {}", account_config.label, e);
                    error!("{}", err_msg);
                    accumulated_general_errors.push(err_msg.clone());
                    detailed_scan_errors.push(AccountScanError{ label_or_arn: account_config.label.clone(), region: None, error: e.to_string()});
                    accounts_failed += 1;
                    return;
                }
            };

            let regions_to_scan = Self::determine_regions_to_scan(aws_global_config, account_config, None);
            for region in &regions_to_scan {
                if self.app_lifecycle.get_cancellation_token().is_cancelled() { return; }

                match self.aws_vpc_info_provider.discover_route53_inbound_endpoint_ips(&base_credentials, region).await {
                    Ok(ips) => discovered_inbound_ips_all_accounts.extend(ips),
                    Err(e) => {
                        let err_msg = format!("Failed to discover Inbound Endpoints in region {} for account {}: {}", region, account_config.label, e);
                        warn!("{}", err_msg);
                        accumulated_general_errors.push(err_msg.clone());
                        detailed_scan_errors.push(AccountScanError{ label_or_arn: account_config.label.clone(), region: Some(region.to_string()), error: e.to_string()});
                    }
                }

                for vpc_id in &account_config.scan_vpc_ids {
                     if self.app_lifecycle.get_cancellation_token().is_cancelled() { return; }
                     match self.aws_vpc_info_provider.discover_private_hosted_zones_for_vpc(&base_credentials, vpc_id, region).await {
                         Ok(zones) => discovered_private_zones_all_accounts.extend(zones),
                         Err(e) => {
                             let err_msg = format!("Failed to discover Private Zones for VPC {} in region {} for account {}: {}", vpc_id, region, account_config.label, e);
                             warn!("{}", err_msg);
                             accumulated_general_errors.push(err_msg.clone());
                             detailed_scan_errors.push(AccountScanError{ label_or_arn: account_config.label.clone(), region: Some(region.to_string()), error: format!("VPC {}: {}", vpc_id, e)});
                         }
                     }
                }

                let current_inbound_ips_vec: Vec<IpAddr> = discovered_inbound_ips_all_accounts.iter().cloned().collect();
                match self.scan_region_with_creds(&base_credentials, account_config, region, &mut proxy_bypass_list_domains, &current_inbound_ips_vec).await {
                    Ok(count) => overall_discovered_endpoints_count += count,
                    Err(e) => {
                        let err_msg = format!("Error scanning service endpoints in region {} for account {}: {}", region, account_config.label, e);
                        warn!("{}", err_msg);
                        accumulated_general_errors.push(err_msg.clone());
                        detailed_scan_errors.push(AccountScanError{ label_or_arn: account_config.label.clone(), region: Some(region.to_string()), error: e.to_string()});
                    }
                }
            }

            for role_config in &account_config.roles_to_assume {
                 if self.app_lifecycle.get_cancellation_token().is_cancelled() { return; }
                 let role_span = tracing::info_span!(parent: &span_for_role, "scan_role", role_arn = %role_config.role_arn);
                 async {
                    info!("Attempting to assume and scan with role: {}", role_config.role_arn);
                    let role_credentials = match self.aws_config_provider
                        .get_credentials_for_role(&base_credentials, role_config, account_config, Arc::clone(&self.user_interaction))
                        .await {
                        Ok(creds) => creds,
                        Err(e) => {
                            let err_msg = format!("Failed to assume role {} for account {}: {}. Skipping role.", role_config.role_arn, account_config.label, e);
                            error!("{}", err_msg);
                            accumulated_general_errors.push(err_msg.clone());
                            detailed_scan_errors.push(AccountScanError{ label_or_arn: role_config.role_arn.clone(), region: None, error: e.to_string()});
                            return;
                        }
                    };
                    let role_regions_to_scan = Self::determine_regions_to_scan(aws_global_config, account_config, Some(role_config));
                     for region in &role_regions_to_scan {
                         if self.app_lifecycle.get_cancellation_token().is_cancelled() { return; }
                         let current_inbound_ips_vec: Vec<IpAddr> = discovered_inbound_ips_all_accounts.iter().cloned().collect();
                         match self.scan_region_with_creds(&role_credentials, account_config, region, &mut proxy_bypass_list_domains, &current_inbound_ips_vec).await {
                             Ok(count) => overall_discovered_endpoints_count += count,
                             Err(e) => {
                                 let err_msg = format!("Error scanning service endpoints in region {} with role {} for account {}: {}", region, role_config.role_arn, account_config.label, e);
                                 warn!("{}", err_msg);
                                 accumulated_general_errors.push(err_msg.clone());
                                 detailed_scan_errors.push(AccountScanError{ label_or_arn: role_config.role_arn.clone(), region: Some(region.clone()), error: e.to_string()});
                             }
                         }
                     }
                 }.instrument(role_span).await;
            }
        }.instrument(span).await;
        }

        {
            let discovered_info = self.app_lifecycle.get_discovered_aws_network_info_view();
            let mut net_info_w = discovered_info.write().await;

            net_info_w.inbound_endpoint_ips =
                discovered_inbound_ips_all_accounts.into_iter().collect();
            net_info_w.private_hosted_zone_names = discovered_private_zones_all_accounts;
            net_info_w.last_discovery_error = if accumulated_general_errors.is_empty() {
                None
            } else {
                Some(accumulated_general_errors.join("; "))
            };
            info!(
                "Updated in-memory discovered AWS network info. Inbound IPs: {}, Private Zones: {}. Errors: {:?}",
                net_info_w.inbound_endpoint_ips.len(),
                net_info_w.private_hosted_zone_names.len(),
                net_info_w.last_discovery_error
            );
        }

        if let Some(output_file) = &aws_global_config.output_file_name {
            if !proxy_bypass_list_domains.is_empty() {
                let bypass_content = Self::format_bypass_list(&proxy_bypass_list_domains);
                match tokio::fs::write(output_file, bypass_content).await {
                    Ok(_) => info!(
                        "Successfully wrote AWS proxy bypass list to {:?}",
                        output_file
                    ),
                    Err(e) => {
                        let err_msg = format!(
                            "Failed to write AWS proxy bypass list to {:?}: {}",
                            output_file, e
                        );
                        error!("{}", err_msg);
                        accumulated_general_errors.push(err_msg);
                    }
                }
            }
        }

        let final_error_message = if !accumulated_general_errors.is_empty() {
            Some(accumulated_general_errors.join("; "))
        } else if accounts_failed > 0 {
            Some(format!(
                "{} accounts had credential failures during scan.",
                accounts_failed
            ))
        } else {
            None
        };

        self.status_reporter
            .report_aws_scanner_status(AwsScannerStatus {
                is_scanning: false,
                last_scan_time: Some(chrono::Utc::now()),
                discovered_entries_count: overall_discovered_endpoints_count,
                error_message: final_error_message,
                accounts_scanned,
                accounts_failed,
                detailed_errors: detailed_scan_errors,
            })
            .await;
        info!(
            "AWS scan finished. Discovered {} service endpoints. {} accounts scanned, {} failed.",
            overall_discovered_endpoints_count, accounts_scanned, accounts_failed
        );
    }

    fn determine_regions_to_scan(
        aws_global_config: &AwsGlobalConfig,
        account_config: &AwsAccountConfig,
        role_config_opt: Option<&AwsRoleConfig>,
    ) -> Vec<String> {
        let mut regions = HashSet::new();
        if let Some(role_conf) = role_config_opt {
            if let Some(role_regions) = &role_conf.scan_regions {
                regions.extend(role_regions.iter().cloned());
            }
        }
        if regions.is_empty() {
            if let Some(acc_regions) = &account_config.scan_regions {
                regions.extend(acc_regions.iter().cloned());
            }
        }
        if regions.is_empty() {
            if let Some(default_region) = &aws_global_config.default_region {
                regions.insert(default_region.clone());
            }
        }
        if regions.is_empty() {
            warn!(
                "No AWS regions specified for scanning for account/role '{}/{}'. Defaulting to us-east-1.",
                account_config.label,
                role_config_opt.map_or("N/A", |r| &r.role_arn)
            );
            regions.insert("us-east-1".to_string());
        }
        regions.into_iter().collect()
    }

    async fn resolve_service_dns_name_internally(
        &self,
        dns_name: &str,
        inbound_ips_to_query: &[IpAddr],
    ) -> Result<Vec<IpAddr>, ResolveError> {
        if inbound_ips_to_query.is_empty() {
            debug!(
                "No Inbound Resolver IPs available to query for {}, skipping internal resolution.",
                dns_name
            );
            return Ok(Vec::new());
        }
        debug!(
            "Attempting internal VPC DNS resolution for: {} via {:?}",
            dns_name, inbound_ips_to_query
        );

        let question_a = DnsQuestion {
            name: dns_name.to_string(),
            record_type: RecordType::A,
            class: DNSClass::IN,
        };
        let question_aaaa = DnsQuestion {
            name: dns_name.to_string(),
            record_type: RecordType::AAAA,
            class: DNSClass::IN,
        };

        let mut resolved_ips = HashSet::new();

        let resolver_ip_strings: Vec<String> = inbound_ips_to_query
            .iter()
            .map(|ip| format!("{}:53", ip))
            .collect();

        match self
            .vpc_internal_resolver
            .resolve_dns(&question_a, &resolver_ip_strings, VPC_DNS_TIMEOUT)
            .await
        {
            Ok(response) => {
                for answer in response.answers() {
                    if let RData::A(ipv4) = answer.data() {
                        resolved_ips.insert(IpAddr::V4(**ipv4));
                    }
                }
            }
            Err(e) => warn!(
                "Internal A record resolution for {} via {:?} failed: {}",
                dns_name, resolver_ip_strings, e
            ),
        }

        match self
            .vpc_internal_resolver
            .resolve_dns(&question_aaaa, &resolver_ip_strings, VPC_DNS_TIMEOUT)
            .await
        {
            Ok(response) => {
                for answer in response.answers() {
                    if let RData::AAAA(ipv6) = answer.data() {
                        resolved_ips.insert(IpAddr::V6(**ipv6));
                    }
                }
            }
            Err(e) => warn!(
                "Internal AAAA record resolution for {} via {:?} failed: {}",
                dns_name, resolver_ip_strings, e
            ),
        }

        if resolved_ips.is_empty() {
            debug!("Internal DNS resolution for {} yielded no IPs.", dns_name);
        }
        Ok(resolved_ips.into_iter().collect())
    }

    async fn scan_region_with_creds(
        &self,
        credentials: &AwsCredentials,
        account_config: &AwsAccountConfig,
        region: &str,
        proxy_bypass_list_domains: &mut HashSet<String>,
        inbound_resolver_ips_for_this_context: &Vec<IpAddr>,
    ) -> Result<usize, AwsApiError> {
        let discovered_endpoints_from_api: Vec<AwsDiscoveredEndpoint> = self
            .aws_vpc_info_provider
            .discover_vpc_endpoints(credentials, account_config, region)
            .await?;

        let mut final_resolved_endpoints: Vec<AwsDiscoveredEndpoint> = Vec::new();
        let mut new_entries_count = 0;

        for mut endpoint_info in discovered_endpoints_from_api {
            let is_cname_service = matches!(
                endpoint_info.service_type.as_str(),
                "RDS"
                    | "ElastiCache-Config"
                    | "ElastiCache-Node"
                    | "DocumentDB-Cluster"
                    | "DocumentDB-Reader"
                    | "APIGateway-Private"
            ) || endpoint_info.service_dns_name.ends_with(".amazonaws.com");

            if endpoint_info.private_ips.is_empty() || is_cname_service {
                if !inbound_resolver_ips_for_this_context.is_empty() {
                    match self
                        .resolve_service_dns_name_internally(
                            &endpoint_info.service_dns_name,
                            inbound_resolver_ips_for_this_context,
                        )
                        .await
                    {
                        Ok(resolved_ips) => {
                            if !resolved_ips.is_empty() {
                                debug!(
                                    "Internally resolved {} to {:?} for service type {}",
                                    endpoint_info.service_dns_name,
                                    resolved_ips,
                                    endpoint_info.service_type
                                );
                                endpoint_info.private_ips = resolved_ips;
                            } else if !endpoint_info.private_ips.is_empty() {
                                debug!(
                                    "Internal DNS resolution for {} (type: {}) yielded no IPs. Retaining previously discovered VPCE IPs: {:?}.",
                                    endpoint_info.service_dns_name,
                                    endpoint_info.service_type,
                                    endpoint_info.private_ips
                                );
                            } else {
                                warn!(
                                    "Internal DNS resolution for {} (type: {}) yielded no IPs. IPs will be missing.",
                                    endpoint_info.service_dns_name, endpoint_info.service_type
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to resolve service DNS name {} internally: {}. IPs might be missing.",
                                endpoint_info.service_dns_name, e
                            );
                        }
                    }
                } else if is_cname_service {
                    warn!(
                        "No Inbound Resolver IPs available to query for CNAME-like service {}. IPs will be missing.",
                        endpoint_info.service_dns_name
                    );
                }
            }

            if !endpoint_info.private_ips.is_empty() {
                self.add_endpoint_to_cache(&endpoint_info).await;
                self.add_endpoint_to_bypass_list(&endpoint_info, proxy_bypass_list_domains);
                final_resolved_endpoints.push(endpoint_info);
                new_entries_count += 1;
            } else {
                debug!(
                    "Skipping endpoint {} (type: {}) for caching as no private IPs were determined.",
                    endpoint_info.service_dns_name, endpoint_info.service_type
                );
            }
        }
        Ok(new_entries_count)
    }

    async fn add_endpoint_to_cache(&self, endpoint: &AwsDiscoveredEndpoint) {
        let config_guard = self.config_manager_config.read().await;
        let ttl_duration = config_guard
            .aws
            .as_ref()
            .map_or(StdDuration::from_secs(900), |ac| ac.scan_interval / 2);

        if endpoint.private_ips.is_empty() {
            debug!(
                "Skipping cache add for endpoint '{}' as it has no private IPs.",
                endpoint.service_dns_name
            );
            return;
        }

        let mut records_for_service_dns = Vec::new();

        for ip in &endpoint.private_ips {
            let rdata = match ip {
                IpAddr::V4(ipv4) => RData::A((*ipv4).into()),
                IpAddr::V6(ipv6) => RData::AAAA((*ipv6).into()),
            };

            if let Ok(name_obj) = Name::from_str(&endpoint.service_dns_name) {
                records_for_service_dns.push(Record::from_rdata(
                    name_obj.clone(),
                    ttl_duration.as_secs() as u32,
                    rdata.clone(),
                ));
            } else {
                warn!(
                    "Invalid DNS name format for service_dns_name: {}",
                    endpoint.service_dns_name
                );
            }
        }

        let dns_cache_clone = Arc::clone(&self.dns_cache);
        let group_and_cache = |dns_name: String, records_list: Vec<Record>| async move {
            if records_list.is_empty() {
                return;
            }

            let mut a_records = Vec::new();
            let mut aaaa_records = Vec::new();

            for rec in records_list {
                match rec.data().record_type() {
                    RecordType::A => a_records.push(rec),
                    RecordType::AAAA => aaaa_records.push(rec),
                    _ => {}
                }
            }

            if !a_records.is_empty() {
                let key_a = CacheKey::new(&dns_name, RecordType::A);
                debug!(
                    "Caching A records for {}: {} records, TTL: {:?}",
                    dns_name,
                    a_records.len(),
                    ttl_duration
                );
                dns_cache_clone
                    .insert_synthetic_entry(key_a, a_records, ttl_duration, ResponseCode::NoError)
                    .await;
            }
            if !aaaa_records.is_empty() {
                let key_aaaa = CacheKey::new(&dns_name, RecordType::AAAA);
                debug!(
                    "Caching AAAA records for {}: {} records, TTL: {:?}",
                    dns_name,
                    aaaa_records.len(),
                    ttl_duration
                );
                dns_cache_clone
                    .insert_synthetic_entry(
                        key_aaaa,
                        aaaa_records,
                        ttl_duration,
                        ResponseCode::NoError,
                    )
                    .await;
            }
        };

        group_and_cache(endpoint.service_dns_name.clone(), records_for_service_dns).await;
    }

    fn add_endpoint_to_bypass_list(
        &self,
        endpoint: &AwsDiscoveredEndpoint,
        bypass_list: &mut HashSet<String>,
    ) {
        bypass_list.insert(endpoint.service_dns_name.clone());
        if let Some(vpce_dns) = &endpoint.vpc_endpoint_dns_name {
            bypass_list.insert(vpce_dns.clone());
        }

        if endpoint.service_type.contains("execute-api") {
            bypass_list.insert(format!("*.execute-api.{}.amazonaws.com", endpoint.region));
        } else if !endpoint.service_type.starts_with("com.amazonaws.") {
            bypass_list.insert(format!(
                "*.{}.{}.amazonaws.com",
                endpoint.service_type, endpoint.region
            ));
        } else {
            let parts: Vec<&str> = endpoint.service_type.split('.').collect();
            if parts.len() >= 4 && parts[0] == "com" && parts[1] == "amazonaws" {
                let service_short_name = parts[3];
                bypass_list.insert(format!(
                    "*.{}.{}.amazonaws.com",
                    service_short_name, endpoint.region
                ));
            }
        }
    }

    fn format_bypass_list(domains: &HashSet<String>) -> String {
        let mut content = String::new();
        content.push_str("# DNS Proxy - AWS VPC Endpoint Bypass List\n");
        content.push_str(&format!(
            "# Generated: {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        content.push_str("[Browser/System Proxy Settings - Semicolon separated]\n");
        let browser_list: Vec<String> = domains.iter().cloned().collect();
        content.push_str(&browser_list.join(";"));
        content.push_str("\n\n");

        content.push_str("[Fiddler Proxy Bypass - Line separated]\n");
        for domain in domains {
            content.push_str(domain);
            content.push('\n');
        }
        content
    }
}
