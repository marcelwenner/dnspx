use crate::adapters::aws::types::AwsDiscoveredEndpoint;
use crate::config::models::AwsAccountConfig;
use crate::core::error::AwsApiError;
use crate::core::types::AwsCredentials;
use crate::ports::AwsVpcInfoProvider;
use async_trait::async_trait;
use aws_config::Region;
use aws_credential_types::Credentials;
use aws_sdk_ec2::types::{Filter as Ec2Filter, InstanceStateName, VpcEndpointType};
use aws_sdk_route53resolver::types::{Filter as ResolverFilter, ResolverEndpointDirection};
use aws_sdk_sts::config::SharedCredentialsProvider;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use tracing::{debug, error, info, warn};

pub(crate) struct AwsSdkVpcInfoProvider;

impl AwsSdkVpcInfoProvider {
    pub(crate) fn new() -> Self {
        Self
    }

    async fn create_sdk_config(
        credentials: &AwsCredentials,
        region_str: &str,
    ) -> aws_config::SdkConfig {
        let aws_credentials = Credentials::new(
            credentials.access_key_id(),
            credentials.secret_access_key(),
            credentials.session_token().map(String::from),
            credentials.expiry(),
            "VpcInfoProviderClient",
        );
        let provider = SharedCredentialsProvider::new(aws_credentials);

        aws_config::SdkConfig::builder()
            .credentials_provider(provider)
            .region(Region::new(region_str.to_string()))
            .build()
    }

    async fn create_ec2_client(credentials: &AwsCredentials, region: &str) -> aws_sdk_ec2::Client {
        let sdk_config = Self::create_sdk_config(credentials, region).await;
        aws_sdk_ec2::Client::new(&sdk_config)
    }

    async fn create_apigw_client(
        credentials: &AwsCredentials,
        region: &str,
    ) -> aws_sdk_apigateway::Client {
        let sdk_config = Self::create_sdk_config(credentials, region).await;
        aws_sdk_apigateway::Client::new(&sdk_config)
    }

    async fn create_rds_client(credentials: &AwsCredentials, region: &str) -> aws_sdk_rds::Client {
        let sdk_config = Self::create_sdk_config(credentials, region).await;
        aws_sdk_rds::Client::new(&sdk_config)
    }

    async fn create_elasticache_client(
        credentials: &AwsCredentials,
        region: &str,
    ) -> aws_sdk_elasticache::Client {
        let sdk_config = Self::create_sdk_config(credentials, region).await;
        aws_sdk_elasticache::Client::new(&sdk_config)
    }

    async fn create_docdb_client(
        credentials: &AwsCredentials,
        region: &str,
    ) -> aws_sdk_docdb::Client {
        let sdk_config = Self::create_sdk_config(credentials, region).await;
        aws_sdk_docdb::Client::new(&sdk_config)
    }

    async fn create_route53_client(
        credentials: &AwsCredentials,
        region_for_api_call: &str,
    ) -> aws_sdk_route53::Client {
        let sdk_config = Self::create_sdk_config(credentials, region_for_api_call).await;
        aws_sdk_route53::Client::new(&sdk_config)
    }

    async fn create_route53resolver_client(
        credentials: &AwsCredentials,
        region: &str,
    ) -> aws_sdk_route53resolver::Client {
        let sdk_config = Self::create_sdk_config(credentials, region).await;
        aws_sdk_route53resolver::Client::new(&sdk_config)
    }

    fn get_vpce_ips_for_service(
        service_vpce_name_pattern: &str,
        vpc_id_filter: Option<&str>,
        region_filter: &str,
        raw_vpce_list: &[AwsDiscoveredEndpoint],
        vpce_details_map: &HashMap<String, (Vec<IpAddr>, Option<String>)>,
    ) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        let full_service_name_pattern = if service_vpce_name_pattern.contains("com.amazonaws.") {
            service_vpce_name_pattern.to_string()
        } else {
            format!("com.amazonaws.{region_filter}.{service_vpce_name_pattern}")
        };

        for vpce_candidate in raw_vpce_list {
            if vpce_candidate.service_type == full_service_name_pattern {
                let vpce_id_from_comment = vpce_candidate
                    .comment
                    .as_ref()
                    .and_then(|c| c.strip_prefix("VPC Endpoint ID: "))
                    .map(String::from);

                if let Some(vpce_id) = vpce_id_from_comment {
                    if let Some((vpce_ips, vpce_actual_vpc_id_opt)) = vpce_details_map.get(&vpce_id)
                    {
                        if vpc_id_filter.is_none_or(|filter_vpc| {
                            vpce_actual_vpc_id_opt.as_deref() == Some(filter_vpc)
                        }) {
                            ips.extend_from_slice(vpce_ips);
                        }
                    }
                }
            }
        }
        if ips.is_empty() {
            debug!(
                "No matching VPCE IPs found for service pattern {} in VPC {:?} and region {}",
                service_vpce_name_pattern, vpc_id_filter, region_filter
            );
        }
        ips.sort();
        ips.dedup();
        ips
    }

    pub(crate) async fn discover_route53_inbound_endpoint_ips(
        &self,
        credentials: &AwsCredentials,
        region: &str,
    ) -> Result<Vec<IpAddr>, AwsApiError> {
        info!(
            "Discovering Route 53 Inbound Resolver Endpoint IPs in region: {}",
            region
        );
        let client = Self::create_route53resolver_client(credentials, region).await;
        let mut discovered_ips = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut request_builder = client.list_resolver_endpoints();
            if let Some(token) = &next_token {
                request_builder = request_builder.next_token(token.clone());
            }

            let direction_filter = ResolverFilter::builder()
                .name("Direction")
                .values(ResolverEndpointDirection::Inbound.as_ref())
                .build();

            request_builder = request_builder.filters(direction_filter);

            match request_builder.send().await {
                Ok(output) => {
                    for endpoint in output.resolver_endpoints() {
                        if endpoint.direction() == Some(&ResolverEndpointDirection::Inbound) {
                            if let Some(endpoint_id) = endpoint.id() {
                                match client
                                    .list_resolver_endpoint_ip_addresses()
                                    .resolver_endpoint_id(endpoint_id)
                                    .send()
                                    .await
                                {
                                    Ok(ip_output) => {
                                        for ip_address_response in ip_output.ip_addresses() {
                                            if let Some(ip_str) = ip_address_response.ip() {
                                                if let Ok(ip_addr) = IpAddr::from_str(ip_str) {
                                                    discovered_ips.push(ip_addr);
                                                    info!(
                                                        "Discovered Route 53 Inbound Endpoint IP: {} for Endpoint ID: {}",
                                                        ip_str, endpoint_id
                                                    );
                                                } else {
                                                    warn!(
                                                        "Failed to parse IP address: {} for R53 Inbound Endpoint {}",
                                                        ip_str, endpoint_id
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to list IP addresses for R53 Inbound Endpoint {}: {}",
                                            endpoint_id,
                                            e.into_service_error()
                                        );
                                    }
                                }
                            }
                        }
                    }

                    if let Some(token) = output.next_token() {
                        next_token = Some(token.to_string());
                    } else {
                        break;
                    }
                }
                Err(e) => {
                    let service_error = e.into_service_error();
                    error!(
                        "Failed to list Route 53 Resolver Endpoints in region {}: {}",
                        region, service_error
                    );
                    return Err(AwsApiError::ApiCall {
                        service: "Route53Resolver".to_string(),
                        resource_id: "ListResolverEndpoints".to_string(),
                        source: Box::new(service_error),
                    });
                }
            }
        }

        discovered_ips.sort();
        discovered_ips.dedup();
        Ok(discovered_ips)
    }

    pub(crate) async fn discover_private_hosted_zones_for_vpc(
        &self,
        credentials: &AwsCredentials,
        vpc_id: &str,
        vpc_region: &str,
    ) -> Result<HashSet<String>, AwsApiError> {
        info!(
            "Discovering Private Hosted Zones associated with VPC {} in region {}",
            vpc_id, vpc_region
        );
        let client = Self::create_route53_client(credentials, vpc_region).await;
        let mut zone_names = HashSet::new();

        match client
            .list_hosted_zones_by_vpc()
            .vpc_id(vpc_id)
            .vpc_region(aws_sdk_route53::types::VpcRegion::from_str(vpc_region).unwrap())
            .send()
            .await
        {
            Ok(output) => {
                for summary in output.hosted_zone_summaries() {
                    let name = summary.name();

                    zone_names.insert(name.trim_end_matches('.').to_string());
                    info!(
                        "Discovered Private Hosted Zone: {} associated with VPC {}",
                        name, vpc_id
                    );
                }
            }
            Err(e) => {
                let service_error = e.into_service_error();
                error!(
                    "Failed to list Private Hosted Zones for VPC {} in region {}: {}",
                    vpc_id, vpc_region, service_error
                );
                return Err(AwsApiError::ApiCall {
                    service: "Route53".to_string(),
                    resource_id: format!("ListHostedZonesByVPC for {vpc_id}"),
                    source: Box::new(service_error),
                });
            }
        }
        Ok(zone_names)
    }
}

#[async_trait]
impl AwsVpcInfoProvider for AwsSdkVpcInfoProvider {
    async fn discover_route53_inbound_endpoint_ips(
        &self,
        credentials: &AwsCredentials,
        region: &str,
    ) -> Result<Vec<IpAddr>, AwsApiError> {
        self.discover_route53_inbound_endpoint_ips(credentials, region)
            .await
    }

    async fn discover_private_hosted_zones_for_vpc(
        &self,
        credentials: &AwsCredentials,
        vpc_id: &str,
        vpc_region: &str,
    ) -> Result<HashSet<String>, AwsApiError> {
        self.discover_private_hosted_zones_for_vpc(credentials, vpc_id, vpc_region)
            .await
    }
    async fn discover_vpc_endpoints(
        &self,
        credentials: &AwsCredentials,
        account_config: &AwsAccountConfig,
        region: &str,
    ) -> Result<Vec<AwsDiscoveredEndpoint>, AwsApiError> {
        info!(
            "Discovering AWS service endpoints (VPCEs, RDS, etc.) in region: {} for account: {}",
            region, account_config.label
        );
        let mut all_discovered_endpoints = Vec::new();
        let ec2_client = Self::create_ec2_client(credentials, region).await;

        let mut vpce_details_map: HashMap<String, (Vec<IpAddr>, Option<String>)> = HashMap::new();
        let mut raw_vpce_list: Vec<AwsDiscoveredEndpoint> = Vec::new();

        if account_config.discover_services.vpc_endpoints {
            debug!(
                "Discovering generic VPC Interface Endpoints in region {}",
                region
            );
            let mut filters = Vec::new();
            if !account_config.scan_vpc_ids.is_empty() {
                filters.push(
                    Ec2Filter::builder()
                        .name("vpc-id")
                        .set_values(Some(account_config.scan_vpc_ids.clone()))
                        .build(),
                );
            }
            filters.push(
                Ec2Filter::builder()
                    .name("vpc-endpoint-type")
                    .values(VpcEndpointType::Interface.as_ref())
                    .build(),
            );

            match ec2_client
                .describe_vpc_endpoints()
                .set_filters(Some(filters))
                .send()
                .await
            {
                Ok(output) => {
                    for vpce in output.vpc_endpoints() {
                        let service_name =
                            vpce.service_name().unwrap_or("unknown-service").to_string();
                        let vpc_id_opt = vpce.vpc_id().map(String::from);
                        let vpce_id = vpce.vpc_endpoint_id().unwrap_or_default().to_string();

                        let mut private_ips = Vec::new();
                        let mut network_interface_ids = HashSet::new();
                        for ni_id in vpce.network_interface_ids() {
                            network_interface_ids.insert(ni_id.clone());
                        }

                        if !network_interface_ids.is_empty() {
                            match ec2_client
                                .describe_network_interfaces()
                                .set_network_interface_ids(Some(
                                    network_interface_ids.into_iter().collect(),
                                ))
                                .send()
                                .await
                            {
                                Ok(ni_output) => {
                                    for ni in ni_output.network_interfaces() {
                                        for private_ip_addr_assoc in ni.private_ip_addresses() {
                                            if let Some(ip_str) =
                                                private_ip_addr_assoc.private_ip_address()
                                            {
                                                if let Ok(ip_addr) = ip_str.parse::<IpAddr>() {
                                                    private_ips.push(ip_addr);
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => warn!(
                                    "Failed to describe network interfaces for VPCE {}: {}",
                                    vpce_id,
                                    e.into_service_error()
                                ),
                            }
                        }

                        if !private_ips.is_empty() {
                            vpce_details_map
                                .insert(vpce_id.clone(), (private_ips.clone(), vpc_id_opt.clone()));
                        } else {
                            warn!("No private IPs found for VPC Endpoint: {}", vpce_id);
                        }

                        let primary_service_dns = vpce
                            .dns_entries()
                            .first()
                            .and_then(|d| d.dns_name())
                            .map(String::from)
                            .unwrap_or_else(|| format!("{vpce_id}.{region}.vpce.amazonaws.com"));

                        let vpc_endpoint_dns_name_opt = vpce
                            .dns_entries()
                            .iter()
                            .find(|d| {
                                d.dns_name()
                                    .unwrap_or_default()
                                    .contains(".vpce.amazonaws.com")
                            })
                            .and_then(|d| d.dns_name())
                            .map(String::from);

                        let discovered_vpce = AwsDiscoveredEndpoint {
                            service_dns_name: primary_service_dns,
                            vpc_endpoint_dns_name: vpc_endpoint_dns_name_opt,
                            private_ips,
                            service_type: service_name.clone(),
                            region: region.to_string(),
                            vpc_id: vpc_id_opt,
                            comment: Some(format!("VPC Endpoint ID: {vpce_id}")),
                        };
                        raw_vpce_list.push(discovered_vpce.clone());
                        all_discovered_endpoints.push(discovered_vpce);
                    }
                }
                Err(e) => {
                    return Err(AwsApiError::ApiCall {
                        service: "EC2 (describe_vpc_endpoints)".to_string(),
                        resource_id: "N/A".to_string(),
                        source: Box::new(e.into_service_error()),
                    });
                }
            }
        }

        if account_config.discover_services.api_gateways_private {
            debug!("Discovering Private API Gateways in region {}", region);
            let apigw_client = Self::create_apigw_client(credentials, region).await;
            match apigw_client.get_rest_apis().send().await {
                Ok(output) => {
                    for api in output.items() {
                        if let Some(ep_config) = api.endpoint_configuration() {
                            if ep_config.types().iter().any(|t| t.as_str() == "PRIVATE") {
                                if let Some(api_id) = api.id() {
                                    let service_dns_name =
                                        format!("{api_id}.execute-api.{region}.amazonaws.com");
                                    let execute_api_vpce_service_name_pattern = "execute-api";

                                    let mut vpc_id_for_apigw = None;
                                    let vpce_ids_on_api = ep_config.vpc_endpoint_ids();
                                    if let Some(first_vpce_id) = vpce_ids_on_api.first() {
                                        if let Some((_, v_id)) = vpce_details_map.get(first_vpce_id)
                                        {
                                            vpc_id_for_apigw = v_id.clone();
                                        }
                                    }

                                    let private_ips_for_apigw = Self::get_vpce_ips_for_service(
                                        execute_api_vpce_service_name_pattern,
                                        vpc_id_for_apigw.as_deref(),
                                        region,
                                        &raw_vpce_list,
                                        &vpce_details_map,
                                    );

                                    all_discovered_endpoints.push(AwsDiscoveredEndpoint {
                                        service_dns_name,
                                        vpc_endpoint_dns_name: None,
                                        private_ips: private_ips_for_apigw,
                                        service_type: "APIGateway-Private".to_string(),
                                        region: region.to_string(),
                                        vpc_id: vpc_id_for_apigw,
                                        comment: Some(format!(
                                            "API Gateway ID: {}, Name: {}",
                                            api_id,
                                            api.name().unwrap_or_default()
                                        )),
                                    });
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to discover Private API Gateways in region {}: {}. Skipping.",
                        region,
                        e.into_service_error()
                    );
                }
            }
        }

        if account_config.discover_services.rds_instances {
            debug!("Discovering RDS instances in region {}", region);
            let rds_client = Self::create_rds_client(credentials, region).await;
            match rds_client.describe_db_instances().send().await {
                Ok(output) => {
                    for db_instance in output.db_instances() {
                        if let Some(endpoint) = db_instance.endpoint() {
                            let service_dns_name =
                                endpoint.address().unwrap_or_default().to_string();
                            if service_dns_name.is_empty() {
                                continue;
                            }

                            let rds_vpc_id = db_instance
                                .db_subnet_group()
                                .and_then(|sg| sg.vpc_id())
                                .map(String::from);
                            all_discovered_endpoints.push(AwsDiscoveredEndpoint {
                                service_dns_name,
                                vpc_endpoint_dns_name: None,
                                private_ips: Vec::new(),
                                service_type: "RDS".to_string(),
                                region: region.to_string(),
                                vpc_id: rds_vpc_id,
                                comment: Some(format!(
                                    "RDS Instance ID: {}",
                                    db_instance.db_instance_identifier().unwrap_or_default()
                                )),
                            });
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to discover RDS instances in region {}: {}. Skipping.",
                        region,
                        e.into_service_error()
                    );
                }
            }
        }

        if account_config.discover_services.elasticache_clusters {
            debug!("Discovering ElastiCache clusters in region {}", region);
            let elasticache_client = Self::create_elasticache_client(credentials, region).await;
            match elasticache_client
                .describe_cache_clusters()
                .show_cache_node_info(true)
                .send()
                .await
            {
                Ok(output) => {
                    for cluster in output.cache_clusters() {
                        let cluster_id = cluster.cache_cluster_id().unwrap_or_default().to_string();
                        let mut vpc_id_for_ec: Option<String> = None;
                        if let Some(subnet_group_name) = cluster.cache_subnet_group_name() {
                            match elasticache_client
                                .describe_cache_subnet_groups()
                                .cache_subnet_group_name(subnet_group_name)
                                .send()
                                .await
                            {
                                Ok(sg_output) => {
                                    if let Some(sg) = sg_output.cache_subnet_groups().first() {
                                        vpc_id_for_ec = sg.vpc_id().map(String::from);
                                    }
                                }
                                Err(sg_err) => warn!(
                                    "Could not describe subnet group {} for ElastiCache cluster {}: {}",
                                    subnet_group_name,
                                    cluster_id,
                                    sg_err.into_service_error()
                                ),
                            }
                        }

                        if let Some(endpoint) = cluster.configuration_endpoint() {
                            let service_dns_name =
                                endpoint.address().unwrap_or_default().to_string();
                            if !service_dns_name.is_empty() {
                                all_discovered_endpoints.push(AwsDiscoveredEndpoint {
                                    service_dns_name,
                                    vpc_endpoint_dns_name: None,
                                    private_ips: Vec::new(),
                                    service_type: "ElastiCache-Config".to_string(),
                                    region: region.to_string(),
                                    vpc_id: vpc_id_for_ec.clone(),
                                    comment: Some(format!("ElastiCache Cluster ID: {cluster_id}")),
                                });
                            }
                        }
                        for node in cluster.cache_nodes() {
                            if let Some(node_endpoint) = node.endpoint() {
                                let node_dns_name =
                                    node_endpoint.address().unwrap_or_default().to_string();
                                if !node_dns_name.is_empty() {
                                    all_discovered_endpoints.push(AwsDiscoveredEndpoint {
                                        service_dns_name: node_dns_name,
                                        vpc_endpoint_dns_name: None,
                                        private_ips: Vec::new(),
                                        service_type: "ElastiCache-Node".to_string(),
                                        region: region.to_string(),
                                        vpc_id: vpc_id_for_ec.clone(),
                                        comment: Some(format!(
                                            "ElastiCache Node for Cluster: {cluster_id}"
                                        )),
                                    });
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to discover ElastiCache clusters in region {}: {}. Skipping.",
                        region,
                        e.into_service_error()
                    );
                }
            }
        }

        if account_config.discover_services.docdb_clusters {
            debug!("Discovering DocumentDB clusters in region {}", region);
            let docdb_client = Self::create_docdb_client(credentials, region).await;
            match docdb_client.describe_db_clusters().send().await {
                Ok(output) => {
                    for cluster in output.db_clusters() {
                        let cluster_id = cluster
                            .db_cluster_identifier()
                            .unwrap_or_default()
                            .to_string();
                        let service_dns_name = cluster.endpoint().unwrap_or_default().to_string();
                        let reader_endpoint =
                            cluster.reader_endpoint().unwrap_or_default().to_string();

                        let mut vpc_id_for_docdb: Option<String> = None;
                        if let Some(subnet_group_name) = cluster.db_subnet_group() {
                            match docdb_client
                                .describe_db_subnet_groups()
                                .db_subnet_group_name(subnet_group_name)
                                .send()
                                .await
                            {
                                Ok(sg_output) => {
                                    if let Some(sg) = sg_output.db_subnet_groups().first() {
                                        vpc_id_for_docdb = sg.vpc_id().map(String::from);
                                    }
                                }
                                Err(sg_err) => warn!(
                                    "Could not describe subnet group {} for DocDB cluster {}: {}",
                                    subnet_group_name,
                                    cluster_id,
                                    sg_err.into_service_error()
                                ),
                            }
                        }

                        if !service_dns_name.is_empty() {
                            all_discovered_endpoints.push(AwsDiscoveredEndpoint {
                                service_dns_name: service_dns_name.clone(),
                                vpc_endpoint_dns_name: None,
                                private_ips: Vec::new(),
                                service_type: "DocumentDB-Cluster".to_string(),
                                region: region.to_string(),
                                vpc_id: vpc_id_for_docdb.clone(),
                                comment: Some(format!("DocumentDB Cluster ID: {cluster_id}")),
                            });
                        }
                        if !reader_endpoint.is_empty() && reader_endpoint != service_dns_name {
                            all_discovered_endpoints.push(AwsDiscoveredEndpoint {
                                service_dns_name: reader_endpoint,
                                vpc_endpoint_dns_name: None,
                                private_ips: Vec::new(),
                                service_type: "DocumentDB-Reader".to_string(),
                                region: region.to_string(),
                                vpc_id: vpc_id_for_docdb,
                                comment: Some(format!(
                                    "DocumentDB Reader for Cluster: {cluster_id}"
                                )),
                            });
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to discover DocumentDB clusters in region {}: {}. Skipping.",
                        region,
                        e.into_service_error()
                    );
                }
            }
        }

        if account_config.discover_services.ec2_instances {
            debug!("Discovering EC2 instances in region {}", region);
            let mut ec2_filters = vec![
                Ec2Filter::builder()
                    .name("instance-state-name")
                    .values(InstanceStateName::Running.as_ref())
                    .values(InstanceStateName::Pending.as_ref())
                    .build(),
            ];
            if !account_config.scan_vpc_ids.is_empty() {
                ec2_filters.push(
                    Ec2Filter::builder()
                        .name("vpc-id")
                        .set_values(Some(account_config.scan_vpc_ids.clone()))
                        .build(),
                );
            }

            match ec2_client
                .describe_instances()
                .set_filters(Some(ec2_filters))
                .send()
                .await
            {
                Ok(output) => {
                    for reservation in output.reservations() {
                        for instance in reservation.instances() {
                            let instance_id =
                                instance.instance_id().unwrap_or_default().to_string();
                            let vpc_id = instance.vpc_id().map(String::from);
                            let mut ips = Vec::new();
                            if let Some(private_ip) = instance.private_ip_address() {
                                if let Ok(ip_addr) = private_ip.parse() {
                                    ips.push(ip_addr);
                                }
                            }
                            for ni in instance.network_interfaces() {
                                for private_ip_detail in ni.private_ip_addresses() {
                                    if let Some(ip_str) = private_ip_detail.private_ip_address() {
                                        if let Ok(ip_addr) = ip_str.parse() {
                                            if !ips.contains(&ip_addr) {
                                                ips.push(ip_addr);
                                            }
                                        }
                                    }
                                }
                            }

                            let private_dns_name =
                                instance.private_dns_name().unwrap_or_default().to_string();
                            if !private_dns_name.is_empty() && !ips.is_empty() {
                                all_discovered_endpoints.push(AwsDiscoveredEndpoint {
                                    service_dns_name: private_dns_name,
                                    vpc_endpoint_dns_name: None,
                                    private_ips: ips.clone(),
                                    service_type: "EC2-Instance".to_string(),
                                    region: region.to_string(),
                                    vpc_id: vpc_id.clone(),
                                    comment: Some(format!("EC2 Instance ID: {instance_id}")),
                                });
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to discover EC2 instances in region {}: {}. Skipping.",
                        region,
                        e.into_service_error()
                    );
                }
            }
        }

        info!(
            "Finished API discovery in region {}. Found {} candidate service endpoints.",
            region,
            all_discovered_endpoints.len()
        );
        Ok(all_discovered_endpoints)
    }
}
