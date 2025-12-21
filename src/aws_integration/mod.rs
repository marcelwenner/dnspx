#[cfg(feature = "aws")]
pub(crate) mod scanner;

#[cfg(not(feature = "aws"))]
pub(crate) mod scanner {
    use std::collections::HashSet;
    use std::net::IpAddr;

    #[derive(Debug, Clone, Default)]
    pub(crate) struct DiscoveredAwsNetworkInfo {
        pub inbound_endpoint_ips: Vec<IpAddr>,
        pub private_hosted_zone_names: HashSet<String>,
        pub last_discovery_error: Option<String>,
    }
}
