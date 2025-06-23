use crate::adapters::aws::types::AwsDiscoveredEndpoint;
use crate::config::models::{
    AppConfig, AwsAccountConfig, AwsGlobalConfig, AwsServiceDiscoveryConfig,
};
use crate::core::dns_cache::{CacheKey, DnsCache};
use crate::core::types::AwsScannerStatus;
use hickory_proto::rr::RecordType;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

pub(crate) fn create_test_aws_discovered_endpoint(
    service_name: &str,
    private_ip: &str,
    region: &str,
    service_type: &str,
) -> AwsDiscoveredEndpoint {
    AwsDiscoveredEndpoint {
        service_dns_name: format!("{}.{}.amazonaws.com", service_name, region),
        vpc_endpoint_dns_name: None,
        private_ips: vec![IpAddr::from_str(private_ip).unwrap()],
        service_type: service_type.to_string(),
        region: region.to_string(),
        vpc_id: Some("vpc-test123".to_string()),
        comment: Some(format!("Test {} endpoint", service_type)),
    }
}

pub(crate) fn create_minimal_aws_config() -> AppConfig {
    AppConfig {
        aws: Some(AwsGlobalConfig {
            default_region: Some("us-east-1".to_string()),
            output_file_name: None,
            scan_interval: Duration::from_secs(300),
            credentials_cache_enabled: true,
            credential_cache_ttl: Duration::from_secs(3600),
            accounts: vec![AwsAccountConfig {
                label: "test-account".to_string(),
                account_id: Some("123456789012".to_string()),
                profile_name: Some("default".to_string()),
                scan_vpc_ids: vec![],
                scan_regions: Some(vec!["us-east-1".to_string()]),
                roles_to_assume: vec![],
                discover_services: AwsServiceDiscoveryConfig {
                    vpc_endpoints: true,
                    ec2_instances: true,
                    rds_instances: true,
                    elasticache_clusters: false,
                    docdb_clusters: false,
                    api_gateways_private: false,
                },
            }],
            route53_inbound_endpoint_ips: None,
            private_aws_suffixes: Some(vec![
                ".rds.amazonaws.com".to_string(),
                ".cache.amazonaws.com".to_string(),
            ]),
            discovered_private_zones: None,
        }),
        ..Default::default()
    }
}

pub(crate) async fn verify_dns_cache_contains_entries(
    cache: &DnsCache,
    expected_dns_names: &[&str],
) -> Result<(), String> {
    for dns_name in expected_dns_names {
        let cache_key = CacheKey::new(dns_name, RecordType::A);
        let entry = cache.get(&cache_key, false).await;
        if entry.is_none() {
            return Err(format!(
                "Expected DNS cache entry for {} not found",
                dns_name
            ));
        }
    }
    Ok(())
}

pub(crate) fn verify_aws_scanner_status(
    status: &AwsScannerStatus,
    expected_scanning: bool,
    expected_accounts_scanned: u32,
    expected_accounts_failed: u32,
    expected_entries_count: usize,
) -> Result<(), String> {
    if status.is_scanning != expected_scanning {
        return Err(format!(
            "Expected is_scanning: {}, got: {}",
            expected_scanning, status.is_scanning
        ));
    }

    if status.accounts_scanned != expected_accounts_scanned {
        return Err(format!(
            "Expected accounts_scanned: {}, got: {}",
            expected_accounts_scanned, status.accounts_scanned
        ));
    }

    if status.accounts_failed != expected_accounts_failed {
        return Err(format!(
            "Expected accounts_failed: {}, got: {}",
            expected_accounts_failed, status.accounts_failed
        ));
    }

    if status.discovered_entries_count != expected_entries_count {
        return Err(format!(
            "Expected discovered_entries_count: {}, got: {}",
            expected_entries_count, status.discovered_entries_count
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_aws_discovered_endpoint() {
        let endpoint =
            create_test_aws_discovered_endpoint("test-instance", "10.0.1.100", "us-east-1", "EC2");

        assert_eq!(
            endpoint.service_dns_name,
            "test-instance.us-east-1.amazonaws.com"
        );
        assert_eq!(endpoint.private_ips.len(), 1);
        assert_eq!(
            endpoint.private_ips[0],
            IpAddr::from_str("10.0.1.100").unwrap()
        );
        assert_eq!(endpoint.service_type, "EC2");
        assert_eq!(endpoint.region, "us-east-1");
        assert_eq!(endpoint.vpc_id, Some("vpc-test123".to_string()));
    }

    #[test]
    fn test_create_minimal_aws_config() {
        let config = create_minimal_aws_config();

        assert!(config.aws.is_some());
        let aws_config = config.aws.unwrap();
        assert_eq!(aws_config.accounts.len(), 1);
        assert_eq!(aws_config.accounts[0].label, "test-account");
        assert_eq!(
            aws_config.accounts[0].scan_regions,
            Some(vec!["us-east-1".to_string()])
        );
        assert!(aws_config.accounts[0].discover_services.vpc_endpoints);
        assert!(aws_config.accounts[0].discover_services.ec2_instances);
        assert!(aws_config.accounts[0].discover_services.rds_instances);
    }

    #[tokio::test]
    async fn test_dns_cache_verification() {
        let cache = DnsCache::new(
            100,
            Duration::from_secs(1),
            Duration::from_secs(300),
            false,
            Duration::from_secs(600),
        );

        let result = verify_dns_cache_contains_entries(&cache, &["test.example.com"]).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_aws_scanner_status_verification() {
        let status = AwsScannerStatus {
            is_scanning: false,
            last_scan_time: None,
            discovered_entries_count: 5,
            error_message: None,
            accounts_scanned: 2,
            accounts_failed: 0,
            detailed_errors: vec![],
        };

        let result = verify_aws_scanner_status(&status, false, 2, 0, 5);
        assert!(result.is_ok());

        let result = verify_aws_scanner_status(&status, true, 2, 0, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("is_scanning"));
    }

    #[test]
    fn test_aws_service_discovery_config_defaults() {
        let config = AwsServiceDiscoveryConfig::default();

        println!("vpc_endpoints: {}", config.vpc_endpoints);
        println!("ec2_instances: {}", config.ec2_instances);

        assert!(!config.ec2_instances);
        assert!(!config.rds_instances);
        assert!(!config.elasticache_clusters);
        assert!(!config.docdb_clusters);
        assert!(!config.api_gateways_private);
    }

    #[test]
    fn test_aws_global_config_construction() {
        let global_config = AwsGlobalConfig::default();

        assert_eq!(global_config.default_region, Some("us-east-1".to_string()));
        assert!(global_config.credentials_cache_enabled);
        assert_eq!(global_config.scan_interval, Duration::from_secs(15 * 60));
        assert_eq!(
            global_config.credential_cache_ttl,
            Duration::from_secs(50 * 60)
        );
        assert!(global_config.accounts.is_empty());

        assert!(global_config.private_aws_suffixes.is_some());
        let suffixes = global_config.private_aws_suffixes.unwrap();
        assert!(suffixes.contains(&".rds.amazonaws.com".to_string()));
        assert!(suffixes.contains(&".cache.amazonaws.com".to_string()));
    }

    #[test]
    fn test_detailed_aws_account_config() {
        let account_config = AwsAccountConfig {
            label: "production".to_string(),
            account_id: Some("123456789012".to_string()),
            profile_name: Some("prod-profile".to_string()),
            scan_vpc_ids: vec!["vpc-12345".to_string(), "vpc-67890".to_string()],
            scan_regions: Some(vec!["us-east-1".to_string(), "eu-west-1".to_string()]),
            roles_to_assume: vec![],
            discover_services: AwsServiceDiscoveryConfig {
                vpc_endpoints: true,
                ec2_instances: true,
                rds_instances: true,
                elasticache_clusters: true,
                docdb_clusters: false,
                api_gateways_private: false,
            },
        };

        assert_eq!(account_config.label, "production");
        assert_eq!(account_config.account_id, Some("123456789012".to_string()));
        assert_eq!(account_config.scan_vpc_ids.len(), 2);
        assert_eq!(account_config.scan_regions.as_ref().unwrap().len(), 2);
        assert!(account_config.discover_services.vpc_endpoints);
        assert!(account_config.discover_services.ec2_instances);
        assert!(account_config.discover_services.rds_instances);
        assert!(account_config.discover_services.elasticache_clusters);
        assert!(!account_config.discover_services.docdb_clusters);
    }

    #[test]
    fn test_complete_aws_integration_config_validation() {
        let config = create_minimal_aws_config();

        assert!(config.aws.is_some());
        let aws_config = config.aws.unwrap();

        assert!(aws_config.default_region.is_some());
        assert!(aws_config.credentials_cache_enabled);
        assert!(aws_config.scan_interval > Duration::from_secs(0));
        assert!(aws_config.credential_cache_ttl > Duration::from_secs(0));

        assert_eq!(aws_config.accounts.len(), 1);
        let account = &aws_config.accounts[0];
        assert!(!account.label.is_empty());
        assert!(account.account_id.is_some());
        assert!(account.profile_name.is_some());
        assert!(account.scan_regions.is_some());

        let services = &account.discover_services;
        assert!(services.vpc_endpoints);
        assert!(services.ec2_instances);
        assert!(services.rds_instances);

        assert!(aws_config.private_aws_suffixes.is_some());
        let suffixes = aws_config.private_aws_suffixes.unwrap();
        assert!(!suffixes.is_empty());
        assert!(suffixes.iter().any(|s| s.contains(".rds.amazonaws.com")));

        println!("✅ AWS integration configuration validation completed successfully");
        println!("   - Global config: ✓");
        println!("   - Account config: ✓");
        println!("   - Service discovery: ✓");
        println!("   - DNS suffixes: ✓");
    }
}
