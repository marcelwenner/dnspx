use super::integration_tests::{verify_aws_scanner_status, verify_dns_cache_contains_entries};
use super::mock_providers::MockAwsApiResponse;
use super::test_helpers::AwsScannerTestHarness;
use crate::adapters::aws::types::AwsDiscoveredEndpoint;
use crate::config::models::{
    AwsAccountConfig, AwsGlobalConfig, AwsRoleConfig, AwsServiceDiscoveryConfig,
};
use crate::core::dns_cache::CacheKey;
use crate::ports::AppLifecycleManagerPort;
use hickory_proto::rr::RecordType;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_single_account_single_region_happy_path() {
        let harness = AwsScannerTestHarness::new();

        {
            let mut config_guard = harness.app_config.write().await;
            config_guard.aws = Some(AwsGlobalConfig {
                default_region: Some("us-east-1".to_string()),
                output_file_name: None,
                scan_interval: Duration::from_secs(60),
                credentials_cache_enabled: true,
                credential_cache_ttl: Duration::from_secs(3600),
                accounts: vec![AwsAccountConfig {
                    label: "happy-path-account".to_string(),
                    account_id: Some("123456789012".to_string()),
                    profile_name: Some("test-profile".to_string()),
                    scan_vpc_ids: vec!["vpc-happy123".to_string()],
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
            });
        }

        harness.mock_config_provider.set_credentials_response(
            "test-profile",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "HAPPY_ACCESS_KEY",
                    "HAPPY_SECRET_KEY",
                    Some("HAPPY_SESSION_TOKEN".to_string()),
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "HappyPathProvider",
                ),
            )),
        );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "us-east-1",
                MockAwsApiResponse {
                    endpoints: vec![
                        AwsDiscoveredEndpoint {
                            service_dns_name: "ec2-instance-1.us-east-1.amazonaws.com".to_string(),
                            vpc_endpoint_dns_name: None,
                            private_ips: vec!["10.0.1.100".parse().unwrap()],
                            service_type: "EC2".to_string(),
                            region: "us-east-1".to_string(),
                            vpc_id: Some("vpc-happy123".to_string()),
                            comment: Some("Happy path EC2 instance".to_string()),
                        },
                        AwsDiscoveredEndpoint {
                            service_dns_name: "rds-cluster.us-east-1.amazonaws.com".to_string(),
                            vpc_endpoint_dns_name: None,
                            private_ips: vec!["10.0.1.101".parse().unwrap()],
                            service_type: "RDS".to_string(),
                            region: "us-east-1".to_string(),
                            vpc_id: Some("vpc-happy123".to_string()),
                            comment: Some("Happy path RDS cluster".to_string()),
                        },
                        AwsDiscoveredEndpoint {
                            service_dns_name: "s3-vpce.us-east-1.amazonaws.com".to_string(),
                            vpc_endpoint_dns_name: Some(
                                "vpce-s3.us-east-1.vpce.amazonaws.com".to_string(),
                            ),
                            private_ips: vec!["10.0.1.102".parse().unwrap()],
                            service_type: "com.amazonaws.us-east-1.s3".to_string(),
                            region: "us-east-1".to_string(),
                            vpc_id: Some("vpc-happy123".to_string()),
                            comment: Some("Happy path S3 VPC endpoint".to_string()),
                        },
                    ],
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        harness.mock_vpc_provider.set_route53_response(
            "us-east-1",
            vec![IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 169, 253))],
        );

        let mut zones = HashSet::new();
        zones.insert("company.vpc-happy123.local".to_string());
        zones.insert("internal.vpc-happy123.local".to_string());
        harness
            .mock_vpc_provider
            .set_private_zones_response("us-east-1", "vpc-happy123", zones);

        let lifecycle_manager = harness.create_mock_lifecycle_manager();

        let final_status = harness.trigger_scan_and_wait().await;

        verify_aws_scanner_status(&final_status, false, 1, 0, 3).unwrap();

        assert!(
            final_status.error_message.is_none(),
            "Happy path should have no errors"
        );
        assert!(
            final_status.detailed_errors.is_empty(),
            "Happy path should have no detailed errors"
        );
        assert!(
            final_status.last_scan_time.is_some(),
            "Should have scan timestamp"
        );

        let expected_dns_names = [
            "ec2-instance-1.us-east-1.amazonaws.com",
            "rds-cluster.us-east-1.amazonaws.com",
            "s3-vpce.us-east-1.amazonaws.com",
        ];
        verify_dns_cache_contains_entries(&harness.dns_cache, &expected_dns_names)
            .await
            .unwrap();

        let ec2_cache_key = CacheKey::new("ec2-instance-1.us-east-1.amazonaws.com", RecordType::A);
        let ec2_entry = harness.dns_cache.get(&ec2_cache_key, false).await;
        assert!(ec2_entry.is_some(), "EC2 instance should be cached");

        if let Some(cache_entry) = ec2_entry {
            assert_eq!(cache_entry.records.len(), 1, "Should have one A record");
            assert!(cache_entry.records[0].ttl() > 0, "TTL should be positive");
            assert!(
                cache_entry.records[0].ttl() <= 60,
                "TTL should not exceed scan interval"
            );
        }

        let (vpc_calls, config_calls) = harness.get_call_logs();

        let credential_calls: Vec<_> = config_calls
            .iter()
            .filter(|call| call.contains("get_credentials_for_account:test-profile"))
            .collect();
        assert_eq!(
            credential_calls.len(),
            1,
            "Should have made exactly one credential call"
        );

        let vpc_discovery_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, _, operation)| operation == "discover_vpc_endpoints")
            .collect();
        assert_eq!(
            vpc_discovery_calls.len(),
            1,
            "Should have made exactly one VPC discovery call"
        );

        let route53_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, _, operation)| operation == "discover_route53_inbound_endpoint_ips")
            .collect();
        assert_eq!(
            route53_calls.len(),
            1,
            "Should have made exactly one Route53 call"
        );

        let private_zone_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, _, operation)| operation == "discover_private_hosted_zones_for_vpc")
            .collect();
        assert_eq!(
            private_zone_calls.len(),
            1,
            "Should have made exactly one private zone call"
        );

        let network_info = lifecycle_manager.get_discovered_aws_network_info_view();
        let info_guard = network_info.read().await;
        assert_eq!(
            info_guard.inbound_endpoint_ips.len(),
            1,
            "Should have one inbound endpoint IP"
        );
        assert_eq!(
            info_guard.private_hosted_zone_names.len(),
            2,
            "Should have two private zones"
        );
        assert!(
            info_guard.last_discovery_error.is_none(),
            "Should have no discovery errors"
        );

        println!("✅ Single account single region happy path test completed successfully");
        println!("   - Account: happy-path-account");
        println!("   - Region: us-east-1");
        println!(
            "   - Endpoints discovered: {}",
            final_status.discovered_entries_count
        );
        println!("   - DNS cache entries verified");
        println!("   - Network info updated correctly");
    }

    #[tokio::test]
    async fn test_multi_account_role_assumption() {
        let harness = AwsScannerTestHarness::new();

        {
            let mut config_guard = harness.app_config.write().await;
            config_guard.aws = Some(AwsGlobalConfig {
                default_region: Some("us-east-1".to_string()),
                output_file_name: None,
                scan_interval: Duration::from_secs(60),
                credentials_cache_enabled: true,
                credential_cache_ttl: Duration::from_secs(3600),
                accounts: vec![
                    AwsAccountConfig {
                        label: "base-account".to_string(),
                        account_id: Some("111111111111".to_string()),
                        profile_name: Some("base-profile".to_string()),
                        scan_vpc_ids: vec!["vpc-base123".to_string()],
                        scan_regions: Some(vec!["us-east-1".to_string()]),
                        roles_to_assume: vec![],
                        discover_services: AwsServiceDiscoveryConfig {
                            vpc_endpoints: true,
                            ec2_instances: true,
                            rds_instances: false,
                            elasticache_clusters: false,
                            docdb_clusters: false,
                            api_gateways_private: false,
                        },
                    },
                    AwsAccountConfig {
                        label: "target-account".to_string(),
                        account_id: Some("222222222222".to_string()),
                        profile_name: Some("target-profile".to_string()),
                        scan_vpc_ids: vec!["vpc-target456".to_string()],
                        scan_regions: Some(vec!["us-west-2".to_string()]),
                        roles_to_assume: vec![AwsRoleConfig {
                            role_arn: "arn:aws:iam::222222222222:role/CrossAccountScannerRole"
                                .to_string(),
                            label: Some("CrossAccountScannerRole".to_string()),
                            scan_vpc_ids: vec![],
                            scan_regions: Some(vec![
                                "eu-west-1".to_string(),
                                "ap-southeast-1".to_string(),
                            ]),
                            discover_services: AwsServiceDiscoveryConfig::default(),
                        }],
                        discover_services: AwsServiceDiscoveryConfig {
                            vpc_endpoints: true,
                            ec2_instances: false,
                            rds_instances: true,
                            elasticache_clusters: true,
                            docdb_clusters: false,
                            api_gateways_private: true,
                        },
                    },
                ],
                route53_inbound_endpoint_ips: None,
                private_aws_suffixes: Some(vec![
                    ".rds.amazonaws.com".to_string(),
                    ".cache.amazonaws.com".to_string(),
                ]),
                discovered_private_zones: None,
            });
        }

        harness.mock_config_provider.set_credentials_response(
            "base-profile",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "BASE_ACCESS_KEY",
                    "BASE_SECRET_KEY",
                    None,
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "BaseAccountProvider",
                ),
            )),
        );

        harness.mock_config_provider.set_credentials_response(
            "target-profile",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "TARGET_ACCESS_KEY",
                    "TARGET_SECRET_KEY",
                    None,
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "TargetAccountProvider",
                ),
            )),
        );

        harness.mock_config_provider.set_role_response(
            "arn:aws:iam::222222222222:role/CrossAccountScannerRole",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "ASSUMED_ROLE_ACCESS_KEY",
                    "ASSUMED_ROLE_SECRET_KEY",
                    Some("ASSUMED_ROLE_SESSION_TOKEN".to_string()),
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "AssumedRoleProvider",
                ),
            )),
        );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "us-east-1",
                MockAwsApiResponse {
                    endpoints: vec![AwsDiscoveredEndpoint {
                        service_dns_name: "base-ec2.us-east-1.amazonaws.com".to_string(),
                        vpc_endpoint_dns_name: None,
                        private_ips: vec!["10.1.1.100".parse().unwrap()],
                        service_type: "EC2".to_string(),
                        region: "us-east-1".to_string(),
                        vpc_id: Some("vpc-base123".to_string()),
                        comment: Some("Base account EC2".to_string()),
                    }],
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "us-west-2",
                MockAwsApiResponse {
                    endpoints: vec![AwsDiscoveredEndpoint {
                        service_dns_name: "target-rds.us-west-2.amazonaws.com".to_string(),
                        vpc_endpoint_dns_name: None,
                        private_ips: vec!["10.2.1.100".parse().unwrap()],
                        service_type: "RDS".to_string(),
                        region: "us-west-2".to_string(),
                        vpc_id: Some("vpc-target456".to_string()),
                        comment: Some("Target account RDS".to_string()),
                    }],
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "eu-west-1",
                MockAwsApiResponse {
                    endpoints: vec![AwsDiscoveredEndpoint {
                        service_dns_name: "elasticache-cluster.eu-west-1.amazonaws.com".to_string(),
                        vpc_endpoint_dns_name: None,
                        private_ips: vec!["10.3.1.100".parse().unwrap()],
                        service_type: "ElastiCache-Node".to_string(),
                        region: "eu-west-1".to_string(),
                        vpc_id: Some("vpc-target456".to_string()),
                        comment: Some("Assumed role ElastiCache".to_string()),
                    }],
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "ap-southeast-1",
                MockAwsApiResponse {
                    endpoints: vec![AwsDiscoveredEndpoint {
                        service_dns_name: "api-gateway.ap-southeast-1.amazonaws.com".to_string(),
                        vpc_endpoint_dns_name: Some(
                            "vpce-api.ap-southeast-1.vpce.amazonaws.com".to_string(),
                        ),
                        private_ips: vec!["10.4.1.100".parse().unwrap()],
                        service_type: "APIGateway-Private".to_string(),
                        region: "ap-southeast-1".to_string(),
                        vpc_id: Some("vpc-target456".to_string()),
                        comment: Some("Assumed role API Gateway".to_string()),
                    }],
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        let final_status = harness.trigger_scan_and_wait().await;

        verify_aws_scanner_status(&final_status, false, 2, 0, 4).unwrap();

        assert!(
            final_status.error_message.is_none(),
            "Multi-account scan should have no errors"
        );
        assert!(
            final_status.detailed_errors.is_empty(),
            "Multi-account scan should have no detailed errors"
        );

        let expected_dns_names = [
            "base-ec2.us-east-1.amazonaws.com",
            "target-rds.us-west-2.amazonaws.com",
            "elasticache-cluster.eu-west-1.amazonaws.com",
            "api-gateway.ap-southeast-1.amazonaws.com",
        ];
        verify_dns_cache_contains_entries(&harness.dns_cache, &expected_dns_names)
            .await
            .unwrap();

        let (vpc_calls, config_calls) = harness.get_call_logs();

        let base_credential_calls: Vec<_> = config_calls
            .iter()
            .filter(|call| call.contains("get_credentials_for_account:base-profile"))
            .collect();
        assert_eq!(
            base_credential_calls.len(),
            1,
            "Should have called base account credentials"
        );

        let target_credential_calls: Vec<_> = config_calls
            .iter()
            .filter(|call| call.contains("get_credentials_for_account:target-profile"))
            .collect();
        assert_eq!(
            target_credential_calls.len(),
            1,
            "Should have called target account credentials"
        );

        let role_calls: Vec<_> = config_calls.iter()
            .filter(|call| call.contains("get_credentials_for_role:arn:aws:iam::222222222222:role/CrossAccountScannerRole"))
            .collect();
        assert_eq!(
            role_calls.len(),
            1,
            "Should have assumed the cross-account role"
        );

        let us_east_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, region, _)| region == "us-east-1")
            .collect();
        let us_west_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, region, _)| region == "us-west-2")
            .collect();
        let eu_west_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, region, _)| region == "eu-west-1")
            .collect();
        let ap_southeast_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, region, _)| region == "ap-southeast-1")
            .collect();

        assert!(!us_east_calls.is_empty(), "Should have scanned us-east-1");
        assert!(!us_west_calls.is_empty(), "Should have scanned us-west-2");
        assert!(
            !eu_west_calls.is_empty(),
            "Should have scanned eu-west-1 with assumed role"
        );
        assert!(
            !ap_southeast_calls.is_empty(),
            "Should have scanned ap-southeast-1 with assumed role"
        );

        println!("✅ Multi-account role assumption test completed successfully");
        println!("   - Base account: base-account (us-east-1)");
        println!("   - Target account: target-account (us-west-2)");
        println!("   - Assumed role regions: eu-west-1, ap-southeast-1");
        println!(
            "   - Total endpoints discovered: {}",
            final_status.discovered_entries_count
        );
        println!("   - Role assumption successful");
        println!("   - All regions scanned correctly");
    }
}
