use super::integration_tests::verify_aws_scanner_status;
use super::mock_providers::{MockAwsApiResponse, MockAwsError};
use super::test_helpers::AwsScannerTestHarness;
use crate::adapters::aws::types::AwsDiscoveredEndpoint;
use crate::config::models::{AwsAccountConfig, AwsGlobalConfig, AwsServiceDiscoveryConfig};
use crate::core::error::AwsAuthError;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_credential_error_one_of_multiple_accounts() {
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
                        label: "working-account".to_string(),
                        account_id: Some("111111111111".to_string()),
                        profile_name: Some("working-profile".to_string()),
                        scan_vpc_ids: vec!["vpc-working123".to_string()],
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
                        label: "failing-account".to_string(),
                        account_id: Some("222222222222".to_string()),
                        profile_name: Some("failing-profile".to_string()),
                        scan_vpc_ids: vec!["vpc-failing456".to_string()],
                        scan_regions: Some(vec!["us-west-2".to_string()]),
                        roles_to_assume: vec![],
                        discover_services: AwsServiceDiscoveryConfig {
                            vpc_endpoints: true,
                            ec2_instances: true,
                            rds_instances: true,
                            elasticache_clusters: false,
                            docdb_clusters: false,
                            api_gateways_private: false,
                        },
                    },
                ],
                route53_inbound_endpoint_ips: None,
                private_aws_suffixes: Some(vec![".rds.amazonaws.com".to_string()]),
                discovered_private_zones: None,
            });
        }

        harness.mock_config_provider.set_credentials_response(
            "working-profile",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "WORKING_ACCESS_KEY",
                    "WORKING_SECRET_KEY",
                    None,
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "WorkingProvider",
                ),
            )),
        );

        harness.mock_config_provider.set_credentials_response(
            "failing-profile",
            Err(AwsAuthError::Config(
                "Profile 'failing-profile' not found in AWS credentials file".to_string(),
            )),
        );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "us-east-1",
                MockAwsApiResponse {
                    endpoints: vec![
                        AwsDiscoveredEndpoint {
                            service_dns_name: "working-ec2.us-east-1.amazonaws.com".to_string(),
                            vpc_endpoint_dns_name: None,
                            private_ips: vec!["10.1.1.100".parse().unwrap()],
                            service_type: "EC2".to_string(),
                            region: "us-east-1".to_string(),
                            vpc_id: Some("vpc-working123".to_string()),
                            comment: Some("Working account EC2".to_string()),
                        },
                        AwsDiscoveredEndpoint {
                            service_dns_name: "working-s3.us-east-1.amazonaws.com".to_string(),
                            vpc_endpoint_dns_name: Some(
                                "vpce-s3.us-east-1.vpce.amazonaws.com".to_string(),
                            ),
                            private_ips: vec!["10.1.1.101".parse().unwrap()],
                            service_type: "com.amazonaws.us-east-1.s3".to_string(),
                            region: "us-east-1".to_string(),
                            vpc_id: Some("vpc-working123".to_string()),
                            comment: Some("Working account S3".to_string()),
                        },
                    ],
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        let final_status = harness.trigger_scan_and_wait().await;

        verify_aws_scanner_status(&final_status, false, 2, 1, 2).unwrap();

        assert!(
            final_status.error_message.is_some(),
            "Should have error message for failed account"
        );
        assert!(
            !final_status.detailed_errors.is_empty(),
            "Should have detailed error information"
        );

        let credential_errors: Vec<_> = final_status
            .detailed_errors
            .iter()
            .filter(|e| {
                e.label_or_arn.contains("failing-account")
                    && (e.error.contains("not found") || e.error.contains("Profile"))
            })
            .collect();
        assert!(
            !credential_errors.is_empty(),
            "Should have credential error for failing account"
        );

        assert!(
            final_status.discovered_entries_count > 0,
            "Working account should have discovered endpoints"
        );

        let (vpc_calls, config_calls) = harness.get_call_logs();

        let working_credential_calls: Vec<_> = config_calls
            .iter()
            .filter(|call| call.contains("get_credentials_for_account:working-profile"))
            .collect();
        let failing_credential_calls: Vec<_> = config_calls
            .iter()
            .filter(|call| call.contains("get_credentials_for_account:failing-profile"))
            .collect();

        assert_eq!(
            working_credential_calls.len(),
            1,
            "Working account credentials should have been attempted"
        );
        assert_eq!(
            failing_credential_calls.len(),
            1,
            "Failing account credentials should have been attempted"
        );

        let working_vpc_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(account, _, _)| account.contains("working-account"))
            .collect();
        let failing_vpc_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(account, _, _)| account.contains("failing-account"))
            .collect();

        assert!(
            !working_vpc_calls.is_empty(),
            "Working account should have made VPC calls"
        );
        assert!(
            failing_vpc_calls.is_empty(),
            "Failing account should not have made VPC calls"
        );

        println!("✅ Credential error one of multiple accounts test completed");
        println!(
            "   - Working account: {} endpoints discovered",
            final_status.discovered_entries_count
        );
        println!("   - Failing account: properly handled and logged");
        println!("   - Credential errors: {}", credential_errors.len());
        println!(
            "   - VPC calls from working account: {}",
            working_vpc_calls.len()
        );
    }

    #[tokio::test]
    async fn test_api_error_in_specific_region() {
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
                    label: "multi-region-account".to_string(),
                    account_id: Some("333333333333".to_string()),
                    profile_name: Some("multi-region-profile".to_string()),
                    scan_vpc_ids: vec!["vpc-multi123".to_string()],
                    scan_regions: Some(vec![
                        "us-east-1".to_string(),
                        "eu-west-1".to_string(),
                        "ap-southeast-1".to_string(),
                    ]),
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
                private_aws_suffixes: Some(vec![".rds.amazonaws.com".to_string()]),
                discovered_private_zones: None,
            });
        }

        harness.mock_config_provider.set_credentials_response(
            "multi-region-profile",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "MULTI_REGION_ACCESS_KEY",
                    "MULTI_REGION_SECRET_KEY",
                    None,
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "MultiRegionProvider",
                ),
            )),
        );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "us-east-1",
                MockAwsApiResponse {
                    endpoints: vec![AwsDiscoveredEndpoint {
                        service_dns_name: "east-ec2.us-east-1.amazonaws.com".to_string(),
                        vpc_endpoint_dns_name: None,
                        private_ips: vec!["10.1.1.100".parse().unwrap()],
                        service_type: "EC2".to_string(),
                        region: "us-east-1".to_string(),
                        vpc_id: Some("vpc-multi123".to_string()),
                        comment: Some("US East EC2".to_string()),
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
                    endpoints: vec![],
                    should_fail: true,
                    error_type: Some(MockAwsError::AccessDenied),
                    delay_ms: None,
                },
            );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "ap-southeast-1",
                MockAwsApiResponse {
                    endpoints: vec![AwsDiscoveredEndpoint {
                        service_dns_name: "asia-rds.ap-southeast-1.amazonaws.com".to_string(),
                        vpc_endpoint_dns_name: None,
                        private_ips: vec!["10.3.1.100".parse().unwrap()],
                        service_type: "RDS".to_string(),
                        region: "ap-southeast-1".to_string(),
                        vpc_id: Some("vpc-multi123".to_string()),
                        comment: Some("Asia RDS".to_string()),
                    }],
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        let final_status = harness.trigger_scan_and_wait().await;

        verify_aws_scanner_status(&final_status, false, 1, 0, 2).unwrap();

        assert!(
            final_status.error_message.is_some(),
            "Should have error message for failed region"
        );
        assert!(
            !final_status.detailed_errors.is_empty(),
            "Should have detailed error information"
        );

        let regional_errors: Vec<_> = final_status
            .detailed_errors
            .iter()
            .filter(|e| {
                e.region.as_deref() == Some("eu-west-1")
                    && e.label_or_arn.contains("multi-region-account")
            })
            .collect();
        assert!(
            !regional_errors.is_empty(),
            "Should have error for eu-west-1 region"
        );

        assert!(
            final_status.discovered_entries_count >= 2,
            "Working regions should have discovered endpoints"
        );

        let east_cache_key = crate::core::dns_cache::CacheKey::new(
            "east-ec2.us-east-1.amazonaws.com",
            hickory_proto::rr::RecordType::A,
        );
        let east_entry = harness.dns_cache.get(&east_cache_key, false).await;
        assert!(east_entry.is_some(), "US East endpoint should be cached");

        let asia_cache_key = crate::core::dns_cache::CacheKey::new(
            "asia-rds.ap-southeast-1.amazonaws.com",
            hickory_proto::rr::RecordType::A,
        );
        let asia_entry = harness.dns_cache.get(&asia_cache_key, false).await;
        assert!(asia_entry.is_some(), "Asia endpoint should be cached");

        let (vpc_calls, config_calls) = harness.get_call_logs();

        let credential_calls: Vec<_> = config_calls
            .iter()
            .filter(|call| call.contains("get_credentials_for_account:multi-region-profile"))
            .collect();
        assert_eq!(
            credential_calls.len(),
            1,
            "Should have made exactly one credential call for multi-region-profile"
        );

        let us_east_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, region, _)| region == "us-east-1")
            .collect();
        let eu_west_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, region, _)| region == "eu-west-1")
            .collect();
        let ap_southeast_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, region, _)| region == "ap-southeast-1")
            .collect();

        assert!(
            !us_east_calls.is_empty(),
            "Should have attempted US East discovery"
        );
        assert!(
            !eu_west_calls.is_empty(),
            "Should have attempted EU West discovery (even though it failed)"
        );
        assert!(
            !ap_southeast_calls.is_empty(),
            "Should have attempted AP Southeast discovery"
        );

        println!("✅ API error in specific region test completed");
        println!("   - Total regions scanned: 3");
        println!("   - Working regions: us-east-1, ap-southeast-1");
        println!("   - Failing region: eu-west-1 (access denied)");
        println!(
            "   - Endpoints discovered from working regions: {}",
            final_status.discovered_entries_count
        );
        println!(
            "   - Regional errors properly logged: {}",
            regional_errors.len()
        );
    }

    #[tokio::test]
    async fn test_mixed_credential_and_api_errors() {
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
                        label: "working-account".to_string(),
                        account_id: Some("111111111111".to_string()),
                        profile_name: Some("working-profile".to_string()),
                        scan_vpc_ids: vec!["vpc-working123".to_string()],
                        scan_regions: Some(vec!["us-east-1".to_string(), "us-west-2".to_string()]),
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
                        label: "cred-failing-account".to_string(),
                        account_id: Some("222222222222".to_string()),
                        profile_name: Some("invalid-profile".to_string()),
                        scan_vpc_ids: vec!["vpc-cred-fail".to_string()],
                        scan_regions: Some(vec!["eu-west-1".to_string()]),
                        roles_to_assume: vec![],
                        discover_services: AwsServiceDiscoveryConfig {
                            vpc_endpoints: true,
                            ec2_instances: true,
                            rds_instances: true,
                            elasticache_clusters: false,
                            docdb_clusters: false,
                            api_gateways_private: false,
                        },
                    },
                ],
                route53_inbound_endpoint_ips: None,
                private_aws_suffixes: None,
                discovered_private_zones: None,
            });
        }

        harness.mock_config_provider.set_credentials_response(
            "working-profile",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "WORKING_ACCESS_KEY",
                    "WORKING_SECRET_KEY",
                    None,
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "WorkingProvider",
                ),
            )),
        );

        harness.mock_config_provider.set_credentials_response(
            "invalid-profile",
            Err(AwsAuthError::Config(
                "Invalid profile configuration - access key not found".to_string(),
            )),
        );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "us-east-1",
                MockAwsApiResponse {
                    endpoints: vec![AwsDiscoveredEndpoint {
                        service_dns_name: "working-ec2-east.us-east-1.amazonaws.com".to_string(),
                        vpc_endpoint_dns_name: None,
                        private_ips: vec!["10.1.1.100".parse().unwrap()],
                        service_type: "EC2".to_string(),
                        region: "us-east-1".to_string(),
                        vpc_id: Some("vpc-working123".to_string()),
                        comment: Some("Working EC2 East".to_string()),
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
                    endpoints: vec![],
                    should_fail: true,
                    error_type: Some(MockAwsError::ServiceUnavailable),
                    delay_ms: None,
                },
            );

        let final_status = harness.trigger_scan_and_wait().await;

        verify_aws_scanner_status(&final_status, false, 2, 1, 1).unwrap();

        assert!(
            final_status.error_message.is_some(),
            "Should have error message for multiple failures"
        );
        assert!(
            !final_status.detailed_errors.is_empty(),
            "Should have detailed error information"
        );

        let credential_errors: Vec<_> = final_status
            .detailed_errors
            .iter()
            .filter(|e| e.label_or_arn.contains("cred-failing-account") && e.region.is_none())
            .collect();
        assert!(
            !credential_errors.is_empty(),
            "Should have credential errors"
        );

        let api_errors: Vec<_> = final_status
            .detailed_errors
            .iter()
            .filter(|e| {
                e.label_or_arn.contains("working-account")
                    && e.region.as_deref() == Some("us-west-2")
            })
            .collect();
        assert!(
            !api_errors.is_empty(),
            "Should have API errors for us-west-2"
        );

        assert!(
            final_status.discovered_entries_count >= 1,
            "Should have discovered endpoints from working regions"
        );

        let working_cache_key = crate::core::dns_cache::CacheKey::new(
            "working-ec2-east.us-east-1.amazonaws.com",
            hickory_proto::rr::RecordType::A,
        );
        let working_entry = harness.dns_cache.get(&working_cache_key, false).await;
        assert!(working_entry.is_some(), "Working endpoint should be cached");

        let (vpc_calls, config_calls) = harness.get_call_logs();

        assert!(
            config_calls.len() >= 2,
            "Should have attempted credentials for both accounts"
        );

        let working_vpc_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(account, _, _)| account.contains("working-account"))
            .collect();
        assert!(
            working_vpc_calls.len() >= 2,
            "Working account should have attempted both regions"
        );

        let failing_vpc_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(account, _, _)| account.contains("cred-failing-account"))
            .collect();
        assert!(
            failing_vpc_calls.is_empty(),
            "Credential-failing account should not have made VPC calls"
        );

        println!("✅ Mixed credential and API errors test completed");
        println!("   - Credential errors: {}", credential_errors.len());
        println!("   - API errors: {}", api_errors.len());
        println!(
            "   - Working endpoints discovered: {}",
            final_status.discovered_entries_count
        );
        println!("   - Total error types handled: credential + API failures");
    }
}
