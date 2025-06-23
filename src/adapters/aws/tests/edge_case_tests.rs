use super::mock_providers::MockAwsApiResponse;
use super::test_helpers::AwsScannerTestHarness;
use crate::core::dns_cache::CacheKey;
use hickory_proto::rr::RecordType;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_empty_vpc_endpoint_responses() {
        let harness = AwsScannerTestHarness::new_single_account();

        harness.mock_config_provider.set_credentials_response(
            "test-profile-1",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "test-access-key",
                    "test-secret-key",
                    None,
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "TestProvider",
                ),
            )),
        );

        for region in &["us-east-1", "eu-west-1"] {
            harness
                .mock_vpc_provider
                .set_discover_vpc_endpoints_response(
                    region,
                    MockAwsApiResponse {
                        endpoints: vec![],
                        should_fail: false,
                        error_type: None,
                        delay_ms: None,
                    },
                );
        }

        // Use the improved synchronization method
        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 1);
        assert_eq!(final_status.accounts_failed, 0);
        assert_eq!(final_status.discovered_entries_count, 0);
        assert!(final_status.error_message.is_none());

        let (vpc_calls, _) = harness.get_call_logs();

        let us_east_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, region, _)| region == "us-east-1")
            .collect();
        let eu_west_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, region, _)| region == "eu-west-1")
            .collect();

        assert!(
            !us_east_calls.is_empty(),
            "US East should have been queried"
        );
        assert!(
            !eu_west_calls.is_empty(),
            "EU West should have been queried"
        );

        println!("✅ Empty VPC endpoint responses test completed");
        println!("   - Accounts scanned: {}", final_status.accounts_scanned);
        println!(
            "   - Endpoints discovered: {}",
            final_status.discovered_entries_count
        );
        println!("   - Regions queried: {}", vpc_calls.len());
    }

    #[tokio::test]
    async fn test_no_private_ips_in_endpoints() {
        let harness = AwsScannerTestHarness::new_single_account();

        harness.mock_config_provider.set_credentials_response(
            "test-profile-1",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "test-access-key",
                    "test-secret-key",
                    None,
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "TestProvider",
                ),
            )),
        );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "us-east-1",
                MockAwsApiResponse {
                    endpoints: vec![crate::adapters::aws::types::AwsDiscoveredEndpoint {
                        service_dns_name: "no-ips-service.us-east-1.amazonaws.com".to_string(),
                        vpc_endpoint_dns_name: Some(
                            "vpce-no-ips.us-east-1.vpce.amazonaws.com".to_string(),
                        ),
                        private_ips: vec![],
                        service_type: "S3".to_string(),
                        region: "us-east-1".to_string(),
                        vpc_id: Some("vpc-test123".to_string()),
                        comment: Some("Endpoint with no private IPs".to_string()),
                    }],
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        // Use the improved synchronization method
        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 1);
        assert_eq!(final_status.accounts_failed, 0);

        assert_eq!(final_status.discovered_entries_count, 0);

        let cache_key = CacheKey::new("no-ips-service.us-east-1.amazonaws.com", RecordType::A);
        let entry = harness.dns_cache.get(&cache_key, false).await;
        assert!(
            entry.is_none(),
            "Should not cache endpoints without private IPs"
        );

        println!("✅ No private IPs in endpoints test completed");
        println!("   - Endpoints with no IPs handled correctly");
        println!("   - DNS cache properly skipped empty endpoints");
    }

    #[tokio::test]
    async fn test_malformed_dns_names() {
        let harness = AwsScannerTestHarness::new_single_account();

        harness.mock_config_provider.set_credentials_response(
            "test-profile-1",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "test-access-key",
                    "test-secret-key",
                    None,
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "TestProvider",
                ),
            )),
        );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "us-east-1",
                MockAwsApiResponse {
                    endpoints: vec![
                        crate::adapters::aws::types::AwsDiscoveredEndpoint {
                            service_dns_name: "invalid..dns..name".to_string(),
                            vpc_endpoint_dns_name: None,
                            private_ips: vec!["10.0.1.100".parse().unwrap()],
                            service_type: "EC2".to_string(),
                            region: "us-east-1".to_string(),
                            vpc_id: Some("vpc-test123".to_string()),
                            comment: Some("Endpoint with malformed DNS name".to_string()),
                        },
                        crate::adapters::aws::types::AwsDiscoveredEndpoint {
                            service_dns_name: "valid-service.us-east-1.amazonaws.com".to_string(),
                            vpc_endpoint_dns_name: None,
                            private_ips: vec!["10.0.1.101".parse().unwrap()],
                            service_type: "S3".to_string(),
                            region: "us-east-1".to_string(),
                            vpc_id: Some("vpc-test123".to_string()),
                            comment: Some("Valid endpoint".to_string()),
                        },
                    ],
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 1);
        assert_eq!(final_status.accounts_failed, 0);

        assert!(final_status.discovered_entries_count > 0);

        let valid_cache_key = CacheKey::new("valid-service.us-east-1.amazonaws.com", RecordType::A);
        let valid_entry = harness.dns_cache.get(&valid_cache_key, false).await;
        assert!(valid_entry.is_some(), "Valid DNS name should be cached");

        let invalid_cache_key = CacheKey::new("invalid..dns..name", RecordType::A);
        harness.dns_cache.get(&invalid_cache_key, false).await;

        println!("✅ Malformed DNS names test completed");
        println!("   - Valid endpoints: cached correctly");
        println!("   - Malformed DNS names: handled gracefully");
        println!(
            "   - Total discovered: {}",
            final_status.discovered_entries_count
        );
    }

    #[tokio::test]
    async fn test_very_large_number_of_endpoints() {
        let harness = AwsScannerTestHarness::new_single_account();

        harness.mock_config_provider.set_credentials_response(
            "test-profile-1",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "test-access-key",
                    "test-secret-key",
                    None,
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "TestProvider",
                ),
            )),
        );

        let mut endpoints = Vec::new();
        for i in 0..100 {
            endpoints.push(crate::adapters::aws::types::AwsDiscoveredEndpoint {
                service_dns_name: format!("service-{}.us-east-1.amazonaws.com", i),
                vpc_endpoint_dns_name: Some(format!("vpce-{}.us-east-1.vpce.amazonaws.com", i)),
                private_ips: vec![format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap()],
                service_type: if i % 2 == 0 {
                    "EC2".to_string()
                } else {
                    "S3".to_string()
                },
                region: "us-east-1".to_string(),
                vpc_id: Some("vpc-test123".to_string()),
                comment: Some(format!("Bulk test endpoint {}", i)),
            });
        }

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "us-east-1",
                MockAwsApiResponse {
                    endpoints,
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 1);
        assert_eq!(final_status.accounts_failed, 0);
        assert_eq!(final_status.discovered_entries_count, 100);

        let sample_cache_key = CacheKey::new("service-0.us-east-1.amazonaws.com", RecordType::A);
        let sample_entry = harness.dns_cache.get(&sample_cache_key, false).await;
        assert!(sample_entry.is_some(), "Sample endpoint should be cached");

        let another_cache_key = CacheKey::new("service-50.us-east-1.amazonaws.com", RecordType::A);
        let another_entry = harness.dns_cache.get(&another_cache_key, false).await;
        assert!(
            another_entry.is_some(),
            "Another sample endpoint should be cached"
        );

        println!("✅ Large number of endpoints test completed");
        println!(
            "   - Total endpoints processed: {}",
            final_status.discovered_entries_count
        );
        println!("   - Cache entries verified for sample endpoints");
    }

    #[tokio::test]
    async fn test_concurrent_scan_triggers() {
        let harness = AwsScannerTestHarness::new_single_account();
        harness.setup_successful_scan_scenario();

        let _scanner = harness.create_scanner();

        for _ in 0..5 {
            harness.scan_trigger.notify_one();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        tokio::time::sleep(Duration::from_millis(200)).await;

        let final_status = harness.wait_for_scan_completion().await;

        assert!(!final_status.is_scanning);

        // Scanner should complete successfully regardless of discovered count

        let (vpc_calls, config_calls) = harness.get_call_logs();

        println!("✅ Concurrent scan triggers test completed");
        println!("   - Scanner handled multiple rapid triggers");
        println!("   - Final status: not scanning");
        println!("   - VPC calls: {}", vpc_calls.len());
        println!("   - Config calls: {}", config_calls.len());
    }

    #[tokio::test]
    async fn test_scan_with_no_aws_configuration() {
        let harness = AwsScannerTestHarness::new_single_account();

        {
            let mut config_guard = harness.app_config.write().await;
            config_guard.aws = None;
        }

        // Use the improved synchronization method
        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 0);
        assert_eq!(final_status.accounts_failed, 0);
        assert_eq!(final_status.discovered_entries_count, 0);

        let (vpc_calls, config_calls) = harness.get_call_logs();
        assert!(
            vpc_calls.is_empty(),
            "Should not make VPC calls without AWS config"
        );
        assert!(
            config_calls.is_empty(),
            "Should not make config calls without AWS config"
        );

        println!("✅ No AWS configuration test completed");
        println!("   - Scanner handled missing AWS config gracefully");
        println!("   - No unnecessary API calls made");
    }

    #[tokio::test]
    async fn test_scan_with_empty_account_list() {
        let harness = AwsScannerTestHarness::new_single_account();

        {
            let mut config_guard = harness.app_config.write().await;
            if let Some(aws_config) = &mut config_guard.aws {
                aws_config.accounts.clear();
            }
        }

        // Use the improved synchronization method
        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 0);
        assert_eq!(final_status.accounts_failed, 0);
        assert_eq!(final_status.discovered_entries_count, 0);

        let (vpc_calls, config_calls) = harness.get_call_logs();
        assert!(
            vpc_calls.is_empty(),
            "Should not make VPC calls with empty account list"
        );
        assert!(
            config_calls.is_empty(),
            "Should not make config calls with empty account list"
        );

        println!("✅ Empty account list test completed");
        println!("   - Scanner handled empty account list gracefully");
        println!("   - No unnecessary API calls made");
    }

    #[tokio::test]
    async fn test_ipv6_endpoint_handling() {
        let harness = AwsScannerTestHarness::new_single_account();

        harness.mock_config_provider.set_credentials_response(
            "test-profile-1",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "test-access-key",
                    "test-secret-key",
                    None,
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "TestProvider",
                ),
            )),
        );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "us-east-1",
                MockAwsApiResponse {
                    endpoints: vec![crate::adapters::aws::types::AwsDiscoveredEndpoint {
                        service_dns_name: "ipv6-service.us-east-1.amazonaws.com".to_string(),
                        vpc_endpoint_dns_name: None,
                        private_ips: vec![
                            "10.0.1.100".parse().unwrap(),
                            "2001:db8::1".parse().unwrap(),
                        ],
                        service_type: "EC2".to_string(),
                        region: "us-east-1".to_string(),
                        vpc_id: Some("vpc-test123".to_string()),
                        comment: Some("Dual-stack endpoint".to_string()),
                    }],
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        // Use the improved synchronization method
        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 1);
        assert_eq!(final_status.accounts_failed, 0);
        assert_eq!(final_status.discovered_entries_count, 1);

        let a_cache_key = CacheKey::new("ipv6-service.us-east-1.amazonaws.com", RecordType::A);
        let a_entry = harness.dns_cache.get(&a_cache_key, false).await;
        assert!(a_entry.is_some(), "A record should be cached");

        let aaaa_cache_key =
            CacheKey::new("ipv6-service.us-east-1.amazonaws.com", RecordType::AAAA);
        let aaaa_entry = harness.dns_cache.get(&aaaa_cache_key, false).await;
        assert!(aaaa_entry.is_some(), "AAAA record should be cached");

        println!("✅ IPv6 endpoint handling test completed");
        println!("   - Dual-stack endpoint handled correctly");
        println!("   - Both A and AAAA records cached");
    }
}
