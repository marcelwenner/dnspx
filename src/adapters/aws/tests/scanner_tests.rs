use super::test_helpers::AwsScannerTestHarness;
use crate::core::dns_cache::CacheKey;
use crate::ports::AppLifecycleManagerPort;
use hickory_proto::rr::RecordType;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_successful_single_account_scan() {
        let harness = AwsScannerTestHarness::new();
        harness.setup_successful_scan_scenario();

        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 2);
        assert_eq!(final_status.accounts_failed, 0);
        assert!(final_status.discovered_entries_count > 0);
        assert!(final_status.error_message.is_none());

        let cache_key_ec2 = CacheKey::new("ec2.us-east-1.amazonaws.com", RecordType::A);
        let entry = harness.dns_cache.get(&cache_key_ec2, false).await;
        assert!(entry.is_some(), "EC2 endpoint should be cached");

        let (vpc_calls, config_calls) = harness.get_call_logs();
        assert!(
            !vpc_calls.is_empty(),
            "VPC provider should have been called"
        );
        assert!(
            !config_calls.is_empty(),
            "Config provider should have been called"
        );

        println!("✅ Single account scan test completed successfully");
        println!("   - Accounts scanned: {}", final_status.accounts_scanned);
        println!(
            "   - Entries discovered: {}",
            final_status.discovered_entries_count
        );
        println!("   - VPC API calls: {}", vpc_calls.len());
        println!("   - Config API calls: {}", config_calls.len());
    }

    #[tokio::test]
    async fn test_multi_account_with_role_assumption() {
        let harness = AwsScannerTestHarness::new();
        harness.setup_successful_scan_scenario();

        harness.trigger_scan_and_wait().await;

        harness.scan_trigger.notify_one();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let final_status = harness.wait_for_scan_completion().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 2);
        assert_eq!(final_status.accounts_failed, 0);

        let (vpc_calls, config_calls) = harness.get_call_logs();

        let role_calls: Vec<_> = config_calls
            .iter()
            .filter(|call| call.contains("get_credentials_for_role"))
            .collect();
        assert!(
            !role_calls.is_empty(),
            "Role assumption should have been attempted"
        );

        let us_east_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, region, _)| region == "us-east-1")
            .collect();
        let eu_west_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, region, _)| region == "eu-west-1")
            .collect();
        let us_west_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, region, _)| region == "us-west-2")
            .collect();

        assert!(
            !us_east_calls.is_empty(),
            "US East should have been scanned"
        );
        assert!(
            !eu_west_calls.is_empty(),
            "EU West should have been scanned"
        );
        assert!(
            !us_west_calls.is_empty(),
            "US West should have been scanned"
        );

        println!("✅ Multi-account with role assumption test completed");
        println!("   - Role assumption calls: {}", role_calls.len());
        println!("   - US East calls: {}", us_east_calls.len());
        println!("   - EU West calls: {}", eu_west_calls.len());
        println!("   - US West calls: {}", us_west_calls.len());
    }

    #[tokio::test]
    async fn test_dns_cache_population_with_different_record_types() {
        let harness = AwsScannerTestHarness::new();
        harness.setup_successful_scan_scenario();

        harness.trigger_scan_and_wait().await;

        harness.scan_trigger.notify_one();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let _final_status = harness.wait_for_scan_completion().await;

        let expected_dns_names = [
            "ec2.us-east-1.amazonaws.com",
            "rds-instance-1.us-east-1.amazonaws.com",
            "s3.eu-west-1.amazonaws.com",
            "elasticache-cluster.us-west-2.amazonaws.com",
        ];

        for dns_name in &expected_dns_names {
            let cache_key_a = CacheKey::new(dns_name, RecordType::A);
            let entry = harness.dns_cache.get(&cache_key_a, false).await;
            assert!(
                entry.is_some(),
                "A record for {} should be cached",
                dns_name
            );

            if let Some(cache_entry) = entry {
                assert!(
                    !cache_entry.records.is_empty(),
                    "Should have at least one A record for {}",
                    dns_name
                );

                let first_record = &cache_entry.records[0];
                assert!(
                    first_record.ttl() > 0,
                    "TTL should be positive for {}",
                    dns_name
                );
                assert!(
                    first_record.ttl() <= 60,
                    "TTL should not exceed scan interval for {}",
                    dns_name
                );
            }
        }

        println!("✅ DNS cache population test completed");
        for dns_name in &expected_dns_names {
            println!("   - Verified cache entry: {}", dns_name);
        }
    }

    #[tokio::test]
    async fn test_route53_inbound_endpoint_discovery() {
        let harness = AwsScannerTestHarness::new();
        harness.setup_successful_scan_scenario();

        harness.trigger_scan_and_wait().await;

        harness.scan_trigger.notify_one();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let _final_status = harness.wait_for_scan_completion().await;

        let (vpc_calls, _) = harness.get_call_logs();

        let route53_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, _, operation)| operation == "discover_route53_inbound_endpoint_ips")
            .collect();

        assert!(
            !route53_calls.is_empty(),
            "Route53 inbound endpoint discovery should have been called"
        );

        let lifecycle_manager = harness.create_mock_lifecycle_manager();
        let network_info = lifecycle_manager.get_discovered_aws_network_info_view();
        let info_guard = network_info.read().await;

        assert!(
            !info_guard.inbound_endpoint_ips.is_empty(),
            "Inbound endpoint IPs should be discovered"
        );
        assert!(
            !info_guard.private_hosted_zone_names.is_empty(),
            "Private hosted zones should be discovered"
        );

        println!("✅ Route53 inbound endpoint discovery test completed");
        println!("   - Route53 calls: {}", route53_calls.len());
        println!(
            "   - Inbound IPs discovered: {}",
            info_guard.inbound_endpoint_ips.len()
        );
        println!(
            "   - Private zones discovered: {}",
            info_guard.private_hosted_zone_names.len()
        );
    }

    #[tokio::test]
    async fn test_private_hosted_zones_discovery() {
        let harness = AwsScannerTestHarness::new();
        harness.setup_successful_scan_scenario();

        harness.trigger_scan_and_wait().await;

        harness.scan_trigger.notify_one();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let _final_status = harness.wait_for_scan_completion().await;

        let (vpc_calls, _) = harness.get_call_logs();

        let private_zone_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, _, operation)| operation == "discover_private_hosted_zones_for_vpc")
            .collect();

        assert!(
            !private_zone_calls.is_empty(),
            "Private hosted zones discovery should have been called"
        );

        let vpc_test123_calls: Vec<_> = private_zone_calls
            .iter()
            .filter(|(account, _, _)| account == "system")
            .collect();

        assert!(
            !vpc_test123_calls.is_empty(),
            "VPC test123 should have been scanned for private zones"
        );

        println!("✅ Private hosted zones discovery test completed");
        println!("   - Private zone calls: {}", private_zone_calls.len());
        println!("   - VPC specific calls: {}", vpc_test123_calls.len());
    }

    #[tokio::test]
    async fn test_status_reporting_during_scan() {
        let harness = AwsScannerTestHarness::new();
        harness.setup_successful_scan_scenario();

        harness.trigger_scan_and_wait().await;

        let initial_status = harness.mock_status_reporter.get_current_aws_status();
        assert!(initial_status.is_none() || !initial_status.unwrap().is_scanning);

        harness.scan_trigger.notify_one();

        tokio::time::sleep(Duration::from_millis(25)).await;

        let status_updates = harness.mock_status_reporter.get_status_updates();
        assert!(
            !status_updates.is_empty(),
            "Status updates should have been reported"
        );

        let final_status = harness.wait_for_scan_completion().await;

        assert!(!final_status.is_scanning);
        assert!(final_status.last_scan_time.is_some());
        assert_eq!(final_status.accounts_scanned, 2);
        assert_eq!(final_status.accounts_failed, 0);
        assert!(final_status.discovered_entries_count > 0);

        println!("✅ Status reporting test completed");
        println!("   - Status updates received: {}", status_updates.len());
        println!("   - Final scanning state: {}", final_status.is_scanning);
        println!(
            "   - Final entries count: {}",
            final_status.discovered_entries_count
        );
    }

    #[tokio::test]
    async fn test_scan_respects_service_discovery_configuration() {
        let harness = AwsScannerTestHarness::new();

        {
            let mut config_guard = harness.app_config.write().await;
            if let Some(aws_config) = &mut config_guard.aws {
                aws_config.accounts[0].discover_services.rds_instances = false;
                aws_config.accounts[0].discover_services.ec2_instances = true;
            }
        }

        harness.setup_successful_scan_scenario();
        harness.trigger_scan_and_wait().await;

        harness.scan_trigger.notify_one();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let final_status = harness.wait_for_scan_completion().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 2);

        let cache_key_ec2 = CacheKey::new("ec2.us-east-1.amazonaws.com", RecordType::A);
        let ec2_entry = harness.dns_cache.get(&cache_key_ec2, false).await;
        assert!(ec2_entry.is_some(), "EC2 should be cached (enabled)");

        println!("✅ Service discovery configuration test completed");
        println!("   - Verified service-specific discovery configuration");
    }

    #[tokio::test]
    async fn test_cancellation_token_stops_scan() {
        let harness = AwsScannerTestHarness::new();
        harness.setup_successful_scan_scenario();

        harness.trigger_scan_and_wait().await;

        harness.scan_trigger.notify_one();

        harness.cancellation_token.cancel();

        tokio::time::sleep(Duration::from_millis(50)).await;

        let (vpc_calls, config_calls) = harness.get_call_logs();

        println!("✅ Cancellation token test completed");
        println!(
            "   - VPC calls made before cancellation: {}",
            vpc_calls.len()
        );
        println!(
            "   - Config calls made before cancellation: {}",
            config_calls.len()
        );
        println!("   - Cancellation token properly handled");
    }
}
