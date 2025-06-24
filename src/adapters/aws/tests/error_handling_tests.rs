use super::mock_providers::{MockAwsApiResponse, MockAwsError};
use super::test_helpers::AwsScannerTestHarness;
use crate::core::error::AwsAuthError;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_credential_retrieval_failure() {
        let harness = AwsScannerTestHarness::new();
        harness.setup_credential_failure_scenario();

        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 2);
        assert_eq!(final_status.accounts_failed, 1);
        assert!(final_status.error_message.is_some());

        assert!(!final_status.detailed_errors.is_empty());
        let credential_errors: Vec<_> = final_status
            .detailed_errors
            .iter()
            .filter(|e| e.error.contains("Access denied") || e.error.contains("credential"))
            .collect();
        assert!(
            !credential_errors.is_empty(),
            "Should have credential-related errors"
        );

        assert!(
            final_status.discovered_entries_count > 0,
            "Working account should have discovered endpoints"
        );

        let (_vpc_calls, config_calls) = harness.get_call_logs();

        let credential_calls: Vec<_> = config_calls
            .iter()
            .filter(|call| call.contains("get_credentials_for_account"))
            .collect();
        assert!(
            credential_calls.len() >= 2,
            "Both accounts should have been attempted"
        );

        println!("✅ Credential retrieval failure test completed");
        println!("   - Accounts failed: {}", final_status.accounts_failed);
        println!(
            "   - Detailed errors: {}",
            final_status.detailed_errors.len()
        );
        println!(
            "   - Working endpoints discovered: {}",
            final_status.discovered_entries_count
        );
    }

    #[tokio::test]
    async fn test_api_call_failures() {
        let harness = AwsScannerTestHarness::new_single_account();
        harness.setup_api_failure_scenario();

        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 1);
        assert!(final_status.error_message.is_some());

        assert!(!final_status.detailed_errors.is_empty());
        let api_errors: Vec<_> = final_status
            .detailed_errors
            .iter()
            .filter(|e| {
                e.error.contains("ServiceUnavailable")
                    || e.error.contains("temporarily unavailable")
            })
            .collect();
        assert!(!api_errors.is_empty(), "Should have API failure errors");

        let (vpc_calls, _) = harness.get_call_logs();

        let discover_calls: Vec<_> = vpc_calls
            .iter()
            .filter(|(_, _, operation)| operation == "discover_vpc_endpoints")
            .collect();
        assert!(
            !discover_calls.is_empty(),
            "VPC endpoint discovery should have been attempted"
        );

        println!("✅ API call failures test completed");
        println!("   - API errors recorded: {}", api_errors.len());
        println!("   - VPC discovery attempts: {}", discover_calls.len());
    }

    #[tokio::test]
    async fn test_mfa_required_scenario() {
        let harness = AwsScannerTestHarness::new();
        harness.setup_mfa_required_scenario();

        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);

        let mfa_errors: Vec<_> = final_status
            .detailed_errors
            .iter()
            .filter(|e| e.error.contains("MFA") || e.error.contains("MultiFactorAuthentication"))
            .collect();

        let messages = harness.mock_user_interaction.get_messages();

        let (_, config_calls) = harness.get_call_logs();

        let role_calls: Vec<_> = config_calls
            .iter()
            .filter(|call| call.contains("get_credentials_for_role"))
            .collect();
        assert!(
            !role_calls.is_empty(),
            "Role assumption should have been attempted"
        );

        println!("✅ MFA required scenario test completed");
        println!("   - MFA errors recorded: {}", mfa_errors.len());
        println!("   - User interaction messages: {}", messages.len());
        println!("   - Role assumption attempts: {}", role_calls.len());
    }

    #[tokio::test]
    async fn test_partial_region_failures() {
        let harness = AwsScannerTestHarness::new_single_account();

        harness.mock_config_provider.set_credentials_response(
            "test-profile-1",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "test-access-key",
                    "test-secret-key",
                    Some("test-session-token".to_string()),
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "TestProvider",
                ),
            )),
        );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "eu-west-1",
                MockAwsApiResponse {
                    endpoints: vec![crate::adapters::aws::types::AwsDiscoveredEndpoint {
                        service_dns_name: "successful-service.eu-west-1.amazonaws.com".to_string(),
                        vpc_endpoint_dns_name: None,
                        private_ips: vec!["10.0.1.100".parse().unwrap()],
                        service_type: "EC2".to_string(),
                        region: "eu-west-1".to_string(),
                        vpc_id: Some("vpc-test123".to_string()),
                        comment: Some("Test EC2 endpoint".to_string()),
                    }],
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "us-east-1",
                MockAwsApiResponse {
                    endpoints: vec![],
                    should_fail: true,
                    error_type: Some(MockAwsError::AccessDenied),
                    delay_ms: None,
                },
            );

        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 1);
        assert!(
            final_status.discovered_entries_count > 0,
            "Should have discovered endpoints from successful region"
        );

        let region_errors: Vec<_> = final_status
            .detailed_errors
            .iter()
            .filter(|e| e.region.is_some())
            .collect();
        assert!(
            !region_errors.is_empty(),
            "Should have region-specific errors"
        );

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
            "US East should have been attempted"
        );
        assert!(
            !eu_west_calls.is_empty(),
            "EU West should have been attempted"
        );

        println!("✅ Partial region failures test completed");
        println!("   - Region-specific errors: {}", region_errors.len());
        println!(
            "   - Successful discoveries: {}",
            final_status.discovered_entries_count
        );
        println!("   - US East attempts: {}", us_east_calls.len());
        println!("   - EU West attempts: {}", eu_west_calls.len());
    }

    #[tokio::test]
    async fn test_timeout_handling() {
        let harness = AwsScannerTestHarness::new();

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
                    endpoints: vec![],
                    should_fail: true,
                    error_type: Some(MockAwsError::Timeout),
                    delay_ms: Some(50),
                },
            );

        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);

        let timeout_errors: Vec<_> = final_status
            .detailed_errors
            .iter()
            .filter(|e| e.error.contains("timeout") || e.error.contains("timed out"))
            .collect();
        assert!(
            !timeout_errors.is_empty(),
            "Should have timeout-related errors"
        );

        println!("✅ Timeout handling test completed");
        println!("   - Timeout errors recorded: {}", timeout_errors.len());
    }

    #[tokio::test]
    async fn test_permission_denied_handling() {
        let harness = AwsScannerTestHarness::new();

        harness.mock_config_provider.set_credentials_response(
            "test-profile-1",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "limited-access-key",
                    "limited-secret-key",
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
                    endpoints: vec![],
                    should_fail: true,
                    error_type: Some(MockAwsError::AccessDenied),
                    delay_ms: None,
                },
            );

        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert!(final_status.error_message.is_some());

        let permission_errors: Vec<_> = final_status
            .detailed_errors
            .iter()
            .filter(|e| e.error.contains("Access") || e.error.contains("permission"))
            .collect();

        let us_east_errors: Vec<_> = final_status
            .detailed_errors
            .iter()
            .filter(|e| e.region.as_deref() == Some("us-east-1"))
            .collect();
        assert!(
            !us_east_errors.is_empty(),
            "Should have errors for US East region"
        );

        println!("✅ Permission denied handling test completed");
        println!("   - Permission errors: {}", permission_errors.len());
        println!("   - US East errors: {}", us_east_errors.len());
    }

    #[tokio::test]
    async fn test_mixed_success_failure_across_accounts() {
        let harness = AwsScannerTestHarness::new();

        harness.mock_config_provider.set_credentials_response(
            "test-profile-1",
            Ok(crate::core::types::AwsCredentials::from(
                aws_credential_types::Credentials::new(
                    "working-access-key-1",
                    "working-secret-key-1",
                    None,
                    Some(std::time::SystemTime::now() + Duration::from_secs(3600)),
                    "TestProvider1",
                ),
            )),
        );

        harness
            .mock_vpc_provider
            .set_discover_vpc_endpoints_response(
                "us-east-1",
                MockAwsApiResponse {
                    endpoints: vec![crate::adapters::aws::types::AwsDiscoveredEndpoint {
                        service_dns_name: "working-service-1.us-east-1.amazonaws.com".to_string(),
                        vpc_endpoint_dns_name: None,
                        private_ips: vec!["10.0.1.100".parse().unwrap()],
                        service_type: "EC2".to_string(),
                        region: "us-east-1".to_string(),
                        vpc_id: Some("vpc-test123".to_string()),
                        comment: Some("Test EC2 endpoint".to_string()),
                    }],
                    should_fail: false,
                    error_type: None,
                    delay_ms: None,
                },
            );

        harness.mock_config_provider.set_credentials_response(
            "test-profile-2",
            Err(AwsAuthError::Config(
                "Invalid profile configuration".to_string(),
            )),
        );

        let final_status = harness.trigger_scan_and_wait().await;

        assert!(!final_status.is_scanning);
        assert_eq!(final_status.accounts_scanned, 2);
        assert_eq!(final_status.accounts_failed, 1);
        assert!(
            final_status.discovered_entries_count > 0,
            "Working account should have discovered endpoints"
        );
        assert!(
            final_status.error_message.is_some(),
            "Should report overall errors"
        );

        assert!(
            !final_status.detailed_errors.is_empty(),
            "Should have detailed error information"
        );

        let (vpc_calls, config_calls) = harness.get_call_logs();

        assert!(
            config_calls.len() >= 2,
            "Both accounts should have been attempted"
        );

        assert!(
            !vpc_calls.is_empty(),
            "Successful account should have made VPC calls"
        );

        println!("✅ Mixed success/failure test completed");
        println!("   - Total accounts: 2");
        println!("   - Failed accounts: {}", final_status.accounts_failed);
        println!(
            "   - Successful discoveries: {}",
            final_status.discovered_entries_count
        );
        println!("   - Config calls: {}", config_calls.len());
        println!("   - VPC calls: {}", vpc_calls.len());
    }
}
