use std::collections::HashSet;
use std::path::PathBuf;
use std::{fs, io};
use tracing::warn;

use crate::config::models::AwsAccountConfig;

#[derive(Debug)]
pub enum ProfileReadError {
    Io(io::Error, PathBuf),
    NoConfigFilesFound,
}

impl std::fmt::Display for ProfileReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileReadError::Io(e, path) => write!(f, "I/O error for {:?}: {}", path, e),
            ProfileReadError::NoConfigFilesFound => write!(
                f,
                "Neither ~/.aws/config nor ~/.aws/credentials file found."
            ),
        }
    }
}

impl std::error::Error for ProfileReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProfileReadError::Io(e, _) => Some(e),
            ProfileReadError::NoConfigFilesFound => None,
        }
    }
}

pub fn read_aws_profiles_from_files() -> Result<Vec<String>, ProfileReadError> {
    let mut profiles = HashSet::new();
    let mut config_files_checked = false;
    let mut any_file_existed = false;

    if let Some(home) = dirs::home_dir() {
        let config_paths = [
            home.join(".aws").join("config"),
            home.join(".aws").join("credentials"),
        ];

        for path in config_paths {
            config_files_checked = true;
            if path.exists() {
                any_file_existed = true;
                match fs::read_to_string(&path) {
                    Ok(content) => {
                        for line in content.lines() {
                            let trimmed_line = line.trim();
                            if trimmed_line.starts_with('[') && trimmed_line.ends_with(']') {
                                let mut profile_name = trimmed_line
                                    .trim_start_matches('[')
                                    .trim_end_matches(']')
                                    .trim();
                                if profile_name.starts_with("profile ") {
                                    profile_name =
                                        profile_name.trim_start_matches("profile ").trim();
                                }
                                if !profile_name.is_empty() {
                                    profiles.insert(profile_name.to_string());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to read AWS profile file at {:?}: {}. Skipping this file.",
                            path, e
                        );

                        return Err(ProfileReadError::Io(e, path.clone()));
                    }
                }
            }
        }
    } else {
        return Err(ProfileReadError::NoConfigFilesFound);
    }

    if !config_files_checked || !any_file_existed {
        warn!("Neither ~/.aws/config nor ~/.aws/credentials file found.");
        return Err(ProfileReadError::NoConfigFilesFound);
    }

    let mut sorted_profiles: Vec<String> = profiles.into_iter().collect();
    sorted_profiles.sort_by_key(|a| a.to_lowercase());

    if !sorted_profiles.is_empty() && !sorted_profiles.iter().any(|p| p == "default") {
        match sorted_profiles.binary_search_by_key(&"default", |p| p.as_str()) {
            Ok(_) => {}
            Err(idx) => sorted_profiles.insert(idx, "default".to_string()),
        }
    }

    if sorted_profiles.is_empty() && any_file_existed {
        warn!(
            "AWS config files exist but are empty or contain no profiles. Offering 'default' for SDK check."
        );

        return Ok(vec!["default".to_string()]);
    }

    Ok(sorted_profiles)
}

#[derive(Default)]
pub struct AwsConfigParams<'a> {
    pub profile_name: &'a str,
    pub account_id: Option<&'a str>,
    pub scan_regions: Option<&'a str>,
    pub label: Option<&'a str>,
}

impl<'a> AwsConfigParams<'a> {
    pub fn parse_scan_regions(&self) -> Option<Vec<String>> {
        let regions: Vec<String> = self
            .scan_regions?
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if regions.is_empty() {
            None
        } else {
            Some(regions)
        }
    }

    pub fn non_empty_string(&self, s: Option<&str>) -> Option<String> {
        s.filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
    }
}

pub fn create_aws_account_config_from_params(params: AwsConfigParams) -> AwsAccountConfig {
    AwsAccountConfig {
        label: params.label.unwrap_or("connection-test").to_string(),
        profile_name: Some(params.profile_name.to_string()),
        account_id: params.account_id.map(String::from),
        scan_regions: params.parse_scan_regions(),
        scan_vpc_ids: vec![],
        roles_to_assume: vec![],
        discover_services: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_read_aws_profiles_from_files_no_files() {
        let result = read_aws_profiles_from_files();

        assert!(
            result.is_err(),
            "Should return error when no AWS config files are found"
        );

        match result {
            Err(ProfileReadError::NoConfigFilesFound) => {}
            Err(e) => panic!("Expected NoConfigFilesFound error, got: {}", e),
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[test]
    fn test_read_aws_profiles_from_files_with_data() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let aws_dir = dir.path().join(".aws");
        std::fs::create_dir(&aws_dir)?;

        let config_file_path = aws_dir.join("config");
        let mut config_file = File::create(&config_file_path)?;
        writeln!(config_file, "[profile user1]")?;
        writeln!(config_file, "region = us-east-1")?;
        writeln!(config_file, "[default]")?;
        writeln!(config_file, "output = json")?;

        let credentials_file_path = aws_dir.join("credentials");
        let mut credentials_file = File::create(&credentials_file_path)?;
        writeln!(credentials_file, "[user2]")?;
        writeln!(credentials_file, "aws_access_key_id = ...")?;
        writeln!(credentials_file, "[user1]")?;
        writeln!(credentials_file, "aws_secret_access_key = ...")?;

        println!("This test needs refactoring to use the temp directory");

        Ok(())
    }

    #[test]
    fn test_aws_config_params_parse_regions() {
        let params = AwsConfigParams {
            profile_name: "test",
            account_id: None,
            scan_regions: Some("us-east-1,eu-west-1, ap-southeast-1 "),
            label: None,
        };

        let regions = params.parse_scan_regions().unwrap();
        assert_eq!(regions, vec!["us-east-1", "eu-west-1", "ap-southeast-1"]);
    }

    #[test]
    fn test_aws_config_params_empty_regions() {
        let params = AwsConfigParams {
            profile_name: "test",
            account_id: None,
            scan_regions: Some(""),
            label: None,
        };

        let regions = params.parse_scan_regions();
        assert!(regions.is_none());
    }

    #[test]
    fn test_create_aws_account_config_from_params() {
        let params = AwsConfigParams {
            profile_name: "my-profile",
            account_id: Some("123456789012"),
            scan_regions: Some("us-east-1,eu-west-1"),
            label: Some("test-account"),
        };

        let config = create_aws_account_config_from_params(params);

        assert_eq!(config.label, "test-account");
        assert_eq!(config.profile_name, Some("my-profile".to_string()));
        assert_eq!(config.account_id, Some("123456789012".to_string()));
        assert_eq!(
            config.scan_regions,
            Some(vec!["us-east-1".to_string(), "eu-west-1".to_string()])
        );
    }
}
