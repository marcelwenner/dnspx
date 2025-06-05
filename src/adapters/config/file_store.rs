use crate::config::DEFAULT_CONFIG_FILE_NAME_V2;
use crate::config::models::{AppConfig, DotNetLegacyConfig};
use crate::core::error::ConfigError;
use crate::ports::ConfigurationStore;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

pub(crate) struct JsonFileConfigAdapter {
    base_path: PathBuf,
}

impl JsonFileConfigAdapter {
    pub(crate) fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    fn read_json_file<T: DeserializeOwned>(&self, file_path: &Path) -> Result<T, ConfigError> {
        debug!("Reading JSON file: {:?}", file_path);
        let file = File::open(file_path).map_err(|e| ConfigError::ReadFile {
            path: file_path.to_path_buf(),
            source: e,
        })?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).map_err(|e| ConfigError::Deserialize {
            path: file_path.to_path_buf(),
            source: Box::new(e),
        })
    }

    fn read_toml_file<T: DeserializeOwned>(&self, file_path: &Path) -> Result<T, ConfigError> {
        debug!("Reading TOML file: {:?}", file_path);
        let content = fs::read_to_string(file_path).map_err(|e| ConfigError::ReadFile {
            path: file_path.to_path_buf(),
            source: e,
        })?;
        toml::from_str(&content).map_err(|e| ConfigError::Deserialize {
            path: file_path.to_path_buf(),
            source: Box::new(e),
        })
    }

    fn write_toml_file<T: Serialize>(&self, data: &T, file_path: &Path) -> Result<(), ConfigError> {
        debug!("Writing TOML file: {:?}", file_path);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).map_err(|e| ConfigError::WriteFile {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let content =
            toml::to_string_pretty(data).map_err(|e| ConfigError::Serialize(Box::new(e)))?;
        fs::write(file_path, content).map_err(|e| ConfigError::WriteFile {
            path: file_path.to_path_buf(),
            source: e,
        })
    }
}

impl ConfigurationStore for JsonFileConfigAdapter {
    fn load_dotnet_legacy_config_files(
        &self,
        main_path_opt: Option<&Path>,
        rules_path_opt: Option<&Path>,
        hosts_path_opt: Option<&Path>,
    ) -> Result<DotNetLegacyConfig, ConfigError> {
        let mut dotnet_legacy_config = DotNetLegacyConfig::default();

        let base_for_legacy = main_path_opt
            .and_then(|p| p.parent())
            .or_else(|| Some(&self.base_path))
            .unwrap_or_else(|| Path::new("."));

        let main_config_path =
            main_path_opt.map_or_else(|| base_for_legacy.join("config.json"), PathBuf::from);

        if main_config_path.exists() {
            info!("Found .NET legacy main config: {:?}", main_config_path);
            dotnet_legacy_config.main_config = self.read_json_file(&main_config_path)?;
            dotnet_legacy_config.main_config_path = Some(main_config_path);

            let rules_base = rules_path_opt
                .and_then(|p| p.parent())
                .unwrap_or(base_for_legacy);
            let rules_path =
                rules_path_opt.map_or_else(|| rules_base.join("rules.json"), PathBuf::from);

            if rules_path.exists() {
                info!("Found .NET legacy rules config: {:?}", rules_path);
                dotnet_legacy_config.rules_config = Some(self.read_json_file(&rules_path)?);
                dotnet_legacy_config.rules_config_path = Some(rules_path);
            } else {
                warn!(
                    ".NET legacy rules.json not found at inferred/provided path: {:?}",
                    rules_path
                );
            }

            let hosts_base = hosts_path_opt
                .and_then(|p| p.parent())
                .unwrap_or(base_for_legacy);
            let hosts_path =
                hosts_path_opt.map_or_else(|| hosts_base.join("hosts.json"), PathBuf::from);

            if hosts_path.exists() {
                info!("Found .NET legacy hosts config: {:?}", hosts_path);
                dotnet_legacy_config.hosts_config = Some(self.read_json_file(&hosts_path)?);
                dotnet_legacy_config.hosts_config_path = Some(hosts_path);
            } else {
                warn!(
                    ".NET legacy hosts.json not found at inferred/provided path: {:?}",
                    hosts_path
                );
            }
        } else {
            info!(
                "No .NET legacy main config file (config.json) found at {:?}. Assuming no .NET legacy config.",
                main_config_path
            );
        }
        Ok(dotnet_legacy_config)
    }

    fn load_app_config_file(&self, path: &Path) -> Result<AppConfig, ConfigError> {
        if !path.exists() {
            info!(
                "App config file (TOML) not found at {:?}. Will use default.",
                path
            );
            let default_config = AppConfig::default();
            return Ok(default_config);
        }
        self.read_toml_file(path)
    }

    fn save_app_config_file(&self, config: &AppConfig, path: &Path) -> Result<(), ConfigError> {
        self.write_toml_file(config, path)
    }

    fn backup_dotnet_legacy_config_files(
        &self,
        legacy_config: &DotNetLegacyConfig,
    ) -> Result<(), ConfigError> {
        let paths_to_backup = [
            &legacy_config.main_config_path,
            &legacy_config.rules_config_path,
            &legacy_config.hosts_config_path,
        ];
        for path_opt in paths_to_backup.iter().filter_map(|p| p.as_ref()) {
            if path_opt.exists() {
                let backup_path = path_opt.with_extension(format!(
                    "{}.migrated_bak",
                    path_opt
                        .extension()
                        .and_then(|os| os.to_str())
                        .unwrap_or("json")
                ));

                info!(
                    "Backing up .NET legacy file {:?} to {:?}",
                    path_opt, backup_path
                );
                fs::rename(path_opt, &backup_path).map_err(|e| ConfigError::WriteFile {
                    path: path_opt.clone(),
                    source: e,
                })?;
            }
        }
        Ok(())
    }

    fn get_default_config_path(&self) -> Result<PathBuf, ConfigError> {
        let path = self.base_path.join(DEFAULT_CONFIG_FILE_NAME_V2);
        if !path.is_absolute() {
            if let Ok(abs_path) = std::env::current_dir().map(|p| p.join(&path)) {
                return Ok(abs_path);
            }
        }
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{AppConfig, DotNetLegacyConfig};
    use crate::core::error::ConfigError;
    use serde::{Deserialize, Serialize};
    use std::fs;
    use tempfile::{TempDir, tempdir};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestJsonData {
        name: String,
        value: i32,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestTomlData {
        title: String,
        count: u32,
    }

    struct TestSetup {
        temp_dir: TempDir,
        adapter: JsonFileConfigAdapter,
    }

    impl TestSetup {
        fn new() -> Self {
            let temp_dir = tempdir().expect("Failed to create temp directory");
            let adapter = JsonFileConfigAdapter::new(temp_dir.path().to_path_buf());
            Self { temp_dir, adapter }
        }

        fn create_file(&self, filename: &str, content: &str) -> PathBuf {
            let file_path = self.temp_dir.path().join(filename);
            fs::write(&file_path, content).expect("Failed to write test file");
            file_path
        }
    }

    mod constructor_tests {
        use super::*;

        #[test]
        fn new_creates_adapter_with_correct_base_path() {
            let base_path = PathBuf::from("/test/path");
            let adapter = JsonFileConfigAdapter::new(base_path.clone());
            assert_eq!(adapter.base_path, base_path);
        }
    }

    mod json_file_reading_tests {
        use super::*;

        #[test]
        fn read_json_file_success() {
            let setup = TestSetup::new();
            let test_data = TestJsonData {
                name: "test".to_string(),
                value: 42,
            };
            let json_content = serde_json::to_string(&test_data).unwrap();
            let file_path = setup.create_file("test.json", &json_content);

            let result: Result<TestJsonData, ConfigError> =
                setup.adapter.read_json_file(&file_path);

            assert!(result.is_ok());
            assert_eq!(result.unwrap(), test_data);
        }

        #[test]
        fn read_json_file_not_found() {
            let setup = TestSetup::new();
            let non_existent_path = setup.temp_dir.path().join("nonexistent.json");

            let result: Result<TestJsonData, ConfigError> =
                setup.adapter.read_json_file(&non_existent_path);

            assert!(result.is_err());
            match result.unwrap_err() {
                ConfigError::ReadFile { path, .. } => {
                    assert_eq!(path, non_existent_path);
                }
                _ => panic!("Expected ReadFile error"),
            }
        }

        #[test]
        fn read_json_file_invalid_json() {
            let setup = TestSetup::new();
            let file_path = setup.create_file("invalid.json", "{ invalid json }");

            let result: Result<TestJsonData, ConfigError> =
                setup.adapter.read_json_file(&file_path);

            assert!(result.is_err());
            match result.unwrap_err() {
                ConfigError::Deserialize { path, .. } => {
                    assert_eq!(path, file_path);
                }
                _ => panic!("Expected Deserialize error"),
            }
        }
    }

    mod toml_file_reading_tests {
        use super::*;

        #[test]
        fn read_toml_file_success() {
            let setup = TestSetup::new();
            let test_data = TestTomlData {
                title: "test".to_string(),
                count: 123,
            };
            let toml_content = toml::to_string(&test_data).unwrap();
            let file_path = setup.create_file("test.toml", &toml_content);

            let result: Result<TestTomlData, ConfigError> =
                setup.adapter.read_toml_file(&file_path);

            assert!(result.is_ok());
            assert_eq!(result.unwrap(), test_data);
        }

        #[test]
        fn read_toml_file_not_found() {
            let setup = TestSetup::new();
            let non_existent_path = setup.temp_dir.path().join("nonexistent.toml");

            let result: Result<TestTomlData, ConfigError> =
                setup.adapter.read_toml_file(&non_existent_path);

            assert!(result.is_err());
            match result.unwrap_err() {
                ConfigError::ReadFile { path, .. } => {
                    assert_eq!(path, non_existent_path);
                }
                _ => panic!("Expected ReadFile error"),
            }
        }

        #[test]
        fn read_toml_file_invalid_toml() {
            let setup = TestSetup::new();
            let file_path = setup.create_file("invalid.toml", "[invalid toml");

            let result: Result<TestTomlData, ConfigError> =
                setup.adapter.read_toml_file(&file_path);

            assert!(result.is_err());
            match result.unwrap_err() {
                ConfigError::Deserialize { path, .. } => {
                    assert_eq!(path, file_path);
                }
                _ => panic!("Expected Deserialize error"),
            }
        }
    }

    mod toml_file_writing_tests {
        use super::*;

        #[test]
        fn write_toml_file_success() {
            let setup = TestSetup::new();
            let test_data = TestTomlData {
                title: "test".to_string(),
                count: 456,
            };
            let file_path = setup.temp_dir.path().join("output.toml");

            let result = setup.adapter.write_toml_file(&test_data, &file_path);

            assert!(result.is_ok());
            assert!(file_path.exists());

            let content = fs::read_to_string(&file_path).unwrap();
            let parsed: TestTomlData = toml::from_str(&content).unwrap();
            assert_eq!(parsed, test_data);
        }

        #[test]
        fn write_toml_file_creates_parent_directories() {
            let setup = TestSetup::new();
            let test_data = TestTomlData {
                title: "nested".to_string(),
                count: 789,
            };
            let file_path = setup
                .temp_dir
                .path()
                .join("nested")
                .join("dir")
                .join("output.toml");

            let result = setup.adapter.write_toml_file(&test_data, &file_path);

            assert!(result.is_ok());
            assert!(file_path.exists());
            assert!(file_path.parent().unwrap().exists());
        }

        #[test]
        fn write_toml_file_invalid_permissions() {
            let setup = TestSetup::new();
            let test_data = TestTomlData {
                title: "test".to_string(),
                count: 123,
            };

            let invalid_path = PathBuf::from("/root/cannot_write/test.toml");

            let result = setup.adapter.write_toml_file(&test_data, &invalid_path);

            assert!(result.is_err());
            match result.unwrap_err() {
                ConfigError::WriteFile { .. } => {}
                _ => panic!("Expected WriteFile error"),
            }
        }
    }

    mod dotnet_legacy_config_tests {
        use super::*;

        #[test]
        fn load_dotnet_legacy_config_files_all_files_exist() {
            let setup = TestSetup::new();

            let main_config = r#"{"version": "1.0", "name": "test"}"#;
            let rules_config = r#"{"rules": ["rule1", "rule2"]}"#;
            let hosts_config = r#"{"hosts": ["localhost", "example.com"]}"#;

            let main_path = setup.create_file("config.json", main_config);
            let rules_path = setup.create_file("rules.json", rules_config);
            let hosts_path = setup.create_file("hosts.json", hosts_config);

            let result = setup.adapter.load_dotnet_legacy_config_files(
                Some(&main_path),
                Some(&rules_path),
                Some(&hosts_path),
            );

            assert!(result.is_ok());
            let config = result.unwrap();
            assert!(config.main_config_path.is_some());
            assert!(config.rules_config_path.is_some());
            assert!(config.hosts_config_path.is_some());
            assert_eq!(config.main_config_path.unwrap(), main_path);
        }

        #[test]
        fn load_dotnet_legacy_config_files_only_main_exists() {
            let setup = TestSetup::new();

            let main_config = r#"{"version": "1.0", "name": "test"}"#;
            let main_path = setup.create_file("config.json", main_config);

            let result =
                setup
                    .adapter
                    .load_dotnet_legacy_config_files(Some(&main_path), None, None);

            assert!(result.is_ok());
            let config = result.unwrap();
            assert!(config.main_config_path.is_some());
            assert!(config.rules_config.is_none());
            assert!(config.hosts_config.is_none());
        }

        #[test]
        fn load_dotnet_legacy_config_files_no_main_config() {
            let setup = TestSetup::new();
            let non_existent_path = setup.temp_dir.path().join("nonexistent.json");

            let result =
                setup
                    .adapter
                    .load_dotnet_legacy_config_files(Some(&non_existent_path), None, None);

            assert!(result.is_ok());
            let config = result.unwrap();
            assert!(config.main_config_path.is_none());
        }

        #[test]
        fn load_dotnet_legacy_config_files_default_paths() {
            let setup = TestSetup::new();

            let main_config = r#"{"version": "1.0", "name": "test"}"#;
            let _main_path = setup.create_file("config.json", main_config);

            let result = setup
                .adapter
                .load_dotnet_legacy_config_files(None, None, None);

            assert!(result.is_ok());
            let config = result.unwrap();
            assert!(config.main_config_path.is_some());
        }

        #[test]
        fn load_dotnet_legacy_config_files_invalid_json() {
            let setup = TestSetup::new();
            let main_path = setup.create_file("config.json", "{ invalid json }");

            let result =
                setup
                    .adapter
                    .load_dotnet_legacy_config_files(Some(&main_path), None, None);

            assert!(result.is_err());
            match result.unwrap_err() {
                ConfigError::Deserialize { .. } => {}
                _ => panic!("Expected Deserialize error"),
            }
        }
    }

    mod app_config_tests {
        use super::*;

        #[test]
        fn load_app_config_file_exists() {
            let setup = TestSetup::new();
            let config_content = r#"
title = "Test App"
version = "1.0.0"

[database]
host = "localhost"
port = 5432
"#;
            let config_path = setup.create_file("app.toml", config_content);

            let result = setup.adapter.load_app_config_file(&config_path);

            assert!(result.is_ok());
        }

        #[test]
        fn load_app_config_file_not_exists() {
            let setup = TestSetup::new();
            let non_existent_path = setup.temp_dir.path().join("nonexistent.toml");

            let result = setup.adapter.load_app_config_file(&non_existent_path);

            assert!(result.is_ok());
        }

        #[test]
        fn save_app_config_file_success() {
            let setup = TestSetup::new();
            let config = AppConfig::default();
            let config_path = setup.temp_dir.path().join("saved_app.toml");

            let result = setup.adapter.save_app_config_file(&config, &config_path);

            assert!(result.is_ok());
            assert!(config_path.exists());
        }
    }

    mod backup_tests {
        use super::*;

        #[test]
        fn backup_dotnet_legacy_config_files_success() {
            let setup = TestSetup::new();

            let main_path = setup.create_file("config.json", r#"{"test": true}"#);
            let rules_path = setup.create_file("rules.json", r#"{"rules": []}"#);

            let legacy_config = DotNetLegacyConfig {
                main_config_path: Some(main_path.clone()),
                rules_config_path: Some(rules_path.clone()),
                ..Default::default()
            };

            let result = setup
                .adapter
                .backup_dotnet_legacy_config_files(&legacy_config);

            assert!(result.is_ok());

            let main_backup = main_path.with_extension("json.migrated_bak");
            let rules_backup = rules_path.with_extension("json.migrated_bak");

            assert!(main_backup.exists());
            assert!(rules_backup.exists());

            assert!(!main_path.exists());
            assert!(!rules_path.exists());
        }

        #[test]
        fn backup_dotnet_legacy_config_files_no_files() {
            let setup = TestSetup::new();
            let legacy_config = DotNetLegacyConfig::default();

            let result = setup
                .adapter
                .backup_dotnet_legacy_config_files(&legacy_config);

            assert!(result.is_ok());
        }

        #[test]
        fn backup_dotnet_legacy_config_files_non_existent() {
            let setup = TestSetup::new();

            let legacy_config = DotNetLegacyConfig {
                main_config_path: Some(setup.temp_dir.path().join("nonexistent.json")),
                ..Default::default()
            };

            let result = setup
                .adapter
                .backup_dotnet_legacy_config_files(&legacy_config);

            assert!(result.is_ok());
        }
    }

    mod default_config_path_tests {
        use super::*;

        #[test]
        fn get_default_config_path_absolute_base() {
            let temp_dir = tempdir().unwrap();
            let adapter = JsonFileConfigAdapter::new(temp_dir.path().to_path_buf());

            let result = adapter.get_default_config_path();

            assert!(result.is_ok());
            let path = result.unwrap();
            assert!(path.is_absolute());
            assert!(path.ends_with(DEFAULT_CONFIG_FILE_NAME_V2));
        }

        #[test]
        fn get_default_config_path_relative_base() {
            let adapter = JsonFileConfigAdapter::new(PathBuf::from("relative/path"));

            let result = adapter.get_default_config_path();

            assert!(result.is_ok());
            let path = result.unwrap();

            assert!(path.to_string_lossy().contains(DEFAULT_CONFIG_FILE_NAME_V2));
        }
    }

    mod integration_tests {
        use super::*;

        #[test]
        fn full_workflow_load_modify_save() {
            let setup = TestSetup::new();

            let config_path = setup.temp_dir.path().join("workflow_test.toml");
            let config = setup.adapter.load_app_config_file(&config_path).unwrap();

            let save_result = setup.adapter.save_app_config_file(&config, &config_path);
            assert!(save_result.is_ok());
            assert!(config_path.exists());
        }

        #[test]
        fn error_handling_chain() {
            let setup = TestSetup::new();

            let invalid_main = setup.create_file("config.json", "{ invalid");

            let result =
                setup
                    .adapter
                    .load_dotnet_legacy_config_files(Some(&invalid_main), None, None);

            assert!(result.is_err());

            match result.unwrap_err() {
                ConfigError::Deserialize { path, .. } => {
                    assert_eq!(path, invalid_main);
                }
                _ => panic!("Expected Deserialize error with correct path"),
            }
        }
    }
}
