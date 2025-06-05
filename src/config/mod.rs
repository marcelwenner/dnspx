pub(crate) mod migration;
pub(crate) mod models;

use crate::core::error::ConfigError;
use std::path::{Path, PathBuf};

pub(crate) const DEFAULT_CONFIG_FILE_NAME_V2: &str = "dnspx_config.toml";

pub(crate) const DOTNET_LEGACY_MAIN_CONFIG_FILE_NAME: &str = "config.json";
pub(crate) const DOTNET_LEGACY_RULES_FILE_NAME: &str = "rules.json";
pub(crate) const DOTNET_LEGACY_HOSTS_FILE_NAME: &str = "hosts.json";

pub(crate) fn find_config_file() -> Result<PathBuf, ConfigError> {
    let current_dir_path = Path::new(".").join(DEFAULT_CONFIG_FILE_NAME_V2);
    if current_dir_path.exists() {
        return Ok(current_dir_path);
    }

    if let Some(user_config_dir) = dirs::config_dir() {
        let user_config_path = user_config_dir
            .join("dnspx")
            .join(DEFAULT_CONFIG_FILE_NAME_V2);
        if user_config_path.exists() {
            return Ok(user_config_path);
        }
        return Ok(user_config_path);
    }
    Ok(current_dir_path)
}

pub(crate) fn find_legacy_config_paths(
    base_search_dir: &Path,
) -> (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
    let main_config = base_search_dir.join(DOTNET_LEGACY_MAIN_CONFIG_FILE_NAME);
    let rules_config = base_search_dir.join(DOTNET_LEGACY_RULES_FILE_NAME);
    let hosts_config = base_search_dir.join(DOTNET_LEGACY_HOSTS_FILE_NAME);

    (
        if main_config.exists() {
            Some(main_config)
        } else {
            None
        },
        if rules_config.exists() {
            Some(rules_config)
        } else {
            None
        },
        if hosts_config.exists() {
            Some(hosts_config)
        } else {
            None
        },
    )
}
