pub(crate) mod migration;
pub(crate) mod models;
pub(crate) mod validation;

use crate::core::error::ConfigError;
use std::path::{Path, PathBuf};

pub(crate) const DEFAULT_CONFIG_FILE_NAME_V2: &str = "dnspx_config.toml";

pub(crate) const DOTNET_LEGACY_MAIN_CONFIG_FILE_NAME: &str = "config.json";
pub(crate) const DOTNET_LEGACY_RULES_FILE_NAME: &str = "rules.json";
pub(crate) const DOTNET_LEGACY_HOSTS_FILE_NAME: &str = "hosts.json";

pub(crate) fn find_config_file() -> Result<PathBuf, ConfigError> {
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(dir) = exe_path.parent()
    {
        let local_path = dir.join(DEFAULT_CONFIG_FILE_NAME_V2);
        if local_path.exists() {
            tracing::info!(
                "Konfigurationsdatei im Anwendungsverzeichnis gefunden: {:?}",
                local_path
            );
            return Ok(local_path);
        }
    }

    if let Some(config_dir) = dirs::config_dir() {
        let user_path = config_dir.join("dnspx").join(DEFAULT_CONFIG_FILE_NAME_V2);
        if user_path.exists() {
            tracing::info!(
                "Konfigurationsdatei im Benutzer-Konfig-Verzeichnis gefunden: {:?}",
                user_path
            );
            return Ok(user_path);
        }
    }

    if let Some(config_dir) = dirs::config_dir() {
        let default_path = config_dir.join("dnspx").join(DEFAULT_CONFIG_FILE_NAME_V2);
        tracing::warn!(
            "Keine Konfigurationsdatei gefunden. Der Standardpfad für eine neue Datei ist: {:?}",
            default_path
        );
        return Ok(default_path);
    }

    if let Ok(exe_path) = std::env::current_exe()
        && let Some(dir) = exe_path.parent()
    {
        let local_path = dir.join(DEFAULT_CONFIG_FILE_NAME_V2);
        tracing::warn!(
            "Kein Benutzer-Konfig-Verzeichnis gefunden. Fallback-Pfad für neue Konfigurationsdatei: {:?}",
            local_path
        );
        return Ok(local_path);
    }

    let fallback_path = PathBuf::from(".").join(DEFAULT_CONFIG_FILE_NAME_V2);
    tracing::warn!(
        "Kein Benutzer-Konfig-Verzeichnis oder Anwendungsverzeichnis gefunden. Fallback-Pfad: {:?}",
        fallback_path
    );
    Ok(fallback_path)
}

pub(crate) fn find_legacy_config_paths(
    base_search_dir: &Path,
) -> (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
    fn check_legacy_files_in_dir(
        dir: &Path,
    ) -> (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
        let main_config = dir.join(DOTNET_LEGACY_MAIN_CONFIG_FILE_NAME);
        let rules_config = dir.join(DOTNET_LEGACY_RULES_FILE_NAME);
        let hosts_config = dir.join(DOTNET_LEGACY_HOSTS_FILE_NAME);

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

    let (main_opt, rules_opt, hosts_opt) = check_legacy_files_in_dir(base_search_dir);

    if main_opt.is_some() {
        return (main_opt, rules_opt, hosts_opt);
    }

    if let Ok(exe_path) = std::env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
        && exe_dir != base_search_dir
    {
        tracing::debug!(
            "Legacy config not found in {:?}, trying executable directory: {:?}",
            base_search_dir,
            exe_dir
        );
        let (exe_main_opt, exe_rules_opt, exe_hosts_opt) = check_legacy_files_in_dir(exe_dir);
        if exe_main_opt.is_some() {
            return (exe_main_opt, exe_rules_opt, exe_hosts_opt);
        }
    }

    (None, None, None)
}
