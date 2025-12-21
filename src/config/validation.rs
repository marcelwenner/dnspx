use crate::adapters::cli::output::Renderable;
use crate::config::models::{AppConfig, RuleAction};
use regex::Regex;
use serde::Serialize;
use std::net::SocketAddr;

/// Severity level for validation findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Severity {
    /// Config won't work correctly
    Error,
    /// Config works but may cause issues
    Warning,
}

/// A single validation finding with location, code, and fix hint.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ValidationFinding {
    pub severity: Severity,
    /// JSON path to the problematic field (e.g., "routing_rules[2].domain_pattern")
    pub path: String,
    /// Machine-readable error code (e.g., "INVALID_REGEX")
    pub code: String,
    /// Human-friendly description
    pub message: String,
    /// Optional hint for fixing the issue
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Summary of the configuration for display.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ValidationSummary {
    pub routing_rules: usize,
    pub aws_accounts: usize,
    pub cache_enabled: bool,
    pub cache_max_entries: u64,
    pub local_hosts_entries: usize,
}

/// Full validation result.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ValidationResult {
    pub config_path: String,
    pub is_valid: bool,
    pub findings: Vec<ValidationFinding>,
    pub summary: ValidationSummary,
}

/// Build-time feature context for validation.
#[derive(Debug, Clone)]
pub(crate) struct ValidationContext {
    pub aws_enabled: bool,
    pub tui_enabled: bool,
    pub split_dns_enabled: bool,
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self {
            aws_enabled: true,
            tui_enabled: true,
            split_dns_enabled: true,
        }
    }
}

impl Renderable for ValidationResult {
    fn command_name(&self) -> &'static str {
        "config validate"
    }

    fn is_ok(&self) -> bool {
        self.is_valid
    }

    fn warnings(&self) -> Vec<String> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .map(|f| f.message.clone())
            .collect()
    }

    fn render_human(&self) -> String {
        let mut output = String::new();

        if self.is_valid {
            output.push_str(&format!("Config valid: {}\n", self.config_path));
        } else {
            output.push_str(&format!("Config INVALID: {}\n", self.config_path));
        }

        output.push_str("\nSummary:\n");
        output.push_str(&format!("  - {} routing rules\n", self.summary.routing_rules));
        output.push_str(&format!("  - {} AWS accounts\n", self.summary.aws_accounts));
        if self.summary.cache_enabled {
            output.push_str(&format!(
                "  - Cache: enabled ({} entries)\n",
                self.summary.cache_max_entries
            ));
        } else {
            output.push_str("  - Cache: disabled\n");
        }
        if self.summary.local_hosts_entries > 0 {
            output.push_str(&format!(
                "  - {} local hosts entries\n",
                self.summary.local_hosts_entries
            ));
        }

        let errors: Vec<_> = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        let warnings: Vec<_> = self
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();

        if !errors.is_empty() {
            output.push_str("\nErrors:\n");
            for finding in errors {
                output.push_str(&format!(
                    "  [{}] {}: {}\n",
                    finding.path, finding.code, finding.message
                ));
                if let Some(hint) = &finding.hint {
                    output.push_str(&format!("    Hint: {hint}\n"));
                }
            }
        }

        if !warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for finding in warnings {
                output.push_str(&format!(
                    "  [{}] {}: {}\n",
                    finding.path, finding.code, finding.message
                ));
                if let Some(hint) = &finding.hint {
                    output.push_str(&format!("    Hint: {hint}\n"));
                }
            }
        }

        output
    }
}

/// Validate the configuration and return structured findings.
pub(crate) fn validate_config(
    config: &AppConfig,
    config_path: &str,
    ctx: &ValidationContext,
) -> ValidationResult {
    let mut findings = Vec::new();

    // Validate listen addresses
    let listen_addresses = config.server.get_listen_addresses();
    for listen_address in &listen_addresses {
        validate_listen_address(listen_address, &mut findings);
        check_privileged_port(listen_address, &mut findings);
    }

    // Validate cache TTL bounds
    validate_cache_ttl(config, &mut findings);

    // Validate default resolver nameservers
    validate_default_resolver(config, &mut findings);

    // Validate routing rules
    validate_routing_rules(config, &mut findings);

    // Validate AWS configuration
    validate_aws_config(config, ctx, &mut findings);

    let has_errors = findings.iter().any(|f| f.severity == Severity::Error);

    let summary = ValidationSummary {
        routing_rules: config.routing_rules.len(),
        aws_accounts: config.aws.as_ref().map(|a| a.accounts.len()).unwrap_or(0),
        cache_enabled: config.cache.enabled,
        cache_max_entries: config.cache.max_capacity,
        local_hosts_entries: config
            .local_hosts
            .as_ref()
            .map(|h| h.entries.len())
            .unwrap_or(0),
    };

    ValidationResult {
        config_path: config_path.to_string(),
        is_valid: !has_errors,
        findings,
        summary,
    }
}

fn validate_listen_address(listen_address: &str, findings: &mut Vec<ValidationFinding>) {
    if listen_address.parse::<SocketAddr>().is_err() {
        findings.push(ValidationFinding {
            severity: Severity::Error,
            path: "server.listen_address".to_string(),
            code: "INVALID_ADDRESS".to_string(),
            message: format!("Cannot parse listen address: '{listen_address}'"),
            hint: Some("Use format 'IP:PORT', e.g., '0.0.0.0:53' or '[::]:53'".to_string()),
        });
    }
}

fn validate_cache_ttl(config: &AppConfig, findings: &mut Vec<ValidationFinding>) {
    if config.cache.min_ttl > config.cache.max_ttl {
        findings.push(ValidationFinding {
            severity: Severity::Error,
            path: "cache".to_string(),
            code: "INVALID_TTL_BOUNDS".to_string(),
            message: format!(
                "min_ttl ({:?}) is greater than max_ttl ({:?})",
                config.cache.min_ttl, config.cache.max_ttl
            ),
            hint: Some("Ensure min_ttl <= max_ttl".to_string()),
        });
    }

    if config.cache.min_ttl.as_secs() == 0 {
        findings.push(ValidationFinding {
            severity: Severity::Warning,
            path: "cache.min_ttl".to_string(),
            code: "LOW_TTL".to_string(),
            message: "min_ttl is 0, which may cause excessive upstream queries".to_string(),
            hint: Some("Consider setting min_ttl to at least 60s".to_string()),
        });
    }
}

fn validate_default_resolver(config: &AppConfig, findings: &mut Vec<ValidationFinding>) {
    if config.default_resolver.nameservers.is_empty() {
        findings.push(ValidationFinding {
            severity: Severity::Warning,
            path: "default_resolver.nameservers".to_string(),
            code: "NO_NAMESERVERS".to_string(),
            message: "No default nameservers configured".to_string(),
            hint: Some(
                "Add at least one nameserver, e.g., '1.1.1.1:53' or 'https://cloudflare-dns.com/dns-query'".to_string(),
            ),
        });
    }

    // Validate each nameserver
    for (i, ns) in config.default_resolver.nameservers.iter().enumerate() {
        validate_nameserver(
            ns,
            &format!("default_resolver.nameservers[{i}]"),
            findings,
        );
    }
}

fn validate_nameserver(nameserver: &str, path: &str, findings: &mut Vec<ValidationFinding>) {
    // Check if it's a DoH URL
    if nameserver.starts_with("https://") {
        if url::Url::parse(nameserver).is_err() {
            findings.push(ValidationFinding {
                severity: Severity::Error,
                path: path.to_string(),
                code: "INVALID_URL".to_string(),
                message: format!("Invalid DoH URL: '{nameserver}'"),
                hint: Some(
                    "Use a valid HTTPS URL, e.g., 'https://cloudflare-dns.com/dns-query'"
                        .to_string(),
                ),
            });
        }
    } else {
        // Standard DNS server - should be IP:PORT
        if nameserver.parse::<SocketAddr>().is_err() {
            findings.push(ValidationFinding {
                severity: Severity::Error,
                path: path.to_string(),
                code: "INVALID_ADDRESS".to_string(),
                message: format!("Invalid DNS server address: '{nameserver}'"),
                hint: Some("Use format 'IP:PORT', e.g., '8.8.8.8:53'".to_string()),
            });
        }
    }
}

fn validate_routing_rules(config: &AppConfig, findings: &mut Vec<ValidationFinding>) {
    for (i, rule) in config.routing_rules.iter().enumerate() {
        let path_prefix = format!("routing_rules[{i}]");

        // Validate regex pattern
        let pattern_str = rule.domain_pattern.0.as_str();
        if Regex::new(pattern_str).is_err() {
            findings.push(ValidationFinding {
                severity: Severity::Error,
                path: format!("{path_prefix}.domain_pattern"),
                code: "INVALID_REGEX".to_string(),
                message: format!("Invalid regex pattern: '{pattern_str}'"),
                hint: Some("Check regex syntax. Common issues: unescaped special characters like . or $".to_string()),
            });
        }

        // Validate nameservers if action is Forward
        if rule.action == RuleAction::Forward {
            if let Some(nameservers) = &rule.nameservers {
                if nameservers.is_empty() {
                    findings.push(ValidationFinding {
                        severity: Severity::Warning,
                        path: format!("{path_prefix}.nameservers"),
                        code: "NO_NAMESERVERS".to_string(),
                        message: format!(
                            "Rule '{}' has Forward action but no nameservers",
                            rule.name
                        ),
                        hint: Some("Add at least one nameserver for Forward rules".to_string()),
                    });
                }
                for (j, ns) in nameservers.iter().enumerate() {
                    validate_nameserver(ns, &format!("{path_prefix}.nameservers[{j}]"), findings);
                }
            } else {
                findings.push(ValidationFinding {
                    severity: Severity::Warning,
                    path: format!("{path_prefix}.nameservers"),
                    code: "NO_NAMESERVERS".to_string(),
                    message: format!("Rule '{}' has Forward action but no nameservers (will use default resolver)", rule.name),
                    hint: None,
                });
            }
        }
    }
}

fn validate_aws_config(
    config: &AppConfig,
    ctx: &ValidationContext,
    findings: &mut Vec<ValidationFinding>,
) {
    if let Some(aws_config) = &config.aws {
        // Check if AWS feature is enabled
        if !ctx.aws_enabled {
            findings.push(ValidationFinding {
                severity: Severity::Warning,
                path: "aws".to_string(),
                code: "FEATURE_DISABLED".to_string(),
                message: "AWS configuration present but 'aws' feature is not enabled".to_string(),
                hint: Some("Build with --features aws to enable AWS integration".to_string()),
            });
        }

        // Validate role ARNs
        for (i, account) in aws_config.accounts.iter().enumerate() {
            for (j, role) in account.roles_to_assume.iter().enumerate() {
                if !role.role_arn.starts_with("arn:aws:iam::")
                    || !role.role_arn.contains(":role/")
                {
                    findings.push(ValidationFinding {
                        severity: Severity::Error,
                        path: format!("aws.accounts[{i}].roles_to_assume[{j}].role_arn"),
                        code: "INVALID_ARN".to_string(),
                        message: format!("Invalid IAM role ARN: '{}'", role.role_arn),
                        hint: Some(
                            "Use format 'arn:aws:iam::123456789012:role/RoleName'".to_string(),
                        ),
                    });
                }
            }
        }
    }
}

fn check_privileged_port(listen_address: &str, findings: &mut Vec<ValidationFinding>) {
    if let Ok(addr) = listen_address.parse::<SocketAddr>() {
        if addr.port() < 1024 {
            findings.push(ValidationFinding {
                severity: Severity::Warning,
                path: "server.listen_address".to_string(),
                code: "PRIVILEGED_PORT".to_string(),
                message: format!(
                    "Port {} requires root/admin privileges",
                    addr.port()
                ),
                hint: Some("Run with sudo or use a port > 1024".to_string()),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{CacheConfig, DefaultResolverConfig, ServerConfig};
    use std::time::Duration;

    fn default_ctx() -> ValidationContext {
        ValidationContext::default()
    }

    #[test]
    fn test_valid_config() {
        let config = AppConfig::default();
        let result = validate_config(&config, "/test/config.toml", &default_ctx());

        assert!(result.is_valid);
        assert!(result.findings.iter().all(|f| f.severity == Severity::Warning));
    }

    #[test]
    fn test_invalid_listen_address() {
        let config = AppConfig {
            server: ServerConfig {
                listen_addresses: vec!["not-an-address".to_string()],
                ..ServerConfig::default()
            },
            ..AppConfig::default()
        };
        let result = validate_config(&config, "/test/config.toml", &default_ctx());

        assert!(!result.is_valid);
        assert!(result.findings.iter().any(|f| f.code == "INVALID_ADDRESS"));
    }

    #[test]
    fn test_invalid_ttl_bounds() {
        let config = AppConfig {
            cache: CacheConfig {
                min_ttl: Duration::from_secs(3600),
                max_ttl: Duration::from_secs(60),
                ..CacheConfig::default()
            },
            ..AppConfig::default()
        };
        let result = validate_config(&config, "/test/config.toml", &default_ctx());

        assert!(!result.is_valid);
        assert!(result
            .findings
            .iter()
            .any(|f| f.code == "INVALID_TTL_BOUNDS"));
    }

    #[test]
    fn test_privileged_port_warning() {
        let config = AppConfig {
            server: ServerConfig {
                listen_addresses: vec!["0.0.0.0:53".to_string()],
                ..ServerConfig::default()
            },
            ..AppConfig::default()
        };
        let result = validate_config(&config, "/test/config.toml", &default_ctx());

        assert!(result.is_valid); // Still valid, just a warning
        assert!(result.findings.iter().any(|f| f.code == "PRIVILEGED_PORT"));
    }

    #[test]
    fn test_empty_nameservers_warning() {
        let config = AppConfig {
            default_resolver: DefaultResolverConfig {
                nameservers: vec![],
                ..DefaultResolverConfig::default()
            },
            ..AppConfig::default()
        };
        let result = validate_config(&config, "/test/config.toml", &default_ctx());

        assert!(result.is_valid); // Still valid, just a warning
        assert!(result.findings.iter().any(|f| f.code == "NO_NAMESERVERS"));
    }

    #[test]
    fn test_low_ttl_warning() {
        let config = AppConfig {
            cache: CacheConfig {
                min_ttl: Duration::from_secs(0),
                ..CacheConfig::default()
            },
            ..AppConfig::default()
        };
        let result = validate_config(&config, "/test/config.toml", &default_ctx());

        assert!(result.is_valid);
        assert!(result.findings.iter().any(|f| f.code == "LOW_TTL"));
    }

    #[test]
    fn test_human_output_format() {
        let config = AppConfig::default();
        let result = validate_config(&config, "/test/config.toml", &default_ctx());

        let output = result.render_human();
        assert!(output.contains("Config valid:"));
        assert!(output.contains("Summary:"));
    }
}
