//! Split-DNS setup command generator.
//!
//! Generates platform-specific commands for configuring split-DNS routing.
//! Supports Windows (NRPT), macOS (/etc/resolver), and Linux (systemd-resolved).

use crate::config::models::{AppConfig, RuleAction};
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::LazyLock;

/// Precompiled safe pattern matchers - capture allows \\ for escaped dots
/// Patterns match the *escaped* form (e.g., example\.com) and normalize after
static SAFE_REGEXES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // ^example\.com$ - captures "example\.com" (with backslash)
        Regex::new(r"^\^([A-Za-z0-9\\.-]+)\$$").unwrap(),
        // (^|\.)example\.com$
        Regex::new(r"^\(\^\|\\\.\)([A-Za-z0-9\\.-]+)\$$").unwrap(),
        // (?:^|\.)example\.com$
        Regex::new(r"^\(\?:\^\|\\\.\)([A-Za-z0-9\\.-]+)\$$").unwrap(),
        // ^([a-z0-9-]+\.)*example\.com$
        Regex::new(r"^\^\(\[a-z0-9-\]\+\\\.\)\*([A-Za-z0-9\\.-]+)\$$").unwrap(),
    ]
});

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SkippedRule {
    pub rule: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DomainInfo {
    pub configured: Vec<String>,
    pub auto_extracted: Vec<String>,
    pub skipped: Vec<SkippedRule>,
    pub effective: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Commands {
    pub setup: Vec<String>,
    pub verify: Vec<String>,
    pub rollback: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SplitDnsOutput {
    pub platform: String,
    pub listen_address: String,
    pub domains: DomainInfo,
    pub commands: Commands,
    pub warnings: Vec<String>,
}

/// Parse listen address handling IPv4 and IPv6 formats.
/// Returns (host, port) tuple.
pub(crate) fn parse_listen_address(addr: &str) -> (String, u16) {
    let addr = addr.trim();

    if addr.starts_with('[') {
        // IPv6 with brackets: [::1]:5353 or [::1]
        if let Some(bracket_end) = addr.find(']') {
            let host = addr[1..bracket_end].to_string();
            let port = addr
                .get(bracket_end + 2..)
                .and_then(|p| p.parse().ok())
                .unwrap_or(53);
            return (host, port);
        }
        // Malformed, return as-is with default port
        return (addr.to_string(), 53);
    }

    // Count colons to distinguish IPv4:port from bare IPv6
    let colon_count = addr.matches(':').count();

    if colon_count > 1 {
        // IPv6 without brackets and without port: ::1, 2001:db8::1
        return (addr.to_string(), 53);
    }

    if colon_count == 1 {
        // Could be IPv4:port
        if let Some(colon_pos) = addr.rfind(':') {
            let host = &addr[..colon_pos];
            let port_str = &addr[colon_pos + 1..];
            if let Ok(port) = port_str.parse::<u16>() {
                return (host.to_string(), port);
            }
        }
    }

    // No colon or unparseable port: return as-is with default port
    (addr.to_string(), 53)
}

/// Validate domain format (labels, length, characters)
fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false; // Need at least TLD + domain
    }

    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

/// Try to extract a domain from a regex pattern.
/// Only works for "safe" patterns that can be reliably parsed.
fn try_extract_domain(pattern: &str) -> Option<String> {
    for safe_re in SAFE_REGEXES.iter() {
        if let Some(caps) = safe_re.captures(pattern) {
            if let Some(domain_match) = caps.get(1) {
                // Normalize: \. -> .
                let domain = domain_match.as_str().replace(r"\.", ".");
                // Validate domain format
                if is_valid_domain(&domain) {
                    return Some(domain);
                }
            }
        }
    }
    None
}

/// Collect domains from config (explicit + auto-extracted from rules).
/// Returns DomainInfo with all domain sources and effective list.
pub(crate) fn collect_domains(config: &AppConfig) -> DomainInfo {
    let mut configured: Vec<String> = Vec::new();
    let mut auto_extracted: Vec<String> = Vec::new();
    let mut skipped: Vec<SkippedRule> = Vec::new();

    // Get explicitly configured domains
    if let Some(split_dns) = &config.split_dns {
        configured = split_dns
            .domains
            .iter()
            .filter(|d| is_valid_domain(d))
            .cloned()
            .collect();
    }

    // Auto-extract from routing rules if no explicit config or as supplement
    for rule in &config.routing_rules {
        // Only consider Forward rules (they route to specific nameservers)
        if !matches!(rule.action, RuleAction::Forward) {
            continue;
        }

        let pattern = rule.domain_pattern.0.as_str();
        if let Some(domain) = try_extract_domain(pattern) {
            auto_extracted.push(domain);
        } else {
            skipped.push(SkippedRule {
                rule: rule.name.clone(),
                pattern: pattern.to_string(),
            });
        }
    }

    // Compute effective domains: deduplicated, sorted union
    let mut effective_set: BTreeSet<String> = BTreeSet::new();
    for d in &configured {
        effective_set.insert(d.clone());
    }
    for d in &auto_extracted {
        effective_set.insert(d.clone());
    }

    let effective: Vec<String> = effective_set.into_iter().collect();

    DomainInfo {
        configured,
        auto_extracted,
        skipped,
        effective,
    }
}

/// Detect current platform
pub(crate) fn detect_platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Generate macOS /etc/resolver commands
fn generate_macos_commands(host: &str, port: u16, domains: &[String]) -> Commands {
    let mut setup = Vec::new();
    let mut rollback = Vec::new();

    setup.push("sudo mkdir -p /etc/resolver".to_string());

    for domain in domains {
        setup.push(format!(
            "sudo tee /etc/resolver/{domain} << 'EOF'\nnameserver {host}\nport {port}\nEOF"
        ));
        rollback.push(format!("sudo rm -f /etc/resolver/{domain}"));
    }

    rollback.push(
        "sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder".to_string(),
    );

    Commands {
        setup,
        verify: vec!["scutil --dns | grep -A5 'resolver #'".to_string()],
        rollback,
    }
}

/// Generate Windows NRPT PowerShell commands
fn generate_windows_commands(host: &str, domains: &[String]) -> Commands {
    let domains_array = domains
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let setup = vec![
        format!("$domains = @({domains_array})"),
        "Get-DnsClientNrptRule | Where-Object { $_.Namespace -in $domains } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue".to_string(),
        format!(
            "foreach ($domain in $domains) {{\n    Add-DnsClientNrptRule -Namespace $domain -NameServers \"{host}\"\n}}"
        ),
    ];

    let verify = vec![
        "Get-DnsClientNrptRule".to_string(),
        "# NOTE: nslookup ignores NRPT! Use Resolve-DnsName instead.".to_string(),
    ];

    let rollback = vec![
        format!("$domains = @({domains_array})"),
        "Get-DnsClientNrptRule | Where-Object { $_.Namespace -in $domains } | Remove-DnsClientNrptRule -Force".to_string(),
    ];

    Commands {
        setup,
        verify,
        rollback,
    }
}

/// Generate Linux systemd-resolved commands
fn generate_linux_commands(host: &str, port: u16, domains: &[String]) -> Commands {
    let domains_tilde: Vec<String> = domains.iter().map(|d| format!("~{d}")).collect();
    let domains_space_separated = domains_tilde.join(" ");
    let domains_config_line = domains_tilde.join(" ");

    let setup = vec![
        "# Prerequisites: Check if systemd-resolved is running:".to_string(),
        "# systemctl status systemd-resolved".to_string(),
        "".to_string(),
        "# Temporary setup (replace INTERFACE with your network interface, e.g., eth0):".to_string(),
        format!("# sudo resolvectl dns INTERFACE {host}:{port}"),
        format!("# sudo resolvectl domain INTERFACE {domains_space_separated}"),
        "".to_string(),
        "# Persistent setup:".to_string(),
        "sudo mkdir -p /etc/systemd/resolved.conf.d".to_string(),
        format!(
            "sudo tee /etc/systemd/resolved.conf.d/dnspx-split-dns.conf << 'EOF'\n[Resolve]\nDNS={host}:{port}\nDomains={domains_config_line}\nEOF"
        ),
        "sudo systemctl restart systemd-resolved".to_string(),
    ];

    let verify = vec![
        "resolvectl status".to_string(),
        "# resolvectl query <your-domain-here>".to_string(),
    ];

    let rollback = vec![
        "# Temporary rollback (replace INTERFACE):".to_string(),
        "# sudo resolvectl revert INTERFACE".to_string(),
        "".to_string(),
        "# Persistent rollback:".to_string(),
        "sudo rm -f /etc/systemd/resolved.conf.d/dnspx-split-dns.conf".to_string(),
        "sudo systemctl restart systemd-resolved".to_string(),
    ];

    Commands {
        setup,
        verify,
        rollback,
    }
}

/// Generate the full split-DNS setup output
pub(crate) fn generate_split_dns_output(config: &AppConfig) -> SplitDnsOutput {
    let platform = detect_platform();
    let listen_address = config.server.listen_address.clone();
    let (host, port) = parse_listen_address(&listen_address);

    let domain_info = collect_domains(config);
    let mut warnings = Vec::new();

    // Check for Windows port limitation
    if platform == "windows" && port != 53 {
        warnings.push(format!(
            "Windows NRPT does not support custom ports! Your DNSPX listens on port {port}, but NRPT requires port 53. Options: (1) Change listen_address to use port 53, (2) Set up port forwarding."
        ));
    }

    // Check if no domains found
    if domain_info.effective.is_empty() {
        warnings.push(
            "No domains configured or extracted. Add domains to [split_dns].domains in your config."
                .to_string(),
        );
    }

    let commands = match platform {
        "macos" => generate_macos_commands(&host, port, &domain_info.effective),
        "windows" => generate_windows_commands(&host, &domain_info.effective),
        _ => generate_linux_commands(&host, port, &domain_info.effective),
    };

    SplitDnsOutput {
        platform: platform.to_string(),
        listen_address,
        domains: domain_info,
        commands,
        warnings,
    }
}

/// Format output as human-readable text
pub(crate) fn format_human_output(output: &SplitDnsOutput) -> String {
    let mut result = String::new();

    // Header
    result.push_str(&format!(
        "\n{}\n",
        "=".repeat(60)
    ));
    result.push_str("DNSPX Split-DNS Setup\n");
    result.push_str(&format!(
        "Platform: {} | DNSPX: {}\n",
        output.platform, output.listen_address
    ));
    result.push_str(&format!("{}\n\n", "=".repeat(60)));

    // Warnings
    for warning in &output.warnings {
        result.push_str(&format!("WARNING: {warning}\n\n"));
    }

    // Domains section
    result.push_str("=== Detected Domains ===\n");
    if !output.domains.configured.is_empty() {
        result.push_str("From config [split_dns.domains]:\n");
        for d in &output.domains.configured {
            result.push_str(&format!("  * {d}\n"));
        }
    }
    if !output.domains.auto_extracted.is_empty() {
        result.push_str("From rules (auto-extracted):\n");
        for d in &output.domains.auto_extracted {
            result.push_str(&format!("  + {d}\n"));
        }
    }
    if !output.domains.skipped.is_empty() {
        result.push_str("Skipped (complex patterns):\n");
        for s in &output.domains.skipped {
            result.push_str(&format!("  ! Rule \"{}\": {}\n", s.rule, s.pattern));
            result.push_str("    -> Add manually to [split_dns].domains\n");
        }
    }
    if output.domains.effective.is_empty() {
        result.push_str("  (none)\n");
    } else {
        result.push_str(&format!(
            "\nEffective domains ({}): {}\n",
            output.domains.effective.len(),
            output.domains.effective.join(", ")
        ));
    }

    // Setup commands
    result.push_str("\n=== Setup Commands ===\n");
    result.push_str("# Run these commands to configure split DNS:\n\n");
    for cmd in &output.commands.setup {
        result.push_str(&format!("{cmd}\n"));
        if !cmd.starts_with('#') && !cmd.is_empty() {
            result.push('\n');
        }
    }

    // Verify commands
    result.push_str("=== Verify ===\n");
    for cmd in &output.commands.verify {
        result.push_str(&format!("{cmd}\n"));
    }

    // Rollback commands
    result.push_str("\n=== Rollback ===\n");
    result.push_str("# To undo, run:\n");
    for cmd in &output.commands.rollback {
        result.push_str(&format!("{cmd}\n"));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_listen_address_ipv4_with_port() {
        let (host, port) = parse_listen_address("127.0.0.1:5353");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 5353);
    }

    #[test]
    fn test_parse_listen_address_ipv4_default_port() {
        let (host, port) = parse_listen_address("127.0.0.1");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 53);
    }

    #[test]
    fn test_parse_listen_address_ipv6_bracketed_with_port() {
        let (host, port) = parse_listen_address("[::1]:5353");
        assert_eq!(host, "::1");
        assert_eq!(port, 5353);
    }

    #[test]
    fn test_parse_listen_address_ipv6_bracketed_no_port() {
        let (host, port) = parse_listen_address("[::1]");
        assert_eq!(host, "::1");
        assert_eq!(port, 53);
    }

    #[test]
    fn test_parse_listen_address_ipv6_bare() {
        let (host, port) = parse_listen_address("::1");
        assert_eq!(host, "::1");
        assert_eq!(port, 53);
    }

    #[test]
    fn test_parse_listen_address_ipv6_full() {
        let (host, port) = parse_listen_address("2001:db8::1");
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 53);
    }

    #[test]
    fn test_is_valid_domain_valid() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("a-b.example.com"));
        assert!(is_valid_domain("amazonaws.com"));
    }

    #[test]
    fn test_is_valid_domain_invalid() {
        assert!(!is_valid_domain("")); // empty
        assert!(!is_valid_domain("localhost")); // single label
        assert!(!is_valid_domain("-example.com")); // starts with dash
        assert!(!is_valid_domain("example-.com")); // ends with dash
        assert!(!is_valid_domain("exam_ple.com")); // underscore
        assert!(!is_valid_domain(&"a".repeat(300))); // too long
    }

    #[test]
    fn test_try_extract_domain_simple_anchor() {
        // ^example\.com$
        let result = try_extract_domain(r"^example\.com$");
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_try_extract_domain_subdomain_anchor() {
        // (^|\.)example\.com$
        let result = try_extract_domain(r"(^|\.)amazonaws\.com$");
        assert_eq!(result, Some("amazonaws.com".to_string()));
    }

    #[test]
    fn test_try_extract_domain_noncapturing_group() {
        // (?:^|\.)example\.com$
        let result = try_extract_domain(r"(?:^|\.)example\.com$");
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_try_extract_domain_wildcard_subdomain() {
        // ^([a-z0-9-]+\.)*example\.com$
        let result = try_extract_domain(r"^([a-z0-9-]+\.)*vpce\.amazonaws\.com$");
        assert_eq!(result, Some("vpce.amazonaws.com".to_string()));
    }

    #[test]
    fn test_try_extract_domain_complex_pattern_fails() {
        // Complex patterns should not be extracted
        let result = try_extract_domain(r"(?:api|internal)\..*\.company\.com");
        assert_eq!(result, None);
    }

    #[test]
    fn test_try_extract_domain_alternation_fails() {
        let result = try_extract_domain(r"^(foo|bar)\.example\.com$");
        assert_eq!(result, None);
    }
}
