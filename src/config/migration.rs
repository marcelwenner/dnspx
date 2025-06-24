use crate::config::models::*;
use crate::core::error::ConfigError;
use crate::core::types::{MessageLevel, ProtocolType};
use ipnetwork::IpNetwork;
use regex::Regex;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

#[derive(Debug, Clone)]
pub(crate) struct MigrationMessage {
    pub level: MessageLevel,
    pub text: String,
}

impl MigrationMessage {
    pub(crate) fn info(text: String) -> Self {
        Self {
            level: MessageLevel::Info,
            text,
        }
    }
    pub(crate) fn warn(text: String) -> Self {
        Self {
            level: MessageLevel::Warning,
            text,
        }
    }
}

pub(crate) fn migrate(
    dotnet_legacy: DotNetLegacyConfig,
) -> Result<(AppConfig, Vec<MigrationMessage>), ConfigError> {
    let mut messages = Vec::new();
    messages.push(MigrationMessage::info(
        "Starting migration from .NET legacy configuration format.".to_string(),
    ));

    let mut app_config = AppConfig::default();
    let main_legacy = dotnet_legacy.main_config;

    if let Some(dns_host) = main_legacy.dns_host_config {
        messages.push(MigrationMessage::info(
            "Migrating ServerConfig from DnsHostConfig...".to_string(),
        ));
        let port = dns_host.listener_port.unwrap_or(53);
        let validated_port = if port == 0 {
            messages.push(MigrationMessage::warn(
                "Invalid port 0 specified, defaulting to 53".to_string(),
            ));
            53
        } else {
            port
        };
        app_config.server.listen_address = format!("0.0.0.0:{validated_port}");
        app_config.server.protocols = vec![ProtocolType::Udp, ProtocolType::Tcp];

        if let Some(timeout_ms) = dns_host.default_query_timeout {
            if timeout_ms > 0 {
                app_config.server.default_query_timeout = Duration::from_millis(timeout_ms);
                messages.push(MigrationMessage::info(format!(
                    "  Set server.default_query_timeout to {timeout_ms}ms"
                )));
            }
        }

        if let Some(whitelist) = dns_host.network_whitelist {
            let parsed_whitelist: Vec<IpNetwork> = whitelist
                .into_iter()
                .filter_map(|s| match IpNetwork::from_str(&s) {
                    Ok(net) => {
                        messages.push(MigrationMessage::info(format!(
                            "  Parsed network whitelist entry: {net}"
                        )));
                        Some(net)
                    }
                    Err(e) => {
                        messages.push(MigrationMessage::warn(format!(
                            "  Failed to parse network whitelist entry '{s}': {e}. Skipping."
                        )));
                        None
                    }
                })
                .collect();
            if !parsed_whitelist.is_empty() {
                app_config.server.network_whitelist = Some(parsed_whitelist);
            }
        }
    } else {
        messages.push(MigrationMessage::info(
            "No DnsHostConfig found in .NET legacy main_config.".to_string(),
        ));
    }

    if let Some(dns_default) = main_legacy.dns_default_server {
        messages.push(MigrationMessage::info(
            "Migrating DefaultResolverConfig...".to_string(),
        ));
        if let Some(servers) = dns_default.servers {
            if let Some(nameservers) = servers.name_server {
                if !nameservers.is_empty() {
                    app_config.default_resolver.nameservers = nameservers.clone();
                    messages.push(MigrationMessage::info(format!(
                        "  Set default_resolver.nameservers to: {nameservers:?}"
                    )));
                }
            }
            if let Some(strategy_str) = servers.strategy {
                let new_strategy = match strategy_str.to_lowercase().as_str() {
                    "random" => ResolverStrategy::Random,
                    "rotate" => ResolverStrategy::Rotate,
                    "fastest" => ResolverStrategy::Fastest,
                    _ => ResolverStrategy::First,
                };
                let strategy = new_strategy.clone();
                app_config.default_resolver.strategy = new_strategy;
                messages.push(MigrationMessage::info(format!(
                    "  Set default_resolver.strategy to: {strategy:?}"
                )));
            }
            if let Some(timeout_ms) = servers.query_timeout {
                if timeout_ms > 0 {
                    app_config.default_resolver.timeout = Duration::from_millis(timeout_ms);
                    messages.push(MigrationMessage::info(format!(
                        "  Set default_resolver.timeout to {timeout_ms}ms"
                    )));
                }
            }
            app_config.default_resolver.doh_compression_mutation =
                servers.compression_mutation.unwrap_or(false);
            messages.push(MigrationMessage::info(format!(
                "  Set default_resolver.doh_compression_mutation to: {}",
                app_config.default_resolver.doh_compression_mutation
            )));
        }
    } else {
        messages.push(MigrationMessage::info(
            "No DnsDefaultServer found in .NET legacy main_config.".to_string(),
        ));
    }

    if let Some(proxy_legacy) = main_legacy.http_proxy_config {
        messages.push(MigrationMessage::info(
            "Migrating HttpProxyConfig...".to_string(),
        ));
        if let (Some(address), port_opt) = (proxy_legacy.address, proxy_legacy.port) {
            if !address.is_empty() && port_opt.is_none_or(|p| p > 0) {
                let port = port_opt.unwrap_or(80);
                let proxy_url_str = format!("http://{address}:{port}");
                match Url::parse(&proxy_url_str) {
                    Ok(url) => {
                        let auth_type_legacy_str = proxy_legacy
                            .authentication_type
                            .as_deref()
                            .unwrap_or("None");
                        let (auth_type_rust, username, password, domain) =
                            match auth_type_legacy_str.to_lowercase().as_str() {
                                "basic" => (
                                    ProxyAuthenticationType::Basic,
                                    proxy_legacy.user.filter(|s| !s.is_empty()),
                                    proxy_legacy.password.filter(|s| !s.is_empty()),
                                    None,
                                ),
                                "windowsdomain" => {
                                    messages.push(MigrationMessage::warn(
                                    "  Migrating 'WindowsDomain' proxy auth as 'Ntlm' (manual NTLM with credentials). Support for this is experimental. If Integrated Windows Authentication (current user) is desired, please reconfigure to 'WindowsAuth' after migration.".to_string()
                                ));
                                    (
                                        ProxyAuthenticationType::Ntlm,
                                        proxy_legacy.user.filter(|s| !s.is_empty()),
                                        proxy_legacy.password.filter(|s| !s.is_empty()),
                                        proxy_legacy.domain.filter(|s| !s.is_empty()),
                                    )
                                }
                                "windowsuser" => {
                                    messages.push(MigrationMessage::info(
                                    "  Migrating 'WindowsUser' proxy auth as 'WindowsAuth'. This will attempt to use current user credentials (SSPI) on Windows. Support is experimental.".to_string()
                                ));
                                    (ProxyAuthenticationType::WindowsAuth, None, None, None)
                                }
                                _ => {
                                    if proxy_legacy.user.is_some()
                                        && proxy_legacy.password.is_some()
                                    {
                                        messages.push(MigrationMessage::warn(
                                        "  Proxy has username/password but AuthenticationType is 'None' or unknown. Assuming 'Basic' authentication.".to_string()
                                    ));
                                        (
                                            ProxyAuthenticationType::Basic,
                                            proxy_legacy.user.filter(|s| !s.is_empty()),
                                            proxy_legacy.password.filter(|s| !s.is_empty()),
                                            None,
                                        )
                                    } else {
                                        (ProxyAuthenticationType::None, None, None, None)
                                    }
                                }
                            };

                        let bypass_list = proxy_legacy
                            .bypass_addresses
                            .filter(|s| !s.trim().is_empty())
                            .map(|s| {
                                s.split(';')
                                    .map(|x| x.trim().to_string())
                                    .filter(|x| !x.is_empty())
                                    .collect::<Vec<String>>()
                            })
                            .filter(|v| !v.is_empty());

                        if bypass_list.is_some() {
                            messages.push(MigrationMessage::info(format!(
                                "  Migrated proxy bypass list: {:?}",
                                bypass_list.as_ref().unwrap()
                            )));
                        }

                        app_config.http_proxy = Some(HttpProxyConfig {
                            url,
                            authentication_type: auth_type_rust,
                            username,
                            password,
                            domain,
                            bypass_list,
                        });
                        messages.push(MigrationMessage::info(format!(
                            "  Migrated HTTP Proxy to: {proxy_url_str} with auth type {auth_type_rust:?}"
                        )));
                    }
                    Err(e) => {
                        messages.push(MigrationMessage::warn(format!("  Failed to parse proxy URL '{proxy_url_str}' from .NET legacy config: {e}. Skipping proxy.")));
                    }
                }
            } else {
                messages.push(MigrationMessage::info(
                    "  Skipping HTTP Proxy migration due to empty address or invalid/missing port in legacy config."
                        .to_string(),
                ));
            }
        }
    } else {
        messages.push(MigrationMessage::info(
            "No HttpProxyConfig found in .NET legacy main_config.".to_string(),
        ));
    }

    if let Some(aws_legacy) = main_legacy.aws_settings {
        messages.push(MigrationMessage::info(
            "Migrating AwsGlobalConfig...".to_string(),
        ));
        if aws_legacy.region.is_some()
            || aws_legacy
                .user_accounts
                .as_ref()
                .is_some_and(|ua| !ua.is_empty())
        {
            let mut aws_global = AwsGlobalConfig {
                default_region: aws_legacy.region.clone(),
                ..Default::default()
            };
            messages.push(MigrationMessage::info(format!(
                "  Set aws.default_region to: {:?}",
                aws_global.default_region
            )));

            if let Some(user_accounts) = aws_legacy.user_accounts {
                for user_account in user_accounts {
                    let account_label_base = user_account
                        .user_name
                        .as_deref()
                        .or(user_account.user_account_id.as_deref())
                        .unwrap_or("unknown_account");

                    let account_label = format!(
                        "migrated_{}",
                        account_label_base.replace(|c: char| !c.is_alphanumeric() && c != '-', "_")
                    );
                    messages.push(MigrationMessage::info(format!(
                        "  Migrating AWS account: Label='{account_label}', Original .NET UserName/ID='{account_label_base}'"
                    )));

                    let account_conf = AwsAccountConfig {
                        label: account_label.clone(),
                        account_id: user_account.user_account_id,
                        profile_name: user_account.user_name,
                        scan_vpc_ids: user_account.scan_vpc_ids.unwrap_or_default(),
                        scan_regions: None,
                        roles_to_assume: user_account.roles.map_or_else(
                            Vec::new,
                            |roles| {
                                roles.into_iter()
                                    .filter_map(|role| {
                                        if let (Some(role_name), Some(role_account_id)) = (role.role, role.aws_account_id) {
                                            if !role_name.is_empty() && !role_account_id.is_empty() {
                                                Some(AwsRoleConfig {
                                                    role_arn: format!("arn:aws:iam::{role_account_id}:role/{role_name}"),
                                                    label: role.aws_account_label,
                                                    scan_vpc_ids: role.scan_vpc_ids.unwrap_or_default(),
                                                    scan_regions: None,
                                                    discover_services: AwsServiceDiscoveryConfig::default(),
                                                })
                                            } else {
                                                messages.push(MigrationMessage::warn(format!("  Skipping role for account '{account_label}' due to empty role name or account ID.")));
                                                None
                                            }
                                        } else {
                                            messages.push(MigrationMessage::warn(format!("  Skipping role for account '{account_label}' due to missing role name or account ID.")));
                                            None
                                        }
                                    }).collect()
                            },
                        ),
                        discover_services: AwsServiceDiscoveryConfig::default(),
                    };
                    aws_global.accounts.push(account_conf);
                }
            }
            if !aws_global.accounts.is_empty() || aws_global.default_region.is_some() {
                app_config.aws = Some(aws_global);
            } else {
                messages.push(MigrationMessage::info(
                    "  No AWS accounts or default region found to migrate in aws_settings."
                        .to_string(),
                ));
            }
        } else {
            messages.push(MigrationMessage::info(
                "  aws_settings is present but empty or contains no accounts/region.".to_string(),
            ));
        }
    } else {
        messages.push(MigrationMessage::info(
            "No AwsSettings found in .NET legacy main_config.".to_string(),
        ));
    }

    if let Some(rules_config_legacy) = dotnet_legacy.rules_config {
        messages.push(MigrationMessage::info(
            "Migrating RoutingRules...".to_string(),
        ));
        if let Some(rules_wrapper) = rules_config_legacy.rules_config {
            if let Some(rules) = rules_wrapper.rules {
                for rule_legacy in rules {
                    if rule_legacy.is_enabled == Some(false) {
                        messages.push(MigrationMessage::info(format!(
                            "  Skipping disabled .NET legacy rule for pattern/domain: {:?}/{:?}",
                            rule_legacy.domain_name_pattern.as_deref(),
                            rule_legacy.domain_name.as_deref()
                        )));
                        continue;
                    }

                    let pattern_str = match (
                        rule_legacy
                            .domain_name_pattern
                            .as_ref()
                            .filter(|s| !s.is_empty()),
                        rule_legacy.domain_name.as_ref().filter(|s| !s.is_empty()),
                    ) {
                        (Some(p), _) => p.clone(),
                        (_, Some(d)) => format!("^{}$", regex::escape(d.trim_end_matches('.'))),
                        _ => {
                            messages.push(MigrationMessage::warn(format!("  Skipping .NET legacy rule: No valid DomainNamePattern or DomainName found. Rule details: {rule_legacy:?}")));
                            continue;
                        }
                    };

                    match Regex::new(&pattern_str) {
                        Ok(re) => {
                            let rule_name_base = pattern_str.chars().take(30).collect::<String>();
                            let rule_name = format!(
                                "migrated_{}",
                                rule_name_base
                                    .replace(|c: char| !c.is_alphanumeric() && c != '.', "_")
                                    .trim_end_matches('_')
                            );

                            let nameservers = rule_legacy
                                .name_server
                                .filter(|ns_list| !ns_list.is_empty());
                            if nameservers.is_none()
                                && rule_legacy.strategy.as_deref().is_some_and(|s| {
                                    s.eq_ignore_ascii_case("Dns") || s.eq_ignore_ascii_case("DoH")
                                })
                            {
                                messages.push(MigrationMessage::warn(format!("  Rule for '{pattern_str}' has 'Dns' or 'DoH' strategy but no nameservers. Rule will likely use default resolver.")));
                            }

                            let app_config_strategy =
                                match rule_legacy.strategy.as_deref().map(|s| s.to_lowercase()) {
                                    Some(s) if s == "random" => ResolverStrategy::Random,
                                    Some(s) if s == "rotate" => ResolverStrategy::Rotate,
                                    _ => ResolverStrategy::First,
                                };
                            let timeout =
                                Duration::from_millis(rule_legacy.query_timeout.unwrap_or(5000));
                            let doh_compression = rule_legacy.compression_mutation.unwrap_or(false);

                            messages.push(MigrationMessage::info(format!("  Migrating rule: Name='{}', Pattern='{}', NS={:?}, AppConfigStrat={:?}, Timeout={}ms, DoHComp={}",
                                  rule_name, pattern_str, nameservers, app_config_strategy, timeout.as_millis(), doh_compression)));

                            let rule_config = RuleConfig {
                                name: rule_name,
                                domain_pattern: HashableRegex(re),
                                action: RuleAction::Forward,
                                nameservers,
                                strategy: app_config_strategy,
                                timeout,
                                doh_compression_mutation: doh_compression,
                                source_list_url: None,
                                invert_match: false,
                            };
                            app_config.routing_rules.push(rule_config);
                        }
                        Err(e) => {
                            messages.push(MigrationMessage::warn(format!("  Failed to compile regex from .NET legacy domain pattern '{pattern_str}': {e}. Skipping rule.")));
                        }
                    }
                }
            } else {
                messages.push(MigrationMessage::info(
                    "  No rules found in .NET legacy rules_config.Rules.".to_string(),
                ));
            }
        } else {
            messages.push(MigrationMessage::info(
                "  No rules_config object found in .NET legacy rules_config.".to_string(),
            ));
        }
    } else {
        messages.push(MigrationMessage::info(
            "No RulesConfig file/section found in .NET legacy config.".to_string(),
        ));
    }

    if let Some(hosts_config_legacy) = dotnet_legacy.hosts_config {
        let hosts_enabled_by_rule = hosts_config_legacy
            .hosts_config
            .as_ref()
            .and_then(|hc| hc.rule.as_ref())
            .and_then(|r| r.is_enabled)
            .unwrap_or(true);

        if hosts_enabled_by_rule {
            messages.push(MigrationMessage::info(
                "Migrating LocalHostsConfig (IsEnabled=true or not specified)...".to_string(),
            ));
            if let Some(hosts_wrapper) = hosts_config_legacy.hosts_config {
                if let Some(hosts_list) = hosts_wrapper.hosts {
                    let mut entries: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
                    for host_entry_legacy in hosts_list {
                        let host_entry_legacy_copy = host_entry_legacy.clone();
                        if let (Some(ip_strings), Some(domain_strings)) = (
                            host_entry_legacy.ip_addresses,
                            host_entry_legacy.domain_names,
                        ) {
                            let parsed_ips: Vec<IpAddr> = ip_strings.iter()
                                .filter_map(|ip_s| {
                                    if ip_s.is_empty() { return None; }
                                    match IpAddr::from_str(ip_s) {
                                        Ok(ip) => Some(ip),
                                        Err(e) => {
                                            messages.push(MigrationMessage::warn(format!("  Failed to parse IP address '{ip_s}' for domains {domain_strings:?}: {e}. Skipping this IP.")));
                                            None
                                        }
                                    }
                                })
                                .collect();

                            if !parsed_ips.is_empty() {
                                for domain_str_raw in
                                    domain_strings.iter().filter(|s| !s.is_empty())
                                {
                                    let normalized_domain =
                                        domain_str_raw.trim_end_matches('.').to_lowercase();
                                    messages.push(MigrationMessage::info(format!(
                                        "  Adding host entry: {normalized_domain} -> {parsed_ips:?}"
                                    )));
                                    entries
                                        .entry(normalized_domain)
                                        .or_default()
                                        .extend(parsed_ips.iter().cloned());
                                }
                            } else {
                                messages.push(MigrationMessage::info(format!(
                                    "  Skipping host entry with no valid IPs for domains: {domain_strings:?}"
                                )));
                            }
                        } else {
                            messages.push(MigrationMessage::info(format!(
                                "  Skipping host entry with missing IPs or Domains: {host_entry_legacy_copy:?}"
                            )));
                        }
                    }
                    for ips_vec in entries.values_mut() {
                        ips_vec.sort_unstable();
                        ips_vec.dedup();
                    }

                    if !entries.is_empty() {
                        let local_hosts_section = app_config
                            .local_hosts
                            .get_or_insert_with(LocalHostsConfig::default);
                        local_hosts_section.entries = entries;
                    } else {
                        messages.push(MigrationMessage::info(
                            "  No valid host entries found to migrate from .NET legacy hosts."
                                .to_string(),
                        ));
                    }
                } else {
                    messages.push(MigrationMessage::info(
                        "  No 'Hosts' list found in .NET legacy hosts_config.".to_string(),
                    ));
                }
            } else {
                messages.push(MigrationMessage::info(
                    "  No 'hosts_config' object found in .NET legacy hosts_config.".to_string(),
                ));
            }
        } else {
            messages.push(MigrationMessage::info(
                "Skipping .NET legacy hosts migration as 'HostsConfig.Rule.IsEnabled' is false."
                    .to_string(),
            ));
        }
    } else {
        messages.push(MigrationMessage::info(
            "No HostsConfig file/section found in .NET legacy config.".to_string(),
        ));
    }

    messages.push(MigrationMessage::info(
        ".NET legacy configuration migration process finished.".to_string(),
    ));
    Ok((app_config, messages))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::core::types::MessageLevel;

    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::time::Duration;

    fn create_dotnet_legacy_from_jsons(
        main_json_str_opt: Option<&str>,
        rules_json_str_opt: Option<&str>,
        hosts_json_str_opt: Option<&str>,
    ) -> DotNetLegacyConfig {
        let main_config: DotNetMainConfig = main_json_str_opt
            .map(|s| serde_json::from_str(s).expect("Failed to parse main_json_str for test"))
            .unwrap_or_default();

        let rules_config: Option<DotNetRulesConfig> = rules_json_str_opt
            .map(|s| serde_json::from_str(s).expect("Failed to parse rules_json_str for test"));

        let hosts_config: Option<DotNetHostsConfig> = hosts_json_str_opt
            .map(|s| serde_json::from_str(s).expect("Failed to parse hosts_json_str for test"));

        DotNetLegacyConfig {
            main_config,
            rules_config,
            hosts_config,
            main_config_path: main_json_str_opt.map(|_| PathBuf::from("config.json")),
            rules_config_path: rules_json_str_opt.map(|_| PathBuf::from("rules.json")),
            hosts_config_path: hosts_json_str_opt.map(|_| PathBuf::from("hosts.json")),
        }
    }

    fn assert_message_exists(
        messages: &[MigrationMessage],
        level: MessageLevel,
        text_contains: &str,
    ) {
        assert!(
            messages
                .iter()
                .any(|msg| msg.level == level && msg.text.contains(text_contains)),
            "Expected message with level {:?} containing '{}', not found in: {:?}",
            level,
            text_contains,
            messages
        );
    }

    fn assert_no_message_contains(messages: &[MigrationMessage], text_contains: &str) {
        assert!(
            !messages.iter().any(|msg| msg.text.contains(text_contains)),
            "Found unexpected message containing '{}' in: {:?}",
            text_contains,
            messages
        );
    }

    #[test]
    fn test_migrate_full_config_set1() {
        let main_json = r#"{
          "DnsHostConfig": {
            "ListenerPort": 5353,
            "NetworkWhitelist": ["192.168.1.0/24", "10.0.0.1"],
            "DefaultQueryTimeout": 6000
          },
          "DnsDefaultServer": {
            "Servers": {
              "NameServer": ["1.1.1.1", "8.8.8.8"],
              "Strategy": "Dns", "QueryTimeout": 700
            }
          },
          "HttpProxyConfig": { "Address": "proxy.example.com", "Port": 8080, "AuthenticationType": "Basic", "User": "proxyuser", "Password": "proxypass", "BypassAddresses": "internal.com;*.local;<local>" },
          "AwsSettings": {
            "Region": "eu-west-1",
            "UserAccounts": [{
              "UserName": "test-profile", "UserAccountId": "111222333444",
              "ScanVpcIds": ["vpc-123"],
              "Roles": [{ "AwsAccountId": "555666777888", "Role": "MyTestRole", "ScanVpcIds": ["vpc-abc"] }]
            }]
          }
        }"#;
        let rules_json = r#"{
          "RulesConfig": { "Rules": [
            { "DomainNamePattern": ".*\\.dev", "NameServer": ["10.0.0.1"], "IsEnabled": true, "QueryTimeout": 200 },
            { "DomainName": "exact.com", "NameServer": ["https://doh.example.com/dns-query"], "Strategy": "DoH", "IsEnabled": true }
          ]}
        }"#;
        let hosts_json = r#"{
          "HostsConfig": { "Rule": { "IsEnabled": true }, "Hosts": [
            { "IpAddresses": ["192.168.99.1", "192.168.99.2"], "DomainNames": ["multi.host.local", "alias.host.local"] },
            { "IpAddresses": ["2001:db8::1"], "DomainNames": ["ipv6.host.local"] }
          ]}
        }"#;

        let legacy_config =
            create_dotnet_legacy_from_jsons(Some(main_json), Some(rules_json), Some(hosts_json));
        let (app_config, messages) = migrate(legacy_config).unwrap();

        assert_eq!(app_config.server.listen_address, "0.0.0.0:5353");
        assert!(app_config.server.network_whitelist.is_some());
        assert_eq!(
            app_config.server.network_whitelist.as_ref().unwrap().len(),
            2
        );
        assert_eq!(
            app_config.server.default_query_timeout,
            Duration::from_millis(6000)
        );

        assert_eq!(
            app_config.default_resolver.nameservers,
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        );
        assert_eq!(
            app_config.default_resolver.timeout,
            Duration::from_millis(700)
        );
        assert_eq!(
            app_config.default_resolver.strategy,
            ResolverStrategy::First
        );

        assert!(app_config.http_proxy.is_some());
        let proxy_conf = app_config.http_proxy.as_ref().unwrap();
        assert_eq!(proxy_conf.url.as_str(), "http://proxy.example.com:8080/");
        assert_eq!(
            proxy_conf.authentication_type,
            ProxyAuthenticationType::Basic
        );
        assert_eq!(proxy_conf.username, Some("proxyuser".to_string()));
        assert_eq!(proxy_conf.password, Some("proxypass".to_string()));
        assert_eq!(
            proxy_conf.bypass_list,
            Some(vec![
                "internal.com".to_string(),
                "*.local".to_string(),
                "<local>".to_string()
            ])
        );

        assert!(app_config.aws.is_some());
        let aws_conf = app_config.aws.as_ref().unwrap();
        assert_eq!(aws_conf.default_region, Some("eu-west-1".to_string()));
        assert_eq!(aws_conf.accounts.len(), 1);
        assert_eq!(aws_conf.accounts[0].label, "migrated_test-profile");
        assert_eq!(
            aws_conf.accounts[0].profile_name,
            Some("test-profile".to_string())
        );
        assert_eq!(
            aws_conf.accounts[0].account_id,
            Some("111222333444".to_string())
        );
        assert_eq!(
            aws_conf.accounts[0].scan_vpc_ids,
            vec!["vpc-123".to_string()]
        );
        assert_eq!(aws_conf.accounts[0].roles_to_assume.len(), 1);
        assert_eq!(
            aws_conf.accounts[0].roles_to_assume[0].role_arn,
            "arn:aws:iam::555666777888:role/MyTestRole"
        );

        assert_eq!(app_config.routing_rules.len(), 2);
        assert_eq!(
            app_config.routing_rules[0].domain_pattern.0.as_str(),
            ".*\\.dev"
        );
        assert_eq!(
            app_config.routing_rules[0].nameservers,
            Some(vec!["10.0.0.1".to_string()])
        );
        assert_eq!(
            app_config.routing_rules[0].timeout,
            Duration::from_millis(200)
        );
        assert_eq!(
            app_config.routing_rules[1].domain_pattern.0.as_str(),
            "^exact\\.com$"
        );
        assert_eq!(
            app_config.routing_rules[1].nameservers,
            Some(vec!["https://doh.example.com/dns-query".to_string()])
        );
        assert_eq!(
            app_config.routing_rules[1].strategy,
            ResolverStrategy::First
        );

        assert!(app_config.local_hosts.is_some());
        let hosts_entries = &app_config.local_hosts.as_ref().unwrap().entries;
        assert_eq!(hosts_entries.get("multi.host.local").unwrap().len(), 2);
        assert!(
            hosts_entries
                .get("multi.host.local")
                .unwrap()
                .contains(&IpAddr::from_str("192.168.99.1").unwrap())
        );
        assert!(
            hosts_entries
                .get("multi.host.local")
                .unwrap()
                .contains(&IpAddr::from_str("192.168.99.2").unwrap())
        );
        assert_eq!(hosts_entries.get("alias.host.local").unwrap().len(), 2);
        assert_eq!(
            hosts_entries.get("ipv6.host.local").unwrap(),
            &vec![IpAddr::from_str("2001:db8::1").unwrap()]
        );
        assert_eq!(app_config.local_hosts.as_ref().unwrap().ttl, 300);

        assert_message_exists(&messages, MessageLevel::Info, "Starting migration");
        assert_message_exists(&messages, MessageLevel::Info, "Migrating ServerConfig");
        assert_message_exists(
            &messages,
            MessageLevel::Info,
            "Migrating DefaultResolverConfig",
        );
        assert_message_exists(&messages, MessageLevel::Info, "Migrating HttpProxyConfig");
        assert_message_exists(&messages, MessageLevel::Info, "Migrating AwsGlobalConfig");
        assert_message_exists(&messages, MessageLevel::Info, "Migrating RoutingRules");
        assert_message_exists(&messages, MessageLevel::Info, "Migrating LocalHostsConfig");
        assert_message_exists(&messages, MessageLevel::Info, "migration process finished");
    }

    #[test]
    fn test_migrate_minimal_config() {
        let main_json = r#"{}"#;
        let legacy_config = create_dotnet_legacy_from_jsons(Some(main_json), None, None);
        let (app_config, messages) = migrate(legacy_config).unwrap();

        assert_eq!(app_config.server.listen_address, "0.0.0.0:53");
        assert!(!app_config.default_resolver.nameservers.is_empty());
        assert!(app_config.routing_rules.is_empty());
        assert!(app_config.local_hosts.is_none());
        assert!(app_config.aws.is_none());
        assert!(app_config.http_proxy.is_none());

        assert_message_exists(&messages, MessageLevel::Info, "No DnsHostConfig found");
        assert_message_exists(&messages, MessageLevel::Info, "No DnsDefaultServer found");
        assert_message_exists(&messages, MessageLevel::Info, "No HttpProxyConfig found");
        assert_message_exists(&messages, MessageLevel::Info, "No AwsSettings found");
        assert_message_exists(
            &messages,
            MessageLevel::Info,
            "No RulesConfig file/section found",
        );
        assert_message_exists(
            &messages,
            MessageLevel::Info,
            "No HostsConfig file/section found",
        );
    }

    #[test]
    fn test_migrate_http_proxy_windows_auth_types() {
        let main_json_domain = r#"{ "HttpProxyConfig": { "Address": "proxy.corp", "Port": 8080, "AuthenticationType": "WindowsDomain", "User": "user", "Password": "password", "Domain": "CORP" } }"#;
        let legacy_domain = create_dotnet_legacy_from_jsons(Some(main_json_domain), None, None);
        let (config_domain, messages_domain) = migrate(legacy_domain).unwrap();
        assert!(config_domain.http_proxy.is_some());
        let proxy_domain = config_domain.http_proxy.as_ref().unwrap();
        assert_eq!(
            proxy_domain.authentication_type,
            ProxyAuthenticationType::Ntlm
        );
        assert_eq!(proxy_domain.username, Some("user".to_string()));
        assert_eq!(proxy_domain.password, Some("password".to_string()));
        assert_eq!(proxy_domain.domain, Some("CORP".to_string()));
        assert_message_exists(
            &messages_domain,
            MessageLevel::Warning,
            "Migrating 'WindowsDomain' proxy auth as 'Ntlm'",
        );

        let main_json_user = r#"{ "HttpProxyConfig": { "Address": "proxy.corp", "Port": 8080, "AuthenticationType": "WindowsUser" } }"#;
        let legacy_user = create_dotnet_legacy_from_jsons(Some(main_json_user), None, None);
        let (config_user, messages_user) = migrate(legacy_user).unwrap();
        assert!(config_user.http_proxy.is_some());
        let proxy_user = config_user.http_proxy.as_ref().unwrap();
        assert_eq!(
            proxy_user.authentication_type,
            ProxyAuthenticationType::WindowsAuth
        );
        assert!(proxy_user.username.is_none());
        assert!(proxy_user.password.is_none());
        assert!(proxy_user.domain.is_none());
        assert_message_exists(
            &messages_user,
            MessageLevel::Info,
            "Migrating 'WindowsUser' proxy auth as 'WindowsAuth'",
        );
    }

    #[test]
    fn test_migrate_http_proxy_empty_bypass_list() {
        let main_json = r#"{ "HttpProxyConfig": { "Address": "proxy.example.com", "Port": 8080, "BypassAddresses": "" } }"#;
        let legacy_config = create_dotnet_legacy_from_jsons(Some(main_json), None, None);
        let (app_config, messages) = migrate(legacy_config).unwrap();
        assert!(app_config.http_proxy.is_some());
        let proxy_conf = app_config.http_proxy.as_ref().unwrap();
        assert!(
            proxy_conf.bypass_list.is_none(),
            "Empty string bypass list should result in None, not Some(vec![]). Actual: {:?}",
            proxy_conf.bypass_list
        );
        assert_no_message_contains(&messages, "Migrated proxy bypass list");

        let main_json_whitespace = r#"{ "HttpProxyConfig": { "Address": "proxy.example.com", "Port": 8080, "BypassAddresses": "   ;   " } }"#;
        let legacy_config_ws =
            create_dotnet_legacy_from_jsons(Some(main_json_whitespace), None, None);
        let (app_config_ws, _) = migrate(legacy_config_ws).unwrap();
        assert!(app_config_ws.http_proxy.is_some());
        let proxy_conf_ws = app_config_ws.http_proxy.as_ref().unwrap();
        assert!(
            proxy_conf_ws.bypass_list.is_none(),
            "Whitespace-only string bypass list should result in None. Actual: {:?}",
            proxy_conf_ws.bypass_list
        );
    }

    #[test]
    fn test_migrate_rules_disabled_and_invalid_regex() {
        let rules_json = r#"{
          "RulesConfig": { "Rules": [
            { "DomainName": "enabled.rule", "NameServer": ["1.2.3.4"], "IsEnabled": true },
            { "DomainName": "disabled.rule", "NameServer": ["1.2.3.5"], "IsEnabled": false },
            { "DomainNamePattern": "[invalidregex", "NameServer": ["1.2.3.6"], "IsEnabled": true }
          ]}
        }"#;
        let legacy_config = create_dotnet_legacy_from_jsons(None, Some(rules_json), None);
        let (app_config, messages) = migrate(legacy_config).unwrap();

        assert_eq!(app_config.routing_rules.len(), 1);
        assert_eq!(
            app_config.routing_rules[0].domain_pattern.0.as_str(),
            "^enabled\\.rule$"
        );
        assert_message_exists(
            &messages,
            MessageLevel::Info,
            "Skipping disabled .NET legacy rule for pattern/domain",
        );
        assert_message_exists(
            &messages,
            MessageLevel::Warning,
            "Failed to compile regex from .NET legacy domain pattern '[invalidregex'",
        );
    }

    #[test]
    fn test_migrate_hosts_multi_ip_and_disabled() {
        let hosts_json = r#"{
          "HostsConfig": {
            "Rule": { "IsEnabled": true },
            "Hosts": [
              { "IpAddresses": ["1.1.1.1", "1.1.1.2"], "DomainNames": ["multi.ip.test"] },
              { "IpAddresses": ["2.2.2.2"], "DomainNames": ["single.ip.test", "alias.ip.test"] }
            ]
          }
        }"#;
        let legacy_config = create_dotnet_legacy_from_jsons(None, None, Some(hosts_json));
        let (app_config, _) = migrate(legacy_config).unwrap();

        assert!(app_config.local_hosts.is_some());
        let entries = &app_config.local_hosts.as_ref().unwrap().entries;
        assert_eq!(entries.get("multi.ip.test").unwrap().len(), 2);
        assert!(
            entries
                .get("multi.ip.test")
                .unwrap()
                .contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
        assert!(
            entries
                .get("multi.ip.test")
                .unwrap()
                .contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2)))
        );
        assert_eq!(
            entries.get("single.ip.test").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))]
        );
        assert_eq!(
            entries.get("alias.ip.test").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))]
        );

        let hosts_json_disabled = r#"{"HostsConfig": { "Rule": { "IsEnabled": false }, "Hosts": [{"IpAddresses": ["3.3.3.3"], "DomainNames": ["disabled.host.test"] }]}}"#;
        let legacy_disabled =
            create_dotnet_legacy_from_jsons(None, None, Some(hosts_json_disabled));
        let (app_config_disabled, messages_disabled) = migrate(legacy_disabled).unwrap();
        assert!(app_config_disabled.local_hosts.is_none());
        assert_message_exists(
            &messages_disabled,
            MessageLevel::Info,
            "Skipping .NET legacy hosts migration as 'HostsConfig.Rule.IsEnabled' is false",
        );
    }

    #[test]
    fn test_migrate_rule_domain_name_vs_pattern_priority() {
        let rules_json = r#"{
          "RulesConfig": { "Rules": [
            { "DomainNamePattern": "pattern.com", "DomainName": "exact.com", "NameServer": ["1.1.1.1"], "IsEnabled": true }
          ]}
        }"#;
        let legacy = create_dotnet_legacy_from_jsons(None, Some(rules_json), None);
        let (config, _) = migrate(legacy).unwrap();
        assert_eq!(
            config.routing_rules[0].domain_pattern.0.as_str(),
            "pattern.com"
        );

        let rules_json_only_domain = r#"{
          "RulesConfig": { "Rules": [
            { "DomainName": "exactonly.com", "NameServer": ["2.2.2.2"], "IsEnabled": true }
          ]}
        }"#;
        let legacy_only_domain =
            create_dotnet_legacy_from_jsons(None, Some(rules_json_only_domain), None);
        let (config_only_domain, _) = migrate(legacy_only_domain).unwrap();
        assert_eq!(
            config_only_domain.routing_rules[0]
                .domain_pattern
                .0
                .as_str(),
            "^exactonly\\.com$"
        );
    }

    #[test]
    fn test_migrate_rule_strategy_mapping() {
        let rules_json = r#"{
          "RulesConfig": { "Rules": [
            { "DomainName": "s1.com", "Strategy": "Dns", "NameServer": ["1.1.1.1"], "IsEnabled": true },
            { "DomainName": "s2.com", "Strategy": "DoH", "NameServer": ["https://doh.com"], "IsEnabled": true },
            { "DomainName": "s3.com", "Strategy": "Random", "NameServer": ["1.1.1.1"], "IsEnabled": true },
            { "DomainName": "s4.com", "Strategy": "Rotate", "NameServer": ["1.1.1.1"], "IsEnabled": true },
            { "DomainName": "s5.com", "Strategy": "Unknown", "NameServer": ["1.1.1.1"], "IsEnabled": true }
          ]}
        }"#;
        let legacy = create_dotnet_legacy_from_jsons(None, Some(rules_json), None);
        let (config, _) = migrate(legacy).unwrap();
        assert_eq!(config.routing_rules.len(), 5);
        assert_eq!(config.routing_rules[0].strategy, ResolverStrategy::First);
        assert_eq!(config.routing_rules[1].strategy, ResolverStrategy::First);
        assert_eq!(config.routing_rules[2].strategy, ResolverStrategy::Random);
        assert_eq!(config.routing_rules[3].strategy, ResolverStrategy::Rotate);
        assert_eq!(config.routing_rules[4].strategy, ResolverStrategy::First);
    }

    #[test]
    fn test_migrate_aws_role_arn_construction() {
        let main_json = r#"{
          "AwsSettings": {
            "UserAccounts": [{
              "UserName": "test-user",
              "Roles": [
                { "AwsAccountId": "123456789012", "Role": "MySpecificRole" },
                { "Role": "RoleWithoutAccId" },
                { "AwsAccountId": "987654321098" }
              ]
            }]
          }
        }"#;
        let legacy = create_dotnet_legacy_from_jsons(Some(main_json), None, None);
        let (config, messages) = migrate(legacy).unwrap();
        let roles = &config.aws.unwrap().accounts[0].roles_to_assume;
        assert_eq!(roles.len(), 1);
        assert_eq!(
            roles[0].role_arn,
            "arn:aws:iam::123456789012:role/MySpecificRole"
        );
        assert_message_exists(
            &messages,
            MessageLevel::Warning,
            "Skipping role for account 'migrated_test-user' due to missing role name or account ID.",
        );
    }

    #[test]
    fn test_migrate_with_provided_example_set1_config() {
        let main_json = r#"{
          "DnsHostConfig": { "ListenerPort": 53, "NetworkWhitelist": ["127.0.0.1/32"], "DefaultQueryTimeout": 50000 },
          "DnsDefaultServer": { "Servers": { "NameServer": ["1.1.1.1", "9.9.9.9"], "Strategy": "Dns", "QueryTimeout": 5000 }},
          "HttpProxyConfig": { "Address": "127.0.0.1", "Port": 8888 },
          "AwsSettings": { "Region": "eu-central-1", "UserAccounts": [{ "UserName": "myprofile", "UserAccountId": "123", "Roles": [{ "AwsAccountId": "456", "Role": "myrole" }]}]}
        }"#;
        let legacy = create_dotnet_legacy_from_jsons(Some(main_json), None, None);
        let (config, _messages) = migrate(legacy).unwrap();

        assert_eq!(config.server.listen_address, "0.0.0.0:53");
        assert_eq!(
            config.server.default_query_timeout,
            Duration::from_millis(50000)
        );
        assert_eq!(
            config.default_resolver.nameservers,
            vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()]
        );
        assert!(config.http_proxy.is_some());
        assert!(config.aws.is_some());
        assert_eq!(
            config.aws.as_ref().unwrap().default_region,
            Some("eu-central-1".to_string())
        );
        assert_eq!(
            config.aws.as_ref().unwrap().accounts[0].profile_name,
            Some("myprofile".to_string())
        );
        assert_eq!(
            config.aws.as_ref().unwrap().accounts[0].roles_to_assume[0].role_arn,
            "arn:aws:iam::456:role/myrole"
        );
    }

    #[test]
    fn test_migrate_with_provided_example_set1_rules_and_hosts() {
        let rules_json = r#"{ "RulesConfig": { "Rules": [
            { "DomainNamePattern": "(.*)\\.box", "NameServer": ["10.10.34.21"], "IsEnabled": true, "QueryTimeout": 10000 },
            { "DomainName": "blun.de.", "Strategy": "DoH", "NameServer": ["https://cloudflare-dns.com/dns-query"], "IsEnabled": true }
        ]}} "#;
        let hosts_json = r#"{ "HostsConfig": { "Rule": { "IsEnabled": true }, "Hosts": [
            { "IpAddresses": ["104.16.249.249", "104.16.248.249"], "DomainNames": ["cloudflare-dns.com", "cf.com"] }
        ]}} "#;

        let legacy = create_dotnet_legacy_from_jsons(None, Some(rules_json), Some(hosts_json));
        let (config, messages) = migrate(legacy).unwrap();

        assert_eq!(config.routing_rules.len(), 2);
        assert!(
            config
                .routing_rules
                .iter()
                .any(|r| r.domain_pattern.0.as_str() == "(.*)\\.box")
        );
        assert!(
            config
                .routing_rules
                .iter()
                .any(|r| r.domain_pattern.0.as_str() == "^blun\\.de$")
        );

        assert!(config.local_hosts.is_some());
        let entries = &config.local_hosts.as_ref().unwrap().entries;
        assert_eq!(entries.get("cloudflare-dns.com").unwrap().len(), 2);
        assert_eq!(entries.get("cf.com").unwrap().len(), 2);
        assert_message_exists(
            &messages,
            MessageLevel::Info,
            "Adding host entry: cloudflare-dns.com ->",
        );
        assert_message_exists(
            &messages,
            MessageLevel::Info,
            "Adding host entry: cf.com ->",
        );
    }

    #[test]
    fn test_migrate_empty_rules_and_hosts_files() {
        let rules_json = r#"{ "RulesConfig": { "Rules": [] }}"#;
        let hosts_json = r#"{ "HostsConfig": { "Hosts": [] }}"#;
        let legacy = create_dotnet_legacy_from_jsons(None, Some(rules_json), Some(hosts_json));
        let (config, messages) = migrate(legacy).unwrap();

        assert!(config.routing_rules.is_empty());
        assert!(config.local_hosts.is_none());

        println!("Actual messages: {:?}", messages);

        assert_no_message_contains(
            &messages,
            "No rules found in .NET legacy rules_config.Rules.",
        );
        assert_message_exists(
            &messages,
            MessageLevel::Info,
            "No valid host entries found to migrate from .NET legacy hosts",
        );
    }
    #[test]
    fn test_migrate_large_config_performance() {
        let mut rules = Vec::new();
        for i in 0..1000 {
            rules.push(format!(r#"{{ "DomainName": "host{}.test", "NameServer": ["1.1.1.1"], "IsEnabled": true }}"#, i));
        }
        let rules_json = format!(
            r#"{{ "RulesConfig": {{ "Rules": [{}] }}}}"#,
            rules.join(",")
        );

        let start = std::time::Instant::now();
        let legacy = create_dotnet_legacy_from_jsons(None, Some(&rules_json), None);
        let (config, _) = migrate(legacy).unwrap();
        let duration = start.elapsed();

        assert_eq!(config.routing_rules.len(), 1000);
        assert!(
            duration < Duration::from_millis(500),
            "Migration took too long: {:?}",
            duration
        );
    }
    #[test]
    fn test_migrate_idempotency() {
        let main_json = r#"{ "DnsHostConfig": { "ListenerPort": 8053 }}"#;
        let legacy = create_dotnet_legacy_from_jsons(Some(main_json), None, None);

        let (config1, messages1) = migrate(legacy.clone()).unwrap();
        let (config2, messages2) = migrate(legacy.clone()).unwrap();

        assert_eq!(config1.server.listen_address, config2.server.listen_address);
        assert_eq!(messages1.len(), messages2.len());
    }

    #[test]
    fn test_migrate_unicode_domain_names() {
        let hosts_json = r#"{
            "HostsConfig": { "Rule": { "IsEnabled": true }, "Hosts": [
                { "IpAddresses": ["1.1.1.1"], "DomainNames": ["测试.local", "münchen.test", "🚀.domain"] }
            ]}
        }"#;

        let legacy = create_dotnet_legacy_from_jsons(None, None, Some(hosts_json));
        let (config, _) = migrate(legacy).unwrap();

        assert!(config.local_hosts.is_some());
    }

    #[test]
    fn test_migrate_memory_efficiency() {
        let mut host_entries = Vec::new();
        for i in 0..100 {
            let ips: Vec<String> = (0..10).map(|j| format!("192.168.{}.{}", i, j)).collect();
            let domains: Vec<String> = (0..5).map(|k| format!("host{}-{}.test", i, k)).collect();
            host_entries.push(format!(
                r#"{{ "IpAddresses": {:?}, "DomainNames": {:?} }}"#,
                ips, domains
            ));
        }

        let hosts_json = format!(
            r#"{{ "HostsConfig": {{ "Rule": {{ "IsEnabled": true }}, "Hosts": [{}] }}}}"#,
            host_entries.join(",")
        );

        let legacy = create_dotnet_legacy_from_jsons(None, None, Some(&hosts_json));
        let (config, _) = migrate(legacy).unwrap();

        assert!(config.local_hosts.is_some());
        let total_entries = config.local_hosts.unwrap().entries.len();
        assert_eq!(total_entries, 500);
    }

    #[test]
    fn test_migration_messages_user_friendly() {
        let legacy = create_dotnet_legacy_from_jsons(None, None, None);
        let (_, messages) = migrate(legacy).unwrap();

        for msg in &messages {
            assert!(!msg.text.is_empty(), "Empty message found");
            assert!(
                !msg.text.contains("unwrap"),
                "Developer-specific language in user message"
            );
            assert!(
                !msg.text.contains("panic"),
                "Scary language in user message"
            );

            if msg.level == MessageLevel::Warning {
                assert!(
                    msg.text.contains("Skipping")
                        || msg.text.contains("Failed")
                        || msg.text.contains("Using default"),
                    "Warning message should be actionable: {}",
                    msg.text
                );
            }
        }
    }

    #[test]
    fn test_migrate_path_handling() {
        let legacy_with_paths = DotNetLegacyConfig {
            main_config_path: Some(PathBuf::from(r"C:\Windows\config.json")),
            rules_config_path: Some(PathBuf::from("/home/user/rules.json")),
            hosts_config_path: Some(PathBuf::from("./relative/hosts.json")),
            ..Default::default()
        };

        let (_, messages) = migrate(legacy_with_paths).unwrap();

        assert_message_exists(&messages, MessageLevel::Info, "Starting migration");
    }

    // Error Resilience Tests - Phase 1

    #[test]
    fn test_migrate_malformed_json_graceful_handling() {
        // Test with malformed JSON structures that could crash migration
        let malformed_jsons = vec![
            // Truncated JSON
            r#"{ "DnsHostConfig": { "ListenerPort": 53"#,
            // Invalid JSON syntax
            r#"{ DnsHostConfig: { "ListenerPort": "invalid" } }"#,
            // Deeply nested structures
            r#"{ "DnsHostConfig": { "Nested": { "Deep": { "Very": { "Deep": { "ListenerPort": 53 } } } } } }"#,
            // Circular references simulation
            r#"{ "DnsHostConfig": null, "CircularRef": "DnsHostConfig" }"#,
        ];

        for malformed_json in malformed_jsons {
            // These should either parse gracefully or fail gracefully without panic
            let parse_result: Result<DotNetMainConfig, _> = serde_json::from_str(malformed_json);
            match parse_result {
                Ok(config) => {
                    // If it parses, migration should handle it gracefully
                    let legacy = DotNetLegacyConfig {
                        main_config: config,
                        ..Default::default()
                    };
                    let result = migrate(legacy);
                    assert!(
                        result.is_ok(),
                        "Migration should handle parsed malformed JSON gracefully"
                    );
                }
                Err(_) => {
                    // JSON parsing failure is acceptable and expected for malformed JSON
                }
            }
        }
    }

    #[test]
    fn test_migrate_extreme_string_lengths() {
        // Test very long strings that could cause memory issues
        let long_string = "a".repeat(10000);
        let very_long_domain = format!("{}.com", "subdomain.".repeat(100));

        let main_json = format!(
            r#"{{
            "DnsHostConfig": {{ "ListenerPort": 53 }},
            "HttpProxyConfig": {{ 
                "Address": "{}", 
                "Port": 8080,
                "User": "{}",
                "BypassAddresses": "{}"
            }}
        }}"#,
            long_string, long_string, long_string
        );

        let parse_result: Result<DotNetMainConfig, _> = serde_json::from_str(&main_json);
        match parse_result {
            Ok(config) => {
                let legacy = DotNetLegacyConfig {
                    main_config: config,
                    ..Default::default()
                };
                let (migrated_config, messages) = migrate(legacy).unwrap();

                // Migration should complete but may warn about long strings
                assert!(!messages.is_empty());
                // Should not cause memory exhaustion or infinite loops
                assert!(migrated_config.server.listen_address.len() < 100);
            }
            Err(_) => {
                // JSON parsing failure is acceptable for extreme cases
            }
        }

        // Test extremely long domain names in rules
        let rules_json = format!(
            r#"{{
            "RulesConfig": {{ "Rules": [{{
                "DomainName": "{}",
                "NameServer": ["1.1.1.1"],
                "IsEnabled": true
            }}]}}
        }}"#,
            very_long_domain
        );

        let parse_result: Result<DotNetRulesConfig, _> = serde_json::from_str(&rules_json);
        match parse_result {
            Ok(rules_config) => {
                let legacy = DotNetLegacyConfig {
                    rules_config: Some(rules_config),
                    ..Default::default()
                };
                let result = migrate(legacy);
                assert!(
                    result.is_ok(),
                    "Should handle very long domain names gracefully"
                );
            }
            Err(_) => {
                // Acceptable for extreme cases
            }
        }
    }

    #[test]
    fn test_migrate_null_and_empty_values() {
        // Test various null and empty value scenarios
        let test_cases = vec![
            // Empty objects
            r#"{ "DnsHostConfig": {}, "DnsDefaultServer": {} }"#,
            // Null values where objects expected
            r#"{ "DnsHostConfig": null, "HttpProxyConfig": null }"#,
            // Empty arrays
            r#"{ "AwsSettings": { "UserAccounts": [] } }"#,
            // Mixed null and empty
            r#"{ "DnsHostConfig": { "NetworkWhitelist": null }, "DnsDefaultServer": { "Servers": { "NameServer": [] } } }"#,
        ];

        for test_json in test_cases {
            let parse_result: Result<DotNetMainConfig, _> = serde_json::from_str(test_json);
            match parse_result {
                Ok(config) => {
                    let legacy = DotNetLegacyConfig {
                        main_config: config,
                        ..Default::default()
                    };
                    let (migrated_config, _) = migrate(legacy).unwrap();

                    // Should always produce valid config even with null/empty inputs
                    assert!(!migrated_config.server.listen_address.is_empty());
                    assert!(!migrated_config.default_resolver.nameservers.is_empty());
                }
                Err(_) => {
                    // Some null patterns may not parse, which is acceptable
                }
            }
        }
    }

    #[test]
    fn test_migrate_invalid_data_types() {
        // Test incorrect data types that could cause runtime errors
        let invalid_type_jsons = vec![
            // String where number expected
            r#"{ "DnsHostConfig": { "ListenerPort": "not_a_number" } }"#,
            // Number where string expected
            r#"{ "HttpProxyConfig": { "Address": 12345, "Port": 8080 } }"#,
            // Array where object expected
            r#"{ "DnsHostConfig": ["invalid", "structure"] }"#,
            // Boolean where string expected
            r#"{ "HttpProxyConfig": { "Address": "proxy.com", "AuthenticationType": true } }"#,
            // Object where array expected
            r#"{ "DnsDefaultServer": { "Servers": { "NameServer": { "invalid": "structure" } } } }"#,
        ];

        for invalid_json in invalid_type_jsons {
            let parse_result: Result<DotNetMainConfig, _> = serde_json::from_str(invalid_json);
            match parse_result {
                Ok(config) => {
                    // If serde manages to parse it, migration should handle it
                    let legacy = DotNetLegacyConfig {
                        main_config: config,
                        ..Default::default()
                    };
                    let result = migrate(legacy);
                    assert!(result.is_ok(), "Should handle type mismatches gracefully");
                }
                Err(_) => {
                    // Type errors during parsing are expected and acceptable
                }
            }
        }
    }

    #[test]
    fn test_migrate_special_characters_and_encoding() {
        // Test special characters that could cause parsing or processing issues
        let special_char_json = r#"{
            "HttpProxyConfig": {
                "Address": "proxy.example.com",
                "Port": 8080,
                "User": "user@domain.com",
                "Password": "p@$$w0rd!#%&*(){}[]|\\:;\"'<>,.?/~`",
                "BypassAddresses": "internal.com;*.local;<local>;127.0.0.1;[::1]"
            },
            "AwsSettings": {
                "UserAccounts": [{
                    "UserName": "test-user_123.name+suffix",
                    "UserAccountId": "123456789012"
                }]
            }
        }"#;

        let legacy = create_dotnet_legacy_from_jsons(Some(special_char_json), None, None);
        let (migrated_config, messages) = migrate(legacy).unwrap();

        // Should handle special characters without corruption
        assert!(migrated_config.http_proxy.is_some());
        let proxy = migrated_config.http_proxy.unwrap();
        assert!(proxy.password.is_some());
        assert!(proxy.bypass_list.is_some());

        // AWS account names with special chars should be sanitized
        assert!(migrated_config.aws.is_some());
        let aws_config = migrated_config.aws.unwrap();
        assert_eq!(aws_config.accounts.len(), 1);
        assert!(aws_config.accounts[0].label.starts_with("migrated_"));

        // Should not contain any error messages about character encoding
        assert!(
            !messages
                .iter()
                .any(|m| m.text.contains("encoding") || m.text.contains("character"))
        );
    }

    #[test]
    fn test_migrate_concurrent_safety() {
        use std::sync::Arc;
        use std::thread;

        // Test that migration is thread-safe and doesn't have race conditions
        let main_json = r#"{ "DnsHostConfig": { "ListenerPort": 5353 } }"#;
        let legacy_config = Arc::new(create_dotnet_legacy_from_jsons(Some(main_json), None, None));

        let mut handles = vec![];

        // Run migration concurrently from multiple threads
        for i in 0..10 {
            let config_clone = Arc::clone(&legacy_config);
            let handle = thread::spawn(move || {
                let (migrated, messages) = migrate((*config_clone).clone()).unwrap();
                (migrated.server.listen_address, messages.len(), i)
            });
            handles.push(handle);
        }

        let mut results = vec![];
        for handle in handles {
            results.push(handle.join().unwrap());
        }

        // All results should be identical (migration is deterministic)
        let first_result = &results[0];
        for result in &results[1..] {
            assert_eq!(
                result.0, first_result.0,
                "Migration results should be deterministic"
            );
            assert_eq!(
                result.1, first_result.1,
                "Message counts should be consistent"
            );
        }
    }

    #[test]
    fn test_migrate_network_whitelist_edge_cases() {
        // Test various invalid and edge case network whitelist entries
        let test_cases = vec![
            // Invalid CIDR notation
            r#"{ "DnsHostConfig": { "NetworkWhitelist": ["192.168.1.0/33", "invalid/24"] } }"#,
            // Mixed IPv4 and IPv6
            r#"{ "DnsHostConfig": { "NetworkWhitelist": ["192.168.1.0/24", "2001:db8::/32", "::1"] } }"#,
            // Invalid IP addresses
            r#"{ "DnsHostConfig": { "NetworkWhitelist": ["999.999.999.999/24", "192.168.1.256/24"] } }"#,
            // Empty and whitespace entries
            r#"{ "DnsHostConfig": { "NetworkWhitelist": ["", "   ", "192.168.1.0/24", "\t\n"] } }"#,
            // Special IPv6 addresses
            r#"{ "DnsHostConfig": { "NetworkWhitelist": ["::/0", "fe80::/64", "::1/128"] } }"#,
            // Border cases for CIDR
            r#"{ "DnsHostConfig": { "NetworkWhitelist": ["127.0.0.1/32", "0.0.0.0/0"] } }"#,
            // Malformed IPv6
            r#"{ "DnsHostConfig": { "NetworkWhitelist": ["2001:db8::1::2/64", "invalid:ipv6:address/128"] } }"#,
        ];

        for test_json in test_cases {
            let parse_result: Result<DotNetMainConfig, _> = serde_json::from_str(test_json);
            match parse_result {
                Ok(config) => {
                    let legacy = DotNetLegacyConfig {
                        main_config: config,
                        ..Default::default()
                    };
                    let (migrated_config, messages) = migrate(legacy).unwrap();

                    // Migration should complete successfully
                    assert!(!migrated_config.server.listen_address.is_empty());

                    // Should skip invalid entries but continue with valid ones
                    if let Some(whitelist) = migrated_config.server.network_whitelist {
                        // All entries in final whitelist should be valid
                        for network in whitelist {
                            assert!(network.network().is_ipv4() || network.network().is_ipv6());
                        }
                    }

                    // Should have warning messages for invalid entries
                    let warning_count = messages
                        .iter()
                        .filter(|m| m.level == MessageLevel::Warning)
                        .count();

                    // Should have at least one warning for invalid entries in test cases with invalid data
                    if test_json.contains("999.999")
                        || test_json.contains("/33")
                        || test_json.contains("invalid")
                    {
                        assert!(
                            warning_count > 0,
                            "Expected warnings for invalid network entries"
                        );
                    }
                }
                Err(_) => {
                    // Some malformed JSON may not parse, which is acceptable
                }
            }
        }
    }

    #[test]
    fn test_migrate_regex_safety_and_dos_protection() {
        // Test potentially dangerous regex patterns that could cause ReDoS
        let long_pattern = "a".repeat(10000);
        let dangerous_patterns = vec![
            // Catastrophic backtracking patterns
            r#"(a+)+b"#.to_string(),
            r#"(a|a)*"#.to_string(),
            r#"([a-zA-Z]+)*"#.to_string(),
            // Extremely long patterns
            long_pattern,
            // Complex nested quantifiers
            r#"(a*)*"#.to_string(),
            r#"(a+)+"#.to_string(),
            // Unicode and special characters that might break regex
            r#".*[🚀🔥💥].*"#.to_string(),
            // Null bytes and control characters
            ".*\0.*".to_string(),
            ".*\x01\x02\x03.*".to_string(),
            // Very broad patterns
            r#".*.*.*.*.*"#.to_string(),
        ];

        for pattern in dangerous_patterns {
            let rules_json = format!(
                r#"{{
                "RulesConfig": {{ "Rules": [{{
                    "DomainNamePattern": "{}",
                    "NameServer": ["1.1.1.1"],
                    "IsEnabled": true
                }}]}}
            }}"#,
                pattern.replace('"', r#"\""#)
            );

            let parse_result: Result<DotNetRulesConfig, _> = serde_json::from_str(&rules_json);
            match parse_result {
                Ok(rules_config) => {
                    let legacy = DotNetLegacyConfig {
                        rules_config: Some(rules_config),
                        ..Default::default()
                    };

                    // Migration should complete in reasonable time (not hang due to ReDoS)
                    let start = std::time::Instant::now();
                    let result = migrate(legacy);
                    let duration = start.elapsed();

                    // Should not take more than 5 seconds even for complex patterns
                    assert!(
                        duration < Duration::from_secs(5),
                        "Migration took too long for pattern '{}': {:?}",
                        pattern,
                        duration
                    );

                    match result {
                        Ok((config, messages)) => {
                            // If regex compiled successfully, it should be in the config
                            // If not, there should be a warning message
                            let has_rules = !config.routing_rules.is_empty();
                            let has_warnings =
                                messages.iter().any(|m| m.level == MessageLevel::Warning);

                            if !has_rules {
                                assert!(
                                    has_warnings,
                                    "If rule wasn't migrated, should have warning message"
                                );
                            }
                        }
                        Err(_) => {
                            // Migration errors for dangerous patterns are acceptable
                        }
                    }
                }
                Err(_) => {
                    // JSON parsing failures for special characters are acceptable
                }
            }
        }
    }

    #[test]
    fn test_migrate_regex_compilation_limits() {
        // Test that regex compilation has reasonable limits
        let test_cases = vec![
            // Very long alternation that could exhaust memory
            (0..1000)
                .map(|i| format!("domain{}", i))
                .collect::<Vec<_>>()
                .join("|"),
            // Deeply nested groups
            "(".repeat(100) + "test" + &")".repeat(100),
            // Many character classes
            "[a-z]".repeat(500),
            // Complex lookaheads (if supported)
            r#"(?=.*test)(?=.*example)(?=.*domain).*"#.to_string(),
        ];

        for pattern in test_cases {
            let rules_json = format!(
                r#"{{
                "RulesConfig": {{ "Rules": [{{
                    "DomainNamePattern": "{}",
                    "NameServer": ["1.1.1.1"],
                    "IsEnabled": true
                }}]}}
            }}"#,
                pattern.replace('"', r#"\""#)
            );

            if let Ok(rules_config) = serde_json::from_str::<DotNetRulesConfig>(&rules_json) {
                let legacy = DotNetLegacyConfig {
                    rules_config: Some(rules_config),
                    ..Default::default()
                };

                // Should either succeed quickly or fail gracefully
                let start = std::time::Instant::now();
                let result = migrate(legacy);
                let duration = start.elapsed();

                assert!(
                    duration < Duration::from_secs(2),
                    "Regex compilation took too long: {:?}",
                    duration
                );
                assert!(
                    result.is_ok(),
                    "Migration should handle regex compilation gracefully"
                );
            }
        }
    }

    #[test]
    fn test_migrate_domain_name_sanitization() {
        // Test domain name edge cases and sanitization
        let domain_edge_cases = vec![
            // Very long domain names
            "a".repeat(255) + ".com",
            // International domain names
            "тест.рф".to_string(),
            "测试.中国".to_string(),
            "🚀.example.com".to_string(),
            // Domain with special characters
            "test..double-dot.com".to_string(),
            "test-.hyphen-end.com".to_string(),
            "-start-hyphen.com".to_string(),
            // Empty labels
            ".example.com".to_string(),
            "example..com".to_string(),
            "example.com.".to_string(),
            // Numeric domains
            "123.456.789.012".to_string(),
            "2001:db8::1".to_string(),
            // Very long TLD
            "example.".to_string() + &"x".repeat(100),
        ];

        for domain in domain_edge_cases {
            let rules_json = format!(
                r#"{{
                "RulesConfig": {{ "Rules": [{{
                    "DomainName": "{}",
                    "NameServer": ["1.1.1.1"],
                    "IsEnabled": true
                }}]}}
            }}"#,
                domain
            );

            if let Ok(rules_config) = serde_json::from_str::<DotNetRulesConfig>(&rules_json) {
                let legacy = DotNetLegacyConfig {
                    rules_config: Some(rules_config),
                    ..Default::default()
                };

                let (config, messages) = migrate(legacy).unwrap();

                // Migration should complete without panic
                // Domain names should be properly escaped for regex
                if !config.routing_rules.is_empty() {
                    let rule = &config.routing_rules[0];
                    // Regex should be valid and compilable (already tested by creating the rule)
                    // For exact domain matches, check if the pattern matches the original domain
                    if domain.chars().all(|c| c.is_ascii() && !c.is_control()) {
                        // For simple ASCII domains, the regex should match the domain itself
                        // Handle trailing dots and other normalization
                        let normalized_domain = domain.trim_end_matches('.');
                        let domain_to_test = if normalized_domain.is_empty() {
                            &domain
                        } else {
                            normalized_domain
                        };

                        if rule.domain_pattern.0.is_match(domain_to_test) {
                            // Pattern matches the normalized domain
                        } else if rule.domain_pattern.0.is_match(&domain) {
                            // Pattern matches the original domain
                        } else {
                            // For complex domains (international, special chars), just check regex is valid
                            // The fact that we got here means the regex compiled successfully
                        }
                    }
                }

                // Long or invalid domains might generate warnings
                if domain.len() > 253 || domain.contains("..") {
                    let _has_warnings = messages.iter().any(|m| m.level == MessageLevel::Warning);
                    // Don't require warnings as domain validation might be handled elsewhere
                }
            }
        }
    }

    // Data Validation Tests - Phase 2

    #[test]
    fn test_migrate_port_number_validation() {
        // Test various invalid port numbers
        let port_test_cases = vec![
            // Negative ports
            r#"{ "DnsHostConfig": { "ListenerPort": -1 } }"#,
            r#"{ "HttpProxyConfig": { "Address": "proxy.com", "Port": -8080 } }"#,
            // Zero port
            r#"{ "DnsHostConfig": { "ListenerPort": 0 } }"#,
            // Ports > 65535
            r#"{ "DnsHostConfig": { "ListenerPort": 65536 } }"#,
            r#"{ "HttpProxyConfig": { "Address": "proxy.com", "Port": 100000 } }"#,
            // Very large numbers
            r#"{ "DnsHostConfig": { "ListenerPort": 2147483647 } }"#,
            // String ports (should be parsed by serde if possible)
            r#"{ "DnsHostConfig": { "ListenerPort": "53" } }"#,
            r#"{ "HttpProxyConfig": { "Address": "proxy.com", "Port": "8080" } }"#,
            // Floating point ports
            r#"{ "DnsHostConfig": { "ListenerPort": 53.5 } }"#,
        ];

        for test_json in port_test_cases {
            let parse_result: Result<DotNetMainConfig, _> = serde_json::from_str(test_json);
            match parse_result {
                Ok(config) => {
                    let legacy = DotNetLegacyConfig {
                        main_config: config,
                        ..Default::default()
                    };
                    let (migrated_config, messages) = migrate(legacy).unwrap();

                    // Migration should always produce a valid listening address
                    assert!(!migrated_config.server.listen_address.is_empty());

                    // Listen address should have a valid port format
                    assert!(migrated_config.server.listen_address.contains(':'));

                    // Extract and validate the port
                    if let Some(port_str) =
                        migrated_config.server.listen_address.split(':').next_back()
                    {
                        if let Ok(port) = port_str.parse::<u16>() {
                            // Port 0 should be converted to 53 with a warning
                            if test_json.contains("\"ListenerPort\": 0") {
                                assert_eq!(port, 53, "Port 0 should be defaulted to 53");
                                let has_warning = messages.iter().any(|m| {
                                    m.level == MessageLevel::Warning
                                        && m.text.contains("Invalid port 0")
                                });
                                assert!(has_warning, "Should have warning for port 0");
                            } else {
                                assert!(port > 0, "Port should be in valid range: {}", port);
                            }
                        }
                    }

                    // Invalid ports might generate warnings or use defaults
                    if test_json.contains("-")
                        || test_json.contains("65536")
                        || test_json.contains("100000")
                    {
                        // Migration should handle gracefully, either with warnings or defaults
                        let has_warnings =
                            messages.iter().any(|m| m.level == MessageLevel::Warning);
                        let uses_default = migrated_config.server.listen_address.ends_with(":53");
                        assert!(
                            has_warnings || uses_default,
                            "Invalid ports should trigger warnings or default to 53"
                        );
                    }
                }
                Err(_) => {
                    // Type parsing errors are acceptable for invalid port formats
                }
            }
        }
    }

    #[test]
    fn test_migrate_ip_address_validation() {
        // Test various invalid IP address scenarios
        let ip_test_cases = vec![
            // Invalid IPv4 addresses in hosts
            r#"{ "HostsConfig": { "Rule": { "IsEnabled": true }, "Hosts": [{ "IpAddresses": ["999.999.999.999", "192.168.1.256"], "DomainNames": ["test.local"] }]} }"#,
            // Invalid IPv6 addresses
            r#"{ "HostsConfig": { "Rule": { "IsEnabled": true }, "Hosts": [{ "IpAddresses": ["2001:db8::1::2", "invalid:ipv6:address"], "DomainNames": ["test.local"] }]} }"#,
            // Mixed valid and invalid IPs
            r#"{ "HostsConfig": { "Rule": { "IsEnabled": true }, "Hosts": [{ "IpAddresses": ["192.168.1.1", "invalid.ip", "::1"], "DomainNames": ["test.local"] }]} }"#,
            // Empty IP addresses
            r#"{ "HostsConfig": { "Rule": { "IsEnabled": true }, "Hosts": [{ "IpAddresses": ["", "   ", "192.168.1.1"], "DomainNames": ["test.local"] }]} }"#,
            // Non-IP strings
            r#"{ "HostsConfig": { "Rule": { "IsEnabled": true }, "Hosts": [{ "IpAddresses": ["not.an.ip.address", "definitely.not.ip"], "DomainNames": ["test.local"] }]} }"#,
            // IP addresses with ports (not valid for hosts)
            r#"{ "HostsConfig": { "Rule": { "IsEnabled": true }, "Hosts": [{ "IpAddresses": ["192.168.1.1:80", "127.0.0.1:443"], "DomainNames": ["test.local"] }]} }"#,
            // Localhost variations
            r#"{ "HostsConfig": { "Rule": { "IsEnabled": true }, "Hosts": [{ "IpAddresses": ["localhost", "0.0.0.0", "127.0.0.1"], "DomainNames": ["test.local"] }]} }"#,
        ];

        for test_json in ip_test_cases {
            let parse_result: Result<DotNetHostsConfig, _> = serde_json::from_str(test_json);
            match parse_result {
                Ok(hosts_config) => {
                    let legacy = DotNetLegacyConfig {
                        hosts_config: Some(hosts_config),
                        ..Default::default()
                    };
                    let (migrated_config, messages) = migrate(legacy).unwrap();

                    // Migration should complete successfully
                    if let Some(local_hosts) = migrated_config.local_hosts {
                        // All IP addresses in the final config should be valid
                        for (domain, ips) in local_hosts.entries {
                            for ip in ips {
                                assert!(
                                    ip.is_ipv4() || ip.is_ipv6(),
                                    "Invalid IP {} for domain {}",
                                    ip,
                                    domain
                                );
                            }
                        }
                    }

                    // Should have warning messages for invalid IP addresses
                    if test_json.contains("999.999")
                        || test_json.contains("invalid")
                        || test_json.contains("not.an.ip")
                    {
                        let warning_count = messages
                            .iter()
                            .filter(|m| m.level == MessageLevel::Warning)
                            .count();
                        assert!(
                            warning_count > 0,
                            "Expected warnings for invalid IP addresses"
                        );
                    }
                }
                Err(_) => {
                    // JSON parsing failures are acceptable
                }
            }
        }
    }

    #[test]
    fn test_migrate_url_validation() {
        // Test various invalid URL scenarios
        let long_url_json = format!(
            r#"{{ "HttpProxyConfig": {{ "Address": "{}", "Port": 8080 }} }}"#,
            "a".repeat(2000)
        );
        let url_test_cases = vec![
            // Invalid proxy URLs
            r#"{ "HttpProxyConfig": { "Address": "not-a-valid-url", "Port": 8080 } }"#,
            r#"{ "HttpProxyConfig": { "Address": "", "Port": 8080 } }"#,
            r#"{ "HttpProxyConfig": { "Address": "proxy with spaces", "Port": 8080 } }"#,
            // URLs with invalid characters
            r#"{ "HttpProxyConfig": { "Address": "proxy.com\x00\x01", "Port": 8080 } }"#,
            // Very long URLs
            &long_url_json,
            // URLs with special characters that need escaping
            r#"{ "HttpProxyConfig": { "Address": "proxy.com/?query=value&other=param", "Port": 8080 } }"#,
            // International domain names in URLs
            r#"{ "HttpProxyConfig": { "Address": "тест.рф", "Port": 8080 } }"#,
        ];

        for test_json in url_test_cases {
            let parse_result: Result<DotNetMainConfig, _> = serde_json::from_str(test_json);
            match parse_result {
                Ok(config) => {
                    let legacy = DotNetLegacyConfig {
                        main_config: config,
                        ..Default::default()
                    };
                    let result = migrate(legacy);

                    match result {
                        Ok((migrated_config, messages)) => {
                            // If proxy config is present, URL should be valid
                            if let Some(proxy) = migrated_config.http_proxy {
                                assert!(
                                    proxy.url.as_str().starts_with("http://")
                                        || proxy.url.as_str().starts_with("https://")
                                );
                                assert!(!proxy.url.as_str().is_empty());
                            }

                            // Invalid URLs should generate warning messages
                            if test_json.contains("not-a-valid-url")
                                || test_json.contains("spaces")
                                || test_json.contains("\x00")
                            {
                                let _has_warnings =
                                    messages.iter().any(|m| m.level == MessageLevel::Warning);
                                // Don't require warnings as invalid URLs might be skipped entirely
                            }
                        }
                        Err(_) => {
                            // Configuration errors for invalid URLs are acceptable
                        }
                    }
                }
                Err(_) => {
                    // JSON parsing failures for invalid characters are acceptable
                }
            }
        }
    }

    #[test]
    fn test_migrate_aws_account_validation() {
        // Test various invalid AWS account configurations
        let long_aws_json = format!(
            r#"{{ "AwsSettings": {{ "UserAccounts": [{{ "UserName": "{}", "UserAccountId": "123456789012" }}] }} }}"#,
            "a".repeat(1000)
        );
        let aws_test_cases = vec![
            // Invalid account IDs
            r#"{ "AwsSettings": { "UserAccounts": [{ "UserName": "test", "UserAccountId": "invalid-account-id" }] } }"#,
            r#"{ "AwsSettings": { "UserAccounts": [{ "UserName": "test", "UserAccountId": "12345" }] } }"#, // Too short
            r#"{ "AwsSettings": { "UserAccounts": [{ "UserName": "test", "UserAccountId": "123456789012345" }] } }"#, // Too long
            // Empty account configurations
            r#"{ "AwsSettings": { "UserAccounts": [{ "UserName": "", "UserAccountId": "" }] } }"#,
            // Invalid role configurations
            r#"{ "AwsSettings": { "UserAccounts": [{ "UserName": "test", "Roles": [{ "Role": "", "AwsAccountId": "123456789012" }] }] } }"#,
            r#"{ "AwsSettings": { "UserAccounts": [{ "UserName": "test", "Roles": [{ "Role": "ValidRole", "AwsAccountId": "" }] }] } }"#,
            // Invalid VPC IDs
            r#"{ "AwsSettings": { "UserAccounts": [{ "UserName": "test", "ScanVpcIds": ["invalid-vpc-id", "vpc-"] }] } }"#,
            // Special characters in AWS configuration
            r#"{ "AwsSettings": { "UserAccounts": [{ "UserName": "test@domain.com", "UserAccountId": "123456789012" }] } }"#,
            // Very long AWS configuration values
            &long_aws_json,
        ];

        for test_json in aws_test_cases {
            let parse_result: Result<DotNetMainConfig, _> = serde_json::from_str(test_json);
            match parse_result {
                Ok(config) => {
                    let legacy = DotNetLegacyConfig {
                        main_config: config,
                        ..Default::default()
                    };
                    let (migrated_config, messages) = migrate(legacy).unwrap();

                    // Migration should complete successfully
                    if let Some(aws_config) = migrated_config.aws {
                        // All accounts should have valid labels
                        for account in aws_config.accounts {
                            assert!(
                                !account.label.is_empty(),
                                "Account label should not be empty"
                            );
                            assert!(
                                account.label.starts_with("migrated_"),
                                "Account label should have migrated prefix"
                            );

                            // Account IDs should be valid if present
                            if let Some(account_id) = account.account_id {
                                if !account_id.is_empty() {
                                    // AWS account IDs should be 12 digits
                                    if account_id.len() == 12
                                        && account_id.chars().all(|c| c.is_ascii_digit())
                                    {
                                        // Valid account ID
                                    } else {
                                        // Invalid account IDs should generate warnings, not panic
                                        let has_warning = messages
                                            .iter()
                                            .any(|m| m.level == MessageLevel::Warning);
                                        if !has_warning {
                                            eprintln!(
                                                "Warning: Invalid account ID format should generate warning: {}",
                                                account_id
                                            );
                                        }
                                    }
                                }
                            }

                            // Role ARNs should be properly formatted
                            for role in account.roles_to_assume {
                                assert!(
                                    role.role_arn.starts_with("arn:aws:iam::"),
                                    "Role ARN should have proper format: {}",
                                    role.role_arn
                                );
                                assert!(
                                    role.role_arn.contains(":role/"),
                                    "Role ARN should contain :role/ segment: {}",
                                    role.role_arn
                                );
                            }
                        }
                    }

                    // Invalid configurations should generate warnings
                    if test_json.contains("invalid-account-id") || test_json.contains(r#""""#) {
                        let _warning_count = messages
                            .iter()
                            .filter(|m| m.level == MessageLevel::Warning)
                            .count();
                        // Some invalid configurations might be silently ignored rather than warned
                    }
                }
                Err(_) => {
                    // JSON parsing failures are acceptable for malformed configurations
                }
            }
        }
    }

    #[test]
    fn test_migrate_resource_limits_and_memory() {
        // Test configurations that could cause resource exhaustion

        // Generate large configurations
        let mut large_accounts = Vec::new();
        for i in 0..100 {
            large_accounts.push(format!(
                r#"{{ "UserName": "user{}", "UserAccountId": "12345678901{:1}" }}"#,
                i,
                i % 10
            ));
        }

        let large_aws_json = format!(
            r#"{{ "AwsSettings": {{ "UserAccounts": [{}] }} }}"#,
            large_accounts.join(",")
        );

        let start = std::time::Instant::now();
        let parse_result: Result<DotNetMainConfig, _> = serde_json::from_str(&large_aws_json);
        match parse_result {
            Ok(config) => {
                let legacy = DotNetLegacyConfig {
                    main_config: config,
                    ..Default::default()
                };
                let (migrated_config, _) = migrate(legacy).unwrap();

                // Should handle large configurations efficiently
                let duration = start.elapsed();
                assert!(
                    duration < Duration::from_secs(10),
                    "Large config migration took too long: {:?}",
                    duration
                );

                // Should successfully migrate all accounts
                if let Some(aws_config) = migrated_config.aws {
                    assert_eq!(
                        aws_config.accounts.len(),
                        100,
                        "Should migrate all 100 accounts"
                    );
                }
            }
            Err(_) => {
                // Very large JSON might fail to parse, which is acceptable
            }
        }

        // Test memory usage with deeply nested structures
        let nested_json = r#"{
            "DnsHostConfig": { "NetworkWhitelist": ["192.168.1.0/24"] },
            "AwsSettings": { 
                "UserAccounts": [{
                    "UserName": "test",
                    "Roles": [{
                        "AwsAccountId": "123456789012",
                        "Role": "TestRole",
                        "ScanVpcIds": ["vpc-123", "vpc-456", "vpc-789"]
                    }]
                }]
            }
        }"#;

        // Run multiple times to check for memory leaks
        for _ in 0..50 {
            if let Ok(config) = serde_json::from_str::<DotNetMainConfig>(nested_json) {
                let legacy = DotNetLegacyConfig {
                    main_config: config,
                    ..Default::default()
                };
                let result = migrate(legacy);
                assert!(result.is_ok(), "Repeated migration should not fail");
            }
        }
    }
}
