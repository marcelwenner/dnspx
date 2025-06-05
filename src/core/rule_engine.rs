use crate::config::models::{AppConfig, HttpProxyConfig, ResolverStrategy, RuleAction};
use crate::dns_protocol::DnsQuestion;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use url::Url;

#[derive(Debug, Clone)]
pub(crate) enum ResolutionInstruction {
    ForwardToDns {
        targets: Vec<String>,
        timeout: Duration,
        strategy: ResolverStrategy,
    },
    ForwardToDoH {
        urls: Vec<Url>,
        timeout: Duration,
        strategy: ResolverStrategy,
        http_proxy: Option<HttpProxyConfig>,
    },
    ResolveViaAws {
        service_hint: String,
    },
    Block,
    Allow,
    ResolveLocal,
    UseDefaultResolver,
}

pub(crate) struct RuleEngine {
    config: Arc<RwLock<AppConfig>>,
}

impl RuleEngine {
    pub(crate) fn new(config: Arc<RwLock<AppConfig>>) -> Self {
        Self { config }
    }

    pub(crate) async fn determine_resolution_instruction(
        &self,
        question: &DnsQuestion,
    ) -> Option<ResolutionInstruction> {
        let config_guard = self.config.read().await;
        let question_name = question.name.trim_end_matches('.');

        for rule in &config_guard.routing_rules {
            let pattern_matches = rule.domain_pattern.0.is_match(question_name);
            let effective_match = if rule.invert_match {
                !pattern_matches
            } else {
                pattern_matches
            };

            if effective_match {
                debug!(
                    "Rule '{}' matched domain '{}' (invert_match: {}). Action: {:?}",
                    rule.name, question_name, rule.invert_match, rule.action
                );
                match rule.action {
                    RuleAction::Forward => {
                        if let Some(nameservers) = &rule.nameservers {
                            let mut dns_targets = Vec::new();
                            let mut doh_urls = Vec::new();
                            for ns in nameservers {
                                if ns.starts_with("https://") {
                                    if let Ok(url) = Url::parse(ns) {
                                        doh_urls.push(url);
                                    } else {
                                        warn!(
                                            "Invalid DoH URL in rule '{}': {}. Skipping this nameserver.",
                                            rule.name, ns
                                        );
                                    }
                                } else if ns.contains("://") {
                                    warn!(
                                        "Unsupported URL scheme (not https) in nameserver list for rule '{}': {}. Skipping.",
                                        rule.name, ns
                                    );
                                } else if ns.contains('/') && !ns.starts_with('[') {
                                    warn!(
                                        "Nameserver '{}' in rule '{}' appears to be a malformed URL or contains a path. Skipping.",
                                        ns, rule.name
                                    );
                                } else {
                                    dns_targets.push(ns.clone());
                                }
                            }

                            if !doh_urls.is_empty() {
                                return Some(ResolutionInstruction::ForwardToDoH {
                                    urls: doh_urls,
                                    timeout: rule.timeout,
                                    strategy: rule.strategy.clone(),
                                    http_proxy: config_guard.http_proxy.clone(),
                                });
                            } else if !dns_targets.is_empty() {
                                return Some(ResolutionInstruction::ForwardToDns {
                                    targets: dns_targets,
                                    timeout: rule.timeout,
                                    strategy: rule.strategy.clone(),
                                });
                            } else {
                                warn!(
                                    "Rule '{}' action is Forward but no valid nameservers defined.",
                                    rule.name
                                );
                            }
                        } else {
                            warn!(
                                "Rule '{}' action is Forward but no nameservers defined.",
                                rule.name
                            );
                        }
                    }
                    RuleAction::Block => return Some(ResolutionInstruction::Block),
                    RuleAction::Allow => return Some(ResolutionInstruction::Allow),
                    RuleAction::ResolveLocal => return Some(ResolutionInstruction::ResolveLocal),
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{
        AppConfig, DefaultResolverConfig, HashableRegex, HttpProxyConfig, ResolverStrategy,
        RuleAction, RuleConfig,
    };
    use crate::dns_protocol::DnsQuestion;
    use assert_matches::assert_matches;
    use hickory_proto::rr::RecordType;
    use regex::Regex;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;
    use url::Url;

    fn create_test_question(name: &str, record_type: RecordType) -> DnsQuestion {
        DnsQuestion {
            name: name.to_string(),
            record_type,
            class: hickory_proto::rr::DNSClass::IN,
        }
    }

    fn create_rule_config(
        name: &str,
        pattern_str: &str,
        action: RuleAction,
        nameservers: Option<Vec<String>>,
        invert_match: bool,
        strategy: ResolverStrategy,
        timeout_ms: u64,
    ) -> RuleConfig {
        RuleConfig {
            name: name.to_string(),
            domain_pattern: HashableRegex(
                Regex::new(pattern_str).expect("Invalid regex in test rule"),
            ),
            action,
            nameservers,
            strategy,
            timeout: Duration::from_millis(timeout_ms),
            doh_compression_mutation: false,
            source_list_url: None,
            invert_match,
        }
    }

    fn create_app_config(
        rules: Vec<RuleConfig>,
        default_resolver: Option<DefaultResolverConfig>,
        http_proxy: Option<HttpProxyConfig>,
    ) -> AppConfig {
        AppConfig {
            routing_rules: rules,
            default_resolver: default_resolver.unwrap_or_default(),
            http_proxy,
            ..AppConfig::default()
        }
    }

    mod domain_pattern_matching {
        use super::*;

        #[tokio::test]
        async fn test_rule_engine_exact_match_returns_correct_instruction() {
            let rule = create_rule_config(
                "exact_example_rule",
                "^exact\\.example\\.com$",
                RuleAction::Block,
                None,
                false,
                ResolverStrategy::First,
                500,
            );
            let app_config = create_app_config(vec![rule], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));

            let matching_question = create_test_question("exact.example.com", RecordType::A);
            let non_matching_subdomain_question =
                create_test_question("sub.exact.example.com", RecordType::A);
            let non_matching_other_domain_question =
                create_test_question("other.com", RecordType::A);

            let result_match = rule_engine
                .determine_resolution_instruction(&matching_question)
                .await;
            assert_matches!(
                result_match,
                Some(ResolutionInstruction::Block),
                "Should match exact.example.com and return Block"
            );

            let result_no_match_subdomain = rule_engine
                .determine_resolution_instruction(&non_matching_subdomain_question)
                .await;
            assert_matches!(
                result_no_match_subdomain,
                None,
                "Should not match sub.exact.example.com for exact rule"
            );

            let result_no_match_other = rule_engine
                .determine_resolution_instruction(&non_matching_other_domain_question)
                .await;
            assert_matches!(result_no_match_other, None, "Should not match other.com");
        }

        #[tokio::test]
        async fn test_rule_engine_wildcard_match_returns_correct_instruction() {
            let rule_pattern_str = r"^(.*\.)?wild\.com$";
            let rule = create_rule_config(
                "wildcard_rule",
                rule_pattern_str,
                RuleAction::Allow,
                None,
                false,
                ResolverStrategy::First,
                500,
            );
            let app_config = create_app_config(vec![rule], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));

            let q_sub = create_test_question("sub.wild.com", RecordType::A);
            let q_sub_sub = create_test_question("another.sub.wild.com", RecordType::A);
            let q_base = create_test_question("wild.com", RecordType::A);
            let q_no_match_other = create_test_question("other.com", RecordType::A);
            let q_no_match_suffix = create_test_question("wild.com.org", RecordType::A);

            assert_matches!(
                rule_engine.determine_resolution_instruction(&q_sub).await,
                Some(ResolutionInstruction::Allow),
                "sub.wild.com should match"
            );
            assert_matches!(
                rule_engine
                    .determine_resolution_instruction(&q_sub_sub)
                    .await,
                Some(ResolutionInstruction::Allow),
                "another.sub.wild.com should match"
            );
            assert_matches!(
                rule_engine.determine_resolution_instruction(&q_base).await,
                Some(ResolutionInstruction::Allow),
                r"wild.com should match due to `?` in `(.*\.)?`"
            );
            assert_matches!(
                rule_engine
                    .determine_resolution_instruction(&q_no_match_other)
                    .await,
                None,
                "other.com should not match"
            );
            assert_matches!(
                rule_engine
                    .determine_resolution_instruction(&q_no_match_suffix)
                    .await,
                None,
                "wild.com.org should not match"
            );
        }

        #[tokio::test]
        async fn test_rule_engine_complex_regex_match_returns_correct_instruction() {
            let rule_pattern_str = r"^(service[0-9]+)\.region1\.corp$";
            let rule = create_rule_config(
                "complex_regex_rule",
                rule_pattern_str,
                RuleAction::ResolveLocal,
                None,
                false,
                ResolverStrategy::First,
                500,
            );
            let app_config = create_app_config(vec![rule], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));

            let q_match = create_test_question("service123.region1.corp", RecordType::A);
            let q_no_match_no_num = create_test_question("service.region1.corp", RecordType::A);
            let q_no_match_wrong_region =
                create_test_question("service123.region2.corp", RecordType::A);

            assert_matches!(
                rule_engine.determine_resolution_instruction(&q_match).await,
                Some(ResolutionInstruction::ResolveLocal),
                "service123.region1.corp should match"
            );
            assert_matches!(
                rule_engine
                    .determine_resolution_instruction(&q_no_match_no_num)
                    .await,
                None,
                "service.region1.corp should not match"
            );
            assert_matches!(
                rule_engine
                    .determine_resolution_instruction(&q_no_match_wrong_region)
                    .await,
                None,
                "service123.region2.corp should not match"
            );
        }

        #[tokio::test]
        async fn test_rule_engine_inverted_exact_match_returns_correct_instruction() {
            let rule = create_rule_config(
                "inverted_exact_rule",
                "^block\\.com$",
                RuleAction::Allow,
                None,
                true,
                ResolverStrategy::First,
                500,
            );
            let app_config = create_app_config(vec![rule], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));

            let q_should_match = create_test_question("allow.com", RecordType::A);
            let q_should_not_match = create_test_question("block.com", RecordType::A);

            assert_matches!(
                rule_engine
                    .determine_resolution_instruction(&q_should_match)
                    .await,
                Some(ResolutionInstruction::Allow),
                "allow.com should trigger inverted match"
            );
            assert_matches!(
                rule_engine
                    .determine_resolution_instruction(&q_should_not_match)
                    .await,
                None,
                "block.com should NOT trigger inverted match"
            );
        }

        #[tokio::test]
        async fn test_rule_engine_inverted_wildcard_match_returns_correct_instruction() {
            let rule_pattern_str = r"^(.*\.)?block-this\.net$";
            let rule_nameservers = vec!["8.8.8.8".to_string()];
            let rule = create_rule_config(
                "inverted_wildcard_rule",
                rule_pattern_str,
                RuleAction::Forward,
                Some(rule_nameservers.clone()),
                true,
                ResolverStrategy::First,
                500,
            );
            let app_config = create_app_config(vec![rule], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));

            let q_should_match = create_test_question("allowed.domain.org", RecordType::A);
            let q_should_not_match_sub = create_test_question("sub.block-this.net", RecordType::A);
            let q_should_not_match_base = create_test_question("block-this.net", RecordType::A);

            let result_match = rule_engine
                .determine_resolution_instruction(&q_should_match)
                .await;
            assert_matches!(
                result_match,
                Some(ResolutionInstruction::ForwardToDns { .. }),
                "allowed.domain.org should trigger inverted match"
            );
            if let Some(ResolutionInstruction::ForwardToDns { targets, .. }) = result_match {
                assert_eq!(targets, rule_nameservers);
            }

            assert_matches!(
                rule_engine
                    .determine_resolution_instruction(&q_should_not_match_sub)
                    .await,
                None,
                "sub.block-this.net should NOT trigger inverted match"
            );
            assert_matches!(
                rule_engine
                    .determine_resolution_instruction(&q_should_not_match_base)
                    .await,
                None,
                "block-this.net should NOT trigger inverted match"
            );
        }

        #[tokio::test]
        async fn test_rule_engine_no_match_returns_none() {
            let rule1 = create_rule_config(
                "rule_a",
                "^a\\.com$",
                RuleAction::Block,
                None,
                false,
                ResolverStrategy::First,
                500,
            );
            let rule2 = create_rule_config(
                "rule_b",
                "^b\\.net$",
                RuleAction::Allow,
                None,
                false,
                ResolverStrategy::First,
                500,
            );
            let app_config = create_app_config(vec![rule1, rule2], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));

            let question = create_test_question("c.org", RecordType::A);

            let result = rule_engine
                .determine_resolution_instruction(&question)
                .await;

            assert_matches!(result, None, "Should return None when no rules match");
        }
    }

    mod rule_priority_and_actions {
        use crate::config::models::ProxyAuthenticationType;

        use super::*;

        #[tokio::test]
        async fn test_rule_engine_first_match_wins() {
            let rule1_pattern = r"^(.*\.)?specific\.com$";
            let rule1_nameservers = vec!["1.1.1.1".to_string()];
            let rule1 = create_rule_config(
                "specific_rule",
                rule1_pattern,
                RuleAction::Forward,
                Some(rule1_nameservers.clone()),
                false,
                ResolverStrategy::First,
                500,
            );

            let rule2_pattern = r"^(.*\.)?com$";
            let rule2 = create_rule_config(
                "general_com_rule",
                rule2_pattern,
                RuleAction::Block,
                None,
                false,
                ResolverStrategy::First,
                500,
            );

            let app_config = create_app_config(vec![rule1, rule2], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));

            let q_specific = create_test_question("host.specific.com", RecordType::A);
            let q_general = create_test_question("another.host.com", RecordType::A);

            let result_specific = rule_engine
                .determine_resolution_instruction(&q_specific)
                .await;
            assert_matches!(
                result_specific,
                Some(ResolutionInstruction::ForwardToDns { .. }),
                "host.specific.com should match rule1 and forward"
            );
            if let Some(ResolutionInstruction::ForwardToDns { targets, .. }) = result_specific {
                assert_eq!(targets, rule1_nameservers);
            }

            let result_general = rule_engine
                .determine_resolution_instruction(&q_general)
                .await;
            assert_matches!(
                result_general,
                Some(ResolutionInstruction::Block),
                "another.host.com should match rule2 and block"
            );
        }

        #[tokio::test]
        async fn test_rule_engine_block_action() {
            let rule = create_rule_config(
                "block_rule",
                "^blockme\\.com$",
                RuleAction::Block,
                None,
                false,
                ResolverStrategy::First,
                500,
            );
            let app_config = create_app_config(vec![rule], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));
            let question = create_test_question("blockme.com", RecordType::A);

            let result = rule_engine
                .determine_resolution_instruction(&question)
                .await;
            assert_matches!(result, Some(ResolutionInstruction::Block));
        }

        #[tokio::test]
        async fn test_rule_engine_allow_action() {
            let rule = create_rule_config(
                "allow_rule",
                "^allowme\\.com$",
                RuleAction::Allow,
                None,
                false,
                ResolverStrategy::First,
                500,
            );
            let app_config = create_app_config(vec![rule], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));
            let question = create_test_question("allowme.com", RecordType::A);

            let result = rule_engine
                .determine_resolution_instruction(&question)
                .await;
            assert_matches!(result, Some(ResolutionInstruction::Allow));
        }

        #[tokio::test]
        async fn test_rule_engine_resolve_local_action() {
            let rule = create_rule_config(
                "local_rule",
                "^local\\.com$",
                RuleAction::ResolveLocal,
                None,
                false,
                ResolverStrategy::First,
                500,
            );
            let app_config = create_app_config(vec![rule], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));
            let question = create_test_question("local.com", RecordType::A);

            let result = rule_engine
                .determine_resolution_instruction(&question)
                .await;
            assert_matches!(result, Some(ResolutionInstruction::ResolveLocal));
        }

        #[tokio::test]
        async fn test_rule_engine_forward_to_dns_action() {
            let nameservers = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
            let rule = create_rule_config(
                "forward_dns_rule",
                "^dns\\.fwd$",
                RuleAction::Forward,
                Some(nameservers.clone()),
                false,
                ResolverStrategy::Rotate,
                750,
            );
            let app_config = create_app_config(vec![rule], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));
            let question = create_test_question("dns.fwd", RecordType::A);

            let result = rule_engine
                .determine_resolution_instruction(&question)
                .await;
            assert_matches!(result, Some(ResolutionInstruction::ForwardToDns { targets, timeout, strategy }) => {
                assert_eq!(targets, nameservers, "DNS targets should match");
                assert_eq!(timeout, Duration::from_millis(750), "Timeout should match");
                assert_eq!(strategy, ResolverStrategy::Rotate, "Strategy should match");
            });
        }

        #[tokio::test]
        async fn test_rule_engine_forward_to_doh_action() {
            let doh_url_str = "https://doh.example/dns-query";
            let nameservers = vec![doh_url_str.to_string()];
            let expected_doh_url = Url::parse(doh_url_str).unwrap();

            let proxy_config = HttpProxyConfig {
                url: Url::parse("http://proxy.example.com:8080").unwrap(),
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
                authentication_type: ProxyAuthenticationType::None,
                domain: None,
                bypass_list: None,
            };

            let rule = create_rule_config(
                "forward_doh_rule",
                "^doh\\.fwd$",
                RuleAction::Forward,
                Some(nameservers.clone()),
                false,
                ResolverStrategy::Fastest,
                600,
            );
            let app_config_with_proxy =
                create_app_config(vec![rule.clone()], None, Some(proxy_config.clone()));
            let rule_engine_with_proxy =
                RuleEngine::new(Arc::new(RwLock::new(app_config_with_proxy)));
            let question = create_test_question("doh.fwd", RecordType::AAAA);

            let result_with_proxy = rule_engine_with_proxy
                .determine_resolution_instruction(&question)
                .await;
            assert_matches!(result_with_proxy, Some(ResolutionInstruction::ForwardToDoH { urls, timeout, strategy, http_proxy }) => {
                assert_eq!(urls, vec![expected_doh_url.clone()], "DoH URLs should match");
                assert_eq!(timeout, Duration::from_millis(600), "Timeout should match");
                assert_eq!(strategy, ResolverStrategy::Fastest, "Strategy should match");
                assert_eq!(http_proxy, Some(proxy_config), "HTTP Proxy config should match");
            });

            let app_config_no_proxy = create_app_config(vec![rule], None, None);
            let rule_engine_no_proxy = RuleEngine::new(Arc::new(RwLock::new(app_config_no_proxy)));
            let result_no_proxy = rule_engine_no_proxy
                .determine_resolution_instruction(&question)
                .await;
            assert_matches!(result_no_proxy, Some(ResolutionInstruction::ForwardToDoH { urls, timeout, strategy, http_proxy }) => {
                assert_eq!(urls, vec![expected_doh_url], "DoH URLs should match (no proxy)");
                assert_eq!(timeout, Duration::from_millis(600), "Timeout should match (no proxy)");
                assert_eq!(strategy, ResolverStrategy::Fastest, "Strategy should match (no proxy)");
                assert_eq!(http_proxy, None, "HTTP Proxy should be None");
            });
        }

        #[tokio::test]
        async fn test_rule_engine_forward_prefers_doh_over_dns_if_mixed() {
            let doh_url_str = "https://cloudflare-dns.com/dns-query";
            let dns_server = "8.8.4.4";
            let nameservers = vec![dns_server.to_string(), doh_url_str.to_string()];
            let expected_doh_urls = vec![Url::parse(doh_url_str).unwrap()];

            let rule = create_rule_config(
                "mixed_fwd_rule",
                "^mixed\\.fwd$",
                RuleAction::Forward,
                Some(nameservers),
                false,
                ResolverStrategy::First,
                500,
            );
            let app_config = create_app_config(vec![rule], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));
            let question = create_test_question("mixed.fwd", RecordType::TXT);

            let result = rule_engine
                .determine_resolution_instruction(&question)
                .await;
            assert_matches!(
                result,
                Some(ResolutionInstruction::ForwardToDoH { .. }),
                "Should select ForwardToDoH due to DoH URL presence"
            );
            if let Some(ResolutionInstruction::ForwardToDoH { urls, .. }) = result {
                assert_eq!(
                    urls, expected_doh_urls,
                    "Only DoH URLs should be in ForwardToDoH targets"
                );
            }
        }

        #[tokio::test]
        async fn test_rule_engine_forward_skips_invalid_doh_url_uses_dns() {
            let invalid_doh_url = "htps:/invalid-doh";
            let valid_dns_server = "1.0.0.1";
            let nameservers = vec![invalid_doh_url.to_string(), valid_dns_server.to_string()];

            let rule = create_rule_config(
                "invalid_doh_fallback_rule",
                "^invalid\\.doh$",
                RuleAction::Forward,
                Some(nameservers),
                false,
                ResolverStrategy::First,
                500,
            );
            let app_config = create_app_config(vec![rule], None, None);
            let rule_engine = RuleEngine::new(Arc::new(RwLock::new(app_config)));
            let question = create_test_question("invalid.doh", RecordType::A);

            let result = rule_engine
                .determine_resolution_instruction(&question)
                .await;
            assert_matches!(
                result,
                Some(ResolutionInstruction::ForwardToDns { .. }),
                "Should fallback to ForwardToDns as the DoH URL was invalid"
            );
            if let Some(ResolutionInstruction::ForwardToDns { targets, .. }) = result {
                assert_eq!(targets, vec![valid_dns_server.to_string()]);
            }
        }

        #[tokio::test]
        async fn test_rule_engine_forward_no_valid_nameservers_returns_none() {
            let rule_empty_ns = create_rule_config(
                "empty_ns_rule",
                "^empty\\.ns$",
                RuleAction::Forward,
                Some(vec![]),
                false,
                ResolverStrategy::First,
                500,
            );
            let app_config_empty = create_app_config(vec![rule_empty_ns], None, None);
            let rule_engine_empty = RuleEngine::new(Arc::new(RwLock::new(app_config_empty)));
            let q_empty = create_test_question("empty.ns", RecordType::A);
            assert_matches!(
                rule_engine_empty
                    .determine_resolution_instruction(&q_empty)
                    .await,
                None,
                "Forward with empty nameservers should return None"
            );

            let nameservers_invalid_doh = vec!["htps:/invalid-doh".to_string()];
            let rule_invalid_doh = create_rule_config(
                "invalid_doh_only_rule",
                "^invalid\\.doh\\.only$",
                RuleAction::Forward,
                Some(nameservers_invalid_doh),
                false,
                ResolverStrategy::First,
                500,
            );
            let app_config_invalid_doh = create_app_config(vec![rule_invalid_doh], None, None);
            let rule_engine_invalid_doh =
                RuleEngine::new(Arc::new(RwLock::new(app_config_invalid_doh)));
            let q_invalid_doh = create_test_question("invalid.doh.only", RecordType::A);
            assert_matches!(
                rule_engine_invalid_doh
                    .determine_resolution_instruction(&q_invalid_doh)
                    .await,
                None,
                "Forward with only invalid DoH URL should return None"
            );

            let rule_no_ns_field = create_rule_config(
                "no_ns_field_rule",
                "^no\\.ns\\.field$",
                RuleAction::Forward,
                None,
                false,
                ResolverStrategy::First,
                500,
            );
            let app_config_no_ns_field = create_app_config(vec![rule_no_ns_field], None, None);
            let rule_engine_no_ns_field =
                RuleEngine::new(Arc::new(RwLock::new(app_config_no_ns_field)));
            let q_no_ns_field = create_test_question("no.ns.field", RecordType::A);
            assert_matches!(
                rule_engine_no_ns_field
                    .determine_resolution_instruction(&q_no_ns_field)
                    .await,
                None,
                "Forward with no nameservers field should return None"
            );
        }
    }
}
