use crate::adapters::cli::output::Renderable;
use crate::config::models::RuleConfig;
use crate::core::rule_engine::ResolutionInstruction;
use serde::Serialize;

#[derive(Debug, Clone, Default)]
pub(crate) struct ResolveOptions {
    pub collect_trace: bool,
    pub skip_cache: bool,
    pub no_store: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RuleEvaluation {
    pub index: usize,
    pub name: String,
    pub pattern: String,
    pub matched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ResolutionTrace {
    pub domain: String,
    pub record_type: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub search_expansion: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_name: Option<String>,
    pub local_hosts_checked: bool,
    pub local_hosts_matched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname_chain: Option<String>,
    pub cache_checked: bool,
    pub cache_hit: bool,
    pub rules_evaluated: Vec<RuleEvaluation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_used: Option<String>,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Renderable for ResolutionTrace {
    fn command_name(&self) -> &'static str {
        "debug resolve"
    }

    fn is_ok(&self) -> bool {
        self.error.is_none()
    }

    fn warnings(&self) -> Vec<String> {
        vec![]
    }

    fn render_human(&self) -> String {
        let mut output = String::new();
        let mut step_num = 1;

        output.push_str(&format!(
            "Resolving: {} ({})\n\n",
            self.domain, self.record_type
        ));

        if !self.search_expansion.is_empty() {
            output.push_str(&format!("{step_num}. Search Expansion:\n"));
            for (i, name) in self.search_expansion.iter().enumerate() {
                let marker = if Some(name) == self.resolved_name.as_ref() {
                    " <- resolved"
                } else {
                    ""
                };
                output.push_str(&format!("   [{}] {}{}\n", i + 1, name, marker));
            }
            step_num += 1;
        }

        output.push_str(&format!(
            "{step_num}. Local Hosts:    {}\n",
            if self.local_hosts_matched {
                "MATCH"
            } else if self.local_hosts_checked {
                "NO MATCH"
            } else {
                "SKIPPED"
            }
        ));
        if let Some(cname) = &self.cname_chain {
            output.push_str(&format!("   CNAME:  {cname}\n"));
        }
        step_num += 1;

        output.push_str(&format!(
            "{step_num}. Cache:          {}\n",
            if self.cache_hit {
                "HIT"
            } else if self.cache_checked {
                "MISS"
            } else {
                "SKIPPED"
            }
        ));
        step_num += 1;

        output.push_str(&format!("{step_num}. Rule Evaluation:\n"));
        if self.rules_evaluated.is_empty() {
            output.push_str("   (no rules configured)\n");
        } else {
            for rule in &self.rules_evaluated {
                let status = if rule.matched { "MATCH" } else { "NO MATCH" };
                output.push_str(&format!(
                    "   [{}] {:<20} {:<10} ({})\n",
                    rule.index + 1,
                    truncate(&rule.name, 20),
                    status,
                    truncate(&rule.pattern, 30)
                ));
                if rule.matched {
                    if let Some(action) = &rule.action {
                        output.push_str(&format!("       Action: {action}\n"));
                    }
                }
            }
        }

        if let Some(instruction) = &self.instruction {
            output.push_str(&format!("   Instruction: {instruction}\n"));
        }
        step_num += 1;

        output.push_str(&format!("{step_num}. Resolution:\n"));
        if let Some(upstream) = &self.upstream_used {
            output.push_str(&format!("   Upstream: {upstream}\n"));
        }
        output.push_str(&format!("   Latency:  {}ms\n", self.latency_ms));

        if let Some(rcode) = &self.response_code {
            output.push_str(&format!("   Response: {rcode}\n"));
        }

        if !self.answers.is_empty() {
            output.push_str("   Answers:\n");
            for answer in &self.answers {
                output.push_str(&format!("     {answer}\n"));
            }
        }

        if let Some(error) = &self.error {
            output.push_str(&format!("   Error: {error}\n"));
        }

        output
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

pub(crate) fn evaluate_rules_for_trace(
    domain: &str,
    rules: &[RuleConfig],
) -> (Vec<RuleEvaluation>, Option<(usize, ResolutionInstruction)>) {
    let mut evaluations = Vec::new();
    let mut matched_instruction = None;

    for (i, rule) in rules.iter().enumerate() {
        let matches = rule.domain_pattern.0.is_match(domain) != rule.invert_match;

        let action = if matches {
            Some(format!("{:?}", rule.action))
        } else {
            None
        };

        evaluations.push(RuleEvaluation {
            index: i,
            name: rule.name.clone(),
            pattern: rule.domain_pattern.0.as_str().to_string(),
            matched: matches,
            action,
        });

        if matches && matched_instruction.is_none() {
            matched_instruction = Some((i, instruction_from_rule(rule)));
        }
    }

    (evaluations, matched_instruction)
}

fn instruction_from_rule(rule: &RuleConfig) -> ResolutionInstruction {
    use crate::config::models::RuleAction;

    match rule.action {
        RuleAction::Block => ResolutionInstruction::Block,
        RuleAction::Allow => ResolutionInstruction::Allow,
        RuleAction::ResolveLocal => ResolutionInstruction::ResolveLocal,
        RuleAction::Refuse => ResolutionInstruction::Refuse,
        RuleAction::Servfail => ResolutionInstruction::Servfail,
        RuleAction::Forward => {
            if let Some(ref nameservers) = rule.nameservers {
                let doh_urls: Vec<_> = nameservers
                    .iter()
                    .filter(|ns| ns.starts_with("https://"))
                    .filter_map(|ns| url::Url::parse(ns).ok())
                    .collect();

                if !doh_urls.is_empty() {
                    ResolutionInstruction::ForwardToDoH {
                        urls: doh_urls,
                        strategy: rule.strategy.clone(),
                        timeout: rule.timeout,
                        http_proxy: None,
                    }
                } else {
                    let dns_targets: Vec<_> = nameservers
                        .iter()
                        .filter_map(|ns| ns.parse().ok())
                        .collect();

                    ResolutionInstruction::ForwardToDns {
                        targets: dns_targets,
                        strategy: rule.strategy.clone(),
                        timeout: rule.timeout,
                    }
                }
            } else {
                ResolutionInstruction::UseDefaultResolver
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{HashableRegex, RuleAction};
    use regex::Regex;
    use std::time::Duration;

    fn make_rule(name: &str, pattern: &str, action: RuleAction) -> RuleConfig {
        RuleConfig {
            name: name.to_string(),
            domain_pattern: HashableRegex(Regex::new(pattern).unwrap()),
            action,
            nameservers: None,
            strategy: Default::default(),
            timeout: Duration::from_millis(500),
            doh_compression_mutation: false,
            source_list_url: None,
            invert_match: false,
        }
    }

    #[test]
    fn test_evaluate_rules_first_match_wins() {
        let rules = vec![
            make_rule("Block Ads", r"^ads\.", RuleAction::Block),
            make_rule("Allow All", r".*", RuleAction::Allow),
        ];

        let (evals, matched) = evaluate_rules_for_trace("ads.example.com", &rules);

        assert_eq!(evals.len(), 2);
        assert!(evals[0].matched);
        assert!(evals[1].matched); // Also matches .*
        assert_eq!(matched.unwrap().0, 0); // First match wins
    }

    #[test]
    fn test_evaluate_rules_no_match() {
        let rules = vec![make_rule("Block Ads", r"^ads\.", RuleAction::Block)];

        let (evals, matched) = evaluate_rules_for_trace("www.example.com", &rules);

        assert_eq!(evals.len(), 1);
        assert!(!evals[0].matched);
        assert!(matched.is_none());
    }

    #[test]
    fn test_render_human() {
        let trace = ResolutionTrace {
            domain: "example.com".to_string(),
            record_type: "A".to_string(),
            search_expansion: vec![],
            resolved_name: None,
            local_hosts_checked: true,
            local_hosts_matched: false,
            cname_chain: None,
            cache_checked: true,
            cache_hit: false,
            rules_evaluated: vec![],
            matched_rule: None,
            instruction: Some("UseDefaultResolver".to_string()),
            upstream_used: Some("1.1.1.1:53".to_string()),
            latency_ms: 12,
            response_code: Some("NOERROR".to_string()),
            answers: vec!["A 93.184.216.34 (TTL 300s)".to_string()],
            error: None,
        };

        let output = trace.render_human();
        assert!(output.contains("Resolving: example.com (A)"));
        assert!(output.contains("Local Hosts:    NO MATCH"));
        assert!(output.contains("Cache:          MISS"));
        assert!(output.contains("Latency:  12ms"));
    }

    #[test]
    fn test_render_human_with_search_expansion() {
        let trace = ResolutionTrace {
            domain: "nas".to_string(),
            record_type: "A".to_string(),
            search_expansion: vec![
                "nas.home.arpa".to_string(),
                "nas.lan".to_string(),
                "nas".to_string(),
            ],
            resolved_name: Some("nas.home.arpa".to_string()),
            local_hosts_checked: true,
            local_hosts_matched: true,
            cname_chain: None,
            cache_checked: false,
            cache_hit: false,
            rules_evaluated: vec![],
            matched_rule: None,
            instruction: None,
            upstream_used: None,
            latency_ms: 1,
            response_code: Some("NOERROR".to_string()),
            answers: vec!["A 192.168.1.100 (TTL 300s)".to_string()],
            error: None,
        };

        let output = trace.render_human();
        assert!(output.contains("Search Expansion:"));
        assert!(output.contains("nas.home.arpa"));
        assert!(output.contains("<- resolved"));
        assert!(output.contains("Local Hosts:    MATCH"));
    }

    #[test]
    fn test_render_human_with_cname() {
        let trace = ResolutionTrace {
            domain: "www.home.arpa".to_string(),
            record_type: "A".to_string(),
            search_expansion: vec![],
            resolved_name: None,
            local_hosts_checked: true,
            local_hosts_matched: true,
            cname_chain: Some("www.home.arpa -> nas.home.arpa".to_string()),
            cache_checked: false,
            cache_hit: false,
            rules_evaluated: vec![],
            matched_rule: None,
            instruction: None,
            upstream_used: None,
            latency_ms: 1,
            response_code: Some("NOERROR".to_string()),
            answers: vec![
                "CNAME nas.home.arpa. (TTL 300s)".to_string(),
                "A 192.168.1.100 (TTL 300s)".to_string(),
            ],
            error: None,
        };

        let output = trace.render_human();
        assert!(output.contains("CNAME:  www.home.arpa -> nas.home.arpa"));
        assert!(output.contains("Local Hosts:    MATCH"));
    }
}
