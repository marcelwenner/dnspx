use crate::core::dns_cache::{CacheKey, DnsCache};
use crate::core::error::{DnsProcessingError, ResolveError};
use crate::core::local_hosts_resolver::LocalHostsResolver;
use crate::core::rule_engine::{ResolutionInstruction, RuleEngine};
use crate::core::types::ProtocolType;
use crate::dns_protocol::{DnsMessage, DnsQuestion, parse_dns_message, serialize_dns_message};
use crate::ports::{AppLifecycleManagerPort, DnsQueryService, UpstreamResolver};
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{Instrument, Level, Span, debug, error, event, field, instrument, warn};
use url::Url;

pub(crate) struct DnsRequestProcessor {
    app_lifecycle_access: Arc<dyn AppLifecycleManagerPort>,
    dns_cache: Arc<DnsCache>,
    rule_engine: Arc<RuleEngine>,
    local_hosts_resolver: Arc<LocalHostsResolver>,
    upstream_resolver: Arc<dyn UpstreamResolver>,
}

impl DnsRequestProcessor {
    pub(crate) fn new(
        app_lifecycle_access: Arc<dyn AppLifecycleManagerPort>,
        dns_cache: Arc<DnsCache>,
        rule_engine: Arc<RuleEngine>,
        local_hosts_resolver: Arc<LocalHostsResolver>,
        upstream_resolver: Arc<dyn UpstreamResolver>,
    ) -> Self {
        Self {
            app_lifecycle_access,
            dns_cache,
            rule_engine,
            local_hosts_resolver,
            upstream_resolver,
        }
    }

    async fn resolve_single_question(
        &self,
        question: &DnsQuestion,
        original_query_message: &Arc<DnsMessage>,
    ) -> Result<DnsMessage, DnsProcessingError> {
        let start_time = Instant::now();
        #[allow(unused_assignments)]
        let mut source_str: &str = "Unknown";

        let config_guard = self.app_lifecycle_access.get_config_for_processor().await;
        let app_config = config_guard.read().await;

        if let Some(mut local_response) = self
            .local_hosts_resolver
            .resolve(question, original_query_message)
            .instrument(tracing::info_span!("local_hosts_resolve"))
            .await
        {
            source_str = "LocalHosts";
            debug!("Resolved by LocalHostsResolver for {}", question.name);
            local_response.set_response_code(ResponseCode::NoError);
            let latency_ms = start_time.elapsed().as_millis();
            event!(Level::INFO, qname = %question.name, qtype = %question.record_type, rcode = ?local_response.response_code(), source = source_str, latency_ms, "Query resolved");
            return Ok(local_response);
        }

        let cache_key = CacheKey::from_question(question);
        if app_config.cache.enabled {
            if let Some(cached_entry_arc) = self
                .dns_cache
                .get(&cache_key, app_config.cache.serve_stale_if_error)
                .instrument(tracing::info_span!("cache_get"))
                .await
            {
                source_str = if cached_entry_arc.is_valid() {
                    "Cache"
                } else {
                    "Cache(Stale)"
                };
                debug!("Resolved from cache for {}: {}", question.name, source_str);
                let mut response = DnsMessage::new_response(
                    original_query_message,
                    cached_entry_arc.response_code,
                );
                for record_from_cache in &cached_entry_arc.records {
                    let mut cloned_record = record_from_cache.clone();
                    cloned_record.set_ttl(cached_entry_arc.current_ttl_remaining_secs());
                    response.add_answer_record(cloned_record);
                }
                response.set_authoritative(false);
                let latency_ms = start_time.elapsed().as_millis();
                event!(Level::INFO, qname = %question.name, qtype = %question.record_type, rcode = ?response.response_code(), source = source_str, latency_ms, "Query resolved");
                return Ok(response);
            }
        }

        let instruction = self
            .rule_engine
            .determine_resolution_instruction(question)
            .instrument(tracing::info_span!("rule_engine_eval"))
            .await
            .unwrap_or(ResolutionInstruction::UseDefaultResolver);

        debug!(
            "Rule engine instruction for {}: {:?}",
            question.name, instruction
        );

        match &instruction {
            ResolutionInstruction::ForwardToDns { strategy, .. } => {
                source_str = Box::leak(format!("ForwardDns({strategy:?})").into_boxed_str())
            }
            ResolutionInstruction::ForwardToDoH { strategy, .. } => {
                source_str = Box::leak(format!("ForwardDoH({strategy:?})").into_boxed_str())
            }
            ResolutionInstruction::ResolveViaAws { service_hint } => {
                source_str = Box::leak(format!("ResolveAws({service_hint})").into_boxed_str())
            }
            ResolutionInstruction::Block => source_str = "BlockRule",
            ResolutionInstruction::Allow => source_str = "AllowRule->Default",
            ResolutionInstruction::ResolveLocal => source_str = "ResolveLocalRule(Fail)",
            ResolutionInstruction::UseDefaultResolver => source_str = "DefaultResolver",
        };

        let mut initial_upstream_response_result: Result<DnsMessage, ResolveError> =
            Err(ResolveError::NoUpstreamServers);

        match &instruction {
            ResolutionInstruction::ForwardToDns {
                targets, timeout, ..
            } => {
                initial_upstream_response_result = self
                    .upstream_resolver
                    .resolve_dns(question, targets, *timeout)
                    .await;
            }
            ResolutionInstruction::ForwardToDoH {
                urls,
                timeout,
                http_proxy,
                ..
            } => {
                initial_upstream_response_result = self
                    .upstream_resolver
                    .resolve_doh(question, urls, *timeout, http_proxy.as_ref())
                    .await;
            }
            ResolutionInstruction::ResolveViaAws { service_hint } => {
                warn!(
                    "ResolveViaAws instruction for {}: service_hint '{}'. Relying on DnsCache.",
                    question.name, service_hint
                );
                initial_upstream_response_result = Err(ResolveError::UpstreamServer {
                    server: "AWS_Scanner_Cache".to_string(),
                    details: format!(
                        "Entry for {} not found in AWS scanner cache or expired.",
                        question.name
                    ),
                });
            }
            ResolutionInstruction::Block => {
                let response =
                    DnsMessage::new_response(original_query_message, ResponseCode::NXDomain);
                let latency_ms = start_time.elapsed().as_millis();
                event!(Level::INFO, qname = %question.name, qtype = %question.record_type, rcode = ?response.response_code(), source = source_str, latency_ms, "Query blocked by rule");
                return Ok(response);
            }
            ResolutionInstruction::Allow | ResolutionInstruction::UseDefaultResolver => {}
            ResolutionInstruction::ResolveLocal => {
                warn!(
                    "Rule specified ResolveLocal for {}, but not found in local hosts. Returning NXDomain.",
                    question.name
                );
                let response =
                    DnsMessage::new_response(original_query_message, ResponseCode::NXDomain);
                let latency_ms = start_time.elapsed().as_millis();
                event!(Level::INFO, qname = %question.name, qtype = %question.record_type, rcode = ?response.response_code(), source = source_str, latency_ms, "Query resolved (local rule miss)");
                return Ok(response);
            }
        }

        let final_resolved_message_result: Result<DnsMessage, ResolveError> =
            match initial_upstream_response_result {
                Ok(msg) => Ok(msg),
                Err(resolve_err) => {
                    if matches!(
                        instruction,
                        ResolutionInstruction::UseDefaultResolver | ResolutionInstruction::Allow
                    ) || matches!(instruction, ResolutionInstruction::ResolveViaAws { .. })
                        || (match instruction {
                            ResolutionInstruction::ForwardToDns { .. }
                            | ResolutionInstruction::ForwardToDoH { .. } => {
                                !matches!(resolve_err, ResolveError::NoUpstreamServers)
                            }
                            _ => false,
                        })
                    {
                        source_str = Box::leak(
                            format!("DefaultResolver(Fallback from {instruction:?})")
                                .into_boxed_str(),
                        );
                        debug!(
                            "Falling back to default resolver for {} due to: {:?}",
                            question.name, resolve_err
                        );

                        let default_resolver_config = &app_config.default_resolver;
                        let mut dns_targets = Vec::new();
                        let mut doh_urls = Vec::new();

                        for ns in &default_resolver_config.nameservers {
                            if ns.starts_with("https://") {
                                if let Ok(url) = Url::parse(ns) {
                                    doh_urls.push(url);
                                }
                            } else {
                                dns_targets.push(ns.clone());
                            }
                        }

                        if !doh_urls.is_empty() {
                            self.upstream_resolver
                                .resolve_doh(
                                    question,
                                    &doh_urls,
                                    default_resolver_config.timeout,
                                    app_config.http_proxy.as_ref(),
                                )
                                .await
                        } else if !dns_targets.is_empty() {
                            self.upstream_resolver
                                .resolve_dns(
                                    question,
                                    &dns_targets,
                                    default_resolver_config.timeout,
                                )
                                .await
                        } else {
                            warn!(
                                "Default resolver has no valid nameservers configured for {}.",
                                question.name
                            );
                            Err(ResolveError::NoUpstreamServers)
                        }
                    } else {
                        Err(resolve_err)
                    }
                }
            };

        let latency_ms = start_time.elapsed().as_millis();
        match final_resolved_message_result {
            Ok(resolved_msg) => {
                if app_config.cache.enabled
                    && (resolved_msg.response_code() == ResponseCode::NoError
                        || resolved_msg.response_code() == ResponseCode::NXDomain)
                {
                    self.dns_cache
                        .insert(cache_key.clone(), &resolved_msg)
                        .await;
                }
                event!(Level::INFO, qname = %question.name, qtype = %question.record_type, rcode = ?resolved_msg.response_code(), source = source_str, latency_ms, "Query resolved");

                let mut response_to_client =
                    DnsMessage::new_response(original_query_message, resolved_msg.response_code());
                for answer in resolved_msg.answers() {
                    response_to_client.add_answer_record(answer.clone());
                }
                for ns_rec in resolved_msg.inner().name_servers() {
                    response_to_client
                        .inner_mut()
                        .add_name_server(ns_rec.clone());
                }
                for ar_rec in resolved_msg.inner().additionals() {
                    response_to_client
                        .inner_mut()
                        .add_additional(ar_rec.clone());
                }
                response_to_client
                    .inner_mut()
                    .set_authoritative(resolved_msg.inner().authoritative());
                response_to_client
                    .inner_mut()
                    .set_recursion_available(resolved_msg.inner().recursion_available());
                response_to_client
                    .inner_mut()
                    .set_truncated(resolved_msg.inner().truncated());
                Ok(response_to_client)
            }
            Err(e) => {
                error!("Resolution failed for {}: {}", question.name, e);
                let rcode = match e {
                    ResolveError::Timeout { .. } => ResponseCode::ServFail,
                    ResolveError::Protocol(ref p_err)
                        if p_err.to_string().contains("Name not found") =>
                    {
                        ResponseCode::NXDomain
                    }
                    ResolveError::UpstreamServer { ref details, .. }
                        if details.contains("REFUSED") =>
                    {
                        ResponseCode::Refused
                    }
                    ResolveError::UpstreamServer { ref server, .. }
                        if server == "AWS_Scanner_Cache" =>
                    {
                        ResponseCode::NXDomain
                    }
                    _ => ResponseCode::ServFail,
                };
                event!(Level::WARN, qname = %question.name, qtype = %question.record_type, rcode = ?rcode, source = source_str, error = %e, latency_ms, "Query resolution failed");
                Ok(DnsMessage::new_response(original_query_message, rcode))
            }
        }
    }
}

#[async_trait]
impl DnsQueryService for DnsRequestProcessor {
    #[instrument(skip(self, query_bytes), fields(client = %_client_addr, proto = ?_protocol, qid=field::Empty, qname=field::Empty, qtype=field::Empty))]
    async fn process_query(
        &self,
        query_bytes: Vec<u8>,
        _client_addr: SocketAddr,
        _protocol: ProtocolType,
    ) -> Result<Vec<u8>, DnsProcessingError> {
        self.app_lifecycle_access
            .increment_total_queries_processed();

        let query_message = parse_dns_message(&query_bytes)?;
        let query_message_arc = Arc::new(query_message);

        let current_span = Span::current();
        current_span.record("qid", query_message_arc.id());
        let first_question_opt = query_message_arc
            .queries()
            .next()
            .map(DnsQuestion::from_hickory_query);

        if let Some(q) = &first_question_opt {
            current_span.record("qname", q.name.as_str());
            current_span.record("qtype", q.record_type.to_string());
        } else {
            current_span.record("qname", "<NoQuestion>");
            current_span.record("qtype", "N/A");
        }

        if first_question_opt.is_none() {
            warn!("Received DNS query with no questions.");
            let response = DnsMessage::new_response(&query_message_arc, ResponseCode::FormErr);
            return serialize_dns_message(&response)
                .map_err(|e| DnsProcessingError::SerializeError(e.to_string()));
        }
        let first_question = first_question_opt.unwrap();

        match self
            .resolve_single_question(&first_question, &query_message_arc)
            .await
        {
            Ok(response_message) => serialize_dns_message(&response_message)
                .map_err(|e| DnsProcessingError::SerializeError(e.to_string())),
            Err(e) => {
                error!(
                    "Internal error in resolve_single_question for {}: {}",
                    first_question.name, e
                );
                let error_response =
                    DnsMessage::new_response(&query_message_arc, ResponseCode::ServFail);
                serialize_dns_message(&error_response)
                    .map_err(|e_ser| DnsProcessingError::SerializeError(e_ser.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::AppConfig;
    use crate::aws_integration::scanner::DiscoveredAwsNetworkInfo;
    use crate::config::models::{
        AwsAccountConfig, CacheConfig, CliConfig, DefaultResolverConfig, HashableRegex,
        LoggingConfig, ResolverStrategy, RuleAction, RuleConfig, ServerConfig,
    };
    use crate::core::error::{CliError, ConfigError};
    use crate::core::types::AppStatus;
    use crate::ports::{AwsConfigProvider, StatusReporterPort, UserInteractionPort};

    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::RecordType;
    use regex::Regex;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{Notify, RwLock};
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;

    use assert_matches::assert_matches;

    #[derive(Debug, Default)]
    pub(super) struct MockUpstreamResolver {
        pub dns_call_count: Arc<std::sync::Mutex<usize>>,
        pub doh_call_count: Arc<std::sync::Mutex<usize>>,
        pub should_dns_be_called: bool,
        pub should_doh_be_called: bool,
    }

    impl MockUpstreamResolver {
        pub(super) fn new() -> Self {
            Self {
                dns_call_count: Arc::new(std::sync::Mutex::new(0)),
                doh_call_count: Arc::new(std::sync::Mutex::new(0)),
                should_dns_be_called: false,
                should_doh_be_called: false,
            }
        }

        #[allow(dead_code)]
        pub(super) fn expect_resolve_dns_to_be_called(&mut self, expected: bool) {
            self.should_dns_be_called = expected;
        }
        #[allow(dead_code)]
        pub(super) fn expect_resolve_doh_to_be_called(&mut self, expected: bool) {
            self.should_doh_be_called = expected;
        }
    }

    #[async_trait]
    impl UpstreamResolver for MockUpstreamResolver {
        async fn resolve_dns(
            &self,
            _question: &crate::dns_protocol::DnsQuestion,
            _upstream_servers: &[String],
            _timeout: Duration,
        ) -> Result<DnsMessage, ResolveError> {
            let mut count = self.dns_call_count.lock().unwrap();
            *count += 1;

            if !self.should_dns_be_called {
                panic!("resolve_dns was called but not expected!");
            }

            Err(ResolveError::Configuration(
                "Mocked DNS response not configured for actual call".to_string(),
            ))
        }

        async fn resolve_doh(
            &self,
            _question: &crate::dns_protocol::DnsQuestion,
            _upstream_urls: &[url::Url],
            _timeout: Duration,
            _http_proxy_config: Option<&crate::config::models::HttpProxyConfig>,
        ) -> Result<DnsMessage, ResolveError> {
            let mut count = self.doh_call_count.lock().unwrap();
            *count += 1;

            if !self.should_doh_be_called {
                panic!("resolve_doh was called but not expected!");
            }
            Err(ResolveError::Configuration(
                "Mocked DoH response not configured for actual call".to_string(),
            ))
        }
    }

    #[derive(Clone)]
    struct MockAppLifecycleManagerForProcessor {
        config: Arc<RwLock<AppConfig>>,
        total_queries_processed: Arc<std::sync::atomic::AtomicU64>,
    }

    impl MockAppLifecycleManagerForProcessor {
        fn new(config: Arc<RwLock<AppConfig>>) -> Self {
            Self {
                config,
                total_queries_processed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            }
        }
    }

    #[async_trait]
    impl AppLifecycleManagerPort for MockAppLifecycleManagerForProcessor {
        fn get_config(&self) -> Arc<RwLock<AppConfig>> {
            self.config.clone()
        }

        fn get_dns_cache(&self) -> Arc<DnsCache> {
            Arc::new(DnsCache::new(
                100,
                Duration::from_secs(1),
                Duration::from_secs(3600),
                false,
                Duration::from_secs(3600),
            ))
        }

        fn get_status_reporter(&self) -> Arc<dyn StatusReporterPort> {
            unimplemented!("StatusReporter not needed in this test mock")
        }

        fn get_user_interaction_port(&self) -> Arc<dyn UserInteractionPort> {
            unimplemented!("UserInteractionPort not needed in this test mock")
        }

        fn get_aws_scan_trigger(&self) -> Arc<Notify> {
            Arc::new(Notify::new())
        }

        fn get_cancellation_token(&self) -> CancellationToken {
            CancellationToken::new()
        }

        fn get_discovered_aws_network_info_view(&self) -> Arc<RwLock<DiscoveredAwsNetworkInfo>> {
            unimplemented!("DiscoveredAwsNetworkInfo not needed in this test mock")
        }

        fn get_local_hosts_resolver(&self) -> Arc<LocalHostsResolver> {
            unimplemented!("LocalHostsResolver not needed in this test mock")
        }

        async fn add_task(&self, _handle: JoinHandle<()>) {
            // Test mock - no-op
        }

        async fn get_total_queries_processed(&self) -> u64 {
            self.total_queries_processed
                .load(std::sync::atomic::Ordering::SeqCst)
        }

        async fn get_active_listeners(&self) -> Vec<String> {
            vec![] // Test mock - empty list
        }

        async fn add_listener_address(&self, _addr: String) {
            // Test mock - no-op
        }

        async fn remove_listener_address(&self, _addr: String) {
            // Test mock - no-op
        }

        async fn start(&self) -> Result<(), String> {
            Ok(()) // Test mock - always success
        }

        async fn stop(&self) {
            // Test mock - no-op
        }

        async fn trigger_config_reload(&self) -> Result<(), CliError> {
            Ok(()) // Test mock - always success
        }

        async fn trigger_aws_scan_refresh(&self) -> Result<(), CliError> {
            Ok(()) // Test mock - always success
        }

        async fn add_or_update_aws_account_config(
            &self,
            _new_account_config: AwsAccountConfig,
            _original_dnspx_label_for_edit: Option<String>,
        ) -> Result<(), ConfigError> {
            Ok(()) // Test mock - always success
        }

        async fn persist_discovered_aws_details(
            &self,
            _discovered_ips: Option<Vec<String>>,
            _discovered_zones: Option<Vec<String>>,
        ) -> Result<(), ConfigError> {
            Ok(()) // Test mock - always success
        }

        async fn get_app_status(&self) -> AppStatus {
            unimplemented!("AppStatus not needed in this test mock")
        }

        fn get_aws_config_provider(&self) -> Arc<dyn AwsConfigProvider> {
            unimplemented!("AwsConfigProvider not needed in this test mock")
        }

        async fn get_config_for_processor(&self) -> Arc<RwLock<AppConfig>> {
            self.config.clone()
        }

        fn increment_total_queries_processed(&self) {
            self.total_queries_processed
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn create_test_config_with_block_rule(domain_to_block: &str) -> AppConfig {
        let block_rule = RuleConfig {
            name: "block_specific_domain_rule".to_string(),
            domain_pattern: HashableRegex(
                Regex::new(&format!("^{}$", regex::escape(domain_to_block)))
                    .expect("Invalid regex in test rule setup"),
            ),
            action: RuleAction::Block,
            nameservers: None,
            strategy: ResolverStrategy::First,
            timeout: Duration::from_secs(1),
            doh_compression_mutation: false,
            source_list_url: None,
            invert_match: false,
        };
        AppConfig {
            server: ServerConfig::default(),
            default_resolver: DefaultResolverConfig::default(),
            routing_rules: vec![block_rule],
            local_hosts: None,
            cache: CacheConfig {
                enabled: false,
                max_capacity: 0,
                min_ttl: Duration::from_secs(1),
                max_ttl: Duration::from_secs(1),
                serve_stale_if_error: false,
                serve_stale_max_ttl: Duration::from_secs(1),
            },
            http_proxy: None,
            aws: None,
            logging: LoggingConfig::default(),
            cli: CliConfig::default(),
        }
    }

    async fn setup_processor_with_config(
        app_config: AppConfig,
        mock_resolver: MockUpstreamResolver,
    ) -> Arc<DnsRequestProcessor> {
        let config_arc = Arc::new(RwLock::new(app_config.clone()));

        let dns_cache_direct = Arc::new(DnsCache::new(
            app_config.cache.max_capacity,
            app_config.cache.min_ttl,
            app_config.cache.max_ttl,
            app_config.cache.serve_stale_if_error,
            app_config.cache.serve_stale_max_ttl,
        ));

        let mock_alm_access =
            Arc::new(MockAppLifecycleManagerForProcessor::new(config_arc.clone()));

        let local_hosts_resolver = LocalHostsResolver::new(config_arc.clone()).await;
        let rule_engine = Arc::new(RuleEngine::new(config_arc.clone()));

        Arc::new(DnsRequestProcessor::new(
            mock_alm_access,
            dns_cache_direct,
            rule_engine,
            local_hosts_resolver,
            Arc::new(mock_resolver),
        ))
    }

    mod block_action_integration {
        use super::*;
        use crate::core::types::ProtocolType;
        use crate::ports::DnsQueryService;

        #[tokio::test]
        async fn test_processor_block_rule_returns_nxdomain_and_no_upstream_call() {
            let domain_to_block = "blocked.com";
            let app_config = create_test_config_with_block_rule(domain_to_block);

            let mut mock_upstream_resolver = MockUpstreamResolver::new();
            mock_upstream_resolver.should_dns_be_called = false;
            mock_upstream_resolver.should_doh_be_called = false;

            let processor = setup_processor_with_config(app_config, mock_upstream_resolver).await;

            let query_id = 123;
            let query_msg_original =
                DnsMessage::new_query(query_id, domain_to_block, RecordType::A)
                    .expect("Failed to create query message");
            let query_bytes =
                serialize_dns_message(&query_msg_original).expect("Failed to serialize query");

            let client_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();
            let protocol = ProtocolType::Udp;

            let response_bytes_result = processor
                .process_query(query_bytes, client_addr, protocol)
                .await;

            assert_matches!(
                response_bytes_result,
                Ok(_),
                "Processing query should succeed overall"
            );
            let response_bytes = response_bytes_result.unwrap();
            let response_message =
                parse_dns_message(&response_bytes).expect("Should be able to parse DNS response");

            assert_eq!(
                response_message.id(),
                query_id,
                "Response ID should match query ID"
            );
            assert_eq!(
                response_message.response_code(),
                ResponseCode::NXDomain,
                "Response code should be NXDomain for a blocked domain"
            );
            assert!(
                response_message.answers().next().is_none(),
                "There should be no answer records for an NXDomain response from a block rule"
            );
        }
    }
}
