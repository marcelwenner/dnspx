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

        async fn add_task(&self, _handle: JoinHandle<()>) {}

        async fn get_total_queries_processed(&self) -> u64 {
            self.total_queries_processed
                .load(std::sync::atomic::Ordering::SeqCst)
        }

        async fn get_active_listeners(&self) -> Vec<String> {
            vec![]
        }

        async fn add_listener_address(&self, _addr: String) {
            // Test mock - no-op
        }

        async fn remove_listener_address(&self, _addr: String) {
            // Test mock - no-op
        }

        async fn start(&self) -> Result<(), String> {
            Ok(())
        }

        async fn stop(&self) {
            // Test mock - no-op
        }

        async fn trigger_config_reload(&self) -> Result<(), CliError> {
            Ok(())
        }

        async fn trigger_aws_scan_refresh(&self) -> Result<(), CliError> {
            Ok(())
        }

        async fn add_or_update_aws_account_config(
            &self,
            _new_account_config: AwsAccountConfig,
            _original_dnspx_label_for_edit: Option<String>,
        ) -> Result<(), ConfigError> {
            Ok(())
        }

        async fn persist_discovered_aws_details(
            &self,
            _discovered_ips: Option<Vec<String>>,
            _discovered_zones: Option<Vec<String>>,
        ) -> Result<(), ConfigError> {
            Ok(())
        }

        async fn get_app_status(&self) -> AppStatus {
            unimplemented!("AppStatus not needed in this test mock")
        }

        fn get_aws_config_provider(&self) -> Arc<dyn AwsConfigProvider> {
            unimplemented!("AwsConfigProvider not needed in this test mock")
        }

        fn get_update_manager(&self) -> Option<Arc<dyn crate::ports::UpdateManagerPort>> {
            None
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
            update: None,
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

    mod end_to_end_request_processing {
        use super::*;
        use crate::core::types::ProtocolType;
        use crate::ports::DnsQueryService;
        use hickory_proto::rr::{RData, Record};
        use std::collections::HashMap;
        use std::net::{IpAddr, Ipv4Addr};
        use std::sync::Mutex;

        #[derive(Debug, Clone)]
        enum TestResolveError {
            Timeout { server: String, duration: Duration },
            Configuration(String),
            Network(String),
        }

        impl std::fmt::Display for TestResolveError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    TestResolveError::Timeout { server, duration } => {
                        write!(f, "Test timeout for server {} after {:?}", server, duration)
                    }
                    TestResolveError::Configuration(msg) => {
                        write!(f, "Test configuration error: {}", msg)
                    }
                    TestResolveError::Network(msg) => write!(f, "Test network error: {}", msg),
                }
            }
        }

        impl std::error::Error for TestResolveError {}

        impl From<TestResolveError> for ResolveError {
            fn from(err: TestResolveError) -> Self {
                match err {
                    TestResolveError::Timeout { server, duration } => ResolveError::Timeout {
                        domain: server,
                        duration,
                    },
                    TestResolveError::Configuration(msg) => ResolveError::Configuration(msg),
                    TestResolveError::Network(msg) => ResolveError::Network(msg),
                }
            }
        }

        #[derive(Debug)]
        struct EnhancedMockResolver {
            name: String,
            call_log: Arc<Mutex<Vec<String>>>,
            response_map: Arc<Mutex<HashMap<String, Result<DnsMessage, TestResolveError>>>>,
        }

        impl EnhancedMockResolver {
            fn new(name: &str) -> Self {
                Self {
                    name: name.to_string(),
                    call_log: Arc::new(Mutex::new(Vec::new())),
                    response_map: Arc::new(Mutex::new(HashMap::new())),
                }
            }

            fn set_response(&self, domain: &str, ip: Ipv4Addr) {
                let response = Self::create_a_record_response(domain, ip);
                let mut map = self.response_map.lock().unwrap();
                map.insert(domain.to_string(), Ok(response));
            }

            fn set_error_response(&self, domain: &str, error: TestResolveError) {
                let mut map = self.response_map.lock().unwrap();
                map.insert(domain.to_string(), Err(error));
            }

            fn get_calls(&self) -> Vec<String> {
                self.call_log.lock().unwrap().clone()
            }

            fn was_called_for(&self, domain: &str) -> bool {
                let calls = self.call_log.lock().unwrap();
                calls.iter().any(|call| call.contains(domain))
            }

            fn call_count(&self) -> usize {
                self.call_log.lock().unwrap().len()
            }

            fn create_a_record_response(domain: &str, ip: Ipv4Addr) -> DnsMessage {
                let query = DnsMessage::new_query(1, domain, RecordType::A).unwrap();
                let mut response =
                    DnsMessage::new_response(&Arc::new(query), ResponseCode::NoError);

                let record = Record::from_rdata(domain.parse().unwrap(), 300, RData::A(ip.into()));
                response.add_answer_record(record);
                response
            }
        }

        #[async_trait]
        impl UpstreamResolver for EnhancedMockResolver {
            async fn resolve_dns(
                &self,
                question: &crate::dns_protocol::DnsQuestion,
                _upstream_servers: &[String],
                _timeout: Duration,
            ) -> Result<DnsMessage, ResolveError> {
                {
                    let mut log = self.call_log.lock().unwrap();
                    log.push(format!("{}:dns:{}", self.name, question.name));
                }

                let map = self.response_map.lock().unwrap();
                if let Some(response) = map.get(&question.name) {
                    match response {
                        Ok(dns_msg) => Ok(dns_msg.clone()),
                        Err(test_err) => Err(test_err.clone().into()),
                    }
                } else {
                    Err(ResolveError::Configuration(format!(
                        "No response configured for {} in resolver {}",
                        question.name, self.name
                    )))
                }
            }

            async fn resolve_doh(
                &self,
                question: &crate::dns_protocol::DnsQuestion,
                _upstream_urls: &[url::Url],
                _timeout: Duration,
                _http_proxy_config: Option<&crate::config::models::HttpProxyConfig>,
            ) -> Result<DnsMessage, ResolveError> {
                {
                    let mut log = self.call_log.lock().unwrap();
                    log.push(format!("{}:doh:{}", self.name, question.name));
                }

                let map = self.response_map.lock().unwrap();
                if let Some(response) = map.get(&question.name) {
                    match response {
                        Ok(dns_msg) => Ok(dns_msg.clone()),
                        Err(test_err) => Err(test_err.clone().into()),
                    }
                } else {
                    Err(ResolveError::Configuration(format!(
                        "No DoH response configured for {} in resolver {}",
                        question.name, self.name
                    )))
                }
            }
        }

        fn create_config_with_forwarding_rule(
            domain_pattern: &str,
            nameservers: Vec<String>,
        ) -> AppConfig {
            let rule = RuleConfig {
                name: "test_forwarding_rule".to_string(),
                domain_pattern: HashableRegex(
                    Regex::new(domain_pattern).expect("Invalid regex in test"),
                ),
                action: RuleAction::Forward,
                nameservers: Some(nameservers),
                strategy: ResolverStrategy::First,
                timeout: Duration::from_secs(5),
                doh_compression_mutation: false,
                source_list_url: None,
                invert_match: false,
            };

            AppConfig {
                server: ServerConfig::default(),
                default_resolver: DefaultResolverConfig {
                    nameservers: vec!["8.8.8.8".to_string()],
                    strategy: ResolverStrategy::First,
                    timeout: Duration::from_secs(5),
                    doh_compression_mutation: false,
                },
                routing_rules: vec![rule],
                local_hosts: None,
                cache: CacheConfig {
                    enabled: false,
                    max_capacity: 0,
                    min_ttl: Duration::from_secs(1),
                    max_ttl: Duration::from_secs(3600),
                    serve_stale_if_error: false,
                    serve_stale_max_ttl: Duration::from_secs(86400),
                },
                http_proxy: None,
                aws: None,
                logging: LoggingConfig::default(),
                cli: CliConfig::default(),
                update: None,
            }
        }

        fn create_config_with_cache_enabled() -> AppConfig {
            AppConfig {
                server: ServerConfig::default(),
                default_resolver: DefaultResolverConfig::default(),
                routing_rules: vec![],
                local_hosts: None,
                cache: CacheConfig {
                    enabled: true,
                    max_capacity: 1000,
                    min_ttl: Duration::from_secs(1),
                    max_ttl: Duration::from_secs(3600),
                    serve_stale_if_error: false,
                    serve_stale_max_ttl: Duration::from_secs(86400),
                },
                http_proxy: None,
                aws: None,
                logging: LoggingConfig::default(),
                cli: CliConfig::default(),
                update: None,
            }
        }

        fn create_config_with_local_hosts(hosts: HashMap<String, Vec<IpAddr>>) -> AppConfig {
            AppConfig {
                server: ServerConfig::default(),
                default_resolver: DefaultResolverConfig::default(),
                routing_rules: vec![],
                local_hosts: Some(crate::config::models::LocalHostsConfig {
                    entries: hosts.into_iter().collect(),
                    file_path: None,
                    watch_file: false,
                    ttl: 300,
                    load_balancing: crate::config::models::HostsLoadBalancing::All,
                }),
                cache: CacheConfig {
                    enabled: true,
                    max_capacity: 1000,
                    min_ttl: Duration::from_secs(1),
                    max_ttl: Duration::from_secs(3600),
                    serve_stale_if_error: false,
                    serve_stale_max_ttl: Duration::from_secs(86400),
                },
                http_proxy: None,
                aws: None,
                logging: LoggingConfig::default(),
                cli: CliConfig::default(),
                update: None,
            }
        }

        fn create_config_with_priority_rules() -> AppConfig {
            let block_rule = RuleConfig {
                name: "block_ads_rule".to_string(),
                domain_pattern: HashableRegex(
                    Regex::new(r"^ads\.google\.com$").expect("Invalid regex"),
                ),
                action: RuleAction::Block,
                nameservers: None,
                strategy: ResolverStrategy::First,
                timeout: Duration::from_secs(5),
                doh_compression_mutation: false,
                source_list_url: None,
                invert_match: false,
            };

            let allow_rule = RuleConfig {
                name: "allow_google_rule".to_string(),
                domain_pattern: HashableRegex(
                    Regex::new(r".*\.google\.com$").expect("Invalid regex"),
                ),
                action: RuleAction::Allow,
                nameservers: None,
                strategy: ResolverStrategy::First,
                timeout: Duration::from_secs(5),
                doh_compression_mutation: false,
                source_list_url: None,
                invert_match: false,
            };

            AppConfig {
                server: ServerConfig::default(),
                default_resolver: DefaultResolverConfig::default(),
                routing_rules: vec![block_rule, allow_rule],
                local_hosts: None,
                cache: CacheConfig {
                    enabled: false,
                    max_capacity: 0,
                    min_ttl: Duration::from_secs(1),
                    max_ttl: Duration::from_secs(3600),
                    serve_stale_if_error: false,
                    serve_stale_max_ttl: Duration::from_secs(86400),
                },
                http_proxy: None,
                aws: None,
                logging: LoggingConfig::default(),
                cli: CliConfig::default(),
                update: None,
            }
        }

        async fn setup_enhanced_processor(
            config: AppConfig,
            resolver: Arc<EnhancedMockResolver>,
        ) -> Arc<DnsRequestProcessor> {
            let config_arc = Arc::new(RwLock::new(config.clone()));
            let dns_cache = Arc::new(DnsCache::new(
                config.cache.max_capacity,
                config.cache.min_ttl,
                config.cache.max_ttl,
                config.cache.serve_stale_if_error,
                config.cache.serve_stale_max_ttl,
            ));

            let mock_alm = Arc::new(MockAppLifecycleManagerForProcessor::new(config_arc.clone()));
            let local_hosts_resolver = LocalHostsResolver::new(config_arc.clone()).await;
            let rule_engine = Arc::new(RuleEngine::new(config_arc.clone()));

            Arc::new(DnsRequestProcessor::new(
                mock_alm,
                dns_cache,
                rule_engine,
                local_hosts_resolver,
                resolver,
            ))
        }

        async fn process_query_helper(
            processor: &DnsRequestProcessor,
            domain: &str,
        ) -> Result<DnsMessage, String> {
            let query_msg = DnsMessage::new_query(12345, domain, RecordType::A)
                .map_err(|e| format!("Failed to create query: {}", e))?;

            let query_bytes = serialize_dns_message(&query_msg)
                .map_err(|e| format!("Failed to serialize query: {}", e))?;

            let client_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();

            let response_bytes = processor
                .process_query(query_bytes, client_addr, ProtocolType::Udp)
                .await
                .map_err(|e| format!("Failed to process query: {}", e))?;

            let response_msg = parse_dns_message(&response_bytes)
                .map_err(|e| format!("Failed to parse response: {}", e))?;

            Ok(response_msg)
        }

        #[tokio::test]
        async fn test_rule_based_forwarding_targets_specific_resolver() {
            let rule_resolver = Arc::new(EnhancedMockResolver::new("rule_resolver"));
            rule_resolver.set_response("service.test.corp.", Ipv4Addr::new(10, 0, 1, 100));

            let config = create_config_with_forwarding_rule(
                r".*\.test\.corp$",
                vec!["192.168.1.1".to_string()],
            );

            let processor = setup_enhanced_processor(config, rule_resolver.clone()).await;

            let response = process_query_helper(&processor, "service.test.corp")
                .await
                .expect("Query should succeed");

            assert_eq!(response.response_code(), ResponseCode::NoError);
            let answers: Vec<_> = response.answers().collect();
            assert_eq!(answers.len(), 1, "Should have exactly one answer");

            if let RData::A(ip) = answers[0].data() {
                assert_eq!(*ip, Ipv4Addr::new(10, 0, 1, 100).into());
            } else {
                panic!("Answer should contain A record with correct IP");
            }

            assert!(rule_resolver.was_called_for("service.test.corp."));
            assert_eq!(rule_resolver.call_count(), 1);
        }

        #[tokio::test]
        async fn test_cache_hit_prevents_second_resolver_call() {
            let resolver = Arc::new(EnhancedMockResolver::new("cache_test_resolver"));
            resolver.set_response("cached.example.com.", Ipv4Addr::new(10, 0, 2, 100));

            let config = create_config_with_cache_enabled();
            let processor = setup_enhanced_processor(config, resolver.clone()).await;

            let response1 = process_query_helper(&processor, "cached.example.com")
                .await
                .expect("First query should succeed");

            assert_eq!(response1.response_code(), ResponseCode::NoError);

            let response2 = process_query_helper(&processor, "cached.example.com")
                .await
                .expect("Second query should succeed");

            assert_eq!(response2.response_code(), ResponseCode::NoError);

            assert_eq!(
                resolver.call_count(),
                1,
                "Resolver should only be called once due to caching"
            );
            assert!(resolver.was_called_for("cached.example.com."));
        }

        #[tokio::test]
        async fn test_block_rule_priority_over_allow_rule() {
            let resolver = Arc::new(EnhancedMockResolver::new("should_not_be_called"));

            let config = create_config_with_priority_rules();
            let processor = setup_enhanced_processor(config, resolver.clone()).await;

            let response = process_query_helper(&processor, "ads.google.com")
                .await
                .expect("Query should succeed with block response");

            assert_eq!(
                response.response_code(),
                ResponseCode::NXDomain,
                "Blocked domain should return NXDOMAIN"
            );
            assert!(
                response.answers().next().is_none(),
                "Blocked domain should have no answer records"
            );

            assert_eq!(
                resolver.call_count(),
                0,
                "No upstream resolver should be called for blocked domains"
            );
        }

        #[tokio::test]
        async fn test_local_hosts_priority_over_everything() {
            let resolver = Arc::new(EnhancedMockResolver::new("should_not_be_called"));

            let mut local_hosts = HashMap::new();
            local_hosts.insert(
                "dev.local".to_string(),
                vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
            );

            let config = create_config_with_local_hosts(local_hosts);
            let processor = setup_enhanced_processor(config, resolver.clone()).await;

            let response = process_query_helper(&processor, "dev.local")
                .await
                .expect("Query should succeed with local hosts response");

            assert_eq!(response.response_code(), ResponseCode::NoError);

            let answers: Vec<_> = response.answers().collect();
            assert_eq!(answers.len(), 1, "Should have exactly one answer record");

            if let RData::A(ip) = answers[0].data() {
                assert_eq!(*ip, Ipv4Addr::new(127, 0, 0, 1).into());
            } else {
                panic!("Answer should contain A record with local hosts IP");
            }

            assert_eq!(
                resolver.call_count(),
                0,
                "No upstream resolver should be called when local hosts has entry"
            );
        }

        #[tokio::test]
        async fn test_query_processing_preserves_query_id() {
            let resolver = Arc::new(EnhancedMockResolver::new("id_test_resolver"));
            resolver.set_response("example.com.", Ipv4Addr::new(93, 184, 216, 34));

            let config = create_config_with_cache_enabled();
            let processor = setup_enhanced_processor(config, resolver.clone()).await;

            let query_id = 54321;
            let query_msg = DnsMessage::new_query(query_id, "example.com", RecordType::A)
                .expect("Failed to create query");

            let query_bytes = serialize_dns_message(&query_msg).expect("Failed to serialize query");

            let client_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();

            let response_bytes = processor
                .process_query(query_bytes, client_addr, ProtocolType::Udp)
                .await
                .expect("Query should succeed");

            let response_msg =
                parse_dns_message(&response_bytes).expect("Failed to parse response");

            assert_eq!(
                response_msg.id(),
                query_id,
                "Response ID should match original query ID"
            );
        }

        #[tokio::test]
        async fn test_processor_increments_query_counter() {
            let resolver = Arc::new(EnhancedMockResolver::new("counter_test_resolver"));
            resolver.set_response("counter.test.", Ipv4Addr::new(10, 0, 0, 1));

            let config = create_config_with_cache_disabled();
            let processor = setup_enhanced_processor(config, resolver.clone()).await;

            let initial_count = processor
                .app_lifecycle_access
                .get_total_queries_processed()
                .await;

            let _response = process_query_helper(&processor, "counter.test")
                .await
                .expect("Query should succeed");

            let final_count = processor
                .app_lifecycle_access
                .get_total_queries_processed()
                .await;
            assert_eq!(
                final_count,
                initial_count + 1,
                "Query counter should be incremented"
            );
        }

        fn create_config_with_cache_disabled() -> AppConfig {
            AppConfig {
                server: ServerConfig::default(),
                default_resolver: DefaultResolverConfig::default(),
                routing_rules: vec![],
                local_hosts: None,
                cache: CacheConfig {
                    enabled: false,
                    max_capacity: 0,
                    min_ttl: Duration::from_secs(1),
                    max_ttl: Duration::from_secs(3600),
                    serve_stale_if_error: false,
                    serve_stale_max_ttl: Duration::from_secs(86400),
                },
                http_proxy: None,
                aws: None,
                logging: LoggingConfig::default(),
                cli: CliConfig::default(),
                update: None,
            }
        }
    }
}
