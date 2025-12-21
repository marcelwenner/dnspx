use crate::config::models::{AppConfig, HostsLoadBalancing, LocalHostsConfig};
use crate::core::error::ConfigError;
use crate::dns_protocol::{DnsMessage, DnsQuestion};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{CNAME, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use notify::{
    Error as NotifyError, Event as NotifyEvent, RecommendedWatcher, RecursiveMode, Watcher,
    event::AccessKind,
};
use rand::seq::IndexedRandom;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader as StdBufReader};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

pub(crate) struct LocalHostsResolver {
    config: Arc<RwLock<AppConfig>>,
    hosts: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
    reverse_hosts: Arc<RwLock<HashMap<IpAddr, Vec<String>>>>,
    /// CNAME aliases: maps hostname to target hostname
    cnames: Arc<RwLock<HashMap<String, String>>>,
    file_watcher: Arc<Mutex<Option<RecommendedWatcher>>>,
    shutdown_token: CancellationToken,
}

impl LocalHostsResolver {
    pub(crate) async fn new(config: Arc<RwLock<AppConfig>>) -> Arc<Self> {
        let (hosts_map, reverse_map, cnames_map) = {
            let config_guard = config.read().await;
            Self::load_hosts_from_config_struct(config_guard.local_hosts.as_ref()).await
        };

        Arc::new(Self {
            config,
            hosts: Arc::new(RwLock::new(hosts_map)),
            reverse_hosts: Arc::new(RwLock::new(reverse_map)),
            cnames: Arc::new(RwLock::new(cnames_map)),
            file_watcher: Arc::new(Mutex::new(None)),
            shutdown_token: CancellationToken::new(),
        })
    }

    async fn load_hosts_from_config_struct(
        local_hosts_config_opt: Option<&LocalHostsConfig>,
    ) -> (
        HashMap<String, Vec<IpAddr>>,
        HashMap<IpAddr, Vec<String>>,
        HashMap<String, String>,
    ) {
        let mut hosts_map: HashMap<String, Vec<IpAddr>> = HashMap::new();
        let mut reverse_map: HashMap<IpAddr, Vec<String>> = HashMap::new();
        let mut cnames_map: HashMap<String, String> = HashMap::new();

        if let Some(local_hosts_config) = local_hosts_config_opt {
            for (domain, ip_vec) in &local_hosts_config.entries {
                let normalized_domain = domain.trim_end_matches('.').to_lowercase();
                if !ip_vec.is_empty() {
                    hosts_map.insert(normalized_domain.clone(), ip_vec.clone());
                    for ip_addr in ip_vec {
                        reverse_map
                            .entry(*ip_addr)
                            .or_default()
                            .push(normalized_domain.clone());
                    }
                }
            }

            // Load CNAME aliases
            for (alias, target) in &local_hosts_config.cnames {
                let normalized_alias = alias.trim_end_matches('.').to_lowercase();
                let normalized_target = target.trim_end_matches('.').to_lowercase();
                cnames_map.insert(normalized_alias, normalized_target);
            }

            if let Some(file_path) = &local_hosts_config.file_path {
                if file_path.exists() {
                    match Self::parse_hosts_file(file_path).await {
                        Ok(file_entries) => {
                            info!(
                                "Successfully parsed hosts file: {:?}, found {} domain mappings.",
                                file_path,
                                file_entries.len()
                            );
                            for (domain, ip_vec) in file_entries {
                                let normalized_domain = domain.trim_end_matches('.').to_lowercase();
                                hosts_map.insert(normalized_domain.clone(), ip_vec.clone());
                                for ip_addr in ip_vec {
                                    reverse_map
                                        .entry(ip_addr)
                                        .or_default()
                                        .push(normalized_domain.clone());
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to parse hosts file {:?}: {}. Skipping file entries.",
                                file_path, e
                            );
                        }
                    }
                } else {
                    warn!("Configured hosts file {:?} does not exist.", file_path);
                }
            }
        }
        info!(
            "LocalHostsResolver: Loaded {} distinct domain entries and {} CNAME aliases from config.",
            hosts_map.len(),
            cnames_map.len()
        );
        (hosts_map, reverse_map, cnames_map)
    }

    pub(crate) async fn update_hosts(&self) {
        info!("LocalHostsResolver: Reloading hosts due to config change or file watch.");
        let (new_hosts, new_reverse_hosts, new_cnames) = {
            let config_guard = self.config.read().await;
            Self::load_hosts_from_config_struct(config_guard.local_hosts.as_ref()).await
        };

        *self.hosts.write().await = new_hosts;
        *self.cnames.write().await = new_cnames;
        let mut reverse_write_guard = self.reverse_hosts.write().await;
        *reverse_write_guard = new_reverse_hosts;

        for host_list in reverse_write_guard.values_mut() {
            host_list.sort_unstable();
            host_list.dedup();
        }

        info!("LocalHostsResolver: Hosts reloaded successfully.");
    }

    pub(crate) async fn resolve(
        &self,
        question: &DnsQuestion,
        query_message: &DnsMessage,
    ) -> Option<DnsMessage> {
        let normalized_name = question.name.trim_end_matches('.').to_lowercase();

        let config_guard = self.config.read().await;
        let local_hosts_conf = match &config_guard.local_hosts {
            Some(conf) => conf,
            None => return None,
        };
        let hosts_ttl = local_hosts_conf.ttl;
        let load_balancing_strategy = local_hosts_conf.load_balancing.clone();
        drop(config_guard);

        let mut response = DnsMessage::new_response(query_message, ResponseCode::NoError);
        response.set_authoritative(true);

        match question.record_type {
            RecordType::CNAME => {
                // Direct CNAME query - return the CNAME record if exists
                let cnames_guard = self.cnames.read().await;
                if let Some(target) = cnames_guard.get(&normalized_name) {
                    debug!(
                        "LocalHosts: Matched CNAME record for {}: {}",
                        normalized_name, target
                    );
                    let fqdn_target = format!("{target}.");
                    if let Ok(target_name) = Name::from_str(&fqdn_target) {
                        if let Ok(query_name_obj) = Name::from_str(&question.name) {
                            let rdata = RData::CNAME(CNAME(target_name));
                            let record = Record::from_rdata(query_name_obj, hosts_ttl, rdata);
                            response.add_answer_record(record);
                            return Some(response);
                        }
                    }
                }
            }
            RecordType::A | RecordType::AAAA => {
                let hosts_guard = self.hosts.read().await;
                let cnames_guard = self.cnames.read().await;

                // First check for direct A/AAAA entry
                let (lookup_name, cname_record) =
                    if let Some(target) = cnames_guard.get(&normalized_name) {
                        // We have a CNAME - create the CNAME record and look up the target
                        debug!(
                            "LocalHosts: Found CNAME for {}: {}",
                            normalized_name, target
                        );
                        let fqdn_target = format!("{target}.");
                        let cname_rec = if let Ok(target_name) = Name::from_str(&fqdn_target) {
                            if let Ok(query_name_obj) = Name::from_str(&question.name) {
                                let rdata = RData::CNAME(CNAME(target_name));
                                Some(Record::from_rdata(query_name_obj, hosts_ttl, rdata))
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        (target.clone(), cname_rec)
                    } else {
                        (normalized_name.clone(), None)
                    };

                let is_cname_lookup = cname_record.is_some();

                if let Some(ip_addrs_vec) = hosts_guard.get(&lookup_name) {
                    if ip_addrs_vec.is_empty() {
                        return None;
                    }

                    let mut records_to_add: Vec<Record> = Vec::new();

                    // Add CNAME record first if we followed a CNAME
                    if let Some(cname_rec) = cname_record {
                        records_to_add.push(cname_rec);
                    }

                    let ips_to_process: Vec<IpAddr> = match load_balancing_strategy {
                        HostsLoadBalancing::All => ip_addrs_vec.clone(),
                        HostsLoadBalancing::First => vec![ip_addrs_vec[0]],
                        HostsLoadBalancing::Random => ip_addrs_vec
                            .choose(&mut rand::rng())
                            .cloned()
                            .map_or(Vec::new(), |ip| vec![ip]),
                    };

                    // For A/AAAA records following a CNAME, use the target name
                    let record_name = if is_cname_lookup {
                        format!("{lookup_name}.")
                    } else {
                        question.name.clone()
                    };

                    for ip_addr_ref in ips_to_process {
                        let ip_addr = ip_addr_ref;
                        match (ip_addr, question.record_type) {
                            (IpAddr::V4(ipv4), RecordType::A) => {
                                debug!(
                                    "LocalHosts: Matched A record for {}: {}",
                                    lookup_name, ipv4
                                );
                                let rdata = RData::A(ipv4.into());
                                match Name::from_str(&record_name) {
                                    Ok(name_obj) => {
                                        records_to_add
                                            .push(Record::from_rdata(name_obj, hosts_ttl, rdata));
                                    }
                                    Err(e) => warn!(
                                        "LocalHosts: Failed to parse name for A record '{}': {}",
                                        record_name, e
                                    ),
                                }
                            }
                            (IpAddr::V6(ipv6), RecordType::AAAA) => {
                                debug!(
                                    "LocalHosts: Matched AAAA record for {}: {}",
                                    lookup_name, ipv6
                                );
                                let rdata = RData::AAAA(ipv6.into());
                                match Name::from_str(&record_name) {
                                    Ok(name_obj) => {
                                        records_to_add
                                            .push(Record::from_rdata(name_obj, hosts_ttl, rdata));
                                    }
                                    Err(e) => warn!(
                                        "LocalHosts: Failed to parse name for AAAA record '{}': {}",
                                        record_name, e
                                    ),
                                }
                            }
                            _ => {}
                        }
                    }

                    if !records_to_add.is_empty() {
                        for record in records_to_add {
                            response.add_answer_record(record);
                        }
                        return Some(response);
                    }
                } else if is_cname_lookup {
                    // We have a CNAME but the target doesn't resolve locally
                    // Return None so upstream can resolve the target
                    return None;
                }
            }
            RecordType::PTR => {
                let reverse_hosts_guard = self.reverse_hosts.read().await;
                if let Ok(ip_from_ptr) = Self::ip_from_ptr_name(&normalized_name)
                    && let Some(hostnames) = reverse_hosts_guard.get(&ip_from_ptr)
                {
                    debug!(
                        "LocalHosts: Found PTR record(s) for {}: {:?}",
                        normalized_name, hostnames
                    );
                    let mut records_added = false;
                    for hostname_str in hostnames {
                        let fqdn_hostname = if hostname_str.ends_with('.') {
                            hostname_str.clone()
                        } else {
                            format!("{hostname_str}.")
                        };
                        match Name::from_str(&fqdn_hostname) {
                            Ok(target_name) => {
                                let rdata = RData::PTR(PTR(target_name));
                                match Name::from_str(&question.name) {
                                    Ok(query_name_obj) => {
                                        let record = Record::from_rdata(
                                            query_name_obj.clone(),
                                            hosts_ttl,
                                            rdata,
                                        );
                                        response.add_answer_record(record);
                                        records_added = true;
                                    }
                                    Err(e) => warn!(
                                        "LocalHosts: Failed to parse name for PTR query '{}': {}",
                                        question.name, e
                                    ),
                                }
                            }
                            Err(e) => warn!(
                                "LocalHosts: Failed to parse target name for PTR record '{}': {}",
                                fqdn_hostname, e
                            ),
                        }
                    }
                    if records_added {
                        return Some(response);
                    }
                }
            }
            _ => {}
        }
        None
    }

    fn ip_from_ptr_name(ptr_name: &str) -> Result<IpAddr, ()> {
        if let Some(stripped) = ptr_name.strip_suffix(".in-addr.arpa") {
            let parts: Vec<&str> = stripped.split('.').rev().collect();
            if parts.len() == 4 {
                let ip_str = parts.join(".");
                if let Ok(ipv4) = ip_str.parse::<std::net::Ipv4Addr>() {
                    return Ok(IpAddr::V4(ipv4));
                }
            }
        } else if let Some(stripped) = ptr_name.strip_suffix(".ip6.arpa") {
            let nibbles_in_ptr_order: Vec<char> = stripped
                .split('.')
                .filter(|s| !s.is_empty())
                .flat_map(|s| s.chars())
                .collect();

            if nibbles_in_ptr_order.len() != 32 {
                warn!(
                    "LocalHostsResolver: Invalid IPv6 PTR length: {} nibbles found in '{}', expected 32.",
                    nibbles_in_ptr_order.len(),
                    ptr_name
                );
                return Err(());
            }
            if !nibbles_in_ptr_order.iter().all(|c| c.is_ascii_hexdigit()) {
                warn!(
                    "LocalHostsResolver: Invalid character in IPv6 PTR nibbles: '{}'",
                    ptr_name
                );
                return Err(());
            }

            let nibbles_reversed: String = nibbles_in_ptr_order.iter().rev().collect();

            let mut ipv6_str = String::new();
            for i in 0..8 {
                let start = i * 4;
                let end = start + 4;
                if end > nibbles_reversed.len() {
                    warn!(
                        "LocalHostsResolver: Index out of bounds during IPv6 PTR parsing for '{}'",
                        ptr_name
                    );
                    return Err(());
                }
                ipv6_str.push_str(&nibbles_reversed[start..end]);
                if i < 7 {
                    ipv6_str.push(':');
                }
            }

            if let Ok(ipv6) = std::net::Ipv6Addr::from_str(&ipv6_str) {
                return Ok(IpAddr::V6(ipv6));
            } else {
                warn!(
                    "LocalHostsResolver: Failed to parse IPv6 from constructed string '{}' (original PTR: '{}')",
                    ipv6_str, ptr_name
                );
            }
        }
        Err(())
    }

    pub(crate) async fn shutdown(&self) {
        info!("LocalHostsResolver: Initiating shutdown...");
        self.shutdown_token.cancel();

        let mut watcher_lock = self.file_watcher.lock().await;
        if let Some(watcher) = watcher_lock.take() {
            drop(watcher);
            info!("LocalHostsResolver: File watcher stopped.");
        }
    }

    pub(crate) async fn start_file_watching(self: Arc<Self>) {
        let config_guard = self.config.read().await;
        let hosts_config_opt = config_guard.local_hosts.clone();
        drop(config_guard);

        if let Some(hosts_config) = hosts_config_opt {
            if hosts_config.watch_file {
                if let Some(file_path_to_watch) = hosts_config.file_path {
                    let file_path_watch_copy = file_path_to_watch.clone();
                    if !file_path_to_watch.exists() {
                        warn!(
                            "LocalHostsResolver: Hosts file {:?} configured for watching does not exist. Cannot watch.",
                            file_path_to_watch
                        );
                        return;
                    }

                    let resolver_clone = Arc::clone(&self);
                    let (tx, mut rx) = mpsc::channel(1);

                    let mut watcher_lock = self.file_watcher.lock().await;
                    if watcher_lock.is_some() {
                        info!(
                            "LocalHostsResolver: File watcher already started for {:?}.",
                            file_path_to_watch
                        );
                        return;
                    }

                    match notify::recommended_watcher(
                        move |res: Result<NotifyEvent, NotifyError>| match res {
                            Ok(event) => {
                                if (event.kind.is_modify()
                                    || event.kind.is_create()
                                    || matches!(
                                        event.kind,
                                        notify::EventKind::Access(AccessKind::Close(
                                            notify::event::AccessMode::Write
                                        ))
                                    ))
                                    && tx.try_send(()).is_err()
                                {
                                    warn!(
                                        "LocalHostsResolver: File watch event channel full or closed for {:?}.",
                                        file_path_to_watch
                                    );
                                }
                            }
                            Err(e) => error!(
                                "LocalHostsResolver: Error watching hosts file {:?}: {}",
                                file_path_to_watch, e
                            ),
                        },
                    ) {
                        Ok(mut new_watcher) => {
                            if let Err(e) = new_watcher
                                .watch(&file_path_watch_copy, RecursiveMode::NonRecursive)
                            {
                                error!(
                                    "LocalHostsResolver: Failed to start watching hosts file {:?}: {}",
                                    file_path_watch_copy, e
                                );
                                return;
                            }
                            info!(
                                "LocalHostsResolver: Started watching hosts file {:?} for changes.",
                                file_path_watch_copy
                            );
                            *watcher_lock = Some(new_watcher);

                            let shutdown_token = resolver_clone.shutdown_token.clone();
                            tokio::spawn(async move {
                                info!(
                                    "LocalHostsResolver: File watcher event processing task started for {:?}.",
                                    file_path_watch_copy
                                );
                                loop {
                                    tokio::select! {
                                        _ = shutdown_token.cancelled() => {
                                            info!(
                                                "LocalHostsResolver: File watcher task cancelled for {:?}.",
                                                file_path_watch_copy
                                            );
                                            break;
                                        }
                                        event_result = rx.recv() => {
                                            match event_result {
                                                Some(_) => {
                                                    info!(
                                                        "LocalHostsResolver: Change detected in hosts file {:?}. Debouncing and reloading...",
                                                        file_path_watch_copy
                                                    );
                                                    tokio::select! {
                                                        _ = shutdown_token.cancelled() => {
                                                            info!("LocalHostsResolver: Shutdown during debounce for {:?}.", file_path_watch_copy);
                                                            break;
                                                        }
                                                        _ = tokio::time::sleep(Duration::from_millis(250)) => {
                                                            if !shutdown_token.is_cancelled() {
                                                                resolver_clone.update_hosts().await;
                                                            }
                                                        }
                                                    }
                                                }
                                                None => {
                                                    info!("LocalHostsResolver: File watcher channel closed for {:?}.", file_path_watch_copy);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                info!(
                                    "LocalHostsResolver: File watcher event processing task stopped for {:?}.",
                                    file_path_watch_copy
                                );
                            });
                        }
                        Err(e) => {
                            error!(
                                "LocalHostsResolver: Could not create file watcher for {:?}: {}",
                                file_path_watch_copy, e
                            );
                        }
                    }
                } else {
                    info!(
                        "LocalHostsResolver: File watching enabled, but no hosts file_path specified."
                    );
                }
            } else {
                info!("LocalHostsResolver: File watching for hosts is not enabled in config.");
            }
        }
    }

    async fn parse_hosts_file(
        file_path: &Path,
    ) -> Result<HashMap<String, Vec<IpAddr>>, ConfigError> {
        info!("LocalHostsResolver: Parsing hosts file: {:?}", file_path);
        let file = File::open(file_path).map_err(|e| ConfigError::ReadFile {
            path: file_path.to_path_buf(),
            source: e,
        })?;
        let reader = StdBufReader::new(file);
        let mut entries: HashMap<String, Vec<IpAddr>> = HashMap::new();

        for line_result in reader.lines() {
            let line = line_result.map_err(|e| ConfigError::ReadFile {
                path: file_path.to_path_buf(),
                source: e,
            })?;
            let line_trimmed = line.trim();

            if line_trimmed.is_empty() || line_trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line_trimmed.split_whitespace().collect();
            if parts.len() < 2 {
                warn!(
                    "LocalHostsResolver: Skipping malformed line in hosts file {:?}: '{}'",
                    file_path, line_trimmed
                );
                continue;
            }

            match IpAddr::from_str(parts[0]) {
                Ok(ip_addr) => {
                    for part in parts.iter().skip(1) {
                        let domain = part.trim_end_matches('.').to_lowercase();
                        if !domain.is_empty() {
                            entries.entry(domain).or_default().push(ip_addr);
                        }
                    }
                }
                Err(_) => {
                    warn!(
                        "LocalHostsResolver: Could not parse IP address '{}' from line in hosts file {:?}: '{}'. Skipping line.",
                        parts[0], file_path, line_trimmed
                    );
                }
            }
        }
        for ips_vec in entries.values_mut() {
            ips_vec.sort_unstable();
            ips_vec.dedup();
        }
        info!(
            "LocalHostsResolver: Parsed {} distinct domain entries from hosts file {:?}",
            entries.len(),
            file_path
        );
        Ok(entries)
    }
}

impl Drop for LocalHostsResolver {
    fn drop(&mut self) {
        self.shutdown_token.cancel();
        info!("LocalHostsResolver: Dropped - shutdown token cancelled.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{AppConfig, HostsLoadBalancing, LocalHostsConfig};
    use crate::dns_protocol::{DnsMessage, DnsQuestion};
    use hickory_proto::op::ResponseCode;

    use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::NamedTempFile;
    use tokio::sync::RwLock;

    fn create_test_app_config(
        local_hosts_config: Option<LocalHostsConfig>,
    ) -> Arc<RwLock<AppConfig>> {
        Arc::new(RwLock::new(AppConfig {
            local_hosts: local_hosts_config,
            ..Default::default()
        }))
    }

    fn create_query(name: &str, rtype: RecordType) -> (DnsQuestion, DnsMessage) {
        let question = DnsQuestion {
            name: name.to_string(),
            record_type: rtype,
            class: DNSClass::IN,
        };
        let query_message = DnsMessage::new_query(123, name, rtype).unwrap();
        (question, query_message)
    }

    fn assert_ip_records(response: &DnsMessage, expected_ips: &[IpAddr], expected_ttl: u32) {
        let answers: Vec<&Record> = response.answers().collect();
        assert!(!answers.is_empty(), "Expected answers, got none.");

        let mut found_ips = Vec::new();
        for record in answers {
            assert_eq!(record.ttl(), expected_ttl, "TTL mismatch");
            match record.data() {
                RData::A(ip) => found_ips.push(IpAddr::V4(**ip)),
                RData::AAAA(ip) => found_ips.push(IpAddr::V6(**ip)),
                _ => panic!("Unexpected record type in answer: {:?}", record.data()),
            }
        }

        let mut sorted_found_ips = found_ips;
        sorted_found_ips.sort();
        let mut sorted_expected_ips = expected_ips.to_vec();
        sorted_expected_ips.sort();

        assert_eq!(sorted_found_ips, sorted_expected_ips, "IP address mismatch");
    }

    #[tokio::test]
    async fn test_resolve_a_record_single_ip() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "test.local".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        );
        let config = create_test_app_config(Some(LocalHostsConfig {
            entries,
            ttl: 60,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;
        let (question, query_msg) = create_query("test.local", RecordType::A);

        let response_opt = resolver.resolve(&question, &query_msg).await;
        assert!(response_opt.is_some());
        let response = response_opt.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_ip_records(&response, &[IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))], 60);
    }

    #[tokio::test]
    async fn test_resolve_aaaa_record_single_ip() {
        let mut entries = BTreeMap::new();
        let ipv6_addr = Ipv6Addr::from_str("2001:db8::1").unwrap();
        entries.insert("ipv6.test.local".to_string(), vec![IpAddr::V6(ipv6_addr)]);
        let config = create_test_app_config(Some(LocalHostsConfig {
            entries,
            ttl: 120,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;
        let (question, query_msg) = create_query("ipv6.test.local", RecordType::AAAA);

        let response_opt = resolver.resolve(&question, &query_msg).await;
        assert!(response_opt.is_some());
        let response = response_opt.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_ip_records(&response, &[IpAddr::V6(ipv6_addr)], 120);
    }

    #[tokio::test]
    async fn test_resolve_a_record_multi_ip_all_strategy() {
        let mut entries = BTreeMap::new();
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
        ];
        entries.insert("multi.local".to_string(), ips.clone());
        let config = create_test_app_config(Some(LocalHostsConfig {
            entries,
            ttl: 30,
            load_balancing: HostsLoadBalancing::All,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;
        let (question, query_msg) = create_query("multi.local", RecordType::A);

        let response_opt = resolver.resolve(&question, &query_msg).await;
        assert!(response_opt.is_some());
        let response = response_opt.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_ip_records(&response, &ips, 30);
        assert_eq!(response.answers().count(), 2);
    }

    #[tokio::test]
    async fn test_resolve_a_record_multi_ip_first_strategy() {
        let mut entries = BTreeMap::new();
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
        ];
        entries.insert("first.local".to_string(), ips.clone());
        let config = create_test_app_config(Some(LocalHostsConfig {
            entries,
            ttl: 10,
            load_balancing: HostsLoadBalancing::First,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;
        let (question, query_msg) = create_query("first.local", RecordType::A);

        let response_opt = resolver.resolve(&question, &query_msg).await;
        assert!(response_opt.is_some());
        let response = response_opt.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_ip_records(&response, &[ips[0]], 10);
        assert_eq!(response.answers().count(), 1);
    }

    #[tokio::test]
    async fn test_resolve_a_record_multi_ip_random_strategy() {
        let mut entries = BTreeMap::new();
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 6)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)),
        ];
        entries.insert("random.local".to_string(), ips.clone());
        let config = create_test_app_config(Some(LocalHostsConfig {
            entries,
            ttl: 5,
            load_balancing: HostsLoadBalancing::Random,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;
        let (question, query_msg) = create_query("random.local", RecordType::A);

        let mut found_ips_over_time = std::collections::HashSet::new();
        for _ in 0..20 {
            let response_opt = resolver.resolve(&question, &query_msg).await;
            assert!(response_opt.is_some());
            let response = response_opt.unwrap();
            assert_eq!(response.response_code(), ResponseCode::NoError);
            assert_eq!(response.answers().count(), 1);
            let record = response.answers().next().unwrap();
            assert_eq!(record.ttl(), 5);
            if let RData::A(ip) = record.data() {
                found_ips_over_time.insert(IpAddr::V4(**ip));
            } else {
                panic!("Expected A record");
            }
        }

        assert!(
            found_ips_over_time.len() > 1,
            "Random strategy should pick different IPs over time. Found: {found_ips_over_time:?}"
        );
        for found_ip in found_ips_over_time {
            assert!(
                ips.contains(&found_ip),
                "Randomly selected IP not in original list"
            );
        }
    }

    #[tokio::test]
    async fn test_no_match_returns_none() {
        let config = create_test_app_config(Some(LocalHostsConfig::default()));
        let resolver = LocalHostsResolver::new(config).await;
        let (question, query_msg) = create_query("unknown.local", RecordType::A);

        let response_opt = resolver.resolve(&question, &query_msg).await;
        assert!(response_opt.is_none());
    }

    #[tokio::test]
    async fn test_match_but_wrong_type_returns_none() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "test.local".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))],
        );
        let config = create_test_app_config(Some(LocalHostsConfig {
            entries,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;

        let (question, query_msg) = create_query("test.local", RecordType::AAAA);

        let response_opt = resolver.resolve(&question, &query_msg).await;
        assert!(response_opt.is_none());
    }

    #[tokio::test]
    async fn test_ptr_resolution_ipv4() {
        let mut entries = BTreeMap::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        entries.insert("example.com".to_string(), vec![ip]);
        entries.insert("alias.example.com".to_string(), vec![ip]);

        let config = create_test_app_config(Some(LocalHostsConfig {
            entries,
            ttl: 90,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;

        resolver.update_hosts().await;

        let (question, query_msg) = create_query("1.2.0.192.in-addr.arpa", RecordType::PTR);
        let response_opt = resolver.resolve(&question, &query_msg).await;
        assert!(response_opt.is_some(), "Expected a response for PTR query");
        let response = response_opt.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);

        let answers: Vec<&Record> = response.answers().collect();
        assert_eq!(answers.len(), 2, "Expected two PTR records");

        let mut ptr_targets = Vec::new();
        for record in answers {
            assert_eq!(record.ttl(), 90);
            if let RData::PTR(ptr_data) = record.data() {
                ptr_targets.push(ptr_data.0.to_utf8().to_lowercase());
            }
        }
        ptr_targets.sort();
        assert_eq!(ptr_targets, vec!["alias.example.com.", "example.com."]);
    }

    #[tokio::test]
    async fn test_ptr_resolution_ipv6() {
        let mut entries = BTreeMap::new();
        let ipv6_addr = Ipv6Addr::from_str("2001:db8::a:b:c:d").unwrap();
        entries.insert("ipv6.example.com".to_string(), vec![IpAddr::V6(ipv6_addr)]);
        let config = create_test_app_config(Some(LocalHostsConfig {
            entries,
            ttl: 180,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;
        resolver.update_hosts().await;

        let (question, query_msg) = create_query(
            "d.0.0.0.c.0.0.0.b.0.0.0.a.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            RecordType::PTR,
        );
        let response_opt = resolver.resolve(&question, &query_msg).await;
        assert!(
            response_opt.is_some(),
            "Expected a response for IPv6 PTR query"
        );
        let response = response_opt.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);

        let answers: Vec<&Record> = response.answers().collect();
        assert_eq!(answers.len(), 1, "Expected one PTR record");
        assert_eq!(answers[0].ttl(), 180);
        if let RData::PTR(ptr_data) = answers[0].data() {
            assert_eq!(ptr_data.0.to_utf8().to_lowercase(), "ipv6.example.com.");
        } else {
            panic!("Expected PTR RData");
        }
    }

    #[tokio::test]
    async fn test_parse_hosts_file_basic() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "127.0.0.1 localhost loopback").unwrap();
        writeln!(temp_file, "::1       localhost6 ipv6-loopback").unwrap();
        writeln!(temp_file, "192.168.1.100 server.test test1").unwrap();
        writeln!(temp_file, "192.168.1.100 another.test").unwrap();
        writeln!(temp_file, "192.168.1.101 server.test").unwrap();
        writeln!(temp_file, "# This is a comment").unwrap();
        writeln!(temp_file, "  10.0.0.1  spaced.entry  ").unwrap();

        let file_path = temp_file.path();
        let parsed_hosts = LocalHostsResolver::parse_hosts_file(file_path)
            .await
            .unwrap();

        assert_eq!(parsed_hosts.get("localhost").unwrap().len(), 1);
        assert_eq!(
            parsed_hosts.get("localhost").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
        );

        assert_eq!(parsed_hosts.get("loopback").unwrap().len(), 1);
        assert_eq!(
            parsed_hosts.get("loopback").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]
        );

        assert_eq!(parsed_hosts.get("localhost6").unwrap().len(), 1);
        assert_eq!(
            parsed_hosts.get("localhost6").unwrap(),
            &vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]
        );

        assert_eq!(parsed_hosts.get("server.test").unwrap().len(), 2);
        let server_test_ips = parsed_hosts.get("server.test").unwrap();
        assert!(server_test_ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(server_test_ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));

        assert_eq!(parsed_hosts.get("test1").unwrap().len(), 1);
        assert_eq!(
            parsed_hosts.get("test1").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))]
        );

        assert_eq!(parsed_hosts.get("another.test").unwrap().len(), 1);
        assert_eq!(
            parsed_hosts.get("another.test").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))]
        );

        assert_eq!(parsed_hosts.get("spaced.entry").unwrap().len(), 1);
        assert_eq!(
            parsed_hosts.get("spaced.entry").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
        );

        assert_eq!(parsed_hosts.len(), 8);
    }

    #[tokio::test]
    async fn test_load_hosts_from_config_struct_with_file_override() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "10.0.0.1 file.override").unwrap();
        writeln!(temp_file, "10.0.0.2 common.entry").unwrap();

        let mut entries_config = BTreeMap::new();
        entries_config.insert(
            "config.only".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))],
        );
        entries_config.insert(
            "common.entry".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2))],
        );

        let local_hosts_conf = LocalHostsConfig {
            entries: entries_config,
            cnames: BTreeMap::new(),
            file_path: Some(temp_file.path().to_path_buf()),
            watch_file: false,
            ttl: 300,
            load_balancing: HostsLoadBalancing::All,
        };

        let (hosts_map, _, _) =
            LocalHostsResolver::load_hosts_from_config_struct(Some(&local_hosts_conf)).await;

        assert_eq!(
            hosts_map.get("config.only").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))]
        );
        assert_eq!(
            hosts_map.get("file.override").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
        );
        assert_eq!(
            hosts_map.get("common.entry").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))]
        );
        assert_eq!(hosts_map.len(), 3);
    }

    #[tokio::test]
    async fn test_file_watching_triggers_update() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "1.1.1.1 initial.host").unwrap();
        temp_file.flush().unwrap();

        let local_hosts_conf = LocalHostsConfig {
            entries: BTreeMap::new(),
            cnames: BTreeMap::new(),
            file_path: Some(temp_file.path().to_path_buf()),
            watch_file: true,
            ttl: 300,
            load_balancing: HostsLoadBalancing::All,
        };
        let config = create_test_app_config(Some(local_hosts_conf));
        let resolver = LocalHostsResolver::new(Arc::clone(&config)).await;

        let resolver_clone_for_watch = Arc::clone(&resolver);
        tokio::spawn(async move {
            resolver_clone_for_watch.start_file_watching().await;
        });

        tokio::time::sleep(Duration::from_millis(500)).await;

        let hosts_guard_initial = resolver.hosts.read().await;
        assert!(hosts_guard_initial.contains_key("initial.host"));
        assert_eq!(
            hosts_guard_initial.get("initial.host").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]
        );
        drop(hosts_guard_initial);

        let mut file_handle = std::fs::OpenOptions::new()
            .append(true)
            .open(temp_file.path())
            .unwrap();
        writeln!(file_handle, "2.2.2.2 new.host").unwrap();
        file_handle.sync_all().unwrap();
        drop(file_handle);

        tokio::time::sleep(Duration::from_millis(1000)).await;

        let hosts_guard_updated = resolver.hosts.read().await;
        assert!(
            hosts_guard_updated.contains_key("initial.host"),
            "initial.host should still exist"
        );
        assert!(
            hosts_guard_updated.contains_key("new.host"),
            "new.host should now exist"
        );
        assert_eq!(
            hosts_guard_updated.get("new.host").unwrap(),
            &vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))]
        );
    }

    #[tokio::test]
    async fn test_large_hosts_file_performance() {
        let mut temp_file = NamedTempFile::new().unwrap();

        for i in 0..1000 {
            writeln!(temp_file, "192.168.{}.{} host{}.test", i / 255, i % 255, i).unwrap();
        }

        let start = std::time::Instant::now();
        let parsed = LocalHostsResolver::parse_hosts_file(temp_file.path())
            .await
            .unwrap();
        let duration = start.elapsed();

        assert_eq!(parsed.len(), 1000);
        assert!(
            duration < Duration::from_millis(100),
            "Parsing took too long: {duration:?}"
        );
    }

    #[tokio::test]
    async fn test_ttl_zero_and_max_values() {
        let test_cases = vec![0, 1, 300, u32::MAX];

        for ttl in test_cases {
            let mut entries = BTreeMap::new();
            entries.insert(
                "test.local".to_string(),
                vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
            );

            let config = create_test_app_config(Some(LocalHostsConfig {
                entries,
                ttl,
                ..Default::default()
            }));

            let resolver = LocalHostsResolver::new(config).await;
            let (question, query_msg) = create_query("test.local", RecordType::A);
            let response = resolver.resolve(&question, &query_msg).await.unwrap();

            assert_eq!(response.answers().next().unwrap().ttl(), ttl);
        }
    }
    #[tokio::test]
    async fn test_concurrent_reads_during_update() {
        let config = create_test_app_config(Some(LocalHostsConfig::default()));
        let resolver = LocalHostsResolver::new(config).await;

        let mut handles = Vec::new();

        for _ in 0..10 {
            let resolver_clone = Arc::clone(&resolver);
            let handle = tokio::spawn(async move {
                for _ in 0..100 {
                    let (question, query_msg) = create_query("test.local", RecordType::A);
                    let _ = resolver_clone.resolve(&question, &query_msg).await;
                    tokio::task::yield_now().await;
                }
            });
            handles.push(handle);
        }

        for _ in 0..5 {
            resolver.update_hosts().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_cname_direct_query() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "nas.home.arpa".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))],
        );
        let mut cnames = BTreeMap::new();
        cnames.insert("www.home.arpa".to_string(), "nas.home.arpa".to_string());

        let config = create_test_app_config(Some(LocalHostsConfig {
            entries,
            cnames,
            ttl: 60,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;

        // Query for CNAME record directly
        let (question, query_msg) = create_query("www.home.arpa", RecordType::CNAME);
        let response_opt = resolver.resolve(&question, &query_msg).await;

        assert!(response_opt.is_some());
        let response = response_opt.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);

        let answers: Vec<&Record> = response.answers().collect();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].ttl(), 60);

        if let RData::CNAME(cname_data) = answers[0].data() {
            assert_eq!(cname_data.0.to_utf8().to_lowercase(), "nas.home.arpa.");
        } else {
            panic!("Expected CNAME record, got {:?}", answers[0].data());
        }
    }

    #[tokio::test]
    async fn test_cname_a_record_resolution() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "nas.home.arpa".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))],
        );
        let mut cnames = BTreeMap::new();
        cnames.insert("www.home.arpa".to_string(), "nas.home.arpa".to_string());

        let config = create_test_app_config(Some(LocalHostsConfig {
            entries,
            cnames,
            ttl: 120,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;

        // Query for A record on CNAME alias
        let (question, query_msg) = create_query("www.home.arpa", RecordType::A);
        let response_opt = resolver.resolve(&question, &query_msg).await;

        assert!(response_opt.is_some());
        let response = response_opt.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);

        let answers: Vec<&Record> = response.answers().collect();
        // Should have CNAME + A record
        assert_eq!(answers.len(), 2);

        // First record should be CNAME
        if let RData::CNAME(cname_data) = answers[0].data() {
            assert_eq!(cname_data.0.to_utf8().to_lowercase(), "nas.home.arpa.");
        } else {
            panic!("Expected CNAME record first, got {:?}", answers[0].data());
        }

        // Second record should be A record for the target
        if let RData::A(ip) = answers[1].data() {
            assert_eq!(**ip, Ipv4Addr::new(192, 168, 1, 100));
        } else {
            panic!("Expected A record second, got {:?}", answers[1].data());
        }
    }

    #[tokio::test]
    async fn test_cname_aaaa_record_resolution() {
        let mut entries = BTreeMap::new();
        let ipv6_addr = Ipv6Addr::from_str("2001:db8::1").unwrap();
        entries.insert("nas.home.arpa".to_string(), vec![IpAddr::V6(ipv6_addr)]);
        let mut cnames = BTreeMap::new();
        cnames.insert("www.home.arpa".to_string(), "nas.home.arpa".to_string());

        let config = create_test_app_config(Some(LocalHostsConfig {
            entries,
            cnames,
            ttl: 60,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;

        // Query for AAAA record on CNAME alias
        let (question, query_msg) = create_query("www.home.arpa", RecordType::AAAA);
        let response_opt = resolver.resolve(&question, &query_msg).await;

        assert!(response_opt.is_some());
        let response = response_opt.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);

        let answers: Vec<&Record> = response.answers().collect();
        assert_eq!(answers.len(), 2);

        // First record should be CNAME
        if let RData::CNAME(cname_data) = answers[0].data() {
            assert_eq!(cname_data.0.to_utf8().to_lowercase(), "nas.home.arpa.");
        } else {
            panic!("Expected CNAME record first");
        }

        // Second record should be AAAA
        if let RData::AAAA(ip) = answers[1].data() {
            assert_eq!(**ip, ipv6_addr);
        } else {
            panic!("Expected AAAA record second");
        }
    }

    #[tokio::test]
    async fn test_cname_target_not_in_local_hosts() {
        // CNAME points to external target - should return None to let upstream resolve
        let mut cnames = BTreeMap::new();
        cnames.insert(
            "alias.home.arpa".to_string(),
            "external.example.com".to_string(),
        );

        let config = create_test_app_config(Some(LocalHostsConfig {
            entries: BTreeMap::new(),
            cnames,
            ttl: 60,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;

        let (question, query_msg) = create_query("alias.home.arpa", RecordType::A);
        let response_opt = resolver.resolve(&question, &query_msg).await;

        // Should return None so the query goes upstream
        assert!(response_opt.is_none());
    }

    #[tokio::test]
    async fn test_cname_no_match() {
        let config = create_test_app_config(Some(LocalHostsConfig {
            entries: BTreeMap::new(),
            cnames: BTreeMap::new(),
            ttl: 60,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;

        let (question, query_msg) = create_query("unknown.home.arpa", RecordType::CNAME);
        let response_opt = resolver.resolve(&question, &query_msg).await;

        assert!(response_opt.is_none());
    }

    #[tokio::test]
    async fn test_cname_case_insensitivity() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "nas.home.arpa".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))],
        );
        let mut cnames = BTreeMap::new();
        cnames.insert("WWW.HOME.ARPA".to_string(), "NAS.HOME.ARPA".to_string());

        let config = create_test_app_config(Some(LocalHostsConfig {
            entries,
            cnames,
            ttl: 60,
            ..Default::default()
        }));
        let resolver = LocalHostsResolver::new(config).await;

        // Query with different case
        let (question, query_msg) = create_query("www.home.arpa", RecordType::A);
        let response_opt = resolver.resolve(&question, &query_msg).await;

        assert!(response_opt.is_some());
        let response = response_opt.unwrap();
        assert_eq!(response.answers().count(), 2); // CNAME + A
    }

    #[tokio::test]
    async fn test_cname_load_from_config() {
        let mut cnames = BTreeMap::new();
        cnames.insert("alias1.test".to_string(), "target1.test".to_string());
        cnames.insert("alias2.test".to_string(), "target2.test".to_string());

        let local_hosts_conf = LocalHostsConfig {
            entries: BTreeMap::new(),
            cnames,
            ttl: 60,
            ..Default::default()
        };

        let (_, _, cnames_map) =
            LocalHostsResolver::load_hosts_from_config_struct(Some(&local_hosts_conf)).await;

        assert_eq!(cnames_map.len(), 2);
        assert_eq!(cnames_map.get("alias1.test"), Some(&"target1.test".to_string()));
        assert_eq!(cnames_map.get("alias2.test"), Some(&"target2.test".to_string()));
    }
}
