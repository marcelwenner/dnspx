use crate::core::types::CacheStats as CoreCacheStats;
use crate::dns_protocol::{DnsMessage, DnsQuestion};
use hickory_proto::{
    op::ResponseCode,
    rr::{RData, Record, RecordType},
};
use moka::future::Cache;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, info};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CacheKey {
    pub name: String,
    pub record_type: RecordType,
}

impl CacheKey {
    pub fn from_question(question: &DnsQuestion) -> Self {
        Self {
            name: question.name.trim_end_matches('.').to_lowercase(),
            record_type: question.record_type,
        }
    }
    pub fn new(name: &str, record_type: RecordType) -> Self {
        Self {
            name: name.trim_end_matches('.').to_lowercase(),
            record_type,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub records: Vec<Record>,
    pub response_code: ResponseCode,
    pub cached_at: std::time::Instant,
    pub ttl: Duration,
}

impl CacheEntry {
    pub fn new(records: Vec<Record>, response_code: ResponseCode, ttl: Duration) -> Self {
        Self {
            records,
            response_code,
            cached_at: std::time::Instant::now(),
            ttl,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.cached_at.elapsed() < self.ttl
    }

    pub fn current_ttl_remaining(&self) -> Duration {
        self.ttl.saturating_sub(self.cached_at.elapsed())
    }

    pub fn current_ttl_remaining_secs(&self) -> u32 {
        self.current_ttl_remaining()
            .as_secs()
            .try_into()
            .unwrap_or(0)
    }
}

pub struct DnsCache {
    cache: Cache<CacheKey, Arc<CacheEntry>>,
    min_ttl: Duration,
    max_ttl: Duration,
    serve_stale_if_error: bool,
    serve_stale_max_ttl: Duration,

    hits: AtomicU64,
    misses: AtomicU64,
    inserts: AtomicU64,
    evictions: AtomicU64,
}

impl DnsCache {
    pub fn new(
        max_capacity: u64,
        min_ttl: Duration,
        max_ttl: Duration,
        serve_stale_if_error: bool,
        serve_stale_max_ttl: Duration,
    ) -> Self {
        let cache = Cache::builder().max_capacity(max_capacity).build();

        Self {
            cache,
            min_ttl,
            max_ttl,
            serve_stale_if_error,
            serve_stale_max_ttl,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            inserts: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    pub async fn get(&self, key: &CacheKey, allow_stale: bool) -> Option<Arc<CacheEntry>> {
        if let Some(entry_arc) = self.cache.get(key).await {
            self.hits.fetch_add(1, Ordering::Relaxed);
            if entry_arc.is_valid() {
                debug!(?key, "Cache hit (valid).");
                Some(entry_arc)
            } else if allow_stale
                && self.serve_stale_if_error
                && (entry_arc.cached_at.elapsed() < (entry_arc.ttl + self.serve_stale_max_ttl))
            {
                debug!(?key, "Cache hit (stale, serving due to config).");
                Some(entry_arc)
            } else {
                debug!(?key, "Cache hit (expired/stale not allowed).");
                self.cache.invalidate(key).await;
                self.evictions.fetch_add(1, Ordering::Relaxed);
                None
            }
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            debug!(?key, "Cache miss.");
            None
        }
    }

    pub async fn insert(&self, key: CacheKey, response_message: &DnsMessage) {
        if response_message.response_code() != ResponseCode::NoError
            && response_message.response_code() != ResponseCode::NXDomain
        {
            debug!(?key, response_code = ?response_message.response_code(), "Skipping cache insert for non-NoError/NXDomain response.");
            return;
        }

        let answer_records: Vec<Record> = response_message.answers().cloned().collect();
        let authority_records: Vec<Record> = response_message.inner().name_servers().to_vec();

        fn duration_from_u32_secs(secs: u32) -> Duration {
            Duration::from_secs(secs as u64)
        }

        let mut effective_ttl = answer_records
            .iter()
            .map(|r| r.ttl())
            .min()
            .map(duration_from_u32_secs)
            .unwrap_or_else(|| {
                authority_records
                    .iter()
                    .find(|r| r.record_type() == RecordType::SOA)
                    .and_then(|soa_record| Some(soa_record.data()))
                    .and_then(|rdata| {
                        if let RData::SOA(ref soa) = *rdata {
                            Some(soa.minimum())
                        } else {
                            None
                        }
                    })
                    .map(duration_from_u32_secs)
                    .unwrap_or(self.min_ttl)
            });

        if effective_ttl < self.min_ttl {
            effective_ttl = self.min_ttl;
        }
        if effective_ttl > self.max_ttl {
            effective_ttl = self.max_ttl;
        }

        let records_to_cache = if response_message.response_code() == ResponseCode::NXDomain {
            if authority_records
                .iter()
                .any(|r| r.record_type() == RecordType::SOA)
            {
                authority_records
            } else {
                Vec::new()
            }
        } else {
            answer_records
        };

        if records_to_cache.is_empty() && response_message.response_code() == ResponseCode::NoError
        {
            debug!(
                ?key,
                "Skipping caching for NoError response with no answers (NODATA)."
            );
            return;
        }

        let entry = CacheEntry::new(
            records_to_cache,
            response_message.response_code(),
            effective_ttl,
        );

        debug!(?key, ttl = ?entry.ttl, response_code = ?entry.response_code, num_records = entry.records.len(), "Caching entry.");
        self.cache.insert(key, Arc::new(entry)).await;
        self.inserts.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn insert_synthetic_entry(
        &self,
        key: CacheKey,
        records: Vec<Record>,
        ttl: Duration,
        response_code: ResponseCode,
    ) {
        if records.is_empty() && response_code == ResponseCode::NoError {
            debug!(
                ?key,
                "Skipping synthetic cache insert for NoError with no records."
            );
            return;
        }
        if response_code != ResponseCode::NoError && response_code != ResponseCode::NXDomain {
            debug!(
                ?key,
                ?response_code,
                "Skipping synthetic cache insert for non-NoError/NXDomain response."
            );
            return;
        }

        let mut effective_ttl = ttl;
        if effective_ttl < self.min_ttl {
            effective_ttl = self.min_ttl;
        }
        if effective_ttl > self.max_ttl {
            effective_ttl = self.max_ttl;
        }

        let entry = CacheEntry::new(records, response_code, effective_ttl);
        debug!(?key, ttl = ?entry.ttl, response_code = ?entry.response_code, num_records = entry.records.len(), "Caching synthetic entry.");
        self.cache.insert(key, Arc::new(entry)).await;
        self.inserts.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn remove(&self, key: &CacheKey) {
        debug!(?key, "Removing entry from cache.");
        if self.cache.get(key).await.is_some() {
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        self.cache.invalidate(key).await;
    }

    pub async fn clear_all(&self) {
        info!("Clearing all entries from DNS cache.");
        let count_before = self.cache.entry_count();
        self.cache.invalidate_all();
        self.evictions.fetch_add(count_before, Ordering::Relaxed);

        debug!(
            "DNS Cache cleared. Current size: {}",
            self.cache.entry_count()
        );
    }

    pub fn get_stats(&self) -> CoreCacheStats {
        CoreCacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            size: self.cache.entry_count(),
            estimated_memory_usage_bytes: self.cache.weighted_size(),
        }
    }

    pub fn get_insert_count(&self) -> u64 {
        self.inserts.load(Ordering::Relaxed)
    }

    pub fn get_hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    pub fn reset_stats(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.inserts.store(0, Ordering::Relaxed);
    }

    pub async fn get_all_active_entries(&self) -> Vec<(CacheKey, Arc<CacheEntry>)> {
        let mut evicted_count = 0;
        let mut active_entries: Vec<(CacheKey, Arc<CacheEntry>)> = self
            .cache
            .iter()
            .filter_map(|(key_arc, entry_arc)| {
                if entry_arc.is_valid()
                    || (self.serve_stale_if_error
                        && entry_arc.cached_at.elapsed()
                            < (entry_arc.ttl + self.serve_stale_max_ttl))
                {
                    Some((key_arc.as_ref().clone(), Arc::clone(&entry_arc)))
                } else {
                    evicted_count += 1;
                    None
                }
            })
            .collect();

        active_entries.sort_by(|(ka, _), (kb, _)| {
            ka.name
                .cmp(&kb.name)
                .then_with(|| ka.record_type.cmp(&kb.record_type))
        });
        active_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_protocol::DnsMessage as AppDnsMessage;
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn create_test_record(name: &str, ttl: u32, ip: &str) -> Record {
        let name = Name::from_str(name).unwrap();
        let rdata = RData::A(ip.parse::<Ipv4Addr>().unwrap().into());
        Record::from_rdata(name, ttl, rdata)
    }

    #[tokio::test]
    async fn test_cache_insert_and_get() {
        let cache = DnsCache::new(
            100,
            Duration::from_secs(10),
            Duration::from_secs(3600),
            false,
            Duration::from_secs(0),
        );
        let question = DnsQuestion {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };
        let key = CacheKey::from_question(&question);

        let query_msg = AppDnsMessage::new_query(1, "example.com.", RecordType::A).unwrap();
        let mut response_msg = AppDnsMessage::new_response(&query_msg, ResponseCode::NoError);
        response_msg.add_answer_record(create_test_record("example.com.", 300, "93.184.216.34"));

        cache.insert(key.clone(), &response_msg).await;

        let cached_entry = cache.get(&key, false).await;
        assert!(cached_entry.is_some());
        let entry = cached_entry.unwrap();
        assert_eq!(entry.response_code, ResponseCode::NoError);
        assert_eq!(entry.records.len(), 1);
        assert!(entry.ttl >= Duration::from_secs(10));
    }

    #[tokio::test]
    async fn test_cache_nxdomain() {
        let cache = DnsCache::new(
            100,
            Duration::from_secs(5),
            Duration::from_secs(60),
            false,
            Duration::from_secs(0),
        );
        let question = DnsQuestion {
            name: "nx.example.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };
        let key = CacheKey::from_question(&question);

        let query_msg = AppDnsMessage::new_query(2, "nx.example.com.", RecordType::A).unwrap();
        let mut response_msg = AppDnsMessage::new_response(&query_msg, ResponseCode::NXDomain);

        let soa_name = Name::from_str("example.com.").unwrap();
        let rname = Name::from_str("admin.example.com.").unwrap();
        let soa_rdata = RData::SOA(hickory_proto::rr::rdata::SOA::new(
            soa_name.clone(),
            rname,
            1,
            7200,
            3600,
            1209600,
            15,
        ));
        let soa_record = Record::from_rdata(soa_name, 60, soa_rdata);
        response_msg.inner_mut().add_name_server(soa_record);

        cache.insert(key.clone(), &response_msg).await;

        let cached_entry = cache.get(&key, false).await;
        assert!(cached_entry.is_some());
        let entry = cached_entry.unwrap();
        assert_eq!(entry.response_code, ResponseCode::NXDomain);
        assert_eq!(entry.records.len(), 1);
        assert_eq!(entry.records[0].record_type(), RecordType::SOA);
        assert_eq!(entry.ttl, Duration::from_secs(15));
    }

    #[tokio::test]
    async fn test_cache_expiry() {
        let cache = DnsCache::new(
            100,
            Duration::from_secs(1),
            Duration::from_secs(1),
            false,
            Duration::from_secs(0),
        );
        let question = DnsQuestion {
            name: "short.example.com".to_string(),
            record_type: RecordType::A,
            class: hickory_proto::rr::DNSClass::IN,
        };
        let key = CacheKey::from_question(&question);

        let query_msg = AppDnsMessage::new_query(3, "short.example.com.", RecordType::A).unwrap();
        let mut response_msg = AppDnsMessage::new_response(&query_msg, ResponseCode::NoError);
        response_msg.add_answer_record(create_test_record("short.example.com.", 1, "1.1.1.1"));

        cache.insert(key.clone(), &response_msg).await;
        assert!(cache.get(&key, false).await.is_some());

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(cache.get(&key, false).await.is_none());
    }

    #[tokio::test]
    async fn test_insert_synthetic_entry() {
        let cache = DnsCache::new(
            100,
            Duration::from_secs(10),
            Duration::from_secs(3600),
            false,
            Duration::from_secs(0),
        );
        let key = CacheKey::new("synthetic.example.com", RecordType::A);
        let record = create_test_record("synthetic.example.com.", 120, "10.0.0.1");

        cache
            .insert_synthetic_entry(
                key.clone(),
                vec![record],
                Duration::from_secs(120),
                ResponseCode::NoError,
            )
            .await;

        let cached_entry = cache.get(&key, false).await;
        assert!(cached_entry.is_some());
        let entry = cached_entry.unwrap();
        assert_eq!(entry.response_code, ResponseCode::NoError);
        assert_eq!(entry.records.len(), 1);
        assert_eq!(entry.records[0].data().record_type(), RecordType::A);
        assert_eq!(entry.ttl, Duration::from_secs(120));
        assert!(entry.is_valid());
    }

    #[tokio::test]
    async fn test_insert_synthetic_entry_ttl_clamping() {
        let min_ttl_duration = Duration::from_secs(60);
        let max_ttl_duration = Duration::from_secs(120);
        let cache = DnsCache::new(
            100,
            min_ttl_duration,
            max_ttl_duration,
            false,
            Duration::from_secs(0),
        );

        let key_low_ttl = CacheKey::new("low.example.com", RecordType::A);
        let record_low = create_test_record("low.example.com.", 10, "10.0.0.2");
        cache
            .insert_synthetic_entry(
                key_low_ttl.clone(),
                vec![record_low],
                Duration::from_secs(10),
                ResponseCode::NoError,
            )
            .await;
        let entry_low = cache.get(&key_low_ttl, false).await.unwrap();
        assert_eq!(entry_low.ttl, min_ttl_duration);

        let key_high_ttl = CacheKey::new("high.example.com", RecordType::A);
        let record_high = create_test_record("high.example.com.", 200, "10.0.0.3");
        cache
            .insert_synthetic_entry(
                key_high_ttl.clone(),
                vec![record_high],
                Duration::from_secs(200),
                ResponseCode::NoError,
            )
            .await;
        let entry_high = cache.get(&key_high_ttl, false).await.unwrap();
        assert_eq!(entry_high.ttl, max_ttl_duration);
    }

    #[tokio::test]
    async fn test_get_all_active_entries() {
        let cache = DnsCache::new(
            100,
            Duration::from_secs(1),
            Duration::from_secs(10),
            false,
            Duration::from_secs(0),
        );

        let key1 = CacheKey::new("active.example.com", RecordType::A);
        let rec1 = create_test_record("active.example.com.", 5, "1.1.1.1");
        cache
            .insert_synthetic_entry(
                key1.clone(),
                vec![rec1],
                Duration::from_secs(5),
                ResponseCode::NoError,
            )
            .await;

        let key2 = CacheKey::new("expired.example.com", RecordType::A);
        let rec2 = create_test_record("expired.example.com.", 1, "2.2.2.2");
        cache
            .insert_synthetic_entry(
                key2.clone(),
                vec![rec2],
                Duration::from_secs(1),
                ResponseCode::NoError,
            )
            .await;

        tokio::time::sleep(Duration::from_secs(2)).await;

        let active_entries = cache.get_all_active_entries().await;
        assert_eq!(active_entries.len(), 1);
        assert_eq!(active_entries[0].0, key1);
        assert!(active_entries[0].1.is_valid());

        assert!(cache.get(&key2, false).await.is_none());
    }
}
