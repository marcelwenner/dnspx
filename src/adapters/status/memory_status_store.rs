use crate::core::types::{AppStatus, AwsScannerStatus, CacheStats, ConfigStatus};
use crate::ports::StatusReporterPort;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Default, Clone)]
pub(crate) struct InMemoryStatusStoreAdapter {
    aws_status: Arc<RwLock<AwsScannerStatus>>,
    config_status: Arc<RwLock<ConfigStatus>>,
}

impl InMemoryStatusStoreAdapter {
    pub(crate) fn new() -> Self {
        Self {
            aws_status: Arc::new(RwLock::new(AwsScannerStatus::default())),
            config_status: Arc::new(RwLock::new(ConfigStatus::default())),
        }
    }
}

#[async_trait]
impl StatusReporterPort for InMemoryStatusStoreAdapter {
    async fn report_aws_scanner_status(&self, status: AwsScannerStatus) {
        let mut guard = self.aws_status.write().await;
        *guard = status;
    }

    async fn get_aws_scanner_status(&self) -> AwsScannerStatus {
        self.aws_status.read().await.clone()
    }

    async fn report_config_status(&self, status: ConfigStatus) {
        let mut guard = self.config_status.write().await;
        *guard = status;
    }

    async fn get_config_status(&self) -> ConfigStatus {
        self.config_status.read().await.clone()
    }

    async fn get_full_app_status(
        &self,
        uptime_seconds: u64,
        active_listeners: Vec<String>,
        config_hash: String,
        cache_stats: Option<CacheStats>,
    ) -> AppStatus {
        let config_guard = self.config_status.read().await;
        let aws_guard = self.aws_status.read().await;
        AppStatus {
            config_status: config_guard.clone(),
            aws_scanner_status: Some(aws_guard.clone()),
            uptime_seconds,
            active_listeners,
            cache_stats,
            active_config_hash: config_hash,
        }
    }
}
