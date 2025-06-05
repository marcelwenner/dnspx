use crate::app_lifecycle::AppLifecycleManager;
use crate::core::types::CliCommand;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub(crate) struct TuiWorker {
    app_lifecycle: Arc<AppLifecycleManager>,
    command_rx: mpsc::Receiver<CliCommand>,
}

impl TuiWorker {
    pub(crate) fn new(
        app_lifecycle: Arc<AppLifecycleManager>,
        command_rx: mpsc::Receiver<CliCommand>,
    ) -> Self {
        Self {
            app_lifecycle,
            command_rx,
        }
    }

    pub(crate) async fn run(mut self) {
        info!("TUI Worker started.");
        while let Some(command) = self.command_rx.recv().await {
            info!("TUI Worker received command: {:?}", command);

            match command {
                CliCommand::TriggerAwsScan => {
                    if let Err(e) = self.app_lifecycle.trigger_aws_scan_refresh().await {
                        error!("TUI Worker: Error triggering AWS scan: {}", e);
                    }
                }
                CliCommand::ReloadConfig => {
                    if let Err(e) = self.app_lifecycle.trigger_config_reload().await {
                        error!("TUI Worker: Error triggering config reload: {}", e);
                    }
                }

                _ => {
                    warn!("TUI Worker received unhandled command: {:?}", command);
                }
            }
        }
        info!("TUI Worker finished.");
    }
}
