#![allow(dead_code)]

mod adapters;
mod app_lifecycle;
mod aws_integration;
mod config;
mod core;
mod dns_protocol;
mod ports;

use crate::adapters::aws::credentials_provider::AwsSdkConfigProvider;
use crate::adapters::aws::vpc_info_provider::AwsSdkVpcInfoProvider;
use crate::adapters::cli::console_cli_adapter::ConsoleCliAdapter;
use crate::adapters::resolver::composite_resolver::CompositeUpstreamResolver;
use crate::adapters::resolver::doh_client::DohClientAdapter;
use crate::adapters::resolver::standard_dns_client::StandardDnsClient;
use crate::adapters::server::{tcp_listener, udp_listener};
use crate::adapters::status::memory_status_store::InMemoryStatusStoreAdapter;
use crate::adapters::tui::{
    app::TuiApp, app::TuiUserInteractionAdapter as TuiInteraction, event::EventManager,
    logging::TuiLoggingLayer,
};
use crate::adapters::update::manager::VerifiedUpdateManager;
use crate::app_lifecycle::AppLifecycleManager;
use crate::aws_integration::scanner::AwsVpcScannerTask;
use crate::config::models::{AppConfig, LogFormat, LoggingConfig};
use crate::core::config_manager::ConfigurationManager;
use crate::core::rule_engine::RuleEngine;
use crate::ports::{AwsConfigProvider, DnsQueryService, StatusReporterPort, UserInteractionPort};
use clap::Parser;
use core::dns_request_processor::DnsRequestProcessor;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ports::{AppLifecycleManagerPort, AwsVpcInfoProvider, ConfigurationStore};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::collections::HashMap;
use std::io::stdout;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock as TokioRwLock;
use tracing::{error, info};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::{EnvFilter, FmtSubscriber, registry::Registry};

use crate::core::types::MessageLevel;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CliArgs {
    #[clap(
        long,
        action,
        help = "Run in simple CLI mode without the TUI dashboard"
    )]
    cli_only: bool,
}

fn determine_initial_log_settings(config_path: &PathBuf) -> (LoggingConfig, bool) {
    let default_logging = LoggingConfig::default();
    let default_colors = true;

    if !config_path.exists() {
        return (default_logging, default_colors);
    }

    match std::fs::read_to_string(config_path) {
        Ok(content) => match toml::from_str::<AppConfig>(&content) {
            Ok(cfg) => (cfg.logging, cfg.cli.enable_colors),
            Err(e) => {
                eprintln!(
                    "[PRE-INIT WARN] Failed to parse app config from {config_path:?} for log settings: {e}. Using defaults."
                );
                (default_logging, default_colors)
            }
        },
        Err(e) => {
            eprintln!(
                "[PRE-INIT WARN] Could not read app config from {config_path:?} for log settings: {e}. Using defaults."
            );
            (default_logging, default_colors)
        }
    }
}

fn init_logger_cli(logging_config: &LoggingConfig, terminal_colors_enabled: bool) {
    let env_filter_str = std::env::var("RUST_LOG").unwrap_or_else(|_| logging_config.level.clone());
    let env_filter = EnvFilter::try_new(&env_filter_str).unwrap_or_else(|e| {
        eprintln!("[LOGGER WARN] Failed to parse RUST_LOG/config log level '{env_filter_str}' for CLI: {e}. Defaulting CLI to 'info'.");
        EnvFilter::new("info")
    });

    let subscriber_builder = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(true);

    match logging_config.format {
        LogFormat::Pretty => {
            let pretty_fmt = subscriber_builder
                .pretty()
                .with_ansi(terminal_colors_enabled);
            let _ = tracing::subscriber::set_global_default(pretty_fmt.finish());
        }
        LogFormat::Json => {
            let _ = tracing::subscriber::set_global_default(subscriber_builder.json().finish());
        }
        LogFormat::Compact => {
            let _ = tracing::subscriber::set_global_default(subscriber_builder.compact().finish());
        }
    }
    tracing::info!(
        "Standard CLI Logger initialized (or updated) with effective filter: '{}' and format '{:?}'",
        env_filter_str,
        logging_config.format
    );
}

fn init_logger_tui(
    logging_config: &LoggingConfig,
    tui_log_tx: tokio::sync::mpsc::Sender<(String, crate::core::types::MessageLevel)>,
) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(logging_config.level.clone()));

    let tui_layer = TuiLoggingLayer::new(tui_log_tx);

    let subscriber = Registry::default().with(env_filter).with(tui_layer);

    tracing::subscriber::set_global_default(subscriber)
        .expect("Setting TUI global default subscriber failed");

    info!("TUI Logger initialized. All logs routed to TUI panel only.");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli_args = CliArgs::parse();
    let is_tui_mode = !cli_args.cli_only;

    let console_supports_color = supports_color::on(supports_color::Stream::Stdout).is_some();
    let config_base_path = std::env::current_dir().expect("Failed to get current directory");
    let preliminary_config_path = config_base_path.join(config::DEFAULT_CONFIG_FILE_NAME_V2);

    let (initial_log_config_for_startup, initial_cli_color_pref) =
        determine_initial_log_settings(&preliminary_config_path);
    let effective_colors_enabled_for_startup = initial_cli_color_pref && console_supports_color;

    if !is_tui_mode {
        let startup_log_level = if initial_log_config_for_startup.level.is_empty()
            || initial_log_config_for_startup.level == "off"
        {
            "error".to_string()
        } else {
            initial_log_config_for_startup.level.clone()
        };

        let startup_filter_str = std::env::var("RUST_LOG").unwrap_or(startup_log_level);
        let temp_startup_filter = EnvFilter::new(startup_filter_str.clone());
        let temp_subscriber = FmtSubscriber::builder()
            .with_env_filter(temp_startup_filter)
            .with_ansi(effective_colors_enabled_for_startup)
            .compact()
            .with_writer(std::io::stderr)
            .finish();
        let _ = tracing::subscriber::set_global_default(temp_subscriber);
        tracing::info!(
            "Temporary startup logger active (filter: {}). Final logger will be set after config load.",
            startup_filter_str
        );
    }

    if is_tui_mode {
        eprintln!("DNS Proxy bootstrap starting (TUI mode)...");
    } else {
        tracing::info!("DNS Proxy bootstrap starting...");
    }

    let config_store_adapter: Arc<dyn ConfigurationStore> = Arc::new(
        adapters::config::file_store::JsonFileConfigAdapter::new(config_base_path.clone()),
    );

    let (config_manager_instance, initial_config_result) =
        match ConfigurationManager::new(Arc::clone(&config_store_adapter)).await {
            Ok((cm, result)) => (Arc::new(cm), result),
            Err(e) => {
                eprintln!("[CRITICAL] Failed to load or initialize configuration: {e}. Exiting.");
                return Err(e.into());
            }
        };

    let (tui_log_tx_for_interaction_adapter, tui_log_rx_for_app) = tokio::sync::mpsc::channel(2048);

    let final_log_config = config_manager_instance
        .get_config()
        .read()
        .await
        .logging
        .clone();
    let final_colors_enabled = config_manager_instance
        .get_config()
        .read()
        .await
        .cli
        .enable_colors
        && console_supports_color;

    let user_interaction_port: Arc<dyn UserInteractionPort>;
    let console_cli_adapter_instance_opt: Option<Arc<ConsoleCliAdapter>>;

    if is_tui_mode {
        init_logger_tui(
            &final_log_config,
            tui_log_tx_for_interaction_adapter.clone(),
        );
        user_interaction_port = Arc::new(TuiInteraction::new(
            tui_log_tx_for_interaction_adapter.clone(),
        ));
        console_cli_adapter_instance_opt = None;
    } else {
        init_logger_cli(&final_log_config, final_colors_enabled);
        let adapter = Arc::new(ConsoleCliAdapter::new(final_colors_enabled));
        user_interaction_port = adapter.clone();
        console_cli_adapter_instance_opt = Some(adapter);
    }

    if initial_config_result.was_migrated {
        user_interaction_port.display_message(
            "--- .NET Legacy Configuration Migration Report ---",
            MessageLevel::Info,
        );
        for msg in initial_config_result.messages {
            user_interaction_port.display_message(&msg.text, msg.level);
        }
        user_interaction_port
            .display_message("--- End of Migration Report ---", MessageLevel::Info);
    } else if !initial_config_result.messages.is_empty() {
        for msg in initial_config_result.messages {
            if msg.level == MessageLevel::Info {
                user_interaction_port.display_message(&msg.text, msg.level);
            }
        }
    }

    if let Err(e) = config_manager_instance.start_watching() {
        user_interaction_port.display_message(
            &format!(
                "Failed to start configuration file watcher: {e}. Hot-reloading might not work."
            ),
            MessageLevel::Warning,
        );
    }

    let status_reporter_adapter: Arc<dyn StatusReporterPort> =
        Arc::new(InMemoryStatusStoreAdapter::new());

    let aws_credentials_cache = Arc::new(TokioRwLock::new(HashMap::new()));
    let aws_config_provider_adapter: Arc<dyn AwsConfigProvider> =
        Arc::new(AwsSdkConfigProvider::new(
            config_manager_instance.get_config(),
            Arc::clone(&user_interaction_port),
            Arc::clone(&aws_credentials_cache),
        ));

    let app_lifecycle_manager_impl = AppLifecycleManager::new(
        config_manager_instance,
        Arc::clone(&status_reporter_adapter),
        Arc::clone(&user_interaction_port),
        Arc::clone(&aws_config_provider_adapter),
    )
    .await;

    let app_lifecycle_manager: Arc<dyn AppLifecycleManagerPort> =
        app_lifecycle_manager_impl.clone();

    let local_hosts_resolver_instance = app_lifecycle_manager.get_local_hosts_resolver();
    let lhr_for_watching = Arc::clone(&local_hosts_resolver_instance);
    let lhr_watch_handle = tokio::spawn(async move {
        lhr_for_watching.start_file_watching().await;
    });
    app_lifecycle_manager.add_task(lhr_watch_handle).await;

    let rule_engine = Arc::new(RuleEngine::new(app_lifecycle_manager.get_config()));

    let std_dns_resolver_adapter = Arc::new(StandardDnsClient::new());
    let doh_resolver_adapter = {
        let config_guard = app_lifecycle_manager.get_config();
        let app_conf = config_guard.read().await;
        Arc::new(
            DohClientAdapter::new(
                app_conf.default_resolver.timeout,
                app_conf.http_proxy.clone(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create DoH client: {}", e))?,
        )
    };

    let composite_resolver = Arc::new(CompositeUpstreamResolver::new(
        Arc::clone(&std_dns_resolver_adapter),
        doh_resolver_adapter,
    ));

    let dns_cache_for_processor = app_lifecycle_manager.get_dns_cache();

    let dns_request_processor = Arc::new(DnsRequestProcessor::new(
        Arc::clone(&app_lifecycle_manager),
        dns_cache_for_processor,
        rule_engine,
        local_hosts_resolver_instance,
        composite_resolver,
    ));

    let aws_vpc_info_provider: Arc<dyn AwsVpcInfoProvider> = Arc::new(AwsSdkVpcInfoProvider::new());

    let mut proceed_with_aws_scanner = false;
    let alm_aws_config = app_lifecycle_manager.get_config().read().await.aws.clone();
    if let Some(aws_config) = alm_aws_config {
        if !aws_config.accounts.is_empty() {
            user_interaction_port.display_message(
                "AWS configuration found. Performing preliminary credential check...",
                MessageLevel::Info,
            );
            let mut any_account_valid = false;
            for account_conf in &aws_config.accounts {
                match aws_config_provider_adapter
                    .get_credentials_for_account(account_conf, Arc::clone(&user_interaction_port))
                    .await
                {
                    Ok(creds) => {
                        match aws_config_provider_adapter
                            .validate_credentials(&creds)
                            .await
                        {
                            Ok(arn) => {
                                user_interaction_port.display_message(
                                    &format!("Preliminary credential check successful for account '{}' (ARN: {}). AWS Scanner will be started.", account_conf.label, arn),
                                    MessageLevel::Info,
                                );
                                any_account_valid = true;
                                break;
                            }
                            Err(e) => {
                                user_interaction_port.display_message(
                                    &format!("Preliminary credential validation failed for account '{}': {}. This account might not be scannable.", account_conf.label, e),
                                    MessageLevel::Warning,
                                );
                            }
                        }
                    }
                    Err(e) => {
                        user_interaction_port.display_message(
                            &format!("Failed to obtain initial credentials for AWS account '{}' during pre-check: {}. This account might not be scannable.", account_conf.label, e),
                            MessageLevel::Warning,
                        );
                    }
                }
            }
            if any_account_valid {
                proceed_with_aws_scanner = true;
            } else {
                user_interaction_port.display_message(
                    "No AWS accounts have initially valid credentials. AWS Scanner will NOT be started. Please check configuration or use TUI (Ctrl+R) for setup.",
                    MessageLevel::Error,
                );
                status_reporter_adapter
                    .report_aws_scanner_status(crate::core::types::AwsScannerStatus {
                        is_scanning: false,
                        error_message: Some(
                            "No initially valid AWS credentials found for any configured account."
                                .to_string(),
                        ),
                        ..Default::default()
                    })
                    .await;
            }
        } else {
            user_interaction_port.display_message(
                "AWS configuration section exists but no accounts are defined. AWS Scanner will not be started.",
                MessageLevel::Info,
            );
        }
    } else {
        user_interaction_port.display_message(
            "No AWS configuration found. AWS VPC Scanner Task will not be started.",
            MessageLevel::Info,
        );
    }

    if proceed_with_aws_scanner {
        user_interaction_port.display_message("Starting AWS VPC Scanner Task.", MessageLevel::Info);
        let scanner_task = Arc::new(AwsVpcScannerTask::new(
            Arc::clone(&app_lifecycle_manager),
            Arc::clone(&aws_config_provider_adapter),
            Arc::clone(&aws_vpc_info_provider),
            std_dns_resolver_adapter.clone(),
        ));
        let scanner_handle = tokio::spawn(async move {
            scanner_task.run().await;
        });
        app_lifecycle_manager.add_task(scanner_handle).await;
    }

    // Initialize update manager if update configuration is present
    let update_config = app_lifecycle_manager
        .get_config()
        .read()
        .await
        .update
        .clone();
    if let Some(update_config) = update_config {
        if update_config.enabled {
            user_interaction_port.display_message("Starting update manager.", MessageLevel::Info);

            let http_client = reqwest::Client::new();
            let current_binary_path =
                std::env::current_exe().unwrap_or_else(|_| PathBuf::from("dnspx"));
            let backup_dir = std::env::temp_dir().join("dnspx_backups");

            let update_manager = Arc::new(VerifiedUpdateManager::new(
                update_config,
                http_client,
                current_binary_path,
                backup_dir,
            ));

            // Set the update manager in the app lifecycle manager
            let update_manager_port: Arc<dyn crate::ports::UpdateManagerPort> =
                update_manager.clone();
            app_lifecycle_manager_impl
                .set_update_manager(update_manager_port)
                .await;

            // Start background update checker task
            let update_manager_clone = Arc::clone(&update_manager);
            let app_lifecycle_clone = Arc::clone(&app_lifecycle_manager);
            let update_handle = tokio::spawn(async move {
                update_manager_clone
                    .run_background_checker(app_lifecycle_clone)
                    .await;
            });
            app_lifecycle_manager.add_task(update_handle).await;
        }
    } else {
        user_interaction_port.display_message(
            "No update configuration found. Automatic updates disabled.",
            MessageLevel::Info,
        );
    }

    let app_lifecycle_manager_clone_udp = Arc::clone(&app_lifecycle_manager);
    let dns_query_service_clone_udp: Arc<dyn DnsQueryService> = dns_request_processor.clone();
    let udp_handle = tokio::spawn(async move {
        if let Err(e) = udp_listener::run_udp_listener(
            app_lifecycle_manager_clone_udp,
            dns_query_service_clone_udp,
        )
        .await
        {
            error!("UDP listener failed: {}", e);
        }
    });
    app_lifecycle_manager.add_task(udp_handle).await;

    let app_lifecycle_manager_clone_tcp = Arc::clone(&app_lifecycle_manager);
    let dns_query_service_clone_tcp: Arc<dyn DnsQueryService> = dns_request_processor.clone();
    let tcp_handle = tokio::spawn(async move {
        if let Err(e) = tcp_listener::run_tcp_listener(
            app_lifecycle_manager_clone_tcp,
            dns_query_service_clone_tcp,
        )
        .await
        {
            error!("TCP listener failed: {}", e);
        }
    });
    app_lifecycle_manager.add_task(tcp_handle).await;

    if let Err(e) = app_lifecycle_manager.start().await {
        user_interaction_port.display_message(
            &format!("Failed to start application subsystems: {e}"),
            MessageLevel::Error,
        );
    }

    if is_tui_mode {
        info!("Starting TUI Dashboard mode...");

        let mut stdout_handle = stdout();
        enable_raw_mode()?;
        execute!(&mut stdout_handle, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout_handle);
        let mut terminal = Terminal::new(backend)?;

        let event_manager = EventManager::new();
        event_manager.start_event_listeners();

        let mut tui_app = TuiApp::new(Arc::clone(&app_lifecycle_manager), None, tui_log_rx_for_app);

        let tui_run_result = tui_app.run(&mut terminal, event_manager).await;

        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        if let Err(e) = tui_run_result {
            eprintln!("\n[CRITICAL TUI ERROR] {e}\nCheck application logs for more details.");
        }
        if !app_lifecycle_manager
            .get_cancellation_token()
            .is_cancelled()
        {
            info!("TUI exited, ensuring application shutdown via AppLifecycleManager::stop().");
            app_lifecycle_manager.stop().await;
        }
    } else {
        user_interaction_port.display_message(
            "Application started in CLI mode. Enter commands or press Ctrl+C to shut down.",
            MessageLevel::Info,
        );

        if let Some(console_cli_adapter_for_loop) = console_cli_adapter_instance_opt {
            let cli_loop_app_lifecycle = Arc::clone(&app_lifecycle_manager);
            let cli_task_handle = tokio::spawn(async move {
                console_cli_adapter_for_loop
                    .run_cli_loop(cli_loop_app_lifecycle)
                    .await;
            });

            let shutdown_token_cli = app_lifecycle_manager.get_cancellation_token();
            #[cfg(unix)]
            {
                let mut sigterm =
                    signal::unix::signal(signal::unix::SignalKind::terminate()).unwrap();
                tokio::select! {
                    _ = signal::ctrl_c() => {
                        user_interaction_port.display_message("Ctrl+C received in CLI mode. Initiating shutdown...", MessageLevel::Info);
                        app_lifecycle_manager.stop().await;
                    }
                    _ = sigterm.recv() => {
                        user_interaction_port.display_message("SIGTERM received in CLI mode. Initiating shutdown...", MessageLevel::Info);
                        app_lifecycle_manager.stop().await;
                    }
                    _ = shutdown_token_cli.cancelled() => {
                        user_interaction_port.display_message("Shutdown initiated by application logic. Waiting for tasks.", MessageLevel::Info);
                    }
                }
            }

            #[cfg(windows)]
            {
                tokio::select! {
                    _ = signal::ctrl_c() => {
                        user_interaction_port.display_message("Ctrl+C received in CLI mode. Initiating shutdown...", MessageLevel::Info);
                        app_lifecycle_manager.stop().await;
                    }
                    _ = shutdown_token_cli.cancelled() => {
                        user_interaction_port.display_message("Shutdown initiated by application logic. Waiting for tasks.", MessageLevel::Info);
                    }
                }
            }
            if let Err(e) = cli_task_handle.await {
                if !e.is_cancelled() {
                    eprintln!("[ERROR] CLI task ended with an error: {e:?}");
                }
            }
        } else {
            error!(
                "CLI mode selected, but no ConsoleCliAdapter instance available. Cannot start CLI loop."
            );
            let shutdown_token_cli = app_lifecycle_manager.get_cancellation_token();
            tokio::select! {
                _ = signal::ctrl_c() => {
                    user_interaction_port.display_message("Ctrl+C received. Initiating shutdown...", MessageLevel::Info);
                }
                _ = shutdown_token_cli.cancelled() => {
                     user_interaction_port.display_message("Shutdown initiated by other logic.", MessageLevel::Info);
                }
            }
            app_lifecycle_manager.stop().await;
        }
    }

    info!("Main function: Ensuring final AppLifecycleManager stop call and waiting for all tasks.");
    app_lifecycle_manager.stop().await;

    info!("DNS Proxy shut down.");
    Ok(())
}
