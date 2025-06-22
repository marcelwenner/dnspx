use crate::core::error::{CliError, UserInputError};
use crate::core::types::{AppStatus, CliCommand, CliOutput, MessageLevel, UpdateResult};
use crate::ports::{AppLifecycleManagerPort, InteractiveCliPort, UserInteractionPort};
use async_trait::async_trait;
use colored::*;
use std::io::Write;
use std::sync::Arc;

pub(crate) struct ConsoleCliAdapter {
    colors_enabled: bool,
}

impl ConsoleCliAdapter {
    pub(crate) fn new(colors_enabled: bool) -> Self {
        Self { colors_enabled }
    }

    fn colorize(&self, text: &str, color: Color) -> ColoredString {
        if self.colors_enabled {
            text.color(color)
        } else {
            text.normal()
        }
    }

    fn display_general_help(&self) {
        println!(
            "{}",
            self.colorize("Available Commands:", Color::Green).bold()
        );
        println!();

        let commands = [
            ("help, h", "Show this help message"),
            ("status, s", "Show application status"),
            ("reload, r", "Reload configuration"),
            ("scan", "Trigger AWS resource scan"),
            ("aws scan", "Trigger AWS resource scan"),
            ("config", "Show current configuration"),
            ("update", "Show update help"),
            ("exit, quit, q", "Exit the application"),
        ];

        for (cmd, desc) in commands {
            println!("  {:<15} {}", self.colorize(cmd, Color::Yellow), desc);
        }

        println!();
        println!(
            "For update commands, type: {}",
            self.colorize("update help", Color::Cyan)
        );
    }

    fn display_update_help(&self) {
        println!("{}", self.colorize("Usage:", Color::Green).bold());
        println!("  update <subcommand>");
        println!();
        println!("{}", self.colorize("Subcommands:", Color::Green).bold());

        let subcommands = [
            ("check", "Check for new updates"),
            (
                "install",
                "Download and install the latest available update",
            ),
            (
                "status",
                "Show the current version and update configuration",
            ),
            ("rollback", "Revert to the previously installed version"),
            ("help", "Show this help message"),
        ];

        for (cmd, desc) in subcommands {
            println!("  {:<15} {}", self.colorize(cmd, Color::Yellow), desc);
        }
    }

    pub(crate) async fn run_cli_loop(
        self: Arc<Self>,
        app_lifecycle: Arc<dyn AppLifecycleManagerPort>,
    ) {
        let mut line_reader = tokio::io::BufReader::new(tokio::io::stdin());
        let mut line_buf = String::new();

        let cancellation_token = app_lifecycle.get_cancellation_token();

        let is_tty = atty::is(atty::Stream::Stdin);

        if !is_tty {
            cancellation_token.cancelled().await;
            println!("CLI loop shutting down due to application stop.");
            return;
        }

        loop {
            self.display_prompt("dnspx> ");
            line_buf.clear();

            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    println!("\nCLI loop shutting down due to application stop.");
                    break;
                }
                read_result = tokio::io::AsyncBufReadExt::read_line(&mut line_reader, &mut line_buf) => {
                    if read_result.is_err() {
                        self.display_message("Failed to read CLI input. Exiting CLI loop.", MessageLevel::Error);
                        break;
                    }
                }
            }

            let command_str = line_buf.trim();
            let cli_command = match command_str {
                "status" | "s" => CliCommand::Status,
                "reload" | "r" => CliCommand::ReloadConfig,
                "scan" | "aws scan" => CliCommand::TriggerAwsScan,
                "config" => CliCommand::GetConfig(None),
                "update check" => CliCommand::UpdateCheck,
                "update install" => CliCommand::UpdateInstall,
                "update status" => CliCommand::UpdateStatus,
                "update rollback" => CliCommand::UpdateRollback,
                "update help" | "update" => CliCommand::UpdateHelp,
                "help" | "h" => CliCommand::Help,
                "exit" | "quit" | "q" => CliCommand::Exit,
                "" => continue,
                _ => {
                    self.display_message(
                        &format!("Unknown command: '{command_str}'. Type 'help' for commands."),
                        MessageLevel::Warning,
                    );
                    continue;
                }
            };

            match self
                .handle_cli_command(cli_command, Arc::clone(&app_lifecycle))
                .await
            {
                Ok(output) => self.display_cli_output(output).await,
                Err(e) => self.display_error(&e),
            }

            if command_str == "exit" || command_str == "quit" || command_str == "q" {
                break;
            }
        }
    }

    async fn display_cli_output(&self, output: CliOutput) {
        match output {
            CliOutput::Message(msg) => self.display_message(&msg, MessageLevel::Info),
            CliOutput::Table(data) => {
                if let Some(headers) = data.first() {
                    self.display_table(headers.clone(), data.iter().skip(1).cloned().collect());
                } else if !data.is_empty() {
                    self.display_table(vec!["Value".to_string()], data);
                }
            }
            CliOutput::Json(val) => {
                if let Ok(pretty_json) = serde_json::to_string_pretty(&val) {
                    println!("{pretty_json}");
                } else {
                    println!("{val:?}");
                }
            }
            CliOutput::Status(status) => self.display_status(&status),
            CliOutput::Config(config_arc) => {
                let config = config_arc.read().await;
                if let Ok(pretty_json) = serde_json::to_string_pretty(&*config) {
                    println!("{pretty_json}");
                } else {
                    println!("{config:?}");
                }
            }
            CliOutput::None => {}
        }
    }
}

#[async_trait]
impl UserInteractionPort for ConsoleCliAdapter {
    async fn prompt_for_mfa_token(
        &self,
        user_identity: &str,
        attempt: u32,
    ) -> Result<String, UserInputError> {
        print!(
            "[Attempt {}] Enter MFA token for {}: ",
            self.colorize(&attempt.to_string(), Color::Yellow),
            self.colorize(user_identity, Color::Green)
        );
        std::io::stdout().flush().unwrap_or_default();

        let token = tokio::task::spawn_blocking(|| {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            Ok::<String, std::io::Error>(input)
        })
        .await
        .map_err(|e| UserInputError::ReadError(std::io::Error::other(e)))?
        .map_err(UserInputError::ReadError)?;

        let token = token.trim().to_string();
        if token.is_empty() {
            Err(UserInputError::CancelledOrEmpty)
        } else {
            Ok(token)
        }
    }

    async fn prompt_for_aws_keys(
        &self,
        account_label: &str,
    ) -> Result<(String, String), UserInputError> {
        println!(
            "Enter Access Key ID for {}: ",
            self.colorize(account_label, Color::Green)
        );
        std::io::stdout().flush().unwrap_or_default();

        let access_key = tokio::task::spawn_blocking(|| {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            Ok::<String, std::io::Error>(input)
        })
        .await
        .map_err(|e| UserInputError::ReadError(std::io::Error::other(e)))?
        .map_err(UserInputError::ReadError)?;

        println!(
            "Enter Secret Access Key for {}: ",
            self.colorize(account_label, Color::Green)
        );
        std::io::stdout().flush().unwrap_or_default();

        let secret_key = tokio::task::spawn_blocking(|| {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            Ok::<String, std::io::Error>(input)
        })
        .await
        .map_err(|e| UserInputError::ReadError(std::io::Error::other(e)))?
        .map_err(UserInputError::ReadError)?;

        let access_key = access_key.trim().to_string();
        let secret_key = secret_key.trim().to_string();

        if access_key.is_empty() || secret_key.is_empty() {
            Err(UserInputError::CancelledOrEmpty)
        } else {
            Ok((access_key, secret_key))
        }
    }

    fn display_message(&self, message: &str, level: MessageLevel) {
        let level_str = format!("[{:<7}]", format!("{level:?}").to_uppercase());
        match level {
            MessageLevel::Error => {
                eprintln!("{} {}", self.colorize(&level_str, Color::Red), message)
            }
            MessageLevel::Warning => {
                println!("{} {}", self.colorize(&level_str, Color::Yellow), message)
            }
            MessageLevel::Info => {
                println!("{} {}", self.colorize(&level_str, Color::Cyan), message)
            }
            MessageLevel::Debug => {
                println!("{} {}", self.colorize(&level_str, Color::Blue), message)
            }
            MessageLevel::Trace => {
                println!("{} {}", self.colorize(&level_str, Color::Magenta), message)
            }
        }
    }

    fn display_status(&self, status_info: &AppStatus) {
        println!(
            "{}",
            self.colorize("Application Status:", Color::Green).bold()
        );
        println!("  Uptime: {} seconds", status_info.uptime_seconds);
        println!(
            "  Active Config Hash: {}",
            self.colorize(&status_info.active_config_hash, Color::Yellow)
        );

        println!("{}", self.colorize("\n  Listeners:", Color::Cyan));
        if status_info.active_listeners.is_empty() {
            println!("    No active listeners.");
        } else {
            for listener in &status_info.active_listeners {
                println!("    - {listener}");
            }
        }

        println!(
            "{}",
            self.colorize("\n  Configuration Status:", Color::Cyan)
        );
        println!(
            "    Valid: {}",
            if status_info.config_status.is_valid {
                self.colorize("Yes", Color::Green)
            } else {
                self.colorize("No", Color::Red)
            }
        );
        if let Some(path) = &status_info.config_status.source_file_path {
            println!("    Source: {path}");
        }
        if let Some(time) = status_info.config_status.last_loaded_time {
            println!("    Last Loaded: {}", time.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        if let Some(err) = &status_info.config_status.error_message {
            println!("    Error: {}", self.colorize(err, Color::Red));
        }

        if let Some(cache_stats) = &status_info.cache_stats {
            println!("{}", self.colorize("\n  DNS Cache Stats:", Color::Cyan));
            println!("    Size: {} entries", cache_stats.size);
            println!("    Hits: {}", cache_stats.hits);
            println!("    Misses: {}", cache_stats.misses);

            println!(
                "    Memory (est.): {} bytes",
                cache_stats.estimated_memory_usage_bytes
            );
        }

        if let Some(aws_status) = &status_info.aws_scanner_status {
            println!("{}", self.colorize("\n  AWS Scanner Status:", Color::Cyan));
            println!(
                "    Scanning: {}",
                if aws_status.is_scanning {
                    self.colorize("Yes", Color::Yellow)
                } else {
                    self.colorize("No", Color::Green)
                }
            );
            if let Some(time) = aws_status.last_scan_time {
                println!("    Last Scan: {}", time.format("%Y-%m-%d %H:%M:%S UTC"));
            } else {
                println!("    Last Scan: Never");
            }
            println!(
                "    Discovered Entries: {}",
                aws_status.discovered_entries_count
            );
            println!("    Accounts Scanned: {}", aws_status.accounts_scanned);
            println!(
                "    Accounts Failed: {}",
                if aws_status.accounts_failed > 0 {
                    self.colorize(&aws_status.accounts_failed.to_string(), Color::Red)
                } else {
                    self.colorize("0", Color::Green)
                }
            );
            if let Some(err) = &aws_status.error_message {
                println!("    Last Error: {}", self.colorize(err, Color::Red));
            }
        } else {
            println!("{}", self.colorize("\n  AWS Scanner Status:", Color::Cyan));
            println!("    AWS integration not configured or enabled.");
        }
        println!();
    }

    fn display_error(&self, error: &dyn std::error::Error) {
        eprintln!("{} {}", self.colorize("[ERROR]", Color::Red).bold(), error);
        let mut source = error.source();
        while let Some(src) = source {
            eprintln!("  Caused by: {src}");
            source = src.source();
        }
    }
    fn display_table(&self, headers: Vec<String>, rows: Vec<Vec<String>>) {
        if headers.is_empty() && rows.is_empty() {
            return;
        }

        let mut column_widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
        for row in &rows {
            for (i, cell) in row.iter().enumerate() {
                if i < column_widths.len() {
                    column_widths[i] = column_widths[i].max(cell.len());
                } else {
                    column_widths.push(cell.len());
                }
            }
        }

        if !headers.is_empty() {
            for (i, header) in headers.iter().enumerate() {
                print!(
                    "| {:<width$} ",
                    self.colorize(header, Color::Yellow).bold(),
                    width = column_widths[i]
                );
            }
            println!("|");
            for width in &column_widths {
                print!("+-");
                for _ in 0..*width {
                    print!("-");
                }
                print!("-");
            }
            println!("+");
        }

        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                print!(
                    "| {:<width$} ",
                    cell,
                    width = column_widths.get(i).copied().unwrap_or(cell.len())
                );
            }
            println!("|");
        }
    }
    fn display_prompt(&self, prompt_text: &str) {
        if self.colors_enabled {
            print!("{}", prompt_text.cyan().bold());
        } else {
            print!("{prompt_text}");
        }
        std::io::stdout().flush().unwrap_or_default();
    }
}

#[async_trait]
impl InteractiveCliPort for ConsoleCliAdapter {
    async fn handle_cli_command(
        &self,
        command: CliCommand,
        app_lifecycle: Arc<dyn AppLifecycleManagerPort>,
    ) -> Result<CliOutput, CliError> {
        match command {
            CliCommand::Status => {
                let status = app_lifecycle.get_app_status().await;
                Ok(CliOutput::Status(Box::new(status)))
            }
            CliCommand::ReloadConfig => {
                app_lifecycle.trigger_config_reload().await?;
                Ok(CliOutput::Message(
                    "Configuration reload relies on file watcher. Save config file to trigger."
                        .to_string(),
                ))
            }
            CliCommand::TriggerAwsScan => {
                app_lifecycle.trigger_aws_scan_refresh().await?;

                Ok(CliOutput::None)
            }
            CliCommand::GetConfig(_path) => {
                let config = app_lifecycle.get_config();
                Ok(CliOutput::Config(config))
            }
            CliCommand::UpdateCheck => {
                if let Some(update_manager) = app_lifecycle.get_update_manager() {
                    match update_manager.check_for_updates().await {
                        Ok(UpdateResult::UpdateAvailable(update_info)) => {
                            let mut message = format!(
                                "Update available: v{} -> v{}\n",
                                update_manager.get_current_version(),
                                update_info.version
                            );
                            if update_info.breaking_changes {
                                message.push_str("⚠️  This update contains breaking changes.\n");
                            }
                            if let Some(release_notes) = &update_info.release_notes {
                                message.push_str(&format!("\nRelease Notes:\n{}", release_notes));
                            }
                            message.push_str("\nUse 'update install' to install this update.");
                            Ok(CliOutput::Message(message))
                        }
                        Ok(UpdateResult::UpToDate) => Ok(CliOutput::Message(format!(
                            "Already up to date: v{}",
                            update_manager.get_current_version()
                        ))),
                        Err(e) => Err(CliError::UpdateFailed(format!(
                            "Update check failed: {}",
                            e
                        ))),
                        _ => Ok(CliOutput::Message("Unexpected update result".to_string())),
                    }
                } else {
                    Ok(CliOutput::Message(
                        "Update manager not available. Check your configuration.".to_string(),
                    ))
                }
            }
            CliCommand::UpdateInstall => {
                if let Some(update_manager) = app_lifecycle.get_update_manager() {
                    match update_manager.check_for_updates().await {
                        Ok(UpdateResult::UpdateAvailable(update_info)) => {
                            match update_manager.install_update(&update_info).await {
                                Ok(UpdateResult::UpdateInstalled {
                                    from_version,
                                    to_version,
                                }) => Ok(CliOutput::Message(format!(
                                    "Successfully updated from v{} to v{}. Restart required.",
                                    from_version, to_version
                                ))),
                                Ok(UpdateResult::UpdateFailed {
                                    error,
                                    rollback_performed,
                                }) => Ok(CliOutput::Message(format!(
                                    "Update failed: {}. Rollback performed: {}",
                                    error, rollback_performed
                                ))),
                                Err(e) => Err(CliError::UpdateFailed(format!(
                                    "Installation failed: {}",
                                    e
                                ))),
                                _ => Ok(CliOutput::Message(
                                    "Unexpected installation result".to_string(),
                                )),
                            }
                        }
                        Ok(UpdateResult::UpToDate) => Ok(CliOutput::Message(
                            "Already up to date. No installation needed.".to_string(),
                        )),
                        Err(e) => Err(CliError::UpdateFailed(format!(
                            "Update check failed: {}",
                            e
                        ))),
                        _ => Ok(CliOutput::Message(
                            "Unexpected update check result".to_string(),
                        )),
                    }
                } else {
                    Ok(CliOutput::Message(
                        "Update manager not available. Check your configuration.".to_string(),
                    ))
                }
            }
            CliCommand::UpdateStatus => {
                if let Some(update_manager) = app_lifecycle.get_update_manager() {
                    let current_version = update_manager.get_current_version();
                    let rollback_available = update_manager.is_rollback_available().await;

                    let config_arc = app_lifecycle.get_config();
                    let config = config_arc.read().await;
                    let auto_update_enabled = config
                        .update
                        .as_ref()
                        .map(|u| {
                            u.auto_update_policy.update_level
                                != crate::config::models::UpdateLevel::None
                        })
                        .unwrap_or(false);
                    let check_interval = config
                        .update
                        .as_ref()
                        .map(|u| format!("{:?}", u.check_interval))
                        .unwrap_or_else(|| "N/A".to_string());

                    let status_message = format!(
                        "Update Status:\n  Current Version: v{}\n  Auto-update: {}\n  Check Interval: {}\n  Rollback Available: {}",
                        current_version,
                        if auto_update_enabled {
                            "Enabled"
                        } else {
                            "Disabled"
                        },
                        check_interval,
                        if rollback_available { "Yes" } else { "No" }
                    );
                    Ok(CliOutput::Message(status_message))
                } else {
                    Ok(CliOutput::Message(
                        "Update manager not available. Check your configuration.".to_string(),
                    ))
                }
            }
            CliCommand::UpdateRollback => {
                if let Some(update_manager) = app_lifecycle.get_update_manager() {
                    match update_manager.rollback_update().await {
                        Ok(UpdateResult::UpdateInstalled {
                            from_version,
                            to_version,
                        }) => Ok(CliOutput::Message(format!(
                            "Successfully rolled back from v{} to v{}. Restart required.",
                            from_version, to_version
                        ))),
                        Err(e) => Err(CliError::UpdateFailed(format!("Rollback failed: {}", e))),
                        _ => Ok(CliOutput::Message("Unexpected rollback result".to_string())),
                    }
                } else {
                    Ok(CliOutput::Message(
                        "Update manager not available. Check your configuration.".to_string(),
                    ))
                }
            }
            CliCommand::Help => {
                self.display_general_help();
                Ok(CliOutput::None)
            }
            CliCommand::UpdateHelp => {
                self.display_update_help();
                Ok(CliOutput::None)
            }
            CliCommand::Exit => Ok(CliOutput::Message("Initiating shutdown...".to_string())),
        }
    }
}
