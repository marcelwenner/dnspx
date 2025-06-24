use crate::adapters::tui::app::{StatusPanelView, TuiApp};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub(crate) fn draw_status_panel(frame: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    match app.current_status_panel_view {
        StatusPanelView::AwsScanner => {
            draw_aws_scanner_view(frame, app, area);
        }
        StatusPanelView::Dashboard => {
            draw_dashboard_view(frame, app, area);
        }
    }
}

fn draw_more_indicator_if_needed(
    frame: &mut Frame<'_>,
    content_area: Rect,
    actual_lines_generated: usize,
    available_height_for_content: u16,
) {
    if actual_lines_generated > available_height_for_content as usize {
        let indicator_text = " [...more...] ";
        let indicator_width = indicator_text.len() as u16;
        if content_area.height > 0 {
            let indicator_area = Rect {
                x: content_area.x + (content_area.width.saturating_sub(indicator_width)) / 2,
                y: content_area.y + content_area.height - 1,
                width: indicator_width.min(content_area.width),
                height: 1,
            };
            frame.render_widget(
                Paragraph::new(Span::styled(
                    indicator_text,
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                )),
                indicator_area,
            );
        }
    }
}

fn draw_dashboard_view(frame: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let mut lines = Vec::new();

    let status_str = if app.app_lifecycle.get_cancellation_token().is_cancelled() || app.should_quit
    {
        Span::styled(
            "Shutting Down",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "Running",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    };
    lines.push(Line::from(vec![Span::raw("🚀 Status: "), status_str]));

    if let Some(status) = &app.status_cache {
        lines.push(Line::from(vec![
            Span::raw("📊 Uptime: "),
            Span::styled(
                format!("{}s", status.uptime_seconds),
                Style::default().fg(Color::LightBlue),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::raw("🌐 Queries: "),
            Span::styled(
                app.total_queries_for_ui.to_string(),
                Style::default().fg(Color::LightCyan),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::raw("📈 QPS: "),
            Span::styled(
                format!("{:.2}", app.current_qps),
                Style::default().fg(Color::LightCyan),
            ),
        ]));
        if let Some(cache_stats) = &status.cache_stats {
            let hit_rate = if (cache_stats.hits + cache_stats.misses) > 0 {
                (cache_stats.hits as f64 / (cache_stats.hits + cache_stats.misses) as f64) * 100.0
            } else {
                0.0
            };
            lines.push(Line::from(vec![
                Span::raw("⚡ Cache: "),
                Span::styled(
                    format!("{} entries", cache_stats.size),
                    Style::default().fg(Color::Green),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::raw("🎯 Hit Rate: "),
                Span::styled(format!("{hit_rate:.1}%"), Style::default().fg(Color::Green)),
            ]));
        }
        lines.push(Line::from(vec![
            Span::raw("📜 Config Hash: "),
            Span::styled(
                status
                    .active_config_hash
                    .chars()
                    .take(12)
                    .collect::<String>(),
                Style::default().fg(Color::Magenta),
            ),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Listeners:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        if status.active_listeners.is_empty() {
            lines.push(Line::from("  None"));
        } else {
            for listener in &status.active_listeners {
                lines.push(Line::from(format!("  - {listener}")));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Config Status:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        let config_valid_style = if status.config_status.is_valid {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::Red)
        };
        lines.push(Line::from(vec![
            Span::raw("  Valid: "),
            Span::styled(
                if status.config_status.is_valid {
                    "Yes"
                } else {
                    "No"
                },
                config_valid_style,
            ),
        ]));
        if let Some(time) = status.config_status.last_loaded_time {
            lines.push(Line::from(format!(
                "  Loaded: {}",
                time.with_timezone(&chrono::Local).format("%H:%M:%S")
            )));
        }
        if let Some(err) = &status.config_status.error_message {
            lines.push(Line::from(Span::styled(
                format!(
                    "  Error: {}",
                    if err.len() > 30 {
                        format!("{}...", &err[..27])
                    } else {
                        err.clone()
                    }
                ),
                Style::default().fg(Color::Red),
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "AWS Scanner:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        let aws_summary_span = if let Some(aws_status) = &status.aws_scanner_status {
            if aws_status.is_scanning {
                Span::styled(
                    "SCANNING",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
            } else if aws_status.error_message.is_some() || aws_status.accounts_failed > 0 {
                Span::styled(
                    "ERROR",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )
            } else if aws_status.last_scan_time.is_some() && aws_status.accounts_scanned > 0 {
                Span::styled(
                    "ON",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("IDLE", Style::default().fg(Color::DarkGray))
            }
        } else {
            Span::styled(
                "OFF (Not Configured)",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
        };
        lines.push(Line::from(vec![Span::raw("  State: "), aws_summary_span]));

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Auto-Update:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));

        if let Some(update_status) = &status.update_status {
            let update_summary_span = if update_status.installing_update {
                Span::styled(
                    "INSTALLING",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
            } else if update_status.checking_for_updates {
                Span::styled(
                    "CHECKING",
                    Style::default()
                        .fg(Color::LightBlue)
                        .add_modifier(Modifier::BOLD),
                )
            } else if update_status.update_available {
                Span::styled(
                    "UPDATE AVAILABLE",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
            } else if update_status.last_error.is_some() {
                Span::styled(
                    "ERROR",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("UP TO DATE", Style::default().fg(Color::Green))
            };
            lines.push(Line::from(vec![
                Span::raw("  Status: "),
                update_summary_span,
            ]));

            lines.push(Line::from(vec![
                Span::raw("  Version: "),
                Span::styled(
                    format!("v{}", update_status.current_version),
                    Style::default().fg(Color::LightBlue),
                ),
            ]));

            if let Some(latest) = &update_status.latest_version {
                lines.push(Line::from(vec![
                    Span::raw("  Latest: "),
                    Span::styled(
                        format!("v{}", latest),
                        Style::default().fg(Color::LightGreen),
                    ),
                ]));
            }
        } else {
            lines.push(Line::from(vec![
                Span::raw("  Status: "),
                Span::styled(
                    "DISABLED",
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        }
    } else {
        lines.push(Line::from("Loading status..."));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title("📊 DNSPX Dashboard (Ctrl+A: AWS View)");

    let content_area = block.inner(area);
    let available_height_for_content = content_area.height;

    let paragraph = Paragraph::new(lines.clone())
        .block(block)
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);

    draw_more_indicator_if_needed(
        frame,
        content_area,
        lines.len(),
        available_height_for_content,
    );
}

fn draw_aws_scanner_view(frame: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let mut lines = Vec::new();

    if let Some(status) = &app.status_cache {
        if let Some(aws_status) = &status.aws_scanner_status {
            let scanning_style = if aws_status.is_scanning {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Green)
            };
            lines.push(Line::from(vec![
                Span::styled(
                    "Status: ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    if aws_status.is_scanning {
                        "🔄 SCANNING"
                    } else {
                        "✅ IDLE"
                    },
                    scanning_style,
                ),
            ]));
            lines.push(Line::from(""));
            if let Some(time) = aws_status.last_scan_time {
                lines.push(Line::from(vec![
                    Span::raw("🕐 Last Scan: "),
                    Span::styled(
                        time.with_timezone(&chrono::Local)
                            .format("%m-%d %H:%M:%S")
                            .to_string(),
                        Style::default().fg(Color::LightBlue),
                    ),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::raw("🕐 Last Scan: "),
                    Span::styled("Never", Style::default().fg(Color::Gray)),
                ]));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Discovery Statistics:",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(vec![
                Span::raw("  📦 Total Entries: "),
                Span::styled(
                    aws_status.discovered_entries_count.to_string(),
                    Style::default()
                        .fg(Color::LightGreen)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::raw("  🏢 Accounts Scanned: "),
                Span::styled(
                    aws_status.accounts_scanned.to_string(),
                    Style::default().fg(Color::Cyan),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::raw("  ❌ Accounts Failed: "),
                Span::styled(
                    aws_status.accounts_failed.to_string(),
                    if aws_status.accounts_failed > 0 {
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Green)
                    },
                ),
            ]));
            let total_accounts_attempted = aws_status.accounts_scanned + aws_status.accounts_failed;
            let successful_scans = if total_accounts_attempted > 0
                && aws_status.accounts_failed == total_accounts_attempted
            {
                0
            } else {
                aws_status.accounts_scanned
            };
            if total_accounts_attempted > 0 {
                let success_rate =
                    (successful_scans as f64 / total_accounts_attempted as f64) * 100.0;
                lines.push(Line::from(vec![
                    Span::raw("  📈 Success Rate: "),
                    Span::styled(
                        format!("{success_rate:.1}%"),
                        if success_rate >= 90.0 {
                            Style::default()
                                .fg(Color::Green)
                                .add_modifier(Modifier::BOLD)
                        } else if success_rate >= 70.0 {
                            Style::default().fg(Color::Yellow)
                        } else {
                            Style::default().fg(Color::Red)
                        },
                    ),
                ]));
            }
            lines.push(Line::from(""));
            if aws_status.is_scanning {
                lines.push(Line::from(Span::styled(
                    "  🔄 Currently scanning accounts...",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(""));
            }
            if let Some(err) = &aws_status.error_message {
                lines.push(Line::from(Span::styled(
                    "Latest General Error:",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));
                let max_width = (area.width as usize).saturating_sub(6).max(10);
                let words: Vec<&str> = err.split_whitespace().collect();
                let mut current_line = "    ".to_string();
                for word in words {
                    if current_line.len() + word.len() + 1 > max_width
                        && current_line.trim_start() != ""
                    {
                        lines.push(Line::from(Span::styled(
                            current_line.clone(),
                            Style::default().fg(Color::Red),
                        )));
                        current_line = "    ".to_string();
                    }
                    if current_line.trim_start() != "" {
                        current_line.push(' ');
                    }
                    current_line.push_str(word);
                }
                if current_line.trim_start() != "" {
                    lines.push(Line::from(Span::styled(
                        current_line,
                        Style::default().fg(Color::Red),
                    )));
                }
                lines.push(Line::from(""));
            }
            if !aws_status.detailed_errors.is_empty() {
                lines.push(Line::from(Span::styled(
                    "Detailed Errors:",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));
                for detail_err in &aws_status.detailed_errors {
                    lines.push(Line::from(Span::styled(
                        format!("  - Acc/Role: {}", detail_err.label_or_arn),
                        Style::default().fg(Color::LightRed),
                    )));
                    if let Some(region) = &detail_err.region {
                        lines.push(Line::from(Span::styled(
                            format!("    Region: {region}"),
                            Style::default().fg(Color::LightRed),
                        )));
                    }

                    let max_err_width = (area.width as usize).saturating_sub(10).max(10);
                    let err_words: Vec<&str> = detail_err.error.split_whitespace().collect();
                    let mut current_err_line = "      Error: ".to_string();
                    for word in err_words {
                        if current_err_line.len() + word.len() + 1 > max_err_width
                            && current_err_line.trim_start() != "Error:"
                        {
                            lines.push(Line::from(Span::styled(
                                current_err_line.clone(),
                                Style::default().fg(Color::LightRed),
                            )));
                            current_err_line = "             ".to_string();
                        }
                        if current_err_line.trim_start() != "Error:"
                            && current_err_line.trim_start() != ""
                        {
                            current_err_line.push(' ');
                        }
                        current_err_line.push_str(word);
                    }
                    if (current_err_line.trim_start() != "Error:"
                        && current_err_line.trim_start() != "")
                        || (detail_err.error.is_empty()
                            && current_err_line.trim_start() == "Error:")
                    {
                        lines.push(Line::from(Span::styled(
                            current_err_line,
                            Style::default().fg(Color::LightRed),
                        )));
                    }
                }
            } else if aws_status.accounts_failed == 0
                && total_accounts_attempted > 0
                && aws_status.error_message.is_none()
            {
                lines.push(Line::from(Span::styled(
                    "✅ No errors in last scan",
                    Style::default().fg(Color::Green),
                )));
            }
        } else {
            lines.push(Line::from(Span::styled(
                "AWS Scanner Not Configured",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from("AWS resource discovery is not configured."));
        }
    } else {
        lines.push(Line::from("Loading AWS scanner status..."));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title("☁️  AWS Scanner (Ctrl+A: Dashboard View)");

    let content_area = block.inner(area);
    let available_height_for_content = content_area.height;

    let paragraph = Paragraph::new(lines.clone())
        .block(block)
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);

    draw_more_indicator_if_needed(
        frame,
        content_area,
        lines.len(),
        available_height_for_content,
    );
}
