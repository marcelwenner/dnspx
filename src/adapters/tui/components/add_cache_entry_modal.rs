use crate::adapters::tui::app::{CacheAddStep, TuiApp};
use hickory_proto::rr::RecordType;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

fn centered_rect_for_modal(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

pub(crate) fn draw_add_cache_entry_modal(frame: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let modal_area = centered_rect_for_modal(70, 40, area);
    frame.render_widget(Clear, modal_area);

    let base_title = "Add Synthetic Cache Entry";
    let current_step_str = app.current_add_cache_step.as_ref().map_or_else(
        || "Unknown".to_string(),
        |s| format!("{s:?}").replace("Prompt", ""),
    );
    let title = format!("{base_title} - {current_step_str} (Esc for Back)");

    let mut content_lines: Vec<Line<'_>> = Vec::new();
    let prompt = app.get_add_cache_prompt();

    match app.current_add_cache_step {
        Some(CacheAddStep::PromptType) => {
            content_lines.push(Line::from(prompt));
            let types = [
                RecordType::A,
                RecordType::AAAA,
                RecordType::CNAME,
                RecordType::TXT,
            ];
            for (idx, rtype) in types.iter().enumerate() {
                let display_text = format!("{}. {:?}", idx + 1, rtype);
                let style = if idx == app.cache_add_type_selection_idx {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                content_lines.push(Line::from(Span::styled(display_text, style)));
            }
        }
        Some(CacheAddStep::ConfirmAdd) => {
            content_lines.push(Line::from(Span::styled(
                "Review New Cache Entry:",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            content_lines.push(Line::from(format!(
                "  Name: {}",
                app.pending_cache_add_data.name
            )));
            if let Some(rt) = app.pending_cache_add_data.record_type {
                content_lines.push(Line::from(format!("  Type: {rt:?}")));
                match rt {
                    RecordType::A => content_lines.push(Line::from(format!(
                        "  Value: {}",
                        app.pending_cache_add_data
                            .value_a
                            .map_or_else(|| "N/A".to_string(), |ip| ip.to_string())
                    ))),
                    RecordType::AAAA => content_lines.push(Line::from(format!(
                        "  Value: {}",
                        app.pending_cache_add_data
                            .value_aaaa
                            .map_or_else(|| "N/A".to_string(), |ip| ip.to_string())
                    ))),
                    RecordType::CNAME => content_lines.push(Line::from(format!(
                        "  Value: {}",
                        app.pending_cache_add_data
                            .value_cname
                            .as_deref()
                            .unwrap_or("N/A")
                    ))),
                    RecordType::TXT => content_lines.push(Line::from(format!(
                        "  Value: \"{}\"",
                        app.pending_cache_add_data
                            .value_txt
                            .as_ref()
                            .map_or_else(|| "".to_string(), |v| v.join("\", \""))
                    ))),
                    _ => {}
                }
            }
            content_lines.push(Line::from(format!(
                "  TTL: {}s",
                app.pending_cache_add_data.ttl_seconds.unwrap_or(0)
            )));
            content_lines.push(Line::from(""));
            content_lines.push(Line::from(prompt));
        }
        Some(_) => {
            content_lines.push(Line::from(prompt));
            content_lines.push(Line::from(app.current_input_with_cursor()));
        }
        None => {
            content_lines.push(Line::from("Invalid add cache step."));
        }
    }

    let paragraph = Paragraph::new(Text::from(content_lines))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default().bg(Color::DarkGray))
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, modal_area);
}

pub(crate) fn draw_confirm_delete_cache_modal(frame: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let modal_area = centered_rect_for_modal(50, 20, area);
    frame.render_widget(Clear, modal_area);

    let key_to_delete_str = if let Some(key) = &app.cache_entry_to_delete {
        format!("{} ({:?})", key.name, key.record_type)
    } else {
        "Unknown entry".to_string()
    };

    let text = vec![
        Line::from(Span::styled(
            "Confirm Deletion",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Really delete cache entry for:".to_string()),
        Line::from(Span::styled(
            key_to_delete_str,
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from("[Y]es / [N]o / [Esc]ape".to_string()),
    ];

    let paragraph = Paragraph::new(text)
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Confirm Delete")
                .border_style(Style::default().fg(Color::Red)),
        )
        .style(Style::default().bg(Color::DarkGray));

    frame.render_widget(paragraph, modal_area);
}
