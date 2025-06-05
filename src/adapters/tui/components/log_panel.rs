use crate::adapters::tui::app::TuiApp;
use crate::core::types::MessageLevel;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
};

pub(crate) fn draw_log_panel(frame: &mut Frame<'_>, app: &mut TuiApp, area: Rect) {
    let content_area_height = area.height.saturating_sub(2);
    app.log_panel_actual_height = content_area_height.max(1);

    let filtered_logs_lines: Vec<Line<'_>> = app
        .log_buffer
        .iter()
        .filter(|(_, level)| app.tui_log_filter_level.matches(level))
        .map(|(msg, level)| {
            let style = match level {
                MessageLevel::Error => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                MessageLevel::Warning => Style::default().fg(Color::Yellow),
                MessageLevel::Info => Style::default().fg(Color::White),
                MessageLevel::Debug => Style::default().fg(Color::Gray),
                MessageLevel::Trace => Style::default().fg(Color::DarkGray),
            };
            Line::from(Span::styled(msg.clone(), style))
        })
        .collect();

    let total_content_lines = filtered_logs_lines.len();
    let visible_viewport_height = app.log_panel_actual_height as usize;

    let max_possible_scroll_offset = total_content_lines.saturating_sub(visible_viewport_height);

    app.log_scroll_offset = (app.log_scroll_offset as usize).min(max_possible_scroll_offset) as u16;

    let title = format!(
        "Logs (Filter: {:?}, Follow: {}, Scroll: {}/{}, Count: {}, ViewHeight: {})",
        app.tui_log_filter_level,
        if app.log_follow_mode { "On" } else { "Off" },
        app.log_scroll_offset,
        max_possible_scroll_offset,
        total_content_lines,
        visible_viewport_height
    );

    let log_block = Block::default().borders(Borders::ALL).title(title);

    let paragraph = Paragraph::new(Text::from(filtered_logs_lines))
        .block(log_block.clone())
        .wrap(Wrap { trim: false })
        .scroll((app.log_scroll_offset, 0));

    frame.render_widget(paragraph, area);

    if total_content_lines > visible_viewport_height {
        let scrollbar_area = log_block.inner(area);
        let scrollbar_x = scrollbar_area.right().saturating_sub(1);
        let track_height = scrollbar_area.height as f64;

        let content_ratio = visible_viewport_height as f64 / total_content_lines as f64;
        let thumb_size = (track_height * content_ratio).max(1.0).round() as u16;

        let scroll_ratio = if max_possible_scroll_offset > 0 {
            app.log_scroll_offset as f64 / max_possible_scroll_offset as f64
        } else {
            0.0
        };

        let available_thumb_travel = track_height - thumb_size as f64;
        let thumb_position = (scroll_ratio * available_thumb_travel).round() as u16;

        for y in 0..scrollbar_area.height {
            let cell_y = scrollbar_area.y + y;
            let is_thumb = y >= thumb_position && y < thumb_position + thumb_size;

            let (symbol, style) = if is_thumb {
                ("█", Style::default().fg(Color::White))
            } else {
                ("│", Style::default().fg(Color::DarkGray))
            };

            if scrollbar_x < area.right() && cell_y < area.bottom() {
                frame
                    .buffer_mut()
                    .set_string(scrollbar_x, cell_y, symbol, style);
            }
        }
    }
}
