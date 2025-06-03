use crate::adapters::tui::app::TuiApp;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

fn draw_more_indicator_if_needed(
    frame: &mut Frame,
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

pub fn draw_hotkey_panel(frame: &mut Frame, _app: &TuiApp, area: Rect) {
    let hotkeys_content = vec![
        Line::from(vec![
            Span::styled("h, ?", Style::default().fg(Color::Yellow)),
            Span::raw(": Help"),
        ]),
        Line::from(vec![
            Span::styled("Ctrl+Q/X/C", Style::default().fg(Color::Yellow)),
            Span::raw(": Quit"),
        ]),
        Line::from(vec![
            Span::styled("Ctrl+R", Style::default().fg(Color::Yellow)),
            Span::raw(": AWS Profile Setup"),
        ]),
        Line::from(vec![
            Span::styled("r", Style::default().fg(Color::Yellow)),
            Span::raw(": Reload Config"),
        ]),
        Line::from(vec![
            Span::styled("Ctrl+V", Style::default().fg(Color::Yellow)),
            Span::raw(": Cache Viewer"),
        ]),
        Line::from(vec![
            Span::styled("c (Cache)", Style::default().fg(Color::Yellow)),
            Span::raw(": Clear Cache"),
        ]),
        Line::from(vec![
            Span::styled("s", Style::default().fg(Color::Yellow)),
            Span::raw(": Refresh Status"),
        ]),
        Line::from(vec![
            Span::styled("d", Style::default().fg(Color::Yellow)),
            Span::raw(": Cycle Log Filter"),
        ]),
        Line::from(vec![
            Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
            Span::raw(": Scroll Active Panel"),
        ]),
        Line::from(vec![
            Span::styled("PgUp/PgDn", Style::default().fg(Color::Yellow)),
            Span::raw(": Page Scroll"),
        ]),
        Line::from(vec![
            Span::styled("Home/End", Style::default().fg(Color::Yellow)),
            Span::raw(": Scroll Top/Bottom"),
        ]),
        Line::from(vec![
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::raw(": Close Popup/Input/Back"),
        ]),
    ];

    let block = Block::default().borders(Borders::ALL).title("Hotkeys");
    let content_area = block.inner(area);
    let available_height_for_content = content_area.height;

    let actual_lines_generated = hotkeys_content.len();

    let paragraph = Paragraph::new(hotkeys_content.clone())
        .block(block)
        .style(Style::default());

    frame.render_widget(paragraph, area);

    draw_more_indicator_if_needed(
        frame,
        content_area,
        actual_lines_generated,
        available_height_for_content,
    );
}
