use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Text},
    widgets::{Block, Borders, Clear, Paragraph},
};

pub fn draw_popup(
    frame: &mut Frame,
    title: &str,
    content_lines_ratatui: &[Line<'static>],
    screen_area: Rect,
    percent_x: u16,
    percent_y: u16,
    scroll_offset: u16,
    content_area_height: &mut u16,
) {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(screen_area);

    let area = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1];

    let popup_block = Block::default()
        .title(title.bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let inner_content_rect = popup_block.inner(area);
    *content_area_height = inner_content_rect.height;

    let total_text_lines = content_lines_ratatui.len();
    let visible_viewport_height = *content_area_height as usize;

    let clamped_scroll_offset =
        safe_scroll_clamp(scroll_offset, total_text_lines, visible_viewport_height);

    let text_object = Text::from(content_lines_ratatui.to_vec());
    let paragraph = Paragraph::new(text_object.clone())
        .block(popup_block)
        .style(Style::default().bg(Color::DarkGray))
        .scroll((clamped_scroll_offset, 0));

    frame.render_widget(Clear, area);
    frame.render_widget(paragraph, area);

    if total_text_lines > visible_viewport_height && visible_viewport_height > 0 {
        let scrollbar_area_for_popup = inner_content_rect;
        let scrollbar_x = scrollbar_area_for_popup.right().saturating_sub(1);
        let track_height = scrollbar_area_for_popup.height as f64;

        let content_ratio = visible_viewport_height as f64 / total_text_lines.max(1) as f64;
        let thumb_size = (track_height * content_ratio).max(1.0).round() as u16;
        let max_scroll_for_scrollbar = if total_text_lines > visible_viewport_height {
            (total_text_lines - visible_viewport_height).min(u16::MAX as usize) as u16
        } else {
            0u16
        };
        let scroll_ratio = if max_scroll_for_scrollbar > 0 {
            clamped_scroll_offset as f64 / max_scroll_for_scrollbar as f64
        } else {
            0.0
        };

        let available_thumb_travel = (track_height - thumb_size as f64).max(0.0);
        let thumb_position = (scroll_ratio * available_thumb_travel).round() as u16;

        for y_offset in 0..scrollbar_area_for_popup.height {
            let cell_y = scrollbar_area_for_popup.y + y_offset;
            let is_thumb = y_offset >= thumb_position
                && y_offset < (thumb_position + thumb_size).min(scrollbar_area_for_popup.height);

            let (symbol, style) = if is_thumb {
                ("█", Style::default().fg(Color::LightYellow))
            } else {
                ("│", Style::default().fg(Color::Gray))
            };

            if scrollbar_x < area.right()
                && cell_y < area.bottom()
                && scrollbar_x >= area.x
                && cell_y >= area.y
            {
                frame
                    .buffer_mut()
                    .set_string(scrollbar_x, cell_y, symbol, style);
            }
        }
    }
}

pub fn safe_scroll_clamp(scroll_offset: u16, total_lines: usize, visible_height: usize) -> u16 {
    if total_lines <= visible_height {
        return 0;
    }

    let max_scroll_usize = total_lines - visible_height;
    let max_scroll_u16 = max_scroll_usize.min(u16::MAX as usize) as u16;

    scroll_offset.min(max_scroll_u16)
}
