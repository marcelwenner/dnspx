use crate::adapters::tui::app::{InputMode as TuiInputMode, TuiApp};
use hickory_proto::rr::RData;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

fn format_rdata(rdata: Option<&RData>) -> String {
    match rdata {
        Some(RData::A(ip)) => ip.to_string(),
        Some(RData::AAAA(ip)) => ip.to_string(),
        Some(RData::CNAME(name)) => name.to_string(),
        Some(RData::TXT(txt)) => {
            let data_strings: Vec<String> = txt
                .iter()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .collect();
            if data_strings.len() > 1 {
                format!(
                    "{}...",
                    data_strings
                        .first()
                        .map(|s| s.chars().take(20).collect::<String>())
                        .unwrap_or_default()
                )
            } else {
                data_strings.join(" ")
            }
        }
        Some(RData::MX(mx)) => format!("{} {}", mx.preference(), mx.exchange()),
        Some(RData::SOA(soa)) => soa.mname().to_string(),

        Some(other) => format!("{:?}", other.record_type()),
        None => "<No RData>".to_string(),
    }
}

fn create_table_header() -> Row<'static> {
    let header_cells = ["Domain Name", "Type", "TTL (rem.)", "Value(s)"]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        });
    Row::new(header_cells).height(1).bottom_margin(1)
}

pub fn draw_cache_viewer(frame: &mut Frame, app: &mut TuiApp, area: Rect) {
    app.cache_panel_actual_height = area.height.saturating_sub(4);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    let filter_text = if app.input_mode == TuiInputMode::CacheViewFilterInput {
        format!("Filter: {}_", app.cache_view_filter)
    } else {
        format!("Filter: {}", app.cache_view_filter)
    };
    let filter_paragraph = Paragraph::new(filter_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Cache Filter (Press '/' to edit)"),
    );
    frame.render_widget(filter_paragraph, chunks[0]);

    let header = create_table_header();

    let rows: Vec<Row> = app
        .cache_view_items
        .iter()
        .enumerate()
        .map(|(idx, (key, entry_arc))| {
            let ttl_remaining = entry_arc.current_ttl_remaining_secs();
            let values_summary = entry_arc
                .records
                .iter()
                .map(|r| format_rdata(r.data()))
                .take(2)
                .collect::<Vec<String>>()
                .join(", ");

            let item_style = if idx == app.cache_view_selected_index {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(key.name.as_str()),
                Cell::from(format!("{:?}", key.record_type)),
                Cell::from(format!("{}s", ttl_remaining)),
                Cell::from(values_summary),
            ])
            .style(item_style)
        })
        .collect();

    let table_widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(10),
        Constraint::Percentage(15),
        Constraint::Percentage(35),
    ];

    let visible_items_start = app.cache_view_scroll_offset as usize;
    let visible_items_end = (app.cache_view_scroll_offset + app.cache_panel_actual_height)
        .min(app.cache_view_items.len() as u16) as usize;

    let visible_rows: Vec<Row> = app
        .cache_view_items
        .get(visible_items_start..visible_items_end)
        .unwrap_or(&[])
        .iter()
        .enumerate()
        .map(|(relative_idx, (key, entry_arc))| {
            let absolute_idx = visible_items_start + relative_idx;
            let ttl_remaining = entry_arc.current_ttl_remaining_secs();
            let values_summary = entry_arc
                .records
                .iter()
                .map(|r| format_rdata(r.data()))
                .take(2)
                .collect::<Vec<String>>()
                .join(", ");

            let item_style = if absolute_idx == app.cache_view_selected_index {
                Style::default()
                    .bg(Color::DarkGray)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(key.name.as_str()),
                Cell::from(format!("{:?}", key.record_type)),
                Cell::from(format!("{}s", ttl_remaining)),
                Cell::from(values_summary),
            ])
            .style(item_style)
        })
        .collect();

    let table_scrolled = Table::new(visible_rows, table_widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(
            format!("Cached DNS Entries (Showing {} of {})", 
        app.cache_view_items.get(visible_items_start..visible_items_end).map_or(0, |s| s.len()),
        app.cache_view_items.len()
    ),
        ))
        .column_spacing(1);

    frame.render_widget(table_scrolled, chunks[1]);

    let hotkey_text = Text::from(Line::from(vec![
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::raw(":Close "),
        Span::styled("/", Style::default().fg(Color::Yellow)),
        Span::raw(":Filter "),
        Span::styled("a/Ins", Style::default().fg(Color::Yellow)),
        Span::raw(":Add "),
        Span::styled("d/Del", Style::default().fg(Color::Yellow)),
        Span::raw(":Delete "),
        Span::styled("Up/Down/Pg/Home/End", Style::default().fg(Color::Yellow)),
        Span::raw(":Navigate"),
    ]));
    let hotkey_paragraph =
        Paragraph::new(hotkey_text).alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(hotkey_paragraph, chunks[2]);
}
