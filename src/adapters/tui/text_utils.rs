use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

const DEFAULT_LICENSE_TEXT: &str = include_str!("../../../LICENSE.md");
const DEFAULT_RELEASE_NOTES_TEXT: &str = include_str!("../../../RELEASE_NOTES.md");

fn markdown_to_ratatui_lines(markdown_input: &'static str) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut current_line_spans: Vec<Span<'static>> = Vec::new();
    let mut current_style = Style::default();
    let mut list_stack: Vec<(u64, ListType)> = Vec::new();
    let mut in_code_block = false;

    enum ListType {
        Ordered,
        Unordered,
    }

    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_TASKLISTS);

    let parser = Parser::new_ext(markdown_input, opts);

    for event in parser {
        match event {
            Event::Start(tag) => match tag {
                Tag::Heading { level, .. } => {
                    if !current_line_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_line_spans)));
                    }

                    if !lines.is_empty() {
                        lines.push(Line::from(Vec::new()));
                    }

                    let (prefix, style) = match level {
                        pulldown_cmark::HeadingLevel::H1 => (
                            "",
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD)
                                .add_modifier(Modifier::UNDERLINED),
                        ),
                        pulldown_cmark::HeadingLevel::H2 => (
                            "",
                            Style::default()
                                .fg(Color::LightBlue)
                                .add_modifier(Modifier::BOLD),
                        ),
                        pulldown_cmark::HeadingLevel::H3 => (
                            "",
                            Style::default()
                                .fg(Color::LightGreen)
                                .add_modifier(Modifier::BOLD),
                        ),
                        _ => (
                            "",
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                    };

                    current_line_spans.push(Span::styled(prefix, style));
                    current_style = style;
                }
                Tag::List(_) => {
                    if !current_line_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_line_spans)));
                    }
                    if list_stack.is_empty() {
                        lines.push(Line::from(Span::raw("")));
                    }
                    let list_type = if tag == Tag::List(Some(1)) {
                        ListType::Ordered
                    } else {
                        ListType::Unordered
                    };
                    list_stack.push((1, list_type));
                }
                Tag::Item => {
                    if !current_line_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_line_spans)));
                    }

                    let indent = "  ".repeat(list_stack.len().saturating_sub(1));
                    current_line_spans.push(Span::raw(indent));

                    if let Some((number, list_type)) = list_stack.last_mut() {
                        match list_type {
                            ListType::Ordered => {
                                current_line_spans.push(Span::styled(
                                    format!("{}. ", number),
                                    Style::default()
                                        .fg(Color::Cyan)
                                        .add_modifier(Modifier::BOLD),
                                ));
                                *number += 1;
                            }
                            ListType::Unordered => {
                                current_line_spans.push(Span::styled(
                                    "* ",
                                    Style::default()
                                        .fg(Color::Green)
                                        .add_modifier(Modifier::BOLD),
                                ));
                            }
                        }
                    }
                }
                Tag::CodeBlock(kind) => {
                    if !current_line_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_line_spans)));
                    }

                    let lang = match kind {
                        pulldown_cmark::CodeBlockKind::Indented => "".to_string(),
                        pulldown_cmark::CodeBlockKind::Fenced(lang_cow) => lang_cow.into_string(),
                    };

                    let header = if !lang.is_empty() {
                        format!("[{}]", lang.to_uppercase())
                    } else {
                        "[CODE]".to_string()
                    };

                    lines.push(Line::from(Span::styled(
                        header,
                        Style::default().fg(Color::DarkGray),
                    )));

                    current_style = Style::default().fg(Color::Green).bg(Color::Black);
                    in_code_block = true;
                }
                Tag::Emphasis => {
                    current_style = current_style
                        .add_modifier(Modifier::ITALIC)
                        .fg(Color::LightYellow);
                }
                Tag::Strong => {
                    current_style = current_style.add_modifier(Modifier::BOLD).fg(Color::White);
                }
                _ => {}
            },
            Event::End(tag_end) => match tag_end {
                TagEnd::Heading(_) => {
                    current_style = Style::default();
                    if !current_line_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_line_spans)));
                    }
                }
                TagEnd::CodeBlock => {
                    current_style = Style::default();

                    lines.push(Line::from(Span::raw("")));
                    in_code_block = false;
                }
                TagEnd::List(_) => {
                    list_stack.pop();
                    if !current_line_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_line_spans)));
                    }
                    if list_stack.is_empty() {
                        lines.push(Line::from(Span::raw("")));
                    }
                }
                TagEnd::Item => {
                    if !current_line_spans.is_empty() {
                        lines.push(Line::from(std::mem::take(&mut current_line_spans)));
                    }
                }
                TagEnd::Emphasis => {
                    current_style = current_style.remove_modifier(Modifier::ITALIC);
                }
                TagEnd::Strong => {
                    current_style = current_style.remove_modifier(Modifier::BOLD);
                }
                _ => {}
            },
            Event::Text(text) => {
                if in_code_block {
                    current_line_spans
                        .push(Span::styled("  ", Style::default().fg(Color::DarkGray)));
                    current_line_spans.push(Span::styled(text.into_string(), current_style));
                } else {
                    current_line_spans.push(Span::styled(text.into_string(), current_style));
                }
            }
            Event::Code(text) => {
                current_line_spans.push(Span::styled(
                    text.into_string(),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ));
            }
            Event::Rule => {
                if !current_line_spans.is_empty() {
                    lines.push(Line::from(std::mem::take(&mut current_line_spans)));
                }

                lines.push(Line::from(Span::raw("")));
                lines.push(Line::from(Span::styled(
                    "=".repeat(60),
                    Style::default().fg(Color::Magenta),
                )));
                lines.push(Line::from(Span::raw("")));
            }
            _ => {}
        }
    }

    if !current_line_spans.is_empty() {
        lines.push(Line::from(current_line_spans));
    }

    if lines.len() > 1 && lines.last().is_some_and(|l| l.spans.is_empty()) {
        lines.pop();
    }

    lines
}

fn prepare_raw_text_for_popup(raw_text: &'static str) -> Vec<Line<'static>> {
    raw_text.lines().map(Line::from).collect()
}

pub fn get_license_text_lines() -> Vec<Line<'static>> {
    prepare_raw_text_for_popup(DEFAULT_LICENSE_TEXT)
}

pub fn get_release_notes_lines() -> Vec<Line<'static>> {
    markdown_to_ratatui_lines(DEFAULT_RELEASE_NOTES_TEXT)
}
