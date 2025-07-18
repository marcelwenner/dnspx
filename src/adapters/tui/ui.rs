use crate::adapters::tui::app::InputMode;
use crate::adapters::tui::app::{AwsSetupField, TuiApp};
use crate::adapters::tui::components::{
    add_cache_entry_modal, cache_view_panel, hotkey_panel, log_panel,
    popup::{self, PopupConfig},
    status_panel,
};
use crate::core::types::AwsAuthMethod;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
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

pub(crate) fn draw(frame: &mut Frame<'_>, app: &mut TuiApp) {
    if app.input_mode == InputMode::AwsProfileSetupForm {
        draw_aws_profile_setup_form(frame, app);
    } else if app.show_cache_viewer {
        cache_view_panel::draw_cache_viewer(frame, app, frame.area());
        if app.show_add_cache_entry_modal {
            add_cache_entry_modal::draw_add_cache_entry_modal(frame, app, frame.area());
        } else if app.show_confirm_delete_cache_modal {
            add_cache_entry_modal::draw_confirm_delete_cache_modal(frame, app, frame.area());
        }
    } else {
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(40), Constraint::Min(0)])
            .split(frame.area());
        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(main_chunks[0]);
        status_panel::draw_status_panel(frame, app, left_chunks[0]);
        hotkey_panel::draw_hotkey_panel(frame, app, left_chunks[1]);
        log_panel::draw_log_panel(frame, app, main_chunks[1]);
    }

    if app.show_help_popup {
        let help_text_static_slices: Vec<&'static str> = vec![
            "TUI Hotkeys:",
            "  h / ?        : Toggle Help Popup",
            "  Ctrl+L       : Toggle License Popup",
            "  Ctrl+N       : Toggle Release Notes Popup",
            "  Ctrl+V       : Toggle DNS Cache Viewer",
            "  Ctrl+Q/X/C   : Quit Application",
            "  Ctrl+R       : AWS Profile Config / Scan",
            "  r            : Trigger Configuration Reload",
            "  c            : Clear DNS Cache (Global)",
            "  s            : Manual Status Refresh",
            "  d            : Cycle Log Filter Level",
            "  Up/Down Arrow: Scroll Logs / Select (in menus/lists) / Navigate Form",
            "  Tab/Shift+Tab: Navigate AWS Profile Setup Form",
            "  PgUp/PgDown  : Scroll Logs by Page",
            "  Home         : Scroll to Top of Logs",
            "  End          : Scroll to Bottom (Enable Follow Mode)",
            "  Esc          : Close Popups / Cancel or Back in AWS/Cache Setup",
            "  Enter        : Confirm Input / Select / Toggle Checkbox / Activate Button",
            "",
            "Cache Viewer Hotkeys (when active):",
            "  /            : Enter/Edit Filter",
            "  a / Insert   : Add New Cache Entry",
            "  d / Delete   : Delete Selected Entry",
            "  Esc          : Close Cache Viewer / Back in Add Entry",
            "",
            "AWS Profile Setup Form:",
            "  Enter on Profile field: Open/Close profile dropdown",
        ];
        let help_text_lines: Vec<Line<'static>> = help_text_static_slices
            .iter()
            .map(|&s| Line::from(s))
            .collect();

        popup::draw_popup(
            frame,
            PopupConfig {
                title: "Help (Press 'h' or 'Esc' to close)",
                content_lines: &help_text_lines,
                screen_area: frame.area(),
                percent_x: 70,
                percent_y: 90,
                scroll_offset: 0,
            },
            &mut app.license_popup_content_area_height,
        );
    }
    if app.show_license_popup {
        popup::draw_popup(
            frame,
            PopupConfig {
                title: "License Information (Press Ctrl+L or Esc to close)",
                content_lines: &app.license_text_lines,
                screen_area: frame.area(),
                percent_x: 70,
                percent_y: 80,
                scroll_offset: app.license_popup_scroll_offset,
            },
            &mut app.license_popup_content_area_height,
        );
    }
    if app.show_releasenotes_popup {
        popup::draw_popup(
            frame,
            PopupConfig {
                title: "Release Notes (Press Ctrl+N or Esc to close)",
                content_lines: &app.release_notes_lines,
                screen_area: frame.area(),
                percent_x: 70,
                percent_y: 70,
                scroll_offset: app.releasenotes_popup_scroll_offset,
            },
            &mut app.releasenotes_popup_content_area_height,
        );
    }
}

fn draw_aws_profile_setup_form(frame: &mut Frame<'_>, app: &mut TuiApp) {
    let area = frame.area();
    let form_area = centered_rect(80, 85, area);
    frame.render_widget(Clear, form_area);

    let main_block_title = "AWS Account Setup".to_string();

    let block = Block::default()
        .title(main_block_title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let inner_form_area = block.inner(form_area);
    frame.render_widget(block, form_area);

    let mut show_simplified_error_ui = false;
    if let Some(error_message) = &app.aws_form_validation_error {
        if error_message
            == "No AWS profiles found or 'default' is not configured. Please create one using AWS CLI."
            || error_message.starts_with("Failed to read AWS profiles")
            || error_message.starts_with(
                "AWS configuration files (~/.aws/config, ~/.aws/credentials) not found",
            )
        {
            show_simplified_error_ui = true;
        }
    }

    if show_simplified_error_ui {
        let error_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .split(inner_form_area);

        let display_error_message = app.aws_form_validation_error.as_deref().unwrap_or(
            "Error: AWS Profile information is unavailable. Please check logs or AWS CLI setup.",
        );

        let error_p = Paragraph::new(display_error_message.red().bold())
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        frame.render_widget(error_p, error_chunks[0]);

        let close_button_style = if app.aws_setup_current_field == AwsSetupField::CancelButton {
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Red)
        };
        let close_button =
            Paragraph::new(Line::from(Span::styled(" [ Close ] ", close_button_style)))
                .alignment(Alignment::Center);
        frame.render_widget(close_button, error_chunks[1]);
    } else {
        let field_label_width = 28;
        let constraints = vec![
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ];

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints(constraints)
            .split(inner_form_area);

        let mut current_chunk_idx = 0;

        fn draw_text_input_field(
            frame: &mut Frame<'_>,
            chunk: Rect,
            app: &TuiApp,
            field_type: AwsSetupField,
            label: &str,
            field_label_width: u16,
        ) {
            let focused = app.aws_setup_current_field == field_type;
            let value_from_data = match field_type {
                AwsSetupField::Label => &app.aws_profile_form_data.dnspx_label_input,
                _ => panic!("draw_text_input_field called for non-text field or unhandled field"),
            };

            let display_val = if focused && (field_type == AwsSetupField::Label) {
                &app.aws_form_current_input_buffer
            } else {
                value_from_data
            };

            let text_line = Line::from(vec![
                Span::styled(
                    format!(
                        "{:<width$}",
                        format!("{}:", label),
                        width = field_label_width as usize
                    ),
                    Style::default(),
                ),
                Span::styled(
                    format!("[{display_val}]"),
                    if focused {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default().fg(Color::White)
                    },
                ),
                Span::styled(
                    if focused && (field_type == AwsSetupField::Label) {
                        "█"
                    } else {
                        ""
                    },
                    Style::default().fg(Color::Cyan),
                ),
            ]);
            frame.render_widget(Paragraph::new(text_line), chunk);
        }

        fn draw_radio_buttons(
            frame: &mut Frame<'_>,
            chunk: Rect,
            app: &TuiApp,
            field_type: AwsSetupField,
            label: &str,
            options: &[(AwsAuthMethod, &str)],
            field_label_width: u16,
        ) {
            let focused = app.aws_setup_current_field == field_type;
            let current_selection = app.aws_selected_auth_method;

            let mut spans = vec![Span::styled(
                format!(
                    "{:<width$}",
                    format!("{}:", label),
                    width = field_label_width as usize
                ),
                Style::default(),
            )];

            for (idx, (method_enum_val, display_text)) in options.iter().enumerate() {
                let is_selected = *method_enum_val == current_selection;
                let radio_char = if is_selected { "◉" } else { "○" };

                let style = if focused && is_selected {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else if focused && idx == 0 && current_selection != options[0].0 {
                    Style::default().fg(Color::Cyan)
                } else if is_selected {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                };

                spans.push(Span::styled(
                    format!("{radio_char} {display_text}  "),
                    style,
                ));
            }
            if focused {
                spans.push(Span::raw(" "));
                spans.push(Span::styled("█", Style::default().fg(Color::Cyan)));
            }

            frame.render_widget(Paragraph::new(Line::from(spans)), chunk);
        }

        fn draw_profile_dropdown(
            frame: &mut Frame<'_>,
            chunk: Rect,
            app: &TuiApp,
            field_type: AwsSetupField,
            label: &str,
            field_label_width: u16,
        ) {
            let focused = app.aws_setup_current_field == field_type;
            let current_profile_name = if app.aws_profiles_loading {
                "Loading profiles...".to_string()
            } else {
                app.aws_profile_form_data.selected_profile_name.clone()
            };

            let text_line = Line::from(vec![
                Span::styled(
                    format!(
                        "{:<width$}",
                        format!("{}:", label),
                        width = field_label_width as usize
                    ),
                    Style::default(),
                ),
                Span::styled(
                    format!("[{current_profile_name}]"),
                    if focused {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default().fg(Color::White)
                    },
                ),
                Span::styled(
                    if focused && app.aws_profile_dropdown_open {
                        " ▲"
                    } else if focused {
                        " ▼█"
                    } else {
                        " ▼"
                    },
                    Style::default().fg(Color::Yellow),
                ),
            ]);
            frame.render_widget(Paragraph::new(text_line), chunk);

            if app.aws_profile_dropdown_open && focused && !app.aws_profiles_loading {
                let list_items: Vec<ListItem<'_>> = app
                    .aws_available_profiles
                    .iter()
                    .enumerate()
                    .map(|(i, item_text)| {
                        let item_style = if i == app.aws_profile_selection_idx {
                            Style::default()
                                .bg(Color::DarkGray)
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        };
                        ListItem::new(Span::styled(item_text.clone(), item_style))
                    })
                    .collect();

                let list_height = (app.aws_available_profiles.len().min(5) + 2).max(3) as u16;
                let list_area = Rect {
                    x: chunk.x + field_label_width + 1,
                    y: chunk.y + 1,
                    width: chunk.width.saturating_sub(field_label_width + 1).max(20),
                    height: list_height,
                };
                frame.render_widget(Clear, list_area);
                frame.render_widget(
                    List::new(list_items)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_style(Style::default().fg(Color::Yellow)),
                        )
                        .style(Style::default().bg(Color::DarkGray)),
                    list_area,
                );
            }
        }

        fn draw_info_field(
            frame: &mut Frame<'_>,
            chunk: Rect,
            label: &str,
            value: Option<&String>,
            is_loading: bool,
            field_label_width: u16,
            is_highlighted: bool,
        ) {
            let display_value_str = if is_loading {
                "Loading...".to_string()
            } else {
                value.map_or_else(|| "N/A".to_string(), |s| s.clone())
            };

            let base_style = if is_loading
                || value.is_none()
                || value.is_some_and(|s| s.starts_with("N/A") || s.starts_with("Error parsing"))
            {
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC)
            } else {
                Style::default().fg(Color::White)
            };

            let mut text_spans = vec![
                Span::styled(
                    format!(
                        "{:<width$}",
                        format!("{}:", label),
                        width = field_label_width as usize
                    ),
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(display_value_str, base_style),
            ];

            if !is_loading
                && is_highlighted
                && value.is_some()
                && !value.unwrap_or(&String::new()).starts_with("N/A")
                && !value.unwrap_or(&String::new()).starts_with("Error")
            {
                text_spans.push(Span::styled(
                    "  ← Auto-detected!",
                    Style::default()
                        .fg(Color::LightGreen)
                        .add_modifier(Modifier::ITALIC),
                ));
            }

            frame.render_widget(Paragraph::new(Line::from(text_spans)), chunk);
        }

        draw_text_input_field(
            frame,
            chunks[current_chunk_idx],
            app,
            AwsSetupField::Label,
            "Label",
            field_label_width,
        );
        current_chunk_idx += 1;

        let auth_options = [
            (crate::core::types::AwsAuthMethod::AwsProfile, "AWS Profile"),
            (crate::core::types::AwsAuthMethod::AccessKeys, "Access Keys"),
            (crate::core::types::AwsAuthMethod::IamRole, "IAM Role"),
        ];
        draw_radio_buttons(
            frame,
            chunks[current_chunk_idx],
            app,
            AwsSetupField::AuthMethod,
            "Auth Method",
            &auth_options,
            field_label_width,
        );
        current_chunk_idx += 1;

        if app.aws_selected_auth_method == AwsAuthMethod::AwsProfile {
            draw_profile_dropdown(
                frame,
                chunks[current_chunk_idx],
                app,
                AwsSetupField::AwsProfile,
                "Profile Name",
                field_label_width,
            );
        } else {
            frame.render_widget(Paragraph::new(" "), chunks[current_chunk_idx]);
        }
        current_chunk_idx += 1;

        draw_info_field(
            frame,
            chunks[current_chunk_idx],
            "Account ID",
            app.aws_profile_form_data.detected_account_id.as_ref(),
            app.aws_profile_info_loading,
            field_label_width,
            app.aws_profile_form_data.detected_account_id.is_some(),
        );
        current_chunk_idx += 1;

        draw_info_field(
            frame,
            chunks[current_chunk_idx],
            "Region",
            app.aws_profile_form_data.detected_default_region.as_ref(),
            app.aws_profile_info_loading,
            field_label_width,
            app.aws_profile_form_data.detected_default_region.is_some(),
        );
        current_chunk_idx += 1;

        draw_info_field(
            frame,
            chunks[current_chunk_idx],
            "MFA Serial",
            app.aws_profile_form_data.detected_mfa_serial.as_ref(),
            app.aws_profile_info_loading,
            field_label_width,
            false,
        );
        current_chunk_idx += 1;

        draw_info_field(
            frame,
            chunks[current_chunk_idx],
            "MFA Role ARN",
            app.aws_profile_form_data.detected_mfa_role_arn.as_ref(),
            app.aws_profile_info_loading,
            field_label_width,
            false,
        );
        current_chunk_idx += 1;

        current_chunk_idx += 1;

        let checkbox_char = if app.aws_form_test_connection_checked {
            "X"
        } else {
            " "
        };
        let checkbox_text_content = "Test connection before saving";
        let is_checkbox_focused =
            app.aws_setup_current_field == AwsSetupField::TestConnectionCheckbox;
        let checkbox_style = if is_checkbox_focused {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let checkbox_paragraph_line = Line::from(vec![
            Span::raw(" ".repeat(field_label_width as usize)),
            Span::styled(format!("[{checkbox_char}] "), checkbox_style),
            Span::styled(checkbox_text_content, checkbox_style),
            Span::styled(
                if is_checkbox_focused { "█" } else { "" },
                checkbox_style.fg(Color::Cyan),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(checkbox_paragraph_line),
            chunks[current_chunk_idx],
        );
        current_chunk_idx += 1;

        current_chunk_idx += 1;

        if let Some(err_msg) = &app.aws_form_validation_error {
            let error_p = Paragraph::new(err_msg.clone().red().bold())
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true });
            frame.render_widget(error_p, chunks[current_chunk_idx]);
        } else if app.aws_connection_testing {
            let testing_msg = Paragraph::new("Testing connection...".yellow().italic())
                .alignment(Alignment::Center);
            frame.render_widget(testing_msg, chunks[current_chunk_idx]);
        } else {
            let instruction_text = "Tab/Arrows: Navigate, Enter: Select/Confirm, Esc: Close/Cancel";
            frame.render_widget(
                Paragraph::new(instruction_text.dark_gray()).alignment(Alignment::Center),
                chunks[current_chunk_idx],
            );
        }
        current_chunk_idx += 1;

        let focused_button_style = Style::default()
            .bg(Color::DarkGray)
            .fg(Color::White)
            .add_modifier(Modifier::BOLD);
        let button_style = Style::default().fg(Color::Gray);

        let no_profile_selected_or_initial_error = app
            .aws_profile_form_data
            .selected_profile_name
            .starts_with('<')
            || app.aws_available_profiles.is_empty()
            || (app.aws_available_profiles.len() == 1
                && app.aws_available_profiles[0].starts_with('<'));

        let is_loading =
            app.aws_profiles_loading || app.aws_profile_info_loading || app.aws_connection_testing;

        let test_conn_style = if is_loading || no_profile_selected_or_initial_error {
            button_style.fg(Color::DarkGray)
        } else if app.aws_setup_current_field == AwsSetupField::TestConnectionButton {
            focused_button_style
        } else {
            button_style
        };

        let save_style = if is_loading
            || no_profile_selected_or_initial_error
            || app.aws_form_validation_error.is_some()
        {
            button_style.fg(Color::DarkGray)
        } else if app.aws_setup_current_field == AwsSetupField::SaveButton {
            focused_button_style.fg(Color::Green)
        } else {
            button_style.fg(Color::Green)
        };

        let cancel_style = if app.aws_setup_current_field == AwsSetupField::CancelButton {
            focused_button_style.fg(Color::Red)
        } else {
            button_style.fg(Color::Red)
        };

        let buttons_line = Line::from(vec![
            Span::styled(" [ Test Connection ] ", test_conn_style),
            Span::raw("  "),
            Span::styled(" [ Save ] ", save_style),
            Span::raw("  "),
            Span::styled(" [ Cancel ] ", cancel_style),
        ]);
        frame.render_widget(
            Paragraph::new(buttons_line).alignment(Alignment::Center),
            chunks[current_chunk_idx],
        );
    }
}
