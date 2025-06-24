#[cfg(test)]
mod tests {
    use crate::adapters::cli::console_cli_adapter::ConsoleCliAdapter;
    use crate::adapters::tui::app::TuiUserInteractionAdapter;
    use crate::core::types::{
        AppStatus, AwsScannerStatus, CacheStats, ConfigStatus, MessageLevel, UpdateStatus,
    };
    use crate::ports::UserInteractionPort;

    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_cli_adapter_creation() {
        let _cli_adapter_color = ConsoleCliAdapter::new(true);
        let _cli_adapter_no_color = ConsoleCliAdapter::new(false);
    }

    #[tokio::test]
    async fn test_tui_user_interaction_adapter() {
        let (tx, mut rx) = mpsc::channel(100);
        let tui_interaction = TuiUserInteractionAdapter::new(tx);

        tui_interaction.display_message("Test message", MessageLevel::Info);

        let received = rx.try_recv();
        assert!(received.is_ok());
        if let Ok((message, level)) = received {
            assert_eq!(message, "Test message");
            assert_eq!(level, MessageLevel::Info);
        }
    }

    #[tokio::test]
    async fn test_tui_user_interaction_different_message_levels() {
        let (tx, mut rx) = mpsc::channel(100);
        let tui_interaction = TuiUserInteractionAdapter::new(tx);

        let test_cases = vec![
            ("Error message", MessageLevel::Error),
            ("Warning message", MessageLevel::Warning),
            ("Info message", MessageLevel::Info),
            ("Debug message", MessageLevel::Debug),
            ("Trace message", MessageLevel::Trace),
        ];

        for (message, level) in test_cases {
            tui_interaction.display_message(message, level);

            let received = rx.try_recv();
            assert!(received.is_ok());
            if let Ok((received_message, received_level)) = received {
                assert_eq!(received_message, message);
                assert_eq!(received_level, level);
            }
        }
    }

    #[tokio::test]
    async fn test_app_status_display_comprehensive() {
        let cli_adapter = ConsoleCliAdapter::new(false);

        let comprehensive_status = AppStatus {
            uptime_seconds: 12345,
            active_config_hash: "abc123def456".to_string(),
            active_listeners: vec![
                "UDP:127.0.0.1:5353".to_string(),
                "TCP:127.0.0.1:5353".to_string(),
            ],
            config_status: ConfigStatus {
                is_valid: true,
                source_file_path: Some("/test/config.toml".to_string()),
                last_loaded_time: Some(chrono::Utc::now()),
                error_message: None,
            },
            cache_stats: Some(CacheStats {
                size: 150,
                hits: 1000,
                misses: 50,
                evictions: 10,
                estimated_memory_usage_bytes: 51200,
            }),
            aws_scanner_status: Some(AwsScannerStatus {
                is_scanning: false,
                last_scan_time: Some(chrono::Utc::now()),
                discovered_entries_count: 25,
                accounts_scanned: 2,
                accounts_failed: 0,
                error_message: None,
                detailed_errors: vec![],
            }),
            update_status: Some(UpdateStatus {
                current_version: "1.0.0".to_string(),
                latest_version: None,
                last_check_time: None,
                update_available: false,
                checking_for_updates: false,
                installing_update: false,
                last_error: None,
                rollback_available: false,
            }),
        };

        cli_adapter.display_status(&comprehensive_status);
    }

    #[tokio::test]
    async fn test_app_status_display_minimal() {
        let cli_adapter = ConsoleCliAdapter::new(false);

        let minimal_status = AppStatus {
            uptime_seconds: 60,
            active_config_hash: "minimal".to_string(),
            active_listeners: vec![],
            config_status: ConfigStatus {
                is_valid: false,
                source_file_path: None,
                last_loaded_time: None,
                error_message: Some("Test error".to_string()),
            },
            cache_stats: None,
            aws_scanner_status: None,
            update_status: None,
        };

        cli_adapter.display_status(&minimal_status);
    }

    #[tokio::test]
    async fn test_cli_adapter_table_display() {
        let cli_adapter = ConsoleCliAdapter::new(false);

        cli_adapter.display_table(vec![], vec![]);

        cli_adapter.display_table(vec!["Header1".to_string(), "Header2".to_string()], vec![]);

        cli_adapter.display_table(
            vec!["Name".to_string(), "Value".to_string()],
            vec![
                vec!["Setting1".to_string(), "Value1".to_string()],
                vec!["Setting2".to_string(), "Value2".to_string()],
            ],
        );

        cli_adapter.display_table(
            vec!["Short".to_string(), "Very Long Header".to_string()],
            vec![
                vec!["A".to_string(), "B".to_string()],
                vec!["Much longer value".to_string(), "Short".to_string()],
            ],
        );
    }

    #[tokio::test]
    async fn test_cli_adapter_prompt_display() {
        let cli_adapter = ConsoleCliAdapter::new(false);

        cli_adapter.display_prompt("test> ");
        cli_adapter.display_prompt("");
        cli_adapter.display_prompt("very-long-prompt-text-that-might-cause-issues> ");
    }

    #[tokio::test]
    async fn test_message_level_display_formatting() {
        let cli_adapter = ConsoleCliAdapter::new(false);

        let test_messages = vec![
            ("Error test", MessageLevel::Error),
            ("Warning test", MessageLevel::Warning),
            ("Info test", MessageLevel::Info),
            ("Debug test", MessageLevel::Debug),
            ("Trace test", MessageLevel::Trace),
        ];

        for (message, level) in test_messages {
            cli_adapter.display_message(message, level);
        }
    }

    #[tokio::test]
    async fn test_cli_adapter_color_support() {
        let cli_adapter_color = ConsoleCliAdapter::new(true);

        let cli_adapter_no_color = ConsoleCliAdapter::new(false);

        let test_message = "Test message for color display";
        cli_adapter_color.display_message(test_message, MessageLevel::Info);
        cli_adapter_no_color.display_message(test_message, MessageLevel::Info);
    }

    #[tokio::test]
    async fn test_ui_component_robustness() {
        let (tx, _rx) = mpsc::channel(1);
        let tui_interaction = TuiUserInteractionAdapter::new(tx);

        tui_interaction.display_message("", MessageLevel::Info);

        let long_message = "a".repeat(10000);
        tui_interaction.display_message(&long_message, MessageLevel::Warning);

        tui_interaction.display_message("Test\n\t\r\x00message", MessageLevel::Error);

        tui_interaction.display_message("测试消息 🚀 مرحبا", MessageLevel::Debug);
    }

    #[tokio::test]
    async fn test_cli_output_types() {
        let cli_adapter = ConsoleCliAdapter::new(false);

        let status = AppStatus {
            uptime_seconds: 100,
            active_config_hash: "test123".to_string(),
            active_listeners: vec!["UDP:127.0.0.1:5353".to_string()],
            config_status: ConfigStatus {
                is_valid: true,
                source_file_path: Some("/test/config.toml".to_string()),
                last_loaded_time: None,
                error_message: None,
            },
            cache_stats: None,
            aws_scanner_status: None,
            update_status: None,
        };

        cli_adapter.display_status(&status);

        let headers = vec!["Column1".to_string(), "Column2".to_string()];
        let rows = vec![
            vec!["Value1".to_string(), "Value2".to_string()],
            vec!["Value3".to_string(), "Value4".to_string()],
        ];
        cli_adapter.display_table(headers, rows);
    }

    #[tokio::test]
    async fn test_error_display_functionality() {
        let cli_adapter = ConsoleCliAdapter::new(false);

        let test_error = std::io::Error::new(std::io::ErrorKind::NotFound, "Test file not found");

        cli_adapter.display_error(&test_error);

        let nested_error = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Permission denied accessing test file",
        );
        cli_adapter.display_error(&nested_error);
    }

    #[tokio::test]
    async fn test_concurrent_ui_operations() {
        let (tx, _rx) = mpsc::channel(1000);
        let tui_interaction = Arc::new(TuiUserInteractionAdapter::new(tx));

        let handles = (0..10)
            .map(|i| {
                let ui = Arc::clone(&tui_interaction);
                tokio::spawn(async move {
                    ui.display_message(&format!("Concurrent message {}", i), MessageLevel::Info);
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle.await.expect("Task should not panic");
        }
    }

    #[tokio::test]
    async fn test_tui_message_channel_capacity() {
        let (tx, _rx) = mpsc::channel(2);
        let tui_interaction = TuiUserInteractionAdapter::new(tx);

        for i in 0..10 {
            tui_interaction.display_message(&format!("Message {}", i), MessageLevel::Info);
        }
    }

    #[tokio::test]
    async fn test_cli_help_display() {
        let cli_adapter = ConsoleCliAdapter::new(true);

        cli_adapter.display_message(
            "Help: Available commands: status, reload, scan",
            MessageLevel::Info,
        );
        cli_adapter.display_message(
            "Update Help: check, install, status, rollback",
            MessageLevel::Info,
        );
    }

    #[tokio::test]
    async fn test_cli_component_construction_variants() {
        let adapters = vec![ConsoleCliAdapter::new(true), ConsoleCliAdapter::new(false)];

        for adapter in adapters {
            adapter.display_message("Test construction", MessageLevel::Info);
            adapter.display_prompt("test> ");

            adapter.display_table(vec!["Test".to_string()], vec![vec!["Value".to_string()]]);
        }
    }

    #[tokio::test]
    async fn test_ui_integration_stress() {
        let cli_adapter = Arc::new(ConsoleCliAdapter::new(false));
        let (tx, _rx) = mpsc::channel(1000);
        let tui_interaction = Arc::new(TuiUserInteractionAdapter::new(tx));

        let cli_handle = {
            let adapter = Arc::clone(&cli_adapter);
            tokio::spawn(async move {
                for i in 0..100 {
                    adapter.display_message(&format!("CLI stress test {}", i), MessageLevel::Debug);
                    if i % 10 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            })
        };

        let tui_handle = {
            let interaction = Arc::clone(&tui_interaction);
            tokio::spawn(async move {
                for i in 0..100 {
                    interaction
                        .display_message(&format!("TUI stress test {}", i), MessageLevel::Trace);
                    if i % 10 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
            })
        };

        cli_handle.await.expect("CLI stress test should complete");
        tui_handle.await.expect("TUI stress test should complete");
    }
}
