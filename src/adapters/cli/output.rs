use clap::ValueEnum;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub(crate) enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(Serialize)]
pub(crate) struct CommandResult<T: Serialize> {
    pub command: &'static str,
    pub ok: bool,
    pub data: T,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub(crate) trait Renderable: Serialize {
    fn command_name(&self) -> &'static str;

    fn is_ok(&self) -> bool {
        true
    }

    fn warnings(&self) -> Vec<String> {
        vec![]
    }

    fn render_human(&self) -> String;
}

pub(crate) fn render<T: Renderable>(item: &T, format: OutputFormat) -> String {
    match format {
        OutputFormat::Human => item.render_human(),
        OutputFormat::Json => {
            let envelope = CommandResult {
                command: item.command_name(),
                ok: item.is_ok(),
                data: item,
                warnings: item.warnings(),
            };
            serde_json::to_string_pretty(&envelope).unwrap_or_else(|e| {
                format!("{{\"error\": \"JSON serialization failed: {e}\"}}")
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct TestData {
        value: i32,
        message: String,
    }

    impl Renderable for TestData {
        fn command_name(&self) -> &'static str {
            "test"
        }

        fn render_human(&self) -> String {
            format!("Value: {}\nMessage: {}", self.value, self.message)
        }
    }

    #[test]
    fn test_human_output() {
        let data = TestData {
            value: 42,
            message: "hello".to_string(),
        };
        let output = render(&data, OutputFormat::Human);
        assert_eq!(output, "Value: 42\nMessage: hello");
    }

    #[test]
    fn test_json_output() {
        let data = TestData {
            value: 42,
            message: "hello".to_string(),
        };
        let output = render(&data, OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["command"], "test");
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["data"]["value"], 42);
        assert_eq!(parsed["data"]["message"], "hello");
        assert!(parsed.get("warnings").is_none());
    }

    #[derive(Serialize)]
    struct WarningData {
        valid: bool,
        #[serde(skip)]
        warning_list: Vec<String>,
    }

    impl Renderable for WarningData {
        fn command_name(&self) -> &'static str {
            "validate"
        }

        fn is_ok(&self) -> bool {
            self.valid
        }

        fn warnings(&self) -> Vec<String> {
            self.warning_list.clone()
        }

        fn render_human(&self) -> String {
            if self.valid {
                "Valid".to_string()
            } else {
                "Invalid".to_string()
            }
        }
    }

    #[test]
    fn test_json_with_warnings() {
        let data = WarningData {
            valid: true,
            warning_list: vec!["Port 53 requires root".to_string()],
        };
        let output = render(&data, OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["warnings"][0], "Port 53 requires root");
    }

    #[test]
    fn test_json_with_failure() {
        let data = WarningData {
            valid: false,
            warning_list: vec![],
        };
        let output = render(&data, OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["ok"], false);
    }
}
