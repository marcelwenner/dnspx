use crate::core::types::MessageLevel;
use std::collections::BTreeMap;
use std::fmt::{self, Write};
use tokio::sync::mpsc;
use tracing::{Event, Level, Subscriber, field::Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

#[derive(Default)]
struct FieldExtractor {
    fields: BTreeMap<String, String>,
    message: Option<String>,
}

impl Visit for FieldExtractor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        let field_name = field.name();
        if field_name == "message" {
            self.message = Some(format!("{:?}", value));
        } else {
            self.fields
                .insert(field_name.to_string(), format!("{:?}", value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .insert(field.name().to_string(), value.to_string());
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }
}

pub struct TuiLoggingLayer {
    log_tx: mpsc::Sender<(String, MessageLevel)>,
}

impl TuiLoggingLayer {
    pub fn new(log_tx: mpsc::Sender<(String, MessageLevel)>) -> Self {
        Self { log_tx }
    }
}

impl<S> Layer<S> for TuiLoggingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let level = metadata.level();
        let tui_level = match *level {
            Level::ERROR => MessageLevel::Error,
            Level::WARN => MessageLevel::Warning,
            Level::INFO => MessageLevel::Info,
            Level::DEBUG => MessageLevel::Debug,
            Level::TRACE => MessageLevel::Trace,
        };

        let target = if !metadata.target().is_empty() {
            metadata.target()
        } else {
            metadata.module_path().unwrap_or("<unknown>")
        };

        let mut extractor = FieldExtractor::default();
        event.record(&mut extractor);

        let core_message = extractor.message.as_deref().unwrap_or("");

        let span_fields_str = String::new();

        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {}
        }

        let mut extra_fields_str = String::new();
        let mut latency_ms: Option<String> = None;
        let mut source: Option<String> = None;

        for (name, value) in extractor.fields.iter() {
            if name == "latency_ms" {
                latency_ms = Some(value.clone());
            } else if name == "source" {
                source = Some(value.clone());
            } else if name != "message" {
                if !extra_fields_str.is_empty() {
                    extra_fields_str.push_str(", ");
                }
                write!(extra_fields_str, "{}={}", name, value).ok();
            }
        }

        let mut final_message = format!("[{}] {}", target, core_message);
        if let Some(s) = source {
            final_message.push_str(&format!(" (Src: {})", s));
        }
        if let Some(l_ms) = latency_ms {
            final_message.push_str(&format!(" ({}ms)", l_ms));
        }
        if !extra_fields_str.is_empty() {
            final_message.push_str(&format!(" {{{}}}", extra_fields_str));
        }
        if !span_fields_str.is_empty() {
            final_message.push_str(&format!(" [{}]", span_fields_str.trim()));
        }

        if self
            .log_tx
            .try_send((final_message.trim().to_string(), tui_level))
            .is_err()
        {}
    }
}
