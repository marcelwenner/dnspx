use crate::core::types::CliCommand;
use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::error;

#[derive(Debug, Clone)]
pub enum AppEvent {
    Input(KeyEvent),
    Tick,
    Command(CliCommand),
}

const TICK_RATE: Duration = Duration::from_millis(250);

pub struct EventManager {
    event_tx: mpsc::Sender<AppEvent>,
    event_rx: mpsc::Receiver<AppEvent>,
}

impl EventManager {
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::channel(128);
        Self { event_tx, event_rx }
    }

    pub fn start_event_listeners(&self) {
        let tx_input = self.event_tx.clone();
        tokio::spawn(async move {
            loop {
                match crossterm::event::read() {
                    Ok(CrosstermEvent::Key(key_event)) => {
                        if tx_input.send(AppEvent::Input(key_event)).await.is_err() {
                            error!("Failed to send key event to TUI app. Channel closed.");
                            break;
                        }
                    }
                    Ok(CrosstermEvent::Resize(_, _)) => {}
                    Ok(_) => {}
                    Err(e) => {
                        error!(
                            "Error reading crossterm event: {}. Stopping input listener.",
                            e
                        );
                        break;
                    }
                }
            }
        });

        let tx_tick = self.event_tx.clone();
        tokio::spawn(async move {
            let mut tick_interval = interval(TICK_RATE);
            loop {
                tick_interval.tick().await;
                if tx_tick.send(AppEvent::Tick).await.is_err() {
                    error!("Failed to send tick event to TUI app. Channel closed.");
                    break;
                }
            }
        });
    }

    pub async fn next_event(&mut self) -> Option<AppEvent> {
        self.event_rx.recv().await
    }

    pub fn get_event_sender(&self) -> mpsc::Sender<AppEvent> {
        self.event_tx.clone()
    }
}

pub fn is_quit_event(key_event: &KeyEvent) -> bool {
    match key_event.code {
        KeyCode::Char('q') => true,
        KeyCode::Char('x') if key_event.modifiers == KeyModifiers::CONTROL => true,
        KeyCode::Char('c') if key_event.modifiers == KeyModifiers::CONTROL => true,
        _ => false,
    }
}
