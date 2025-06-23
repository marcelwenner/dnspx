use crate::core::types::CliCommand;
use crossterm::event::{Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::error;

#[derive(Debug, Clone)]
pub(crate) enum AppEvent {
    Input(KeyEvent),
    Tick,
    Command(CliCommand),
}

const TICK_RATE: Duration = Duration::from_millis(250);

pub(crate) struct EventManager {
    event_tx: mpsc::Sender<AppEvent>,
    event_rx: mpsc::Receiver<AppEvent>,
    shutdown_token: CancellationToken,
}

impl EventManager {
    pub(crate) fn new() -> Self {
        let (event_tx, event_rx) = mpsc::channel(128);
        Self {
            event_tx,
            event_rx,
            shutdown_token: CancellationToken::new(),
        }
    }

    pub(crate) fn shutdown(&self) {
        self.shutdown_token.cancel();
    }

    pub(crate) fn start_event_listeners(&self) {
        let tx_input = self.event_tx.clone();
        let shutdown_token_input = self.shutdown_token.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_token_input.cancelled() => {
                        error!("Input listener task cancelled.");
                        break;
                    }
                    result = tokio::task::spawn_blocking(|| {
                        if crossterm::event::poll(Duration::from_millis(100)).unwrap_or(false) {
                            crossterm::event::read()
                        } else {
                            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "poll timeout"))
                        }
                    }) => {
                        match result {
                            Ok(Ok(CrosstermEvent::Key(key_event))) => {
                                if tx_input.send(AppEvent::Input(key_event)).await.is_err() {
                                    error!("Failed to send key event to TUI app. Channel closed.");
                                    break;
                                }
                            }
                            Ok(Ok(CrosstermEvent::Resize(_, _))) => {}
                            Ok(Ok(_)) => {}
                            Ok(Err(e)) => {
                                if e.kind() != std::io::ErrorKind::TimedOut {
                                    error!(
                                        "Error reading crossterm event: {}. Stopping input listener.",
                                        e
                                    );
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("spawn_blocking failed: {}. Stopping input listener.", e);
                                break;
                            }
                        }
                    }
                }
            }
        });

        let tx_tick = self.event_tx.clone();
        let shutdown_token_tick = self.shutdown_token.clone();

        tokio::spawn(async move {
            let mut tick_interval = interval(TICK_RATE);
            loop {
                tokio::select! {
                    _ = shutdown_token_tick.cancelled() => {
                        error!("Tick timer task cancelled.");
                        break;
                    }
                    _ = tick_interval.tick() => {
                        if tx_tick.send(AppEvent::Tick).await.is_err() {
                            error!("Failed to send tick event to TUI app. Channel closed.");
                            break;
                        }
                    }
                }
            }
        });
    }

    pub(crate) async fn next_event(&mut self) -> Option<AppEvent> {
        self.event_rx.recv().await
    }

    pub(crate) fn get_event_sender(&self) -> mpsc::Sender<AppEvent> {
        self.event_tx.clone()
    }
}

pub(crate) fn is_quit_event(key_event: &KeyEvent) -> bool {
    match key_event.code {
        KeyCode::Char('q') => true,
        KeyCode::Char('x') if key_event.modifiers == KeyModifiers::CONTROL => true,
        KeyCode::Char('c') if key_event.modifiers == KeyModifiers::CONTROL => true,
        _ => false,
    }
}
