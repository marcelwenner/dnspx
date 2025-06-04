use crate::adapters::aws::profile_utils::{
    self, AwsConfigParams, create_aws_account_config_from_params,
};
use crate::adapters::tui::event::{AppEvent, EventManager, is_quit_event};
use crate::adapters::tui::text_utils;
use crate::adapters::tui::ui;
use crate::app_lifecycle::AppLifecycleManager;
use crate::config::models::{AwsAccountConfig, AwsServiceDiscoveryConfig};
use crate::core::dns_cache::{CacheEntry, CacheKey};
use crate::core::error::{AwsAuthError, UserInputError};
use crate::core::types::{AppStatus, AwsAuthMethod, CliCommand, MessageLevel};
use crate::ports::{AppLifecycleManagerPort, UserInteractionPort};
use async_trait::async_trait;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::Name as HickoryName;
use hickory_proto::rr::RecordType;
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::text::Line;
use std::collections::VecDeque;
use std::io::Stdout;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TuiLogFilter {
    All,
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}
impl TuiLogFilter {
    pub fn next_level(&self) -> Self {
        match self {
            TuiLogFilter::All => TuiLogFilter::Trace,
            TuiLogFilter::Trace => TuiLogFilter::Debug,
            TuiLogFilter::Debug => TuiLogFilter::Info,
            TuiLogFilter::Info => TuiLogFilter::Warn,
            TuiLogFilter::Warn => TuiLogFilter::Error,
            TuiLogFilter::Error => TuiLogFilter::All,
        }
    }
    pub fn matches(&self, level: &MessageLevel) -> bool {
        match self {
            TuiLogFilter::All => true,
            TuiLogFilter::Trace => true,
            TuiLogFilter::Debug => !matches!(level, MessageLevel::Trace),
            TuiLogFilter::Info => !matches!(level, MessageLevel::Trace | MessageLevel::Debug),
            TuiLogFilter::Warn => matches!(level, MessageLevel::Warning | MessageLevel::Error),
            TuiLogFilter::Error => matches!(level, MessageLevel::Error),
        }
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Copy, Hash)]
pub enum AwsSetupField {
    Label,
    AuthMethod,
    AwsProfile,
    TestConnectionCheckbox,
    TestConnectionButton,
    SaveButton,
    CancelButton,
}

#[derive(Debug, Clone, Default)]
pub struct AwsProfileFormData {
    pub original_dnspx_label: Option<String>,
    pub dnspx_label_input: String,
    pub selected_profile_name: String,
    pub detected_account_id: Option<String>,
    pub detected_default_region: Option<String>,
    pub detected_mfa_serial: Option<String>,
    pub detected_mfa_role_arn: Option<String>,
}

pub type AwsAccountSubmitData = AwsAccountConfig;

#[derive(PartialEq, Eq, Clone, Debug, Copy, Default)]
pub enum InputMode {
    #[default]
    Normal,
    AwsProfileSetupForm,
    CacheViewFilterInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheAddStep {
    PromptName,
    PromptType,
    PromptValueA,
    PromptValueAAAA,
    PromptValueCNAME,
    PromptValueTXT,
    PromptTTL,
    ConfirmAdd,
}
#[derive(Debug, Clone, Default)]
pub struct SyntheticCacheAddData {
    pub name: String,
    pub record_type: Option<RecordType>,
    pub value_a: Option<std::net::Ipv4Addr>,
    pub value_aaaa: Option<std::net::Ipv6Addr>,
    pub value_cname: Option<String>,
    pub value_txt: Option<Vec<String>>,
    pub ttl_seconds: Option<u32>,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
pub enum StatusPanelView {
    #[default]
    Dashboard,
    AwsScanner,
}

const MAX_LOG_BUFFER_SIZE: usize = 2000;

pub struct TuiApp {
    pub app_lifecycle: Arc<dyn AppLifecycleManagerPort>,
    pub should_quit: bool,
    pub status_cache: Option<AppStatus>,
    pub log_buffer: VecDeque<(String, MessageLevel)>,
    pub log_scroll_offset: u16,
    pub log_follow_mode: bool,
    pub show_help_popup: bool,
    pub show_license_popup: bool,
    pub show_releasenotes_popup: bool,
    pub license_text_lines: Vec<Line<'static>>,
    pub release_notes_lines: Vec<Line<'static>>,
    pub license_popup_scroll_offset: u16,
    pub license_popup_content_area_height: u16,
    pub releasenotes_popup_scroll_offset: u16,
    pub releasenotes_popup_content_area_height: u16,
    pub current_status_panel_view: StatusPanelView,

    pub input_mode: InputMode,
    pub aws_setup_current_field: AwsSetupField,
    pub aws_profile_form_data: AwsProfileFormData,
    pub aws_selected_auth_method: AwsAuthMethod,

    pub aws_profile_dropdown_open: bool,
    pub aws_profile_selection_idx: usize,
    pub aws_available_profiles: Vec<String>,
    pub aws_profiles_loading: bool,
    pub aws_profile_info_loading: bool,
    pub aws_connection_testing: bool,
    profile_info_update_receiver: Option<
        mpsc::Receiver<
            Result<
                (
                    Option<String>,
                    Option<String>,
                    Option<String>,
                    Option<String>,
                ),
                String,
            >,
        >,
    >,
    connection_test_receiver: Option<mpsc::Receiver<Result<String, AwsAuthError>>>,
    aws_init_profile_receiver:
        Option<mpsc::Receiver<Result<Vec<String>, profile_utils::ProfileReadError>>>,
    aws_init_profile_receiver_for_edit: Option<(
        mpsc::Receiver<Result<Vec<String>, profile_utils::ProfileReadError>>,
        String,
        Option<String>,
    )>,

    pub aws_form_validation_error: Option<String>,
    pub aws_form_test_connection_checked: bool,
    pub aws_form_current_input_buffer: String,

    pub show_cache_viewer: bool,
    pub cache_view_items: Vec<(CacheKey, Arc<CacheEntry>)>,
    pub cache_view_full_list: Vec<(CacheKey, Arc<CacheEntry>)>,
    pub cache_view_scroll_offset: u16,
    pub cache_view_selected_index: usize,
    pub cache_view_filter: String,
    pub show_add_cache_entry_modal: bool,
    pub current_add_cache_step: Option<CacheAddStep>,
    pub cache_add_step_history: Vec<CacheAddStep>,
    pub pending_cache_add_data: SyntheticCacheAddData,
    pub cache_add_error: Option<String>,
    pub cache_add_type_selection_idx: usize,
    pub show_confirm_delete_cache_modal: bool,
    pub cache_entry_to_delete: Option<CacheKey>,
    pub cache_add_input_buffer: String,

    event_tx_to_worker: Option<mpsc::Sender<CliCommand>>,
    log_rx_from_trace: mpsc::Receiver<(String, MessageLevel)>,
    pub total_queries_for_ui: u64,
    pub current_qps: f32,
    last_qps_calculation_time: Instant,
    last_query_count_for_qps: u64,
    pub tui_log_filter_level: TuiLogFilter,
    pub log_panel_actual_height: u16,
    pub cache_panel_actual_height: u16,
}

impl TuiApp {
    pub fn new(
        app_lifecycle: Arc<dyn AppLifecycleManagerPort>,
        event_tx_to_worker: Option<mpsc::Sender<CliCommand>>,
        log_rx_from_trace: mpsc::Receiver<(String, MessageLevel)>,
    ) -> Self {
        Self {
            app_lifecycle,
            should_quit: false,
            status_cache: None,
            log_buffer: VecDeque::with_capacity(MAX_LOG_BUFFER_SIZE),
            log_scroll_offset: 0,
            log_follow_mode: true,
            show_help_popup: false,
            show_license_popup: false,
            show_releasenotes_popup: false,
            license_text_lines: text_utils::get_license_text_lines(),
            release_notes_lines: text_utils::get_release_notes_lines(),
            license_popup_scroll_offset: 0,
            license_popup_content_area_height: 0,
            releasenotes_popup_scroll_offset: 0,
            releasenotes_popup_content_area_height: 0,
            current_status_panel_view: StatusPanelView::default(),
            input_mode: InputMode::Normal,
            aws_setup_current_field: AwsSetupField::Label,
            aws_profile_form_data: AwsProfileFormData::default(),
            aws_selected_auth_method: AwsAuthMethod::default(),
            aws_profile_dropdown_open: false,
            aws_profile_selection_idx: 0,
            aws_available_profiles: Vec::new(),
            aws_profiles_loading: false,
            aws_profile_info_loading: false,
            aws_connection_testing: false,
            profile_info_update_receiver: None,
            aws_init_profile_receiver_for_edit: None,
            aws_init_profile_receiver: None,
            connection_test_receiver: None,
            aws_form_validation_error: None,
            aws_form_test_connection_checked: true,
            aws_form_current_input_buffer: String::new(),
            show_cache_viewer: false,
            cache_view_items: Vec::new(),
            cache_view_full_list: Vec::new(),
            cache_view_scroll_offset: 0,
            cache_view_selected_index: 0,
            cache_view_filter: String::new(),
            show_add_cache_entry_modal: false,
            current_add_cache_step: None,
            cache_add_step_history: Vec::new(),
            pending_cache_add_data: SyntheticCacheAddData::default(),
            cache_add_error: None,
            cache_add_type_selection_idx: 0,
            show_confirm_delete_cache_modal: false,
            cache_entry_to_delete: None,
            cache_add_input_buffer: String::new(),
            event_tx_to_worker,
            log_rx_from_trace,
            total_queries_for_ui: 0,
            current_qps: 0.0,
            last_qps_calculation_time: Instant::now(),
            last_query_count_for_qps: 0,
            tui_log_filter_level: TuiLogFilter::Info,
            log_panel_actual_height: 0,
            cache_panel_actual_height: 0,
        }
    }

    pub fn toggle_status_panel_view(&mut self) {
        self.current_status_panel_view = match self.current_status_panel_view {
            StatusPanelView::Dashboard => StatusPanelView::AwsScanner,
            StatusPanelView::AwsScanner => StatusPanelView::Dashboard,
        };
        let next_view_str = match self.current_status_panel_view {
            StatusPanelView::Dashboard => "Dashboard",
            StatusPanelView::AwsScanner => "AWS Scanner",
        };
        self.add_log_message_internal(
            format!("Status panel view switched to: {}", next_view_str),
            MessageLevel::Debug,
        );
    }

    pub fn current_input_with_cursor(&self) -> String {
        if self.input_mode == InputMode::AwsProfileSetupForm
            && self.aws_setup_current_field == AwsSetupField::Label
        {
            format!("{}_", self.aws_form_current_input_buffer)
        } else if self.input_mode == InputMode::CacheViewFilterInput {
            format!("{}_", self.cache_view_filter)
        } else if self.show_add_cache_entry_modal {
            match self.current_add_cache_step {
                Some(CacheAddStep::PromptName)
                | Some(CacheAddStep::PromptValueA)
                | Some(CacheAddStep::PromptValueAAAA)
                | Some(CacheAddStep::PromptValueCNAME)
                | Some(CacheAddStep::PromptValueTXT)
                | Some(CacheAddStep::PromptTTL) => format!("{}_", self.cache_add_input_buffer),
                _ => String::new(),
            }
        } else {
            String::new()
        }
    }

    pub fn clamp_release_notes_scroll(&mut self) {
        let total_lines = self.release_notes_lines.len();
        let view_height = self.releasenotes_popup_content_area_height as usize;

        if total_lines > view_height && view_height > 0 {
            let max_scroll = (total_lines - view_height) as u16;
            self.releasenotes_popup_scroll_offset =
                self.releasenotes_popup_scroll_offset.min(max_scroll);
        } else {
            self.releasenotes_popup_scroll_offset = 0;
        }
    }

    pub fn get_add_cache_prompt(&self) -> String {
        let error_prefix = if let Some(err) = &self.cache_add_error {
            format!("[ERROR: {}] ", err)
        } else {
            String::new()
        };
        let step_title = match self.current_add_cache_step {
            Some(CacheAddStep::PromptName) => format!(
                "{}Enter Domain Name (e.g., test.example.com):",
                error_prefix
            ),
            Some(CacheAddStep::PromptType) => {
                "Select Record Type (Up/Down, Enter, Esc for Back):".to_string()
            }
            Some(CacheAddStep::PromptValueA) => {
                format!("{}Enter IPv4 Address (e.g., 1.2.3.4):", error_prefix)
            }
            Some(CacheAddStep::PromptValueAAAA) => {
                format!("{}Enter IPv6 Address (e.g., ::1):", error_prefix)
            }
            Some(CacheAddStep::PromptValueCNAME) => format!(
                "{}Enter Target Domain for CNAME (e.g., target.example.com):",
                error_prefix
            ),
            Some(CacheAddStep::PromptValueTXT) => format!(
                "{}Enter TXT Record Value (max 255 chars per string):",
                error_prefix
            ),
            Some(CacheAddStep::PromptTTL) => {
                format!("{}Enter TTL in seconds (e.g., 300, min 60):", error_prefix)
            }
            Some(CacheAddStep::ConfirmAdd) => {
                "Review and Confirm (Enter/Y to Add, Esc/N for Back)".to_string()
            }
            None => "".to_string(),
        };
        format!("{} (Esc for Back)", step_title)
    }

    fn add_log_message_internal(&mut self, message: String, level: MessageLevel) {
        if self.log_buffer.len() >= MAX_LOG_BUFFER_SIZE {
            self.log_buffer.pop_front();
        }
        let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
        self.log_buffer
            .push_back((format!("[{}] {}", timestamp, message), level));

        if self.log_follow_mode {
            self.scroll_to_log_end();
        }
    }
    fn get_filtered_log_count(&self) -> usize {
        self.log_buffer
            .iter()
            .filter(|(_, lvl)| self.tui_log_filter_level.matches(lvl))
            .count()
    }

    fn scroll_to_log_end(&mut self) {
        let filtered_log_count = self.get_filtered_log_count();
        if self.log_panel_actual_height > 0 {
            if filtered_log_count > self.log_panel_actual_height as usize {
                self.log_scroll_offset =
                    (filtered_log_count - self.log_panel_actual_height as usize) as u16;
            } else {
                self.log_scroll_offset = 0;
            }
        } else if filtered_log_count > 0 {
            self.log_scroll_offset = filtered_log_count.saturating_sub(1) as u16;
        } else {
            self.log_scroll_offset = 0;
        }
    }

    fn log_scroll_up(&mut self, amount: u16) {
        self.log_scroll_offset = self.log_scroll_offset.saturating_sub(amount);
        self.log_follow_mode = false;
    }

    fn log_scroll_down(&mut self, amount: u16) {
        self.log_follow_mode = false;
        let filtered_log_count = self.get_filtered_log_count();

        let max_scroll = if filtered_log_count > self.log_panel_actual_height as usize
            && self.log_panel_actual_height > 0
        {
            (filtered_log_count - self.log_panel_actual_height as usize) as u16
        } else {
            0
        };

        self.log_scroll_offset = (self.log_scroll_offset.saturating_add(amount)).min(max_scroll);

        if self.log_scroll_offset >= max_scroll
            && (filtered_log_count == 0
                || filtered_log_count > self.log_panel_actual_height as usize)
        {
            if filtered_log_count > self.log_panel_actual_height as usize {
                self.log_follow_mode = true;
            } else if filtered_log_count == 0 {
                self.log_follow_mode = true;
            }
        }
    }

    async fn is_specific_profile_actually_configured(&self, profile_name: &str) -> bool {
        if profile_name.starts_with('<') {
            return false;
        }
        let temp_config_for_check =
            crate::adapters::aws::profile_utils::create_aws_account_config_from_params(
                crate::adapters::aws::profile_utils::AwsConfigParams {
                    profile_name,
                    label: Some(&format!("{}-existence-check", profile_name)),
                    ..Default::default()
                },
            );
        let interaction_port = self.app_lifecycle.get_user_interaction_port();
        self.app_lifecycle
            .get_aws_config_provider()
            .get_credentials_for_account(&temp_config_for_check, interaction_port)
            .await
            .is_ok()
    }

    pub async fn aws_init_profile_form_for_add(&mut self) {
        self.aws_profiles_loading = true;
        self.aws_profile_info_loading = false;
        self.input_mode = InputMode::AwsProfileSetupForm;
        self.aws_profile_form_data = AwsProfileFormData::default();
        self.aws_setup_current_field = AwsSetupField::Label;
        self.aws_form_validation_error = None;
        self.aws_selected_auth_method = AwsAuthMethod::AwsProfile;
        self.aws_form_test_connection_checked = true;
        self.aws_form_current_input_buffer.clear();

        let (profiles_tx, profiles_rx) =
            mpsc::channel::<Result<Vec<String>, profile_utils::ProfileReadError>>(1);

        tokio::spawn(async move {
            let result = profile_utils::read_aws_profiles_from_files();
            if profiles_tx.send(result).await.is_err() {
                error!("Failed to send loaded profiles to TUI app");
            }
        });

        self.aws_init_profile_receiver = Some(profiles_rx);

        self.aws_load_field_value_into_input_buffer();
        self.add_log_message_internal(
            "AWS Profile Setup form opened. Loading profiles...".to_string(),
            MessageLevel::Info,
        );
    }

    pub async fn aws_init_profile_form_for_edit(&mut self, label_to_edit: &str) {
        self.aws_profiles_loading = true;
        self.aws_profile_info_loading = false;
        self.input_mode = InputMode::AwsProfileSetupForm;
        self.aws_setup_current_field = AwsSetupField::Label;
        self.aws_form_validation_error = None;
        self.aws_selected_auth_method = AwsAuthMethod::AwsProfile;
        self.aws_form_test_connection_checked = true;
        self.aws_form_current_input_buffer.clear();

        let current_config = self.app_lifecycle.get_config();
        let config_guard = current_config.read().await;
        let acc_to_edit_profile_name = config_guard
            .aws
            .as_ref()
            .and_then(|aws_conf| {
                aws_conf
                    .accounts
                    .iter()
                    .find(|acc| acc.label == label_to_edit)
            })
            .and_then(|acc| acc.profile_name.clone());
        drop(config_guard);

        let (profiles_tx, profiles_rx) =
            mpsc::channel::<Result<Vec<String>, profile_utils::ProfileReadError>>(1);
        tokio::spawn(async move {
            let result = profile_utils::read_aws_profiles_from_files();
            if profiles_tx.send(result).await.is_err() {
                error!("Failed to send loaded profiles to TUI app for edit");
            }
        });
        self.aws_init_profile_receiver_for_edit = Some((
            profiles_rx,
            label_to_edit.to_string(),
            acc_to_edit_profile_name,
        ));

        self.add_log_message_internal(
            format!(
                "AWS Profile Setup form opened for editing account: {}. Loading profiles...",
                label_to_edit
            ),
            MessageLevel::Info,
        );
    }

    async fn check_for_aws_init_profiles_add(&mut self) {
        if let Some(receiver) = &mut self.aws_init_profile_receiver {
            match receiver.try_recv() {
                Ok(Ok(mut profiles_from_file)) => {
                    self.aws_profiles_loading = false;
                    let mut usable_profiles_found = false;
                    let mut actual_profiles_to_use = Vec::new();

                    if profiles_from_file.is_empty() {
                        usable_profiles_found = false;
                    } else if profiles_from_file.len() == 1 && profiles_from_file[0] == "default" {
                        if self
                            .is_specific_profile_actually_configured("default")
                            .await
                        {
                            usable_profiles_found = true;
                            actual_profiles_to_use.push("default".to_string());
                        } else {
                            usable_profiles_found = false;
                        }
                    } else {
                        profiles_from_file.retain(|p| !p.starts_with('<'));
                        if !profiles_from_file.is_empty() {
                            usable_profiles_found = true;
                            actual_profiles_to_use = profiles_from_file;
                        } else {
                            usable_profiles_found = false;
                        }
                    }

                    if usable_profiles_found {
                        self.aws_available_profiles = actual_profiles_to_use;
                        self.aws_profile_selection_idx = self
                            .aws_available_profiles
                            .iter()
                            .position(|p| p == "default")
                            .unwrap_or(0);

                        if !self.aws_available_profiles.is_empty() {
                            self.aws_profile_form_data.selected_profile_name =
                                self.aws_available_profiles[self.aws_profile_selection_idx].clone();
                            self.trigger_aws_profile_info_update(
                                self.aws_profile_form_data.selected_profile_name.clone(),
                            )
                            .await;
                        } else {
                            self.aws_profile_form_data.selected_profile_name =
                                "<Unexpected: No profiles after check>".to_string();
                            self.aws_profile_info_loading = false;
                        }
                    } else {
                        self.aws_available_profiles = vec!["<No profiles found>".to_string()];
                        self.aws_profile_selection_idx = 0;
                        self.aws_profile_form_data.selected_profile_name =
                            "<No profiles found>".to_string();
                        self.aws_form_validation_error = Some(
                            "No AWS profiles found or 'default' is not configured. Please create one using AWS CLI.".to_string(),
                        );
                        self.add_log_message_internal(
                            "AWS Profile Setup: No usable AWS profiles detected.".to_string(),
                            MessageLevel::Error,
                        );
                        self.aws_profile_info_loading = false;
                    }
                    self.aws_init_profile_receiver = None;
                }
                Ok(Err(profile_read_error)) => {
                    self.aws_profiles_loading = false;
                    self.aws_profile_info_loading = false;
                    self.aws_init_profile_receiver = None;

                    match profile_read_error {
                        profile_utils::ProfileReadError::NoConfigFilesFound => {
                            self.aws_available_profiles =
                                vec!["<AWS Config Files Missing>".to_string()];
                            self.aws_form_validation_error = Some(
                                "AWS configuration files (~/.aws/config, ~/.aws/credentials) not found. Please set up AWS CLI.".to_string(),
                            );
                            self.add_log_message_internal(
                                "AWS Profile Setup: AWS config files missing.".to_string(),
                                MessageLevel::Error,
                            );
                        }
                        profile_utils::ProfileReadError::Io(e, path) => {
                            self.aws_available_profiles =
                                vec!["<Error loading profiles>".to_string()];
                            self.aws_form_validation_error = Some(format!(
                                "Error reading AWS profile file {:?}: {}. Please check AWS CLI setup.",
                                path, e
                            ));
                            self.add_log_message_internal(
                                format!(
                                    "AWS Profile Setup: Error reading AWS profile file {:?}: {}",
                                    path, e
                                ),
                                MessageLevel::Error,
                            );
                        }
                    }
                    self.aws_profile_selection_idx = 0;
                    self.aws_profile_form_data.selected_profile_name =
                        self.aws_available_profiles[0].clone();
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.aws_profiles_loading = false;
                    self.aws_profile_info_loading = false;
                    self.aws_init_profile_receiver = None;
                    self.add_log_message_internal(
                        "AWS profile loading task disconnected.".to_string(),
                        MessageLevel::Warning,
                    );
                }
            }
        }
    }

    async fn check_for_aws_init_profiles_edit(&mut self) {
        let mut received_message_or_disconnected = false;

        if let Some((receiver, label_to_edit, acc_to_edit_profile_name_opt)) =
            &mut self.aws_init_profile_receiver_for_edit
        {
            match receiver.try_recv() {
                Ok(Ok(mut profiles_from_file)) => {
                    self.aws_profiles_loading = false;
                    let label_to_edit_clone = label_to_edit.clone();
                    let original_profile_name_for_edit = acc_to_edit_profile_name_opt
                        .clone()
                        .unwrap_or_else(|| "default".to_string());

                    let mut usable_profiles_found = false;
                    let mut final_profiles_list = Vec::new();

                    if profiles_from_file.is_empty() {
                        usable_profiles_found = false;
                    } else if profiles_from_file.len() == 1 && profiles_from_file[0] == "default" {
                        if self
                            .is_specific_profile_actually_configured("default")
                            .await
                        {
                            usable_profiles_found = true;
                            final_profiles_list.push("default".to_string());
                        } else {
                            usable_profiles_found = false;
                        }
                    } else {
                        profiles_from_file.retain(|p| !p.starts_with('<'));
                        if !profiles_from_file.is_empty() {
                            usable_profiles_found = true;
                            final_profiles_list = profiles_from_file;
                        } else {
                            usable_profiles_found = false;
                        }
                    }

                    self.aws_profile_form_data.original_dnspx_label =
                        Some(label_to_edit_clone.clone());
                    self.aws_profile_form_data.dnspx_label_input = label_to_edit_clone;

                    if usable_profiles_found {
                        self.aws_available_profiles = final_profiles_list;
                        self.aws_profile_selection_idx = self
                            .aws_available_profiles
                            .iter()
                            .position(|p| p == &original_profile_name_for_edit)
                            .or_else(|| {
                                self.aws_available_profiles
                                    .iter()
                                    .position(|p| p == "default")
                            })
                            .unwrap_or(0);

                        if !self.aws_available_profiles.is_empty() {
                            self.aws_profile_form_data.selected_profile_name =
                                self.aws_available_profiles[self.aws_profile_selection_idx].clone();
                            self.trigger_aws_profile_info_update(
                                self.aws_profile_form_data.selected_profile_name.clone(),
                            )
                            .await;
                        } else {
                            self.aws_profile_form_data.selected_profile_name =
                                "<Unexpected Error>".to_string();
                            self.aws_profile_info_loading = false;
                        }
                    } else {
                        self.aws_available_profiles = vec!["<No profiles found>".to_string()];
                        self.aws_profile_selection_idx = 0;
                        self.aws_profile_form_data.selected_profile_name =
                            "<No profiles found>".to_string();
                        self.aws_form_validation_error = Some(
                            "No AWS profiles found or 'default' is not configured. Cannot edit effectively. Please create one using AWS CLI.".to_string(),
                        );
                        self.add_log_message_internal(
                            "AWS Profile Edit: No usable AWS profiles detected.".to_string(),
                            MessageLevel::Error,
                        );
                        self.aws_profile_info_loading = false;
                    }
                    self.aws_load_field_value_into_input_buffer();
                    received_message_or_disconnected = true;
                }
                Ok(Err(profile_read_error)) => {
                    self.aws_profiles_loading = false;
                    self.aws_profile_info_loading = false;
                    let label_to_edit_clone = label_to_edit.clone();
                    self.aws_profile_form_data.original_dnspx_label =
                        Some(label_to_edit_clone.clone());
                    self.aws_profile_form_data.dnspx_label_input = label_to_edit_clone;

                    match profile_read_error {
                        profile_utils::ProfileReadError::NoConfigFilesFound => {
                            self.aws_available_profiles =
                                vec!["<AWS Config Files Missing>".to_string()];
                            self.aws_form_validation_error = Some(
                                "AWS configuration files (~/.aws/config, ~/.aws/credentials) not found. Cannot edit profile. Please set up AWS CLI.".to_string(),
                            );
                            self.add_log_message_internal(
                                "AWS Profile Edit: AWS config files missing.".to_string(),
                                MessageLevel::Error,
                            );
                        }
                        profile_utils::ProfileReadError::Io(e, path) => {
                            self.aws_available_profiles =
                                vec!["<Error loading profiles>".to_string()];
                            self.aws_form_validation_error = Some(format!(
                                "Error reading AWS profile file {:?}: {}. Cannot edit profile. Please check AWS CLI setup.",
                                path, e
                            ));
                            self.add_log_message_internal(
                                format!(
                                    "AWS Profile Edit: Error reading AWS profile file {:?}: {}",
                                    path, e
                                ),
                                MessageLevel::Error,
                            );
                        }
                    }
                    self.aws_profile_selection_idx = 0;
                    if !self.aws_available_profiles.is_empty() {
                        self.aws_profile_form_data.selected_profile_name =
                            self.aws_available_profiles[0].clone();
                    } else {
                        self.aws_profile_form_data.selected_profile_name =
                            "<Error State>".to_string();
                    }
                    self.aws_load_field_value_into_input_buffer();
                    received_message_or_disconnected = true;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.aws_profiles_loading = false;
                    self.aws_profile_info_loading = false;
                    self.add_log_message_internal(
                        "AWS profile loading task for edit disconnected.".to_string(),
                        MessageLevel::Warning,
                    );
                    received_message_or_disconnected = true;
                }
            }
        }

        if received_message_or_disconnected {
            self.aws_init_profile_receiver_for_edit = None;
        }
    }

    pub async fn trigger_aws_profile_info_update(&mut self, profile_name: String) {
        if profile_name.is_empty() || profile_name.starts_with('<') {
            self.aws_profile_info_loading = false;
            self.aws_profile_form_data.detected_account_id =
                Some("N/A (No profile selected/invalid)".to_string());
            self.aws_profile_form_data.detected_default_region = Some("N/A".to_string());
            self.aws_profile_form_data.detected_mfa_serial = Some("N/A".to_string());
            self.aws_profile_form_data.detected_mfa_role_arn = Some("N/A".to_string());
            return;
        }

        self.aws_profile_info_loading = true;
        self.aws_profile_form_data.detected_account_id = Some("Loading...".to_string());
        self.aws_profile_form_data.detected_default_region = Some("Loading...".to_string());
        self.aws_profile_form_data.detected_mfa_serial = Some("Loading...".to_string());
        self.aws_profile_form_data.detected_mfa_role_arn = Some("Loading...".to_string());

        let app_lifecycle_clone = Arc::clone(&self.app_lifecycle);
        let (tx, rx) = mpsc::channel::<
            Result<
                (
                    Option<String>,
                    Option<String>,
                    Option<String>,
                    Option<String>,
                ),
                String,
            >,
        >(1);
        self.profile_info_update_receiver = Some(rx);

        tokio::spawn(async move {
            if profile_name.is_empty() || profile_name.starts_with('<') {
                if tx
                    .send(Err("Invalid profile name for info update task.".to_string()))
                    .await
                    .is_err()
                {
                    error!("Failed to send error back for invalid profile name in task.");
                }
                return;
            }
            let interaction_port = app_lifecycle_clone.get_user_interaction_port();
            let temp_config_for_check = create_aws_account_config_from_params(AwsConfigParams {
                profile_name: &profile_name,
                label: Some("profile-info-async-check"),
                ..Default::default()
            });

            let result = match app_lifecycle_clone
                .get_aws_config_provider()
                .get_credentials_for_account(&temp_config_for_check, interaction_port)
                .await
            {
                Ok(creds) => {
                    let mut account_id_res = None;
                    let mut region_res = None;

                    match app_lifecycle_clone
                        .get_aws_config_provider()
                        .validate_credentials(&creds)
                        .await
                    {
                        Ok(arn_str) => {
                            if let Some(account_part) = arn_str.split(':').nth(4) {
                                if account_part.chars().all(char::is_numeric)
                                    && account_part.len() == 12
                                {
                                    account_id_res = Some(account_part.to_string());
                                } else {
                                    account_id_res = Some("Error parsing ARN".to_string());
                                }
                            } else {
                                account_id_res = Some("Unknown (ARN format)".to_string());
                            }
                        }
                        Err(_) => {
                            account_id_res = Some("N/A (Auth Error)".to_string());
                        }
                    }

                    let sdk_config_load_result =
                        aws_config::defaults(aws_config::BehaviorVersion::latest())
                            .profile_name(&profile_name)
                            .load()
                            .await;
                    region_res = sdk_config_load_result
                        .region()
                        .map(|r| r.as_ref().to_string());

                    Ok((
                        account_id_res,
                        region_res,
                        Some("Handled by AWS Profile".to_string()),
                        Some("Handled by AWS Profile".to_string()),
                    ))
                }
                Err(e) => Err(format!("Creds error for profile '{}': {}", profile_name, e)),
            };
            if tx.send(result).await.is_err() {
                error!("Failed to send profile info update back to TUI app");
            }
        });
    }

    async fn check_for_profile_info_updates(&mut self) {
        if let Some(receiver) = &mut self.profile_info_update_receiver {
            match receiver.try_recv() {
                Ok(Ok((acc_id, region, mfa_s, mfa_r))) => {
                    self.aws_profile_form_data.detected_account_id = acc_id;
                    self.aws_profile_form_data.detected_default_region = region;
                    self.aws_profile_form_data.detected_mfa_serial = mfa_s;
                    self.aws_profile_form_data.detected_mfa_role_arn = mfa_r;
                    self.aws_profile_info_loading = false;
                    self.profile_info_update_receiver = None;
                    self.add_log_message_internal(
                        "AWS profile info updated.".to_string(),
                        MessageLevel::Info,
                    );
                }
                Ok(Err(e)) => {
                    self.aws_profile_form_data.detected_account_id = Some(format!("Error: {}", e));
                    self.aws_profile_form_data.detected_default_region = Some("Error".to_string());
                    self.aws_profile_form_data.detected_mfa_serial = Some("Error".to_string());
                    self.aws_profile_form_data.detected_mfa_role_arn = Some("Error".to_string());
                    self.aws_profile_info_loading = false;
                    self.profile_info_update_receiver = None;
                    self.add_log_message_internal(
                        format!("Failed to update AWS profile info: {}", e),
                        MessageLevel::Error,
                    );
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.aws_profile_info_loading = false;
                    self.profile_info_update_receiver = None;
                    self.add_log_message_internal(
                        "Profile info update task disconnected.".to_string(),
                        MessageLevel::Warning,
                    );
                }
            }
        }
    }

    fn aws_save_input_buffer_to_field_value(&mut self) {
        let current_input_val = self.aws_form_current_input_buffer.trim().to_string();
        if self.aws_setup_current_field == AwsSetupField::Label {
            self.aws_profile_form_data.dnspx_label_input = current_input_val;
        }
    }

    fn aws_load_field_value_into_input_buffer(&mut self) {
        self.aws_form_current_input_buffer = match self.aws_setup_current_field {
            AwsSetupField::Label => self.aws_profile_form_data.dnspx_label_input.clone(),
            AwsSetupField::AuthMethod
            | AwsSetupField::AwsProfile
            | AwsSetupField::TestConnectionCheckbox
            | AwsSetupField::TestConnectionButton
            | AwsSetupField::SaveButton
            | AwsSetupField::CancelButton => String::new(),
        };
    }

    fn aws_get_field_order(&self) -> Vec<AwsSetupField> {
        let mut order = vec![AwsSetupField::Label, AwsSetupField::AuthMethod];

        if self.aws_selected_auth_method == AwsAuthMethod::AwsProfile {
            order.push(AwsSetupField::AwsProfile);
        }

        order.extend(&[
            AwsSetupField::TestConnectionCheckbox,
            AwsSetupField::TestConnectionButton,
            AwsSetupField::SaveButton,
            AwsSetupField::CancelButton,
        ]);
        order
    }

    fn aws_next_field(&mut self) {
        self.aws_save_input_buffer_to_field_value();
        let order = self.aws_get_field_order();
        let current_idx = order
            .iter()
            .position(|&f| f == self.aws_setup_current_field)
            .unwrap_or(0);
        let next_idx = (current_idx + 1) % order.len();
        self.aws_setup_current_field = order[next_idx];
        self.aws_load_field_value_into_input_buffer();
        self.aws_form_validation_error = None;
    }

    fn aws_prev_field(&mut self) {
        self.aws_save_input_buffer_to_field_value();
        let order = self.aws_get_field_order();
        let current_idx = order
            .iter()
            .position(|&f| f == self.aws_setup_current_field)
            .unwrap_or(0);
        let prev_idx = if current_idx == 0 {
            order.len() - 1
        } else {
            current_idx - 1
        };
        self.aws_setup_current_field = order[prev_idx];
        self.aws_load_field_value_into_input_buffer();
        self.aws_form_validation_error = None;
    }

    async fn aws_handle_profile_dropdown_select(&mut self) {
        if self.aws_profile_dropdown_open {
            if !self.aws_available_profiles.is_empty()
                && !self.aws_available_profiles[0].starts_with('<')
            {
                if let Some(selected_profile) = self
                    .aws_available_profiles
                    .get(self.aws_profile_selection_idx)
                {
                    self.aws_profile_form_data.selected_profile_name = selected_profile.clone();
                    self.trigger_aws_profile_info_update(selected_profile.clone())
                        .await;
                }
            }
            self.aws_profile_dropdown_open = false;
            self.aws_next_field();
        } else {
            self.aws_profile_dropdown_open = true;
            self.aws_form_current_input_buffer.clear();
        }
    }

    async fn handle_aws_profile_form_input(&mut self, key_event: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let no_profiles_error_active = self.aws_form_validation_error.as_deref()
            == Some(
                "No AWS profiles found or 'default' is not configured. Please create one using AWS CLI.",
            );
        let no_profiles_error_loading_active = self
            .aws_form_validation_error
            .as_deref()
            .is_some_and(|s| s.starts_with("Failed to read AWS profiles"));
        let no_profiles_config_files_missing_active = self
            .aws_form_validation_error
            .as_deref()
            .is_some_and(|s| s.starts_with("AWS configuration files"));

        if no_profiles_error_active
            || no_profiles_error_loading_active
            || no_profiles_config_files_missing_active
        {
            match key_event.code {
                KeyCode::Esc => self.aws_cancel_form(),
                KeyCode::Enter => {
                    self.aws_setup_current_field = AwsSetupField::CancelButton;
                    self.aws_cancel_form();
                }
                KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right | KeyCode::Tab => {}
                _ => {}
            }
            return;
        }

        if key_event.code == KeyCode::Esc {
            if self.aws_profile_dropdown_open {
                self.aws_profile_dropdown_open = false;
                return;
            }
            self.aws_cancel_form();
            return;
        }

        if self.aws_profile_dropdown_open
            && self.aws_setup_current_field == AwsSetupField::AwsProfile
        {
            match key_event.code {
                KeyCode::Up => {
                    self.aws_profile_selection_idx =
                        self.aws_profile_selection_idx.saturating_sub(1)
                }
                KeyCode::Down => {
                    if self.aws_profile_selection_idx
                        < self.aws_available_profiles.len().saturating_sub(1)
                    {
                        self.aws_profile_selection_idx += 1;
                    }
                }
                KeyCode::Enter => self.aws_handle_profile_dropdown_select().await,
                KeyCode::Char(c) => {
                    self.aws_form_current_input_buffer.push(c);
                    let lower_input = self.aws_form_current_input_buffer.to_lowercase();
                    if let Some(idx) = self
                        .aws_available_profiles
                        .iter()
                        .position(|p| p.to_lowercase().starts_with(&lower_input))
                    {
                        self.aws_profile_selection_idx = idx;
                    }
                }
                KeyCode::Backspace => {
                    self.aws_form_current_input_buffer.pop();
                    let lower_input = self.aws_form_current_input_buffer.to_lowercase();
                    if let Some(idx) = self
                        .aws_available_profiles
                        .iter()
                        .position(|p| p.to_lowercase().starts_with(&lower_input))
                    {
                        self.aws_profile_selection_idx = idx;
                    } else if self.aws_form_current_input_buffer.is_empty() {
                        self.aws_profile_selection_idx = self
                            .aws_available_profiles
                            .iter()
                            .position(|p| p == "default")
                            .unwrap_or(0);
                    }
                }
                _ => {}
            }
        } else {
            match key_event.code {
                KeyCode::Tab => {
                    if key_event.modifiers == crossterm::event::KeyModifiers::SHIFT {
                        self.aws_prev_field();
                    } else {
                        self.aws_next_field();
                    }
                }
                KeyCode::Up => {
                    if self.aws_setup_current_field == AwsSetupField::AuthMethod {
                        self.aws_selected_auth_method = self.aws_selected_auth_method.prev();
                    } else {
                        self.aws_prev_field();
                    }
                }
                KeyCode::Down => {
                    if self.aws_setup_current_field == AwsSetupField::AuthMethod {
                        self.aws_selected_auth_method = self.aws_selected_auth_method.next();
                    } else {
                        self.aws_next_field();
                    }
                }
                KeyCode::Enter => match self.aws_setup_current_field {
                    AwsSetupField::AuthMethod => self.aws_next_field(),
                    AwsSetupField::AwsProfile => self.aws_handle_profile_dropdown_select().await,
                    AwsSetupField::TestConnectionCheckbox => {
                        self.aws_form_test_connection_checked =
                            !self.aws_form_test_connection_checked
                    }
                    AwsSetupField::SaveButton => self.aws_save_profile_form_data().await,
                    AwsSetupField::TestConnectionButton => {
                        self.aws_run_profile_connection_test().await
                    }
                    AwsSetupField::CancelButton => self.aws_cancel_form(),
                    _ => self.aws_next_field(),
                },
                KeyCode::Char(c) => {
                    if self.aws_setup_current_field == AwsSetupField::Label {
                        self.aws_form_current_input_buffer.push(c);
                    }
                }
                KeyCode::Backspace => {
                    if self.aws_setup_current_field == AwsSetupField::Label {
                        self.aws_form_current_input_buffer.pop();
                    }
                }
                _ => {}
            }
        }
    }

    async fn aws_run_profile_connection_test(&mut self) {
        self.aws_save_input_buffer_to_field_value();
        self.aws_form_validation_error = None;

        if self
            .aws_profile_form_data
            .selected_profile_name
            .starts_with('<')
        {
            self.aws_form_validation_error =
                Some("Bitte zuerst ein gültiges AWS Profil auswählen.".to_string());
            self.aws_setup_current_field = AwsSetupField::AwsProfile;
            return;
        }
        let profile_name_to_test = self.aws_profile_form_data.selected_profile_name.clone();

        self.add_log_message_internal(
            format!(
                "Teste AWS Verbindung für Profil: {}...",
                profile_name_to_test
            ),
            MessageLevel::Info,
        );
        self.aws_connection_testing = true;

        let app_lifecycle_clone = Arc::clone(&self.app_lifecycle);
        let (tx, rx) = mpsc::channel::<Result<String, AwsAuthError>>(1);
        self.connection_test_receiver = Some(rx);

        tokio::spawn(async move {
            let temp_config = create_aws_account_config_from_params(AwsConfigParams {
                profile_name: &profile_name_to_test,
                label: Some("connection-test-async"),
                ..Default::default()
            });
            let interaction_port = app_lifecycle_clone.get_user_interaction_port();
            let result = match app_lifecycle_clone
                .get_aws_config_provider()
                .get_credentials_for_account(&temp_config, interaction_port)
                .await
            {
                Ok(creds) => {
                    app_lifecycle_clone
                        .get_aws_config_provider()
                        .validate_credentials(&creds)
                        .await
                }
                Err(e) => Err(e),
            };
            if tx.send(result).await.is_err() {
                error!("Failed to send connection test result to TUI app");
            }
        });
    }

    async fn check_for_connection_test_result(&mut self) {
        let mut received_message = false;
        let mut disconnected = false;

        if let Some(receiver) = &mut self.connection_test_receiver {
            match receiver.try_recv() {
                Ok(Ok(arn)) => {
                    self.add_log_message_internal(
                        format!("AWS Verbindungstest erfolgreich! ARN: {}", arn),
                        MessageLevel::Info,
                    );
                    if let Some(parts) = arn.split(':').nth(4) {
                        if parts.chars().all(char::is_numeric) && parts.len() == 12 {
                            self.aws_profile_form_data.detected_account_id =
                                Some(parts.to_string());
                        }
                    }
                    let profile_name_for_sdk_load =
                        self.aws_profile_form_data.selected_profile_name.clone();
                    if !profile_name_for_sdk_load.starts_with('<') {
                        let sdk_config_load_result =
                            aws_config::defaults(aws_config::BehaviorVersion::latest())
                                .profile_name(&profile_name_for_sdk_load)
                                .load()
                                .await;
                        self.aws_profile_form_data.detected_default_region = sdk_config_load_result
                            .region()
                            .map(|r| r.as_ref().to_string());
                    } else {
                        self.aws_profile_form_data.detected_default_region =
                            Some("N/A (Invalid Profile)".to_string());
                    }
                    self.aws_form_validation_error = None;
                    received_message = true;
                }
                Ok(Err(e)) => {
                    self.aws_form_validation_error =
                        Some(format!("Verbindungstest fehlgeschlagen: {}", e));
                    self.add_log_message_internal(
                        format!("AWS Verbindungstest fehlgeschlagen: {}", e),
                        MessageLevel::Error,
                    );
                    received_message = true;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.add_log_message_internal(
                        "Connection test task disconnected.".to_string(),
                        MessageLevel::Warning,
                    );
                    disconnected = true;
                }
            }
        }

        if received_message || disconnected {
            self.aws_connection_testing = false;
            self.connection_test_receiver = None;
        }
    }

    async fn aws_save_profile_form_data(&mut self) {
        self.aws_save_input_buffer_to_field_value();
        self.aws_form_validation_error = None;

        if self.aws_profile_form_data.dnspx_label_input.is_empty() {
            self.aws_form_validation_error = Some("Label darf nicht leer sein.".to_string());
            self.aws_setup_current_field = AwsSetupField::Label;
            self.aws_load_field_value_into_input_buffer();
            return;
        }

        if self
            .aws_profile_form_data
            .selected_profile_name
            .starts_with('<')
            || self.aws_available_profiles.is_empty()
            || (self.aws_available_profiles.len() == 1
                && self.aws_available_profiles[0].starts_with('<'))
        {
            self.aws_form_validation_error = Some(
                "Kein gültiges AWS Profil ausgewählt oder Profile nicht ladbar. Bitte AWS CLI Konfiguration prüfen.".to_string(),
            );
            self.aws_setup_current_field = AwsSetupField::AwsProfile;
            return;
        }

        let app_config_arc = self.app_lifecycle.get_config();
        let config_guard = app_config_arc.read().await;
        if let Some(aws_conf) = &config_guard.aws {
            if aws_conf.accounts.iter().any(|acc| {
                acc.label == self.aws_profile_form_data.dnspx_label_input
                    && Some(&acc.label) != self.aws_profile_form_data.original_dnspx_label.as_ref()
            }) {
                self.aws_form_validation_error = Some(format!(
                    "Label '{}' existiert bereits.",
                    self.aws_profile_form_data.dnspx_label_input
                ));
                self.aws_setup_current_field = AwsSetupField::Label;
                self.aws_load_field_value_into_input_buffer();
                drop(config_guard);
                return;
            }
        }
        drop(config_guard);

        if self.aws_form_test_connection_checked {
            self.aws_run_profile_connection_test().await;

            let mut timeout_counter = 0;
            while self.aws_connection_testing && timeout_counter < 100 {
                self.check_for_connection_test_result().await;
                if !self.aws_connection_testing {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                timeout_counter += 1;
            }
            if self.aws_connection_testing {
                self.aws_form_validation_error =
                    Some("Verbindungstest Zeitüberschreitung.".to_string());
                self.aws_connection_testing = false;
                return;
            }

            if self.aws_form_validation_error.is_some() {
                return;
            }

            if self.aws_profile_form_data.detected_account_id.is_none()
                || self
                    .aws_profile_form_data
                    .detected_account_id
                    .as_ref()
                    .is_some_and(|s| s.starts_with("N/A") || s.starts_with("Error"))
            {
                self.aws_form_validation_error = Some(
                    "Verbindungstest erfolgreich, aber Account ID konnte nicht ermittelt werden. Profil prüfen.".to_string(),
                );
                return;
            }
        }

        let submit_data = self.create_submit_data();

        match self
            .app_lifecycle
            .add_or_update_aws_account_config(
                submit_data,
                self.aws_profile_form_data.original_dnspx_label.clone(),
            )
            .await
        {
            Ok(_) => {
                self.add_log_message_internal(
                    format!(
                        "AWS Account '{}' erfolgreich gespeichert.",
                        self.aws_profile_form_data.dnspx_label_input
                    ),
                    MessageLevel::Info,
                );
                self.aws_cancel_form();
                if let Err(e) = self.app_lifecycle.trigger_aws_scan_refresh().await {
                    self.add_log_message_internal(
                        format!("Fehler beim Starten des AWS Scans: {}", e),
                        MessageLevel::Error,
                    );
                }
            }
            Err(e) => {
                self.add_log_message_internal(
                    format!("Fehler beim Speichern der AWS Konfiguration: {}", e),
                    MessageLevel::Error,
                );
                self.aws_form_validation_error = Some(format!("Speicherfehler: {}", e));
            }
        }
    }

    fn create_submit_data(&self) -> AwsAccountSubmitData {
        let label = self
            .aws_profile_form_data
            .dnspx_label_input
            .trim()
            .to_string();
        let profile_name = Some(self.aws_profile_form_data.selected_profile_name.clone());

        AwsAccountConfig {
            label,
            profile_name,
            account_id: None,
            scan_regions: None,
            scan_vpc_ids: Vec::new(),
            roles_to_assume: Vec::new(),
            discover_services: AwsServiceDiscoveryConfig::default(),
        }
    }

    fn aws_cancel_form(&mut self) {
        self.input_mode = InputMode::Normal;
        self.aws_form_current_input_buffer.clear();
        self.aws_form_validation_error = None;
        self.aws_profile_dropdown_open = false;
        self.aws_profiles_loading = false;
        self.aws_profile_info_loading = false;
        self.aws_connection_testing = false;
        self.profile_info_update_receiver = None;
        self.connection_test_receiver = None;
        self.aws_init_profile_receiver = None;
        self.aws_init_profile_receiver_for_edit = None;
        self.add_log_message_internal(
            "AWS Profile Setup abgebrochen.".to_string(),
            MessageLevel::Info,
        );
    }

    pub async fn run(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
        mut event_manager: EventManager,
    ) -> anyhow::Result<()> {
        self.status_cache = Some(self.app_lifecycle.get_app_status().await);
        self.total_queries_for_ui = self.app_lifecycle.get_total_queries_processed().await;
        self.last_query_count_for_qps = self.total_queries_for_ui;
        self.last_qps_calculation_time = Instant::now();

        info!("TUI run loop started.");
        loop {
            if self.app_lifecycle.get_cancellation_token().is_cancelled() {
                self.should_quit = true;
            }
            if self.should_quit {
                info!("TUI: should_quit is true. Exiting run loop.");
                break;
            }

            while let Ok((message, level)) = self.log_rx_from_trace.try_recv() {
                self.add_log_message_internal(message, level);
            }

            self.check_for_aws_init_profiles_add().await;
            self.check_for_aws_init_profiles_edit().await;
            self.check_for_profile_info_updates().await;
            self.check_for_connection_test_result().await;

            terminal.draw(|frame| ui::draw(frame, self))?;

            match tokio::time::timeout(
                std::time::Duration::from_millis(50),
                event_manager.next_event(),
            )
            .await
            {
                Ok(Some(AppEvent::Input(key_event))) => {
                    let mut event_consumed = false;
                    if self.input_mode != InputMode::AwsProfileSetupForm
                        || (self.aws_form_validation_error.is_none()
                            || !(self.aws_form_validation_error.as_deref()
                                == Some(
                                    "No AWS profiles found or 'default' is not configured. Please create one using AWS CLI.",
                                )
                                || self
                                    .aws_form_validation_error
                                    .as_deref()
                                    .is_some_and(|s| s.starts_with("Failed to read AWS profiles"))
                                || self
                                    .aws_form_validation_error
                                    .as_deref()
                                    .is_some_and(|s| s.starts_with("AWS configuration files"))))
                    {
                        self.aws_form_validation_error = None;
                    }
                    self.cache_add_error = None;

                    if key_event.code == crossterm::event::KeyCode::Esc {
                        if self.show_help_popup {
                            self.show_help_popup = false;
                            event_consumed = true;
                        } else if self.show_license_popup {
                            self.show_license_popup = false;
                            self.license_popup_scroll_offset = 0;
                            event_consumed = true;
                        } else if self.show_releasenotes_popup {
                            self.show_releasenotes_popup = false;
                            self.releasenotes_popup_scroll_offset = 0;
                            event_consumed = true;
                        } else if self.show_confirm_delete_cache_modal {
                            self.show_confirm_delete_cache_modal = false;
                            self.cache_entry_to_delete = None;
                            event_consumed = true;
                        } else if self.show_add_cache_entry_modal {
                            self.handle_add_cache_escape();
                            event_consumed = true;
                        } else if self.input_mode == InputMode::AwsProfileSetupForm {
                            if self.aws_profile_dropdown_open {
                                self.aws_profile_dropdown_open = false;
                                event_consumed = true;
                            } else {
                                self.aws_cancel_form();
                                event_consumed = true;
                            }
                        } else if self.show_cache_viewer
                            && self.input_mode == InputMode::CacheViewFilterInput
                        {
                            self.input_mode = InputMode::Normal;
                            event_consumed = true;
                        } else if self.show_cache_viewer {
                            self.show_cache_viewer = false;
                            self.input_mode = InputMode::Normal;
                            self.cache_view_filter.clear();
                            event_consumed = true;
                        }
                        if event_consumed {
                            continue;
                        }
                    }

                    if self.show_license_popup {
                        match key_event.code {
                            crossterm::event::KeyCode::Up => {
                                self.license_popup_scroll_offset =
                                    self.license_popup_scroll_offset.saturating_sub(1);
                            }
                            crossterm::event::KeyCode::Down => {
                                let total_lines = self.license_text_lines.len();
                                let view_height = self.license_popup_content_area_height as usize;
                                if total_lines > view_height && view_height > 0 {
                                    let max_scroll = (total_lines - view_height) as u16;
                                    self.license_popup_scroll_offset = self
                                        .license_popup_scroll_offset
                                        .saturating_add(1)
                                        .min(max_scroll);
                                }
                            }
                            crossterm::event::KeyCode::PageUp => {
                                let page_size = self
                                    .license_popup_content_area_height
                                    .saturating_sub(1)
                                    .max(1);
                                self.license_popup_scroll_offset =
                                    self.license_popup_scroll_offset.saturating_sub(page_size);
                            }
                            crossterm::event::KeyCode::PageDown => {
                                let page_size = self
                                    .license_popup_content_area_height
                                    .saturating_sub(1)
                                    .max(1);
                                let total_lines = self.license_text_lines.len();
                                let view_height = self.license_popup_content_area_height as usize;
                                if total_lines > view_height && view_height > 0 {
                                    let max_scroll = (total_lines - view_height) as u16;
                                    self.license_popup_scroll_offset = self
                                        .license_popup_scroll_offset
                                        .saturating_add(page_size)
                                        .min(max_scroll);
                                }
                            }
                            crossterm::event::KeyCode::Home => {
                                self.license_popup_scroll_offset = 0;
                            }
                            crossterm::event::KeyCode::End => {
                                let total_lines = self.license_text_lines.len();
                                let view_height = self.license_popup_content_area_height as usize;
                                if total_lines > view_height && view_height > 0 {
                                    self.license_popup_scroll_offset =
                                        (total_lines - view_height) as u16;
                                } else {
                                    self.license_popup_scroll_offset = 0;
                                }
                            }
                            _ => {}
                        }
                        event_consumed = true;
                    } else if self.show_releasenotes_popup {
                        match key_event.code {
                            crossterm::event::KeyCode::Up => {
                                self.releasenotes_popup_scroll_offset =
                                    self.releasenotes_popup_scroll_offset.saturating_sub(1);
                            }
                            crossterm::event::KeyCode::Down => {
                                let total_lines = self.release_notes_lines.len();
                                let view_height =
                                    self.releasenotes_popup_content_area_height as usize;

                                if total_lines > view_height && view_height > 0 {
                                    let max_scroll = (total_lines - view_height) as u16;
                                    self.releasenotes_popup_scroll_offset = self
                                        .releasenotes_popup_scroll_offset
                                        .saturating_add(1)
                                        .min(max_scroll);
                                }
                            }
                            crossterm::event::KeyCode::PageUp => {
                                let page_size = self
                                    .releasenotes_popup_content_area_height
                                    .saturating_sub(1)
                                    .max(1);
                                self.releasenotes_popup_scroll_offset = self
                                    .releasenotes_popup_scroll_offset
                                    .saturating_sub(page_size);
                            }
                            crossterm::event::KeyCode::PageDown => {
                                let page_size = self
                                    .releasenotes_popup_content_area_height
                                    .saturating_sub(1)
                                    .max(1);
                                let total_lines = self.release_notes_lines.len();
                                let view_height =
                                    self.releasenotes_popup_content_area_height as usize;
                                if total_lines > view_height && view_height > 0 {
                                    let max_scroll = (total_lines - view_height) as u16;
                                    self.releasenotes_popup_scroll_offset = self
                                        .releasenotes_popup_scroll_offset
                                        .saturating_add(page_size)
                                        .min(max_scroll);
                                }
                            }
                            crossterm::event::KeyCode::Home => {
                                self.releasenotes_popup_scroll_offset = 0;
                            }
                            crossterm::event::KeyCode::End => {
                                let total_lines = self.release_notes_lines.len();
                                let view_height =
                                    self.releasenotes_popup_content_area_height as usize;
                                if total_lines > view_height && view_height > 0 {
                                    self.releasenotes_popup_scroll_offset =
                                        (total_lines - view_height) as u16;
                                } else {
                                    self.releasenotes_popup_scroll_offset = 0;
                                }
                            }
                            _ => {}
                        }
                        event_consumed = true;
                    } else if self.input_mode == InputMode::AwsProfileSetupForm {
                        self.handle_aws_profile_form_input(key_event).await;
                    } else if self.show_cache_viewer
                        && !self.show_add_cache_entry_modal
                        && !self.show_confirm_delete_cache_modal
                    {
                        self.handle_cache_viewer_input(key_event).await;
                    } else if self.show_add_cache_entry_modal {
                        self.handle_add_cache_input(key_event).await;
                    } else if self.show_confirm_delete_cache_modal {
                        self.handle_confirm_delete_cache_input(key_event).await;
                    } else {
                        if is_quit_event(&key_event) {
                            info!("TUI: Quit event received. Initiating shutdown.");
                            self.should_quit = true;
                            let app_lifecycle_clone = Arc::clone(&self.app_lifecycle);
                            tokio::spawn(async move {
                                app_lifecycle_clone.stop().await;
                            });
                            continue;
                        }
                        match key_event.code {
                            crossterm::event::KeyCode::Char('h')
                            | crossterm::event::KeyCode::Char('?') => {
                                self.show_help_popup = !self.show_help_popup
                            }
                            crossterm::event::KeyCode::Char('l')
                                if key_event
                                    .modifiers
                                    .contains(crossterm::event::KeyModifiers::CONTROL) =>
                            {
                                self.show_license_popup = !self.show_license_popup;
                                if self.show_license_popup {
                                    self.license_popup_scroll_offset = 0;
                                }
                            }
                            crossterm::event::KeyCode::Char('n')
                                if key_event
                                    .modifiers
                                    .contains(crossterm::event::KeyModifiers::CONTROL) =>
                            {
                                self.show_releasenotes_popup = !self.show_releasenotes_popup;
                                if self.show_releasenotes_popup {
                                    self.releasenotes_popup_scroll_offset = 0;
                                    self.clamp_release_notes_scroll();
                                }
                            }
                            crossterm::event::KeyCode::Char('v')
                                if key_event
                                    .modifiers
                                    .contains(crossterm::event::KeyModifiers::CONTROL) =>
                            {
                                self.show_cache_viewer = !self.show_cache_viewer;
                                if self.show_cache_viewer {
                                    self.load_cache_items_for_view().await;
                                } else {
                                    self.input_mode = InputMode::Normal;
                                    self.cache_view_filter.clear();
                                }
                            }
                            crossterm::event::KeyCode::Char('a')
                                if key_event
                                    .modifiers
                                    .contains(crossterm::event::KeyModifiers::CONTROL) =>
                            {
                                if self.input_mode == InputMode::Normal && !self.show_cache_viewer {
                                    self.toggle_status_panel_view();
                                    event_consumed = true;
                                }
                            }
                            crossterm::event::KeyCode::Char('r')
                                if key_event
                                    .modifiers
                                    .contains(crossterm::event::KeyModifiers::CONTROL) =>
                            {
                                let (config_exists_and_has_accounts, first_label_opt) = {
                                    let app_config = self.app_lifecycle.get_config();
                                    let config_guard = app_config.read().await;
                                    let aws_conf_opt = config_guard.aws.as_ref();
                                    let acc_exist = aws_conf_opt
                                        .is_some_and(|a_cfg| !a_cfg.accounts.is_empty());

                                    let label_opt = if acc_exist {
                                        aws_conf_opt.and_then(|a_cfg| {
                                            a_cfg.accounts.first().map(|acc| acc.label.clone())
                                        })
                                    } else {
                                        None
                                    };
                                    (acc_exist, label_opt)
                                };

                                if config_exists_and_has_accounts {
                                    if let Some(label) = first_label_opt {
                                        self.aws_init_profile_form_for_edit(&label).await;
                                    } else {
                                        self.add_log_message_internal(
                                            "AWS config exists but no accounts found or first account has no label. Opening add form.".to_string(),
                                            MessageLevel::Warning
                                        );
                                        self.aws_init_profile_form_for_add().await;
                                    }
                                } else {
                                    self.aws_init_profile_form_for_add().await;
                                }
                                event_consumed = true;
                            }
                            crossterm::event::KeyCode::Char('r') => {
                                self.add_log_message_internal(
                                    "Triggering Config Reload...".to_string(),
                                    MessageLevel::Info,
                                );
                                if let Err(e) = self.app_lifecycle.trigger_config_reload().await {
                                    self.add_log_message_internal(
                                        format!("Failed to trigger config reload: {}", e),
                                        MessageLevel::Error,
                                    );
                                }
                            }
                            crossterm::event::KeyCode::Char('c') => {
                                self.app_lifecycle.get_dns_cache().clear_all().await;
                                self.add_log_message_internal(
                                    "DNS Cache cleared.".to_string(),
                                    MessageLevel::Info,
                                );
                                if self.show_cache_viewer {
                                    self.load_cache_items_for_view().await;
                                }
                            }
                            crossterm::event::KeyCode::Char('s') => {
                                self.status_cache = Some(self.app_lifecycle.get_app_status().await);
                                self.total_queries_for_ui =
                                    self.app_lifecycle.get_total_queries_processed().await;
                                self.add_log_message_internal(
                                    "Status panel manually refreshed.".to_string(),
                                    MessageLevel::Debug,
                                );
                            }
                            crossterm::event::KeyCode::Char('d') => {
                                self.tui_log_filter_level = self.tui_log_filter_level.next_level();
                                self.add_log_message_internal(
                                    format!(
                                        "Log filter level set to: {:?}",
                                        self.tui_log_filter_level
                                    ),
                                    MessageLevel::Debug,
                                );
                                self.log_scroll_offset = 0;
                                self.log_follow_mode = true;
                                self.scroll_to_log_end();
                            }
                            crossterm::event::KeyCode::Up => self.log_scroll_up(1),
                            crossterm::event::KeyCode::Down => self.log_scroll_down(1),
                            crossterm::event::KeyCode::PageUp => self.log_scroll_up(
                                self.log_panel_actual_height.saturating_sub(1).max(1),
                            ),
                            crossterm::event::KeyCode::PageDown => self.log_scroll_down(
                                self.log_panel_actual_height.saturating_sub(1).max(1),
                            ),
                            crossterm::event::KeyCode::Home => {
                                self.log_scroll_offset = 0;
                                self.log_follow_mode = false;
                            }
                            crossterm::event::KeyCode::End => {
                                self.log_follow_mode = true;
                                self.scroll_to_log_end();
                            }
                            _ => {}
                        }
                        if event_consumed {
                            continue;
                        }
                    }
                }
                Ok(Some(AppEvent::Tick)) => {
                    self.status_cache = Some(self.app_lifecycle.get_app_status().await);
                    let queries_now = self.app_lifecycle.get_total_queries_processed().await;
                    self.total_queries_for_ui = queries_now;
                    let now = Instant::now();
                    let duration_since_last_qps = now
                        .duration_since(self.last_qps_calculation_time)
                        .as_secs_f32();
                    if duration_since_last_qps > 0.5 {
                        let query_delta = queries_now.saturating_sub(self.last_query_count_for_qps);
                        self.current_qps = if duration_since_last_qps > 1e-9 {
                            query_delta as f32 / duration_since_last_qps
                        } else {
                            0.0
                        };
                        self.last_query_count_for_qps = queries_now;
                        self.last_qps_calculation_time = now;
                    }
                    if self.show_cache_viewer
                        && !self.show_add_cache_entry_modal
                        && !self.show_confirm_delete_cache_modal
                    {
                        self.load_cache_items_for_view().await;
                    }
                }
                Ok(Some(AppEvent::Command(cmd))) => {
                    if let Some(tx) = &self.event_tx_to_worker {
                        if let Err(e) = tx.send(cmd).await {
                            error!("Failed to send command to TUI worker: {}", e);
                            self.add_log_message_internal(
                                format!("Error sending command to worker: {}", e),
                                MessageLevel::Error,
                            );
                        }
                    } else {
                        self.add_log_message_internal(
                            format!("Cannot process command {:?}: No worker.", cmd),
                            MessageLevel::Warning,
                        );
                    }
                }
                Ok(None) => self.should_quit = true,
                Err(_) => {}
            }
        }
        info!("TUI run loop finished cleanly.");
        Ok(())
    }

    async fn load_cache_items_for_view(&mut self) {
        self.cache_view_full_list = self
            .app_lifecycle
            .get_dns_cache()
            .get_all_active_entries()
            .await;
        self.apply_cache_filter_and_update_view();
        if self.cache_view_selected_index >= self.cache_view_items.len() {
            self.cache_view_selected_index = self.cache_view_items.len().saturating_sub(1);
        }
        if self.cache_view_items.is_empty() {
            self.cache_view_selected_index = 0;
        }
        self.adjust_cache_view_scroll();
    }

    fn apply_cache_filter_and_update_view(&mut self) {
        if self.cache_view_filter.is_empty() {
            self.cache_view_items = self.cache_view_full_list.clone();
        } else {
            let filter_lower = self.cache_view_filter.to_lowercase();
            self.cache_view_items = self
                .cache_view_full_list
                .iter()
                .filter(|(key, entry)| {
                    key.name.to_lowercase().contains(&filter_lower)
                        || format!("{:?}", key.record_type)
                            .to_lowercase()
                            .contains(&filter_lower)
                        || entry.records.iter().any(|r| {
                            format!("{:?}", r.data())
                                .to_lowercase()
                                .contains(&filter_lower)
                        })
                })
                .cloned()
                .collect();
        }
        if self.cache_view_selected_index >= self.cache_view_items.len() {
            self.cache_view_selected_index = self.cache_view_items.len().saturating_sub(1);
        }
        if self.cache_view_items.is_empty() {
            self.cache_view_selected_index = 0;
        }
        self.adjust_cache_view_scroll();
    }

    fn adjust_cache_view_scroll(&mut self) {
        if self.cache_panel_actual_height > 0 && !self.cache_view_items.is_empty() {
            let selected = self.cache_view_selected_index as u16;
            let panel_height = self.cache_panel_actual_height;
            if selected < self.cache_view_scroll_offset {
                self.cache_view_scroll_offset = selected;
            } else if selected >= self.cache_view_scroll_offset + panel_height {
                self.cache_view_scroll_offset = selected - panel_height + 1;
            }
            let max_possible_scroll = self
                .cache_view_items
                .len()
                .saturating_sub(panel_height as usize)
                .max(0) as u16;
            self.cache_view_scroll_offset = self.cache_view_scroll_offset.min(max_possible_scroll);
        } else {
            self.cache_view_scroll_offset = 0;
        }
    }

    async fn handle_cache_viewer_input(&mut self, key_event: crossterm::event::KeyEvent) {
        match self.input_mode {
            InputMode::CacheViewFilterInput => match key_event.code {
                crossterm::event::KeyCode::Enter | crossterm::event::KeyCode::Esc => {
                    self.input_mode = InputMode::Normal
                }
                crossterm::event::KeyCode::Char(c) => {
                    self.cache_view_filter.push(c);
                    self.apply_cache_filter_and_update_view();
                }
                crossterm::event::KeyCode::Backspace => {
                    self.cache_view_filter.pop();
                    self.apply_cache_filter_and_update_view();
                }
                _ => {}
            },
            InputMode::Normal => {
                match key_event.code {
                    crossterm::event::KeyCode::Up => {
                        self.cache_view_selected_index =
                            self.cache_view_selected_index.saturating_sub(1)
                    }
                    crossterm::event::KeyCode::Down => {
                        if !self.cache_view_items.is_empty() {
                            self.cache_view_selected_index = (self.cache_view_selected_index + 1)
                                .min(self.cache_view_items.len() - 1);
                        }
                    }
                    crossterm::event::KeyCode::PageUp => {
                        let page_size =
                            self.cache_panel_actual_height.saturating_sub(1).max(1) as usize;
                        self.cache_view_selected_index =
                            self.cache_view_selected_index.saturating_sub(page_size);
                    }
                    crossterm::event::KeyCode::PageDown => {
                        if !self.cache_view_items.is_empty() {
                            let page_size =
                                self.cache_panel_actual_height.saturating_sub(1).max(1) as usize;
                            self.cache_view_selected_index = (self.cache_view_selected_index
                                + page_size)
                                .min(self.cache_view_items.len().saturating_sub(1).max(0));
                        }
                    }
                    crossterm::event::KeyCode::Home => self.cache_view_selected_index = 0,
                    crossterm::event::KeyCode::End => {
                        if !self.cache_view_items.is_empty() {
                            self.cache_view_selected_index = self.cache_view_items.len() - 1;
                        }
                    }
                    crossterm::event::KeyCode::Char('/') => {
                        self.input_mode = InputMode::CacheViewFilterInput
                    }
                    crossterm::event::KeyCode::Delete | crossterm::event::KeyCode::Char('d') => {
                        if let Some((key, _)) =
                            self.cache_view_items.get(self.cache_view_selected_index)
                        {
                            self.cache_entry_to_delete = Some(key.clone());
                            self.show_confirm_delete_cache_modal = true;
                        }
                    }
                    crossterm::event::KeyCode::Char('a') | crossterm::event::KeyCode::Insert => {
                        self.pending_cache_add_data = SyntheticCacheAddData::default();
                        self.set_add_cache_step(Some(CacheAddStep::PromptName));
                        self.show_add_cache_entry_modal = true;
                        self.cache_add_type_selection_idx = 0;
                    }
                    _ => {}
                }
                self.adjust_cache_view_scroll();
            }
            _ => {}
        }
    }

    async fn handle_confirm_delete_cache_input(&mut self, key_event: crossterm::event::KeyEvent) {
        match key_event.code {
            crossterm::event::KeyCode::Char('y')
            | crossterm::event::KeyCode::Char('Y')
            | crossterm::event::KeyCode::Enter => {
                if let Some(key) = self.cache_entry_to_delete.take() {
                    self.app_lifecycle.get_dns_cache().remove(&key).await;
                    self.add_log_message_internal(
                        format!("Cache entry {:?} deleted.", key),
                        MessageLevel::Info,
                    );
                }
                self.show_confirm_delete_cache_modal = false;
                self.load_cache_items_for_view().await;
            }
            crossterm::event::KeyCode::Char('n')
            | crossterm::event::KeyCode::Char('N')
            | crossterm::event::KeyCode::Esc => {
                self.show_confirm_delete_cache_modal = false;
                self.cache_entry_to_delete = None;
            }
            _ => {}
        }
    }

    fn set_add_cache_step(&mut self, next_step: Option<CacheAddStep>) {
        if let Some(current) = &self.current_add_cache_step {
            if next_step.as_ref() != Some(current) {
                self.cache_add_step_history.push(current.clone());
            }
        } else if next_step.is_some() {
            self.cache_add_step_history.clear();
        }
        self.current_add_cache_step = next_step;
        self.cache_add_input_buffer.clear();
        self.cache_add_error = None;

        if let Some(step) = &self.current_add_cache_step {
            self.cache_add_input_buffer = match step {
                CacheAddStep::PromptName => self.pending_cache_add_data.name.clone(),
                CacheAddStep::PromptValueA => self
                    .pending_cache_add_data
                    .value_a
                    .map_or(String::new(), |ip| ip.to_string()),
                CacheAddStep::PromptValueAAAA => self
                    .pending_cache_add_data
                    .value_aaaa
                    .map_or(String::new(), |ip| ip.to_string()),
                CacheAddStep::PromptValueCNAME => self
                    .pending_cache_add_data
                    .value_cname
                    .clone()
                    .unwrap_or_default(),
                CacheAddStep::PromptValueTXT => self
                    .pending_cache_add_data
                    .value_txt
                    .as_ref()
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_default(),
                CacheAddStep::PromptTTL => self
                    .pending_cache_add_data
                    .ttl_seconds
                    .map_or(String::new(), |t| t.to_string()),
                _ => String::new(),
            };
        }
    }

    async fn handle_add_cache_input(&mut self, key_event: crossterm::event::KeyEvent) {
        match self.current_add_cache_step {
            Some(CacheAddStep::PromptType) => match key_event.code {
                crossterm::event::KeyCode::Up => {
                    self.cache_add_type_selection_idx =
                        self.cache_add_type_selection_idx.saturating_sub(1).max(0)
                }
                crossterm::event::KeyCode::Down => {
                    self.cache_add_type_selection_idx =
                        (self.cache_add_type_selection_idx + 1).min(3)
                }
                crossterm::event::KeyCode::Enter => self.proceed_add_cache_step().await,
                _ => {}
            },
            Some(CacheAddStep::ConfirmAdd) => match key_event.code {
                crossterm::event::KeyCode::Enter
                | crossterm::event::KeyCode::Char('y')
                | crossterm::event::KeyCode::Char('Y') => self.finalize_add_cache_entry().await,
                crossterm::event::KeyCode::Esc
                | crossterm::event::KeyCode::Char('n')
                | crossterm::event::KeyCode::Char('N') => self.handle_add_cache_escape(),
                _ => {}
            },
            Some(_) => match key_event.code {
                crossterm::event::KeyCode::Enter => self.proceed_add_cache_step().await,
                crossterm::event::KeyCode::Char(c) => self.cache_add_input_buffer.push(c),
                crossterm::event::KeyCode::Backspace => {
                    self.cache_add_input_buffer.pop();
                }
                _ => {}
            },
            None => {}
        }
    }

    fn handle_add_cache_escape(&mut self) {
        if let Some(prev_step) = self.cache_add_step_history.pop() {
            self.current_add_cache_step = Some(prev_step);
            self.cache_add_input_buffer.clear();
            self.cache_add_error = None;
            if let Some(step_to_fill) = &self.current_add_cache_step {
                self.aws_form_current_input_buffer = match step_to_fill {
                    CacheAddStep::PromptName => self.pending_cache_add_data.name.clone(),
                    CacheAddStep::PromptValueA => self
                        .pending_cache_add_data
                        .value_a
                        .map_or(String::new(), |ip| ip.to_string()),
                    CacheAddStep::PromptValueAAAA => self
                        .pending_cache_add_data
                        .value_aaaa
                        .map_or(String::new(), |ip| ip.to_string()),
                    CacheAddStep::PromptValueCNAME => self
                        .pending_cache_add_data
                        .value_cname
                        .clone()
                        .unwrap_or_default(),
                    CacheAddStep::PromptValueTXT => self
                        .pending_cache_add_data
                        .value_txt
                        .as_ref()
                        .and_then(|v| v.first())
                        .cloned()
                        .unwrap_or_default(),
                    CacheAddStep::PromptTTL => self
                        .pending_cache_add_data
                        .ttl_seconds
                        .map_or(String::new(), |t| t.to_string()),
                    _ => String::new(),
                };
            }
        } else {
            self.show_add_cache_entry_modal = false;
            self.current_add_cache_step = None;
            self.pending_cache_add_data = SyntheticCacheAddData::default();
            self.cache_add_input_buffer.clear();
            self.cache_add_error = None;
        }
    }

    async fn proceed_add_cache_step(&mut self) {
        let step = self.current_add_cache_step.clone();
        let input = self.cache_add_input_buffer.trim().to_string();
        let mut next_step_opt: Option<CacheAddStep> = None;
        match step {
            Some(CacheAddStep::PromptName) => {
                if input.is_empty() {
                    self.cache_add_error = Some("Name cannot be empty.".to_string());
                    return;
                }
                if HickoryName::from_str(&input).is_err() {
                    self.cache_add_error = Some("Invalid domain name format.".to_string());
                    return;
                }
                self.pending_cache_add_data.name = input;
                next_step_opt = Some(CacheAddStep::PromptType);
            }
            Some(CacheAddStep::PromptType) => {
                self.pending_cache_add_data.record_type = match self.cache_add_type_selection_idx {
                    0 => Some(RecordType::A),
                    1 => Some(RecordType::AAAA),
                    2 => Some(RecordType::CNAME),
                    3 => Some(RecordType::TXT),
                    _ => None,
                };
                if self.pending_cache_add_data.record_type.is_none() {
                    self.cache_add_error = Some("Invalid type selected.".to_string());
                    return;
                }
                next_step_opt = match self.pending_cache_add_data.record_type {
                    Some(RecordType::A) => Some(CacheAddStep::PromptValueA),
                    Some(RecordType::AAAA) => Some(CacheAddStep::PromptValueAAAA),
                    Some(RecordType::CNAME) => Some(CacheAddStep::PromptValueCNAME),
                    Some(RecordType::TXT) => Some(CacheAddStep::PromptValueTXT),
                    _ => None,
                };
            }
            Some(CacheAddStep::PromptValueA) => {
                match input.parse::<std::net::Ipv4Addr>() {
                    Ok(ip) => self.pending_cache_add_data.value_a = Some(ip),
                    Err(_) => {
                        self.cache_add_error = Some("Invalid IPv4 address.".to_string());
                        return;
                    }
                }
                next_step_opt = Some(CacheAddStep::PromptTTL);
            }
            Some(CacheAddStep::PromptValueAAAA) => {
                match input.parse::<std::net::Ipv6Addr>() {
                    Ok(ip) => self.pending_cache_add_data.value_aaaa = Some(ip),
                    Err(_) => {
                        self.cache_add_error = Some("Invalid IPv6 address.".to_string());
                        return;
                    }
                }
                next_step_opt = Some(CacheAddStep::PromptTTL);
            }
            Some(CacheAddStep::PromptValueCNAME) => {
                if input.is_empty() {
                    self.cache_add_error = Some("CNAME target cannot be empty.".to_string());
                    return;
                }
                if HickoryName::from_str(&input).is_err() {
                    self.cache_add_error = Some("Invalid CNAME target domain format.".to_string());
                    return;
                }
                self.pending_cache_add_data.value_cname = Some(input);
                next_step_opt = Some(CacheAddStep::PromptTTL);
            }
            Some(CacheAddStep::PromptValueTXT) => {
                if input.is_empty() {
                    self.cache_add_error = Some("TXT value cannot be empty.".to_string());
                    return;
                }
                if input.len() > 255 {
                    self.cache_add_error = Some("Single TXT string max 255 chars.".to_string());
                    return;
                }
                self.pending_cache_add_data.value_txt = Some(vec![input]);
                next_step_opt = Some(CacheAddStep::PromptTTL);
            }
            Some(CacheAddStep::PromptTTL) => {
                match input.parse::<u32>() {
                    Ok(ttl) if ttl >= 60 => self.pending_cache_add_data.ttl_seconds = Some(ttl),
                    Ok(_) => {
                        self.cache_add_error = Some("TTL must be at least 60 seconds.".to_string());
                        return;
                    }
                    Err(_) => {
                        self.cache_add_error =
                            Some("Invalid TTL (must be positive number).".to_string());
                        return;
                    }
                }
                next_step_opt = Some(CacheAddStep::ConfirmAdd);
            }
            _ => return,
        }
        self.set_add_cache_step(next_step_opt);
    }

    async fn finalize_add_cache_entry(&mut self) {
        use hickory_proto::rr::{Name, RData, Record};
        let data = &self.pending_cache_add_data;
        if data.name.is_empty() || data.record_type.is_none() || data.ttl_seconds.is_none() {
            self.cache_add_error = Some("Incomplete data for cache entry.".to_string());
            self.set_add_cache_step(Some(CacheAddStep::PromptName));
            return;
        }
        let name = match Name::from_str(&data.name) {
            Ok(n) => n,
            Err(_) => {
                self.cache_add_error = Some("Invalid domain name format.".to_string());
                self.set_add_cache_step(Some(CacheAddStep::PromptName));
                return;
            }
        };
        let ttl = data.ttl_seconds.unwrap();
        let rtype = data.record_type.unwrap();
        let rdata_opt: Option<RData> = match rtype {
            RecordType::A => data.value_a.map(|ipv4| RData::A(A(ipv4))),
            RecordType::AAAA => data.value_aaaa.map(|ipv6| RData::AAAA(AAAA(ipv6))),
            RecordType::CNAME => data
                .value_cname
                .as_ref()
                .and_then(|s| Name::from_str(s).ok())
                .map(|name| RData::CNAME(CNAME(name))),
            RecordType::TXT => data
                .value_txt
                .as_ref()
                .map(|v| RData::TXT(hickory_proto::rr::rdata::TXT::new(v.clone()))),
            _ => {
                self.cache_add_error = Some(format!(
                    "Unsupported record type {:?} for manual add.",
                    rtype
                ));
                self.set_add_cache_step(Some(CacheAddStep::PromptType));
                return;
            }
        };
        if let Some(rdata) = rdata_opt {
            let record = Record::from_rdata(name.clone(), ttl, rdata);
            let key = CacheKey::new(&data.name, rtype);
            self.app_lifecycle
                .get_dns_cache()
                .insert_synthetic_entry(
                    key.clone(),
                    vec![record],
                    Duration::from_secs(ttl as u64),
                    ResponseCode::NoError,
                )
                .await;
            self.add_log_message_internal(
                format!(
                    "Added cache entry for {} {:?} TTL {}",
                    data.name, rtype, ttl
                ),
                MessageLevel::Info,
            );
            self.show_add_cache_entry_modal = false;
            self.current_add_cache_step = None;
            self.pending_cache_add_data = SyntheticCacheAddData::default();
            self.cache_add_input_buffer.clear();
            self.cache_add_error = None;
            self.cache_add_step_history.clear();

            self.load_cache_items_for_view().await;
            if let Some(idx) = self.cache_view_items.iter().position(|(k, _)| k == &key) {
                self.cache_view_selected_index = idx;
                self.adjust_cache_view_scroll();
            }
        } else {
            self.cache_add_error =
                Some("Missing or invalid value for selected record type.".to_string());
            self.set_add_cache_step(match rtype {
                RecordType::A => Some(CacheAddStep::PromptValueA),
                RecordType::AAAA => Some(CacheAddStep::PromptValueAAAA),
                RecordType::CNAME => Some(CacheAddStep::PromptValueCNAME),
                RecordType::TXT => Some(CacheAddStep::PromptValueTXT),
                _ => Some(CacheAddStep::PromptType),
            });
        }
    }
}

pub struct TuiUserInteractionAdapter {
    log_tx_to_tui_app: mpsc::Sender<(String, MessageLevel)>,
}
impl TuiUserInteractionAdapter {
    pub fn new(log_tx_to_tui_app: mpsc::Sender<(String, MessageLevel)>) -> Self {
        Self { log_tx_to_tui_app }
    }
}
#[async_trait]
impl UserInteractionPort for TuiUserInteractionAdapter {
    async fn prompt_for_mfa_token(
        &self,
        user_identity: &str,
        attempt: u32,
    ) -> Result<String, UserInputError> {
        warn!(
            "TUI prompt_for_mfa_token: Using fallback blocking prompt. TUI modal not yet implemented."
        );
        let _ = self
            .log_tx_to_tui_app
            .send((
                format!(
                    "[ACTION REQUIRED] MFA Token for {} (Attempt {}) - Check console.",
                    user_identity, attempt
                ),
                MessageLevel::Warning,
            ))
            .await;
        inquire::Text::new(&format!(
            "[Attempt {}] Enter MFA token for {}: ",
            attempt, user_identity
        ))
        .prompt()
        .map_err(|e| UserInputError::ReadError(std::io::Error::other(e.to_string())))
        .and_then(|token| {
            if token.is_empty() {
                Err(UserInputError::CancelledOrEmpty)
            } else {
                Ok(token)
            }
        })
    }
    async fn prompt_for_aws_keys(
        &self,
        account_label: &str,
    ) -> Result<(String, String), UserInputError> {
        warn!(
            "TUI prompt_for_aws_keys: Using fallback blocking prompt. TUI modal not yet implemented."
        );
        let _ = self
            .log_tx_to_tui_app
            .send((
                format!(
                    "[ACTION REQUIRED] AWS Keys for {} - Check console.",
                    account_label
                ),
                MessageLevel::Warning,
            ))
            .await;
        let access_key =
            inquire::Text::new(&format!("Enter Access Key ID for {}: ", account_label))
                .prompt()
                .map_err(|e| UserInputError::ReadError(std::io::Error::other(e.to_string())))?;
        if access_key.is_empty() {
            return Err(UserInputError::CancelledOrEmpty);
        }
        let secret_key =
            inquire::Password::new(&format!("Enter Secret Access Key for {}: ", account_label))
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .prompt()
                .map_err(|e| UserInputError::ReadError(std::io::Error::other(e.to_string())))?;
        if secret_key.is_empty() {
            return Err(UserInputError::CancelledOrEmpty);
        }
        Ok((access_key, secret_key))
    }
    fn display_message(&self, message: &str, level: MessageLevel) {
        if self
            .log_tx_to_tui_app
            .try_send((message.to_string(), level))
            .is_err()
        {
            println!(
                "[{:<7}] (TUI Fallback) {}",
                format!("{:?}", level).to_uppercase(),
                message
            );
        }
    }
    fn display_status(&self, _status_info: &AppStatus) {
        debug!("TUI display_status called - TUI updates status via its Tick event.");
    }
    fn display_error(&self, error: &dyn std::error::Error) {
        let full_error = format!("{}", error);
        if self
            .log_tx_to_tui_app
            .try_send((full_error.clone(), MessageLevel::Error))
            .is_err()
        {
            eprintln!("[ERROR] (TUI Fallback) {}", full_error);
        }
    }
    fn display_table(&self, headers: Vec<String>, rows: Vec<Vec<String>>) {
        let mut table_str = String::new();
        table_str.push_str(&format!("Table: {}\n", headers.join(" | ")));
        for row in rows {
            table_str.push_str(&format!("  {}\n", row.join(" | ")));
        }
        if self
            .log_tx_to_tui_app
            .try_send((table_str.clone(), MessageLevel::Info))
            .is_err()
        {
            println!("[INFO] (TUI Fallback) {}", table_str);
        }
    }
    fn display_prompt(&self, prompt_text: &str) {
        if self
            .log_tx_to_tui_app
            .try_send((format!("Prompt: {}", prompt_text), MessageLevel::Debug))
            .is_err()
        {
            println!("[DEBUG] (TUI Fallback) Prompt: {}", prompt_text);
        }
    }
}
