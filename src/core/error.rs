use hickory_proto::ProtoError;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read configuration file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to write configuration file {path}: {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to deserialize configuration from {path}: {source}")]
    Deserialize {
        path: PathBuf,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("Failed to serialize configuration: {0}")]
    Serialize(Box<dyn std::error::Error + Send + Sync>),
    #[error("Configuration validation failed: {0}")]
    Validation(String),
    #[error("Path not found: {0}")]
    PathNotFound(PathBuf),
    #[error("Migration from legacy config failed: {0}")]
    Migration(String),
    #[error("File watcher error: {0}")]
    Watcher(#[from] notify::Error),
    #[error("Configuration not loaded or unavailable")]
    NotLoaded,
    #[error("Invalid configuration value for '{field}': {message}")]
    InvalidValue { field: String, message: String },
}

#[derive(Error, Debug)]
pub enum DnsProcessingError {
    #[error("Failed to parse DNS query: {0}")]
    ParseError(#[from] ProtoError),
    #[error("Failed to serialize DNS response: {0}")]
    SerializeError(String),
    #[error("Unsupported query type: {0}")]
    UnsupportedQueryType(String),
    #[error("Resolution failed: {0}")]
    ResolutionFailed(#[from] ResolveError),
    #[error("Rule engine error: {0}")]
    RuleEngineError(String),
    #[error("Local hosts resolution error: {0}")]
    LocalHostsError(String),
    #[error("Cache error: {0}")]
    CacheError(String),
    #[error("Operation timed out")]
    Timeout,
    #[error("Internal server error: {0}")]
    InternalError(String),
    #[error("No questions in DNS query")]
    NoQuestions,
}

#[derive(Error, Debug)]
pub enum ResolveError {
    #[error("Upstream server error for {server}: {details}")]
    UpstreamServer { server: String, details: String },
    #[error("No upstream servers available or configured")]
    NoUpstreamServers,
    #[error("DNS query timed out after {duration:?} for {domain}")]
    Timeout {
        domain: String,
        duration: std::time::Duration,
    },
    #[error("Network error: {0}")]
    Network(String),
    #[error("DNS protocol error: {0}")]
    Protocol(#[from] ProtoError),
    #[error("HTTP proxy error: {0}")]
    HttpProxy(String),
    #[error("Invalid response from upstream: {0}")]
    InvalidResponse(String),
    #[error("Configuration error for resolver: {0}")]
    Configuration(String),
}

#[derive(Error, Debug)]
pub enum AwsAuthError {
    #[error("Failed to get AWS credentials for account '{account_label}': {source}")]
    CredentialRetrieval {
        account_label: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("MFA token required for user '{user_identity}' but not provided or invalid")]
    MfaRequired { user_identity: String },
    #[error("Failed to assume role '{role_arn}': {source}")]
    AssumeRole {
        role_arn: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("User interaction failed during auth: {0}")]
    Interaction(#[from] UserInputError),
    #[error("AWS STS client error: {0}")]
    StsClient(String),
    #[error("AWS configuration error: {0}")]
    Config(String),
}

#[derive(Error, Debug)]
pub enum AwsApiError {
    #[error("AWS API call to {service} for resource '{resource_id}' failed: {source}")]
    ApiCall {
        service: String,
        resource_id: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("Failed to discover AWS resources in region '{region}': {details}")]
    Discovery { region: String, details: String },
    #[error("Insufficient permissions for AWS operation: {operation}")]
    Permissions { operation: String },
    #[error("AWS resource not found: {resource_type} '{identifier}'")]
    NotFound {
        resource_type: String,
        identifier: String,
    },
}

#[derive(Error, Debug)]
pub enum UserInputError {
    #[error("Failed to read user input: {0}")]
    ReadError(std::io::Error),
    #[error("User input was cancelled or empty")]
    CancelledOrEmpty,
    #[error("Invalid input format: {0}")]
    InvalidFormat(String),
}

#[derive(Error, Debug)]
pub enum CliError {
    #[error("Command execution failed: {0}")]
    Execution(String),
    #[error("Invalid command or arguments: {0}")]
    InvalidCommand(String),
    #[error("Failed to display output: {0}")]
    Display(String),
    #[error("Application lifecycle error: {0}")]
    Lifecycle(String),
}

impl From<reqwest::Error> for ResolveError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            ResolveError::Network(format!("HTTP request timeout: {}", err))
        } else if err.is_connect() {
            ResolveError::Network(format!("HTTP connection error: {}", err))
        } else {
            let err_string = err.to_string();
            if err_string.contains("proxy") || err_string.contains("Proxy") {
                ResolveError::HttpProxy(format!("HTTP proxy error: {}", err))
            } else {
                ResolveError::Network(format!("HTTP client error: {}", err))
            }
        }
    }
}
