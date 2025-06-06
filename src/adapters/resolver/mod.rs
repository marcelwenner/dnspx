pub(crate) mod composite_resolver;
pub(crate) mod doh_client;
#[cfg(windows)]
mod sspi_auth;
#[cfg(not(windows))]
mod sspi_auth_mock;
pub(crate) mod standard_dns_client;
