#[cfg(feature = "aws")]
pub(crate) mod credentials_provider;
#[cfg(feature = "aws")]
pub(crate) mod profile_utils;
#[cfg(feature = "aws")]
pub(crate) mod types;
#[cfg(feature = "aws")]
pub(crate) mod vpc_info_provider;

#[cfg(all(test, feature = "aws"))]
pub(crate) mod tests;

#[cfg(not(feature = "aws"))]
pub(crate) mod stub;
