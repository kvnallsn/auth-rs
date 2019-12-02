//! WebAuthn Module

pub mod pk;
pub mod request;
pub mod response;

mod config;
mod error;
mod rp;
mod user;

#[cfg(feature = "web")]
pub mod web;

pub use config::WebAuthnConfig;
pub use error::WebAuthnError;
pub use user::User;

use serde::Deserialize;
use std::fmt;

/// The different response types that are possible to receive after receiveing
/// data from the client
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub enum WebAuthnType {
    /// Corresponds to the `navigator.credentials.create()` client api
    #[serde(alias = "webauthn.create")]
    Create,

    /// Corresponds to the `navigator.credentials.get()` client api
    #[serde(alias = "webauthn.get")]
    Get,
}

impl fmt::Display for WebAuthnType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl WebAuthnType {
    /// Returns the string representation that will be seen in the response
    pub fn as_str(&self) -> &str {
        match self {
            WebAuthnType::Create => "webauthn.create",
            WebAuthnType::Get => "webauthn.get",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_webauthn_config() {
        let config = WebAuthnConfig::new("http://app.example.com");
        assert_eq!(config.id(), "app.example.com");
    }

    #[test]
    fn build_webauthn_config_with_trailing_slash() {
        let config = WebAuthnConfig::new("http://app.example.com/");
        assert_eq!(config.id(), "app.example.com");
    }

    #[test]
    fn build_webauthn_config_no_scheme() {
        let config = WebAuthnConfig::new("app.example.com/");
        assert_eq!(config.id(), "app.example.com");
    }
}
