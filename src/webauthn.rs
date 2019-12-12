//! WebAuthn Module

mod config;
mod error;
mod pk;
mod request;
mod response;
mod rp;
mod user;

#[cfg(feature = "web")]
pub mod web;

pub use config::Config;
pub use error::Error;
pub use request::{AuthenticateRequest, RegisterRequest};
pub use response::{authenticate, register, Response};
pub use user::User;

use serde::{Deserialize, Serialize};
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

/// A `WebAuthnDevice` represents a security token or similiar physical hardware
/// device that the user will use to authenticate with the app (e.g., YubiKey).
/// The information contained in this struct is everything needed to authenticate
/// a user against a specific token
#[derive(Debug, Deserialize, Serialize)]
pub struct Device {
    /// The devices's credential id. A unique value per device
    id: Vec<u8>,

    /// The public key belonging to this device
    pk: Vec<u8>,

    /// The number of times this has been used
    count: u32,
}

impl Device {
    /// Creates a new `WebAuthnDevice` with the specified parameters
    ///
    /// # Arguments
    /// * `id` - Credential Id of the device
    /// * `public_key` - Raw public key (as bytes) corresponding to the id
    /// * `count` - Number of times this key has been used
    pub fn new(id: Vec<u8>, public_key: Vec<u8>, count: u32) -> Device {
        Device {
            id,
            pk: public_key,
            count,
        }
    }

    pub fn id(&self) -> &[u8] {
        &self.id
    }

    pub fn public_key(&self) -> &[u8] {
        &self.pk
    }

    pub fn count(&self) -> u32 {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_webauthn_config() {
        let config = Config::new("http://app.example.com");
        assert_eq!(config.id(), "app.example.com");
    }

    #[test]
    fn build_webauthn_config_with_trailing_slash() {
        let config = Config::new("http://app.example.com/");
        assert_eq!(config.id(), "app.example.com");
    }

    #[test]
    fn build_webauthn_config_no_scheme() {
        let config = Config::new("app.example.com/");
        assert_eq!(config.id(), "app.example.com");
    }
}
