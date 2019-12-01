//! WebAuthn Module

pub mod pk;
pub mod request;
pub mod response;

mod error;
mod rp;
mod user;

pub use self::error::WebAuthnError;
pub use rp::RelyingParty;
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
