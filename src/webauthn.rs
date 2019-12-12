//! Server-Side support for the Web Authentication (WebAuthn) specification written by
//! the W3C and FIDO Alliance.  Allows APIs to register and authenticate users with
//! public key cryptography instead of passwords.
//!
//! WebAuthn allows APIs to utilize strong authenticators builtin to modern devices
//! (such as Windows Hello or Apple's Touch ID) instead of a password. The device creates
//! a public/private keypair.  The public key (along with a randomly-generated credential id)
//! is set to the API while the private key never leaves the device.  The API can then use
//! the public key to authenticate the user for future sign-ins.
//!
//! # Example
//!
//! The following example uses [Rocket](https://rocket.rs) to build a simple API with four
//! endpoints: a get/post pair for registering a credential and get/post pair for authenticating
//! a credential. For the backing store, HTTP cookies are used.  For the full example, see ...
//!
//! ```ignore
//! use auth_rs::webauth::{self, AuthenticateRequest, RegisterRequest};
//! use rocket::{get, post, State};
//! use rocket_contrib::{json, json::{Json, JsonValue}};
//!
//! #[get("/fido/register")]
//! fn register_request(cfg: State<Config>, user: User, mut cookies: Cookies) -> Json<RegisterRequest> {
//!     let req = RegisterRequest::new(&cfg, user);
//!
//!     // Save the challenge in a cookie for register post handler to validate
//!     cookies.add(Cookie::new("X-WebAuthn-Challenge", req.challenge()));
//!     Json(req)
//! }
//!
//! #[post("/fido/register", data = "<form>")]
//! fn register_post(cfg: State<Config>, form: Json<webauthn::Response>, mut cookies: Cookies) -> JsonValue {
//!     let form = form.into_inner();
//!
//!     // Retrieve the challenge from the cookie (or database/similar store) then delete the cookie
//!     let challenge = cookies.get("X-WebAuthn-Challenge").unwrap().value();
//!     cookies.remove(Cookie::named("X-WebAuthn-Challenge"));
//!
//!     // Attempt to validate the register request
//!     match webauthn::register(form, &cfg, challenge) {
//!         Ok(device) => { /* save device in backing database/etc */ }
//!         Err(e) => panic!("failed to validate register request: {}", e),
//!     }
//! }
//!
//! #[get("/fido/login")]
//! fn register_request(cfg: State<Config>, mut cookies: Cookies) -> Json<AuthenticateRequest> {
//!     let devices = /* load all registered devices for a user from backing database/etc. */;
//!     let req = AuthenticateRequest::new(&cfg, vec![devices]);
//!
//!     // Save the challenge in a cookie for register post handler to validate
//!     cookies.add(Cookie::new("X-WebAuthn-Challenge", req.challenge()));
//!     Json(req)
//! }
//!
//! #[post("/fido/login", data = "<form>")]
//! fn register_post(cfg: State<Config>, form: Json<webauthn::Response>, mut cookies: Cookies) -> JsonValue {
//!     let form = form.into_inner();
//!
//!     // Retrieve the challenge from the cookie (or database/similar store) then delete the cookie
//!     let challenge = cookies.get("X-WebAuthn-Challenge").unwrap().value();
//!     cookies.remove(Cookie::named("X-WebAuthn-Challenge"));
//!
//!     let devices = /* load all registered devices for a user from backing database/etc. */;
//!      
//!     match webauthn::authenticate(form. &cfg, devices) {
//!         Ok(_) => /* success! finish logging user in */,
//!         Err(e) => panic!("failed to validate login request: {}", e),
//!     }
//! }
//! ```

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
