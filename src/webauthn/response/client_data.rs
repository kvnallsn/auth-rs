//! Client data related code

use crate::webauthn::{response::WebAuthnType, Config};
use serde::Deserialize;
use std::fmt;

#[derive(Debug)]
pub enum ClientDataError {
    /// Occurs when the response we received does not match the operation
    /// we were expecting. For example, requested `webauthn.create` but got
    /// a response for `webauthn.get`
    InvalidWebAuthnType(WebAuthnType, WebAuthnType),

    /// Occurs when the challenge we received does not match the challenge
    /// we sent to the client
    ChallengeMismatch,

    /// Occurs when the origin the reponse specifies does not match the
    /// origin in our config
    OriginMismatch(String, String),
}

impl fmt::Display for ClientDataError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            ClientDataError::InvalidWebAuthnType(got, exp) => format!(
                "WebAuthn Message Type Mismatch: Got '{}', Expected: '{}'",
                got, exp
            ),
            ClientDataError::ChallengeMismatch => format!("Challenge Mismatch!"),
            ClientDataError::OriginMismatch(got, exp) => {
                format!("Origin Mismatch: Got '{}', Expected: '{}'", got, exp)
            }
        };

        write!(f, "{}", msg)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub enum TokenBindingStatus {
    /// Token binding was used when communicating with the Relying Party.
    /// In this case, the id member MUST be present.
    #[serde(alias = "present")]
    Present,

    /// Client supports token binding, but it was not negotiated when communicating
    /// with the Relying Party.
    #[serde(alias = "supported")]
    Supported,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TokenBinding {
    /// Describes what type of token binding occured
    status: TokenBindingStatus,

    /// MUST be present if status is present, and MUST be a base64url encoding
    /// of the Token Binding ID that was used when communicating with the Relying Party.
    id: String,
}

/// Represents the contextual bindings of both the WebAuthn Relying Party and the client.
#[derive(Clone, Debug, Deserialize)]
pub struct ClientData {
    /// Contains the string "webauthn.create" when creating new credentials or
    /// "webauthn.get" when validating existing credentials. The purpose of this
    /// member is to prevent certain types of signature confusion attacks
    /// (where an attacker substitutes one legitimate signature for another)
    #[serde(alias = "type")]
    ty: WebAuthnType,

    /// Base64url-encoded challenge provided by theRelying Party
    challenge: String,

    /// Fully qualified origin of the requester, as provided to the authenticator
    /// by the client, in the syntex defined by [RFC6454](https://w3c.github.io/webauthn/#biblio-rfc6454)
    #[serde(default)]
    origin: String,

    /// Inverse of the sameOriginWithAncestors argument value that was
    /// passed into the internal method.
    #[serde(alias = "crossOrigin")]
    #[serde(default)]
    cross_origin: bool,

    /// OPTIONAL - Information about the state of the Token Binding protocol
    /// used when communicating with the Relying Party. Its absence indicates
    /// that the client doesn’t support token binding.
    #[serde(alias = "tokenBinding")]
    token_binding: Option<TokenBinding>,
}

impl ClientData {
    /// Ensures all criteria match what is anticipated
    ///
    /// # Arguments
    /// * `ty` - What kind of WebAuthn message to validate (i.e., Create or Get)
    /// * `cfg` - The configuration the request was created with (contains, origin, etc.)
    /// * `challenge` - The base64url encoded challenege string that was generated with the request
    pub fn validate<S: Into<String>>(
        &self,
        ty: WebAuthnType,
        cfg: &Config,
        challenge: S,
    ) -> Result<(), ClientDataError> {
        if self.ty != ty {
            return Err(ClientDataError::InvalidWebAuthnType(self.ty.clone(), ty));
        }

        if self.challenge != challenge.into() {
            return Err(ClientDataError::ChallengeMismatch);
        }

        if self.origin != cfg.origin() {
            return Err(ClientDataError::OriginMismatch(
                self.origin.clone(),
                cfg.origin().to_owned(),
            ));
        }

        Ok(())
    }
}
