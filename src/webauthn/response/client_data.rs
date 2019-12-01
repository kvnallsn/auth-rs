//! Client data related code

use crate::webauthn::response::WebAuthnType;
use serde::Deserialize;

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
    pub fn validate(&self, ty: WebAuthnType, challenge: &str, origin: &str) -> bool {
        self.ty == ty && &self.challenge == challenge && &self.origin == origin
    }
}
