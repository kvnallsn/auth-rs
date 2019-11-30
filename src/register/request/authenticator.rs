//! Authenticator Criteria

use crate::common::user::UserVerificationRequirement;
use serde::{Deserialize, Serialize};
use std::default::Default;

/// Specifies what type of authenticator we should prefer and to inform the client
/// the best way to location an authenticator on the device
/// #[WebAuthn Spec](https://www.w3.org/TR/webauthn/#enumdef-authenticatorattachment)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuthenticatorAttachment {
    /// A built-in authenticator (fingerprint reader on Win10, OSX, phones, etc.)
    #[serde(rename = "platform")]
    Platform,

    /// An authenticator plugged in or nearby (e.g., Yubikey, phone prompt, etc.)
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

/// Specifies requirements regarding authenticator attributes
/// [WebAuthn Spec](https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticatorCritera {
    /// If present, filter authenticators to only those that match these requirements.
    ///
    /// Default: None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachement: Option<AuthenticatorAttachment>,

    /// If true, the authenticator must create a client-side-resident public key credential
    /// source when creating a public key-credential.
    ///
    /// Default: false
    pub require_resident_key: bool,

    /// Describes the Relying Party's requirements reguarding user verification for the
    /// `create()` operation.  Eligible authenticators are filtered to only those
    /// capable of satisfying the requirement
    ///
    /// Default: Preferred
    #[serde(rename = "userVerification")]
    pub user_verification: UserVerificationRequirement,
}

impl Default for AuthenticatorCritera {
    fn default() -> AuthenticatorCritera {
        AuthenticatorCritera {
            authenticator_attachement: None,
            require_resident_key: false,
            user_verification: UserVerificationRequirement::Preferred,
        }
    }
}
