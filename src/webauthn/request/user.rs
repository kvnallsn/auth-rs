use serde::{Deserialize, Serialize};

/// Different types of User Verification levels supported by different types
/// of authenticators (e.g., Yubikey, platform, etc.)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum UserVerification {
    /// User Verification is required and will fail if the response does not
    /// have the `UV flag` set
    #[serde(rename = "required")]
    Required,

    /// Prefers User Verification if possible, but will not fail if the response
    /// does not have the `UV flag` set
    #[serde(rename = "preferred")]
    Preferred,

    /// Do not want any User Verification.  Useful to minimze disruption to the
    /// user interaction flow
    #[serde(rename = "discouraged")]
    Discouraged,
}
