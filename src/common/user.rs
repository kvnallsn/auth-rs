//! Represents a user to be validated

use serde::{Deserialize, Serialize};

/// A FidoUser represents information about a user that will be sent
/// to the client
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    /// User Handle (e.g., user id) of the user account entity.  Used to ensure
    /// secure operation, authentication, and authorization decisons
    pub id: Vec<u8>,

    /// A human-palatable name for the user account, intended for display only.
    /// Should be selected by the user (e.g., username, email, etc.)
    pub name: String,

    /// A human-palatable name for the user account, intended for display only.
    /// Should be selected by the user (e.g., username, email, etc.)
    #[serde(rename = "displayName")]
    pub display_name: String,
}

impl User {
    /// Creates a new user that will be authenticated by a FIDO2 token.  It is probably
    /// preferable to the Into<User> rather than using this function directly.
    ///
    /// # Arguments
    /// * `id` - The id of the user
    /// * `name` - A user-friendly name to display
    /// * `display_name` - A user-friendly name to display (same as `name`)
    pub fn new<S: Into<String>, T: Into<String>>(id: Vec<u8>, name: S, display_name: T) -> User {
        let name = name.into();
        let display_name = display_name.into();
        User {
            id,
            name,
            display_name,
        }
    }
}

/// Different types of User Verification levels supported by different types
/// of authenticators (e.g., Yubikey, platform, etc.)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum UserVerificationRequirement {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_user() {
        let _ = User::new(vec![0, 1, 2, 3], "user", "user");
    }
}
