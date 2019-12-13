//! Represents a user to be validated

use serde::{Deserialize, Serialize};

pub trait WebAuthnUser {
    /// User Handle (e.g., user id) that can uniquely identify a user in the service/api.
    /// Generally, this can be mapped to a primary key or similiar construct (e.g., uuid)
    fn id(&self) -> &[u8];

    /// A human-palatable or user-friednlt name for the user account, intended for
    /// display only. Should be selected by the user (e.g., username, email, etc.)
    fn name(&self) -> &str;

    /// Turns any trait implementing WebAuthnUser into a serialize struct
    /// that can be sent to a client WebAuthn implemenation
    fn to_user(&self) -> User {
        User {
            id: self.id().to_vec(),
            name: self.name().to_owned(),
            display_name: self.name().to_owned(),
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_user() {
        let _ = User::new(vec![0, 1, 2, 3], "user", "user");
    }
}
