//! Implementation of the Relying Party (aka server)

use serde::{Deserialize, Serialize};

/// The RelyingParty in this instance is the name of the company
/// (or application name/program name, etc.) that will bepresented
/// to the user
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelyingParty {
    /// Unique string (identifier) for the Relying Party entity, which sets the RP ID.
    /// Generally, this is the name of the company or application
    pub name: String,
}

impl RelyingParty {
    /// Creates a new "RelyingParty" to use for the authentication process.
    ///
    /// # Arguments
    /// * `name` - Name of the company/app/program/etc.
    pub fn new<S: Into<String>>(name: S) -> RelyingParty {
        RelyingParty { name: name.into() }
    }
}

impl Into<RelyingParty> for String {
    fn into(self) -> RelyingParty {
        RelyingParty::new(self)
    }
}

impl Into<RelyingParty> for &str {
    fn into(self) -> RelyingParty {
        RelyingParty::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_relying_party() {
        let _ = RelyingParty::new("servername");
    }
}
