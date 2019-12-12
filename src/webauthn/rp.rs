//! Implementation of the Relying Party (aka server)

use crate::webauthn::Config;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A `RelyingPartyBuilder` constructs a proper `RelyingParty` that can be
/// send to a client for credential generation
pub struct RelyingPartyBuilder {
    /// Name of the RelyingParty (generally the name of the application or company)
    rp_name: String,

    /// The id that will be used to generate the credential.  By default, this will
    /// be set to the effective domain of the server. (i.e., for www.example.com, the
    /// effective domain is example.com).
    ///
    /// Before setting/overriding, read the warnings/notes in the [spec](https://w3c.github.io/webauthn/#relying-party)
    rp_id: Option<String>,
}

impl RelyingPartyBuilder {
    /// Creates a new RelyingPartyBuilder with the specified name
    fn new(cfg: &Config) -> RelyingPartyBuilder {
        RelyingPartyBuilder {
            rp_name: "".to_string(),
            rp_id: Some(cfg.id().to_owned()),
        }
    }
    /// Updates the name on this RelyingParty to the value provided
    pub fn name<S: Into<String>>(mut self, name: S) -> Self {
        self.rp_name = name.into();
        self
    }

    /// Overrides the default id (the server's effective domain).
    ///
    /// Before setting this, review the documention on RelyingParty's as
    /// defined in the [WebAuthn Spec](https://w3c.github.io/webauthn/#relying-party)
    ///
    /// # Arguments
    /// * `id` - The new RelyingParty id to use
    pub fn id<S: Into<String>>(mut self, id: S) -> Self {
        self.rp_id = Some(id.into());
        self
    }

    /// Consumes this builder and returns the RelyingParty than can be sent to clients
    pub fn finish(self) -> RelyingParty {
        RelyingParty {
            name: self.rp_name,
            id: self.rp_id,
        }
    }
}

/// The RelyingParty in this instance is the name of the company
/// (or application name/program name, etc.) that will bepresented
/// to the user
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelyingParty {
    /// Unique string (identifier) for the Relying Party entity, which sets the RP ID.
    /// Generally, this is the name of the company or application
    pub name: String,

    /// Generally the domain name of the service requesting authentication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl RelyingParty {
    /// Creates a new "RelyingParty" to use for the authentication process.
    ///
    /// # Arguments
    /// * `name` - Name of the company/app/program/etc.
    pub fn builder(cfg: &Config) -> RelyingPartyBuilder {
        RelyingPartyBuilder::new(cfg)
    }
}

impl fmt::Display for RelyingParty {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[Relying Party] name = {}; id = {}",
            self.name,
            self.id.as_ref().map(|s| s.as_str()).unwrap_or("None"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_relying_party() {
        let cfg = Config::new("https://www.example.com");
        let _ = RelyingParty::builder(&cfg).finish();
    }
}
