//! file: config.fs

use super::rp::RelyingParty;

/// High Level configuration object that can be utilized to set
/// information about the server ("Relying Party")
#[derive(Clone, Debug)]
pub struct WebAuthnConfig {
    /// The full path (scheme, host, port, domain) of the server
    rp_origin: String,

    /// A unique identifier for the Relying Party entity, which sets the RP ID
    rp_id: String,
}

impl WebAuthnConfig {
    pub fn new<S: Into<String>>(origin: S) -> WebAuthnConfig {
        let origin = origin.into();
        let id = origin.clone();
        let (_, uri) = id.split_at(id.find("://").map(|i| i + 3).unwrap_or(0));
        let (domain, _) = uri.split_at(uri.find("/").unwrap_or(uri.len()));

        WebAuthnConfig {
            rp_origin: origin,
            rp_id: domain.to_owned(),
        }
    }

    /// Set the id to use manually, if id generation fails when the origin is set
    ///
    /// # Arguments
    /// * `id` - The Relying Party Id to use (i.e., the domain)
    pub fn set_id<'a, S: Into<String>>(&'a mut self, id: S) -> &'a mut Self {
        self.rp_id = id.into();
        self
    }

    /// Returns the origin associated with this config
    pub fn origin(&self) -> &str {
        &self.rp_origin
    }

    /// Returns the id associated with this config
    pub fn id(&self) -> &str {
        &self.rp_id
    }

    pub fn as_relying_party(&self) -> RelyingParty {
        RelyingParty::builder(self).finish()
    }
}

impl Into<RelyingParty> for &WebAuthnConfig {
    fn into(self) -> RelyingParty {
        RelyingParty::builder(self).finish()
    }
}

impl Into<RelyingParty> for WebAuthnConfig {
    fn into(self) -> RelyingParty {
        RelyingParty::builder(&self).finish()
    }
}
