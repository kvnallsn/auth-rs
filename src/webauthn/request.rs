//! Request structs/enums for registering a new token

mod attestation;
mod authenticator;

use self::{attestation::AttestationPreference, authenticator::AuthenticatorCritera};
use crate::webauthn::{pk::PublicKeyParams, rp::RelyingParty, user::User};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Options for creating a new PublicKey.  This struct is passed to
/// `navigator.credentials.create()` on the client side.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnRegisterRequest {
    /// Random, cryptographically secure string used to generate client's attestation object
    challenge: Vec<u8>,

    /// Data about the Relying Party responsible for the request
    rp: RelyingParty,

    /// Contains data about the user account for which the Relying Party is requesting attestation
    user: User,

    /// Time, in milliseconds, the caller should wait for the call to complete.  Treated as a
    /// hint, and may be overriden by the client
    ///
    /// Default: None
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u32>,

    /// Which authenticators should be accepted
    authenticator_selection: AuthenticatorCritera,

    /// Relying Party preference for attestation
    ///
    /// Default: None
    attestation: AttestationPreference,

    /// Contains information about the desired properties of the credential to be created.
    /// Ordering is most-preferred (0-index) to least-preferred (n-index).  Client will make
    /// best effort to create the most-preferred credential it can.
    pub_key_cred_params: Vec<PublicKeyParams>,
}

#[allow(dead_code)]
impl WebAuthnRegisterRequest {
    /// Creates a new options struct that can be sent to the client and generate
    /// a new client credential using the available authenticator.
    ///
    /// # Arguments
    /// * `rp` - Name of the Relying Party
    /// * `user` - The user to generate an attestation / credential for
    pub fn new<P: Into<RelyingParty>, U: Into<User>>(rp: P, user: U) -> Self {
        let mut challenge = vec![0; 32];
        rand::thread_rng().fill_bytes(&mut challenge);

        WebAuthnRegisterRequest {
            challenge,
            rp: rp.into(),
            user: user.into(),
            timeout: None,
            authenticator_selection: AuthenticatorCritera::default(),
            attestation: AttestationPreference::Direct,
            pub_key_cred_params: vec![PublicKeyParams::default()],
        }
    }

    /// Sets the timeout for how long to wait for the client to generate a credential
    ///
    /// # Arguments
    /// * `timeout` - Time, in milliseconds, to wait
    pub fn timeout<'a>(&'a mut self, timeout: u32) -> &'a mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the requirements for the Authenticator that will be used
    ///
    /// # Arguments
    /// * `criteria` - Requirements for what authenticator should be used
    pub fn auth_criteria<'a>(&'a mut self, critera: AuthenticatorCritera) -> &'a mut Self {
        self.authenticator_selection = critera;
        self
    }

    /// Changes the attestation preference
    ///
    /// # Arguments
    /// * `attestation` - New attestation preference
    pub fn attestation<'a>(&'a mut self, attestation: AttestationPreference) -> &'a mut Self {
        self.attestation = attestation;
        self
    }

    /// Placebo-method to show we are finished building
    pub fn finish(self) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::{RelyingParty, User};

    fn setup() -> (User, RelyingParty) {
        let user = User::new(vec![0, 1, 2, 3], "user", "user");
        let rp = RelyingParty::builder("rp").finish();
        (user, rp)
    }

    #[test]
    fn pk_create_options_default() {
        let (user, rp) = setup();
        let _ = WebAuthnRegisterRequest::new(rp, user);
    }

    #[test]
    fn pk_create_options_timeout() {
        let (user, rp) = setup();
        let _ = WebAuthnRegisterRequest::new(rp, user).timeout(10000);
    }

    #[test]
    fn pk_create_options_auth_criteria() {
        let (user, rp) = setup();
        let _ =
            WebAuthnRegisterRequest::new(rp, user).auth_criteria(AuthenticatorCritera::default());
    }

    #[test]
    fn pk_create_options_attestation() {
        let (user, rp) = setup();
        let _ = WebAuthnRegisterRequest::new(rp, user).attestation(AttestationPreference::Indirect);
    }

    #[test]
    fn pk_create_options_all() {
        let (user, rp) = setup();
        let _ = WebAuthnRegisterRequest::new(rp, user)
            .timeout(10010)
            .attestation(AttestationPreference::Indirect)
            .auth_criteria(AuthenticatorCritera::default());
    }
}
