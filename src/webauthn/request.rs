//! Request structs/enums for registering a new token

mod attestation;
mod authenticator;

use self::{attestation::AttestationPreference, authenticator::AuthenticatorCritera};
use crate::webauthn::{
    pk::{PublicKeyDescriptor, PublicKeyParams},
    rp::RelyingParty,
    user::{User, UserVerificationRequirement},
    WebAuthnConfig, WebAuthnDevice, WebAuthnError,
};
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
    pub fn set_timeout<'a>(&'a mut self, timeout: u32) -> &'a mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the requirements for the Authenticator that will be used
    ///
    /// # Arguments
    /// * `criteria` - Requirements for what authenticator should be used
    pub fn set_auth_criteria<'a>(&'a mut self, critera: AuthenticatorCritera) -> &'a mut Self {
        self.authenticator_selection = critera;
        self
    }

    /// Changes the attestation preference
    ///
    /// # Arguments
    /// * `attestation` - New attestation preference
    pub fn set_attestation<'a>(&'a mut self, attestation: AttestationPreference) -> &'a mut Self {
        self.attestation = attestation;
        self
    }

    /// Returns the challenge as a base64url-encoded string
    pub fn challenge(&self) -> String {
        base64::encode_config(&self.challenge, base64::URL_SAFE_NO_PAD)
    }

    /// Returns the relying party information about this request
    pub fn relying_party(&self) -> &RelyingParty {
        &self.rp
    }

    /// Converts this request into the equivalent JSON for sending to a client.
    /// This method is (usually) not required when working with web frameworks
    /// like Rocket or Actix-Web since the framework (usually) has it's own
    /// methods for returning JSON data
    pub fn json(&self) -> Result<String, WebAuthnError> {
        Ok(serde_json::to_string(self)?)
    }
}

/// Options for validating an existing, registered PublicKey. The json serialization
/// of this struct is passed to `navigator.credentials.get()` on the client side.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticateRequest {
    /// Random bytes that the selected authenticator signs, along with other data,
    /// when producing an authentication assertion.
    challenge: Vec<u8>,

    /// A time, in milliseconds, that the caller is willing to wait for the call to
    /// complete. The value is treated as a hint, and MAY be overridden by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u32>,

    /// Relying Party Identifer, filled in from config parameter
    #[serde(rename = "rpId", alias = "rpID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    rp_id: Option<String>,

    /// List of PublicKeyCredentialDescriptor objects representing public key credentials
    /// acceptable to the caller, in descending order of the caller’s preference (the first
    /// item in the list is the most preferred credential, and so on down the list).
    #[serde(rename = "allowCredentials")]
    allow_credentials: Vec<PublicKeyDescriptor>,

    /// Relying Party's requirements regarding user verification for the `get()` operation.
    /// Eligible authenticators are filtered to only those capable of satisfying this requirement.
    #[serde(rename = "userVerification")]
    user_verification: UserVerificationRequirement,
}

impl AuthenticateRequest {
    pub fn new(config: &WebAuthnConfig, devices: Vec<WebAuthnDevice>) -> AuthenticateRequest {
        // generate a random challenge
        let mut challenge = vec![0; 32];
        rand::thread_rng().fill_bytes(&mut challenge);

        AuthenticateRequest {
            challenge,
            timeout: None,
            rp_id: Some(config.id().to_owned()),
            allow_credentials: devices
                .iter()
                .map(|d| PublicKeyDescriptor::new(d.id().to_vec()))
                .collect(),
            user_verification: UserVerificationRequirement::Preferred,
        }
    }

    pub fn challenge(&self) -> String {
        base64::encode_config(&self.challenge, base64::URL_SAFE_NO_PAD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::{User, WebAuthnConfig};

    fn setup() -> (WebAuthnConfig, User) {
        let config = WebAuthnConfig::new("http:://www.example.com");
        let user = User::new(vec![0, 1, 2, 3], "user", "user");
        (config, user)
    }

    #[test]
    fn pk_create_options_default() {
        let (config, user) = setup();
        let _ = WebAuthnRegisterRequest::new(config, user);
    }

    #[test]
    fn pk_create_options_default_config_reference() {
        let (config, user) = setup();
        let _ = WebAuthnRegisterRequest::new(&config, user);
    }

    #[test]
    fn pk_create_options_timeout() {
        let (config, user) = setup();
        let _ = WebAuthnRegisterRequest::new(config, user).set_timeout(10000);
    }

    #[test]
    fn pk_create_options_auth_criteria() {
        let (config, user) = setup();
        let _ = WebAuthnRegisterRequest::new(config, user)
            .set_auth_criteria(AuthenticatorCritera::default());
    }

    #[test]
    fn pk_create_options_attestation() {
        let (config, user) = setup();
        let _ = WebAuthnRegisterRequest::new(config, user)
            .set_attestation(AttestationPreference::Indirect);
    }

    #[test]
    fn pk_create_options_all() {
        let (config, user) = setup();
        let _ = WebAuthnRegisterRequest::new(config, user)
            .set_timeout(10010)
            .set_attestation(AttestationPreference::Indirect)
            .set_auth_criteria(AuthenticatorCritera::default());
    }

    #[test]
    fn pk_create_json() {
        let (config, user) = setup();
        let result = WebAuthnRegisterRequest::new(config, user)
            .set_timeout(10010)
            .set_attestation(AttestationPreference::Indirect)
            .set_auth_criteria(AuthenticatorCritera::default())
            .json();
        assert!(result.is_ok())
    }
}
