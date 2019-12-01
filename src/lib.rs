//! FIDO2 WebAuthn implementation

pub mod common;
pub mod register;
pub mod webauthn;

use crate::{
    common::{rp::RelyingParty, user::User},
    webauthn::{
        request::PublicKeyCreationOptions,
        response::{WebAuthnResponse, WebAuthnType},
        WebAuthnError,
    },
};

pub struct SecurityDevice;

impl SecurityDevice {
    /// Creates a request that can be sent to a webauthn api
    ///
    /// # Arguments
    /// * `rp` - The RelyingParty this request represents
    /// * `user` - The user that owns this request
    pub fn register_request<R: Into<RelyingParty>, U: Into<User>>(
        rp: R,
        user: U,
    ) -> PublicKeyCreationOptions {
        PublicKeyCreationOptions::new(rp, user)
    }

    /// Parses the response to a register request
    /// [Spec](https://w3c.github.io/webauthn/#sctn-registering-a-new-credential)
    ///
    /// # Arguments
    /// * `form` - Form received from the client
    pub fn register(form: WebAuthnResponse) -> Result<(), WebAuthnError> {
        form.validate(
            WebAuthnType::Create,
            "s0Tnjjv67CzQxIdneKXRPrUYGyUjuZQJr17fRPkvdoA",
            "https://app.twinscroll.dev",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{rp::RelyingParty, user::User};
    use std::fs::File;

    fn setup() -> (User, RelyingParty) {
        let user = User::new(vec![0], "user", "user");
        let rp = "server".into();
        (user, rp)
    }

    fn read_create_response() -> Result<WebAuthnResponse, Box<dyn std::error::Error>> {
        let file = File::open("test.json")?;
        let form = serde_json::from_reader(file)?;
        Ok(form)
    }

    #[test]
    fn canary() {
        // If this fails we have a problem...
        assert!(true);
    }

    #[test]
    fn register_device_default() -> Result<(), Box<dyn std::error::Error>> {
        let (user, rp) = setup();
        let req = SecurityDevice::register_request(rp, user);
        let _ = serde_json::to_string_pretty(&req)?;
        Ok(())
    }

    #[test]
    fn register_device_response() -> Result<(), Box<dyn std::error::Error>> {
        let resp = read_create_response()?;
        SecurityDevice::register(resp)?;
        Ok(())
    }
}

/*
use crate::{common::PublicKeyAlgorithm, register::request::PublicKeyCreationOptions};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::default::Default;

/// Options for requesting a new PublicKey.  This struct is passed to
/// `navigator.credentials.get()` on the client side.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyRequestOptions {
    /// A challenge that is sent to, then signed by, the selected authenticator
    /// along with other data to produce an authentication assertion.
    challenge: Vec<u8>,

    /// OPTIONAL - Specifies a time, in milliseconds, the caller is willing to wait for the call
    /// to complete.  Treated as a hint and my be overriden by the client.alloc
    ///
    /// Default: None
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u32>,

    /// OPTIONAL - Specifies the relying party identifier claimed by the called.  If omitted, its
    /// value will be the CredentialsContainer object's relevant settings object's orign's
    /// effective domain
    ///
    /// Default: None
    #[serde(skip_serializing_if = "Option::is_none")]
    rp_id: Option<String>,

    /// List of public key credentials representing a public key that are acceptable to use, in
    /// descending order of preference (i.e., index 0 is most preferred, index n is least preferred)
    allow_credentials: Vec<PublicKeyCredential>,

    /// OPTIONAL - Relying Parties requirements for user verification for the `get()` operation.
    /// Eligible authenticators are filtered to only those capable of satisying the requirement.
    ///
    /// Default: None
    #[serde(skip_serializing_if = "Option::is_none")]
    user_verification: Option<UserVerificationRequirement>,
}

impl PublicKeyRequestOptions {
    /// Creates a new Request in order to validate a public key/authenticator in the client
    pub fn new() -> PublicKeyRequestOptions {
        PublicKeyRequestOptions::default()
    }

    /// Add allowed credentials for this request
    ///
    /// # Arguments
    /// * `credentials` - Valid security devices to allow for this request
    pub fn add_credentials(
        mut self,
        mut credentials: Vec<PublicKeyCredential>,
    ) -> PublicKeyRequestOptions {
        self.allow_credentials.append(&mut credentials);
        self
    }
}

impl Default for PublicKeyRequestOptions {
    fn default() -> PublicKeyRequestOptions {
        let mut challenge = vec![0; 32];
        rand::thread_rng().fill_bytes(&mut challenge);

        let s = base64::encode_config(&challenge, base64::URL_SAFE);
        println!("Challenge: {}", s);

        PublicKeyRequestOptions {
            challenge,
            timeout: None,
            rp_id: None,
            allow_credentials: vec![],
            user_verification: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct PublicKeyResponse {
    /// What type of request was performed: `webauthn.get` or `webauthn.create`
    #[serde(rename = "type")]
    pub ty: String,

    /// The base64url encoded version of the cryptographic challenge sent from
    /// the relying party's server
    pub challenge: String,

    /// Fully-Qualified origin of the requestor which has been given by the client/
    /// browser to the authenticator.  We should expect the relying party's id to
    /// be a suffix of this value
    pub origin: String,
}

impl PublicKeyResponse {
    pub fn from_response(resp: String) -> Result<PublicKeyResponse, Box<dyn std::error::Error>> {
        let client_data_json = base64::decode_config(&resp, base64::URL_SAFE)?;
        let client_data = serde_json::from_slice(&client_data_json)?;
        Ok(client_data)
    }
}
*/
