//! FIDO2 responses

mod attestation;
mod auth_data;
mod client_data;

pub use self::attestation::AttestationError;
pub use self::auth_data::AuthError;
pub use self::client_data::ClientDataError;

use crate::{
    parsers,
    webauthn::{
        response::{attestation::AttestationFormat, auth_data::AuthData},
        WebAuthnConfig, WebAuthnError, WebAuthnType,
    },
};

use client_data::ClientData;
use ring::{
    digest::{digest, SHA256},
    signature,
};
use serde::Deserialize;
use untrusted::Input;

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
enum Response {
    #[serde(rename = "create")]
    Create(CreateResponse),

    #[serde(rename = "get")]
    Get(GetResponse),
}

#[derive(Clone, Debug, Deserialize)]
struct CreateResponse {
    /// Base64-encoded CBOR data representing the attestation result
    #[serde(alias = "attestationData", alias = "attestationObject")]
    attestation_data: String,

    /// Base64-encode JSON that the client passed to the call
    #[serde(alias = "clientDataJson", alias = "clientDataJSON")]
    client_data_json: String,
}

impl CreateResponse {
    fn validate<S: Into<String>>(
        &self,
        ty: WebAuthnType,
        cfg: &WebAuthnConfig,
        challenge: S,
    ) -> Result<(String, String, u32), WebAuthnError> {
        // Get the client data the SHA256 hash of it
        let client_data = base64::decode_config(&self.client_data_json, base64::URL_SAFE)?;
        let client_data_hash = digest(&SHA256, &client_data);
        let client_data: ClientData = serde_json::from_slice(&client_data)?;

        // Get the attestation data
        let (auth_data, attestation_format) = attestation::parse(base64::decode_config(
            &self.attestation_data,
            base64::STANDARD,
        )?)?;

        client_data.validate(ty, cfg, challenge)?;
        auth_data.validate(cfg)?;

        // Verify the attestation statement as specified by the attestation format
        let (cred_id, cred_pubkey) = match attestation_format {
            AttestationFormat::FidoU2f(fido) => fido.validate(&auth_data, client_data_hash)?,
            _ => Err(AttestationError::UnsupportedAttestationFormat)?,
        };

        Ok((
            base64::encode_config(&cred_id, base64::URL_SAFE_NO_PAD),
            base64::encode_config(&cred_pubkey, base64::URL_SAFE_NO_PAD),
            auth_data.count(),
        ))
    }
}

#[derive(Clone, Debug, Deserialize)]
struct GetResponse {
    /// Authenticator data returned by the authenticator
    #[serde(rename = "authenticatorData")]
    #[serde(deserialize_with = "parsers::base64")]
    authenticator_data: Vec<u8>,

    /// Base64url-encoded raw signature returned from the authenticator
    #[serde(deserialize_with = "parsers::base64")]
    signature: Vec<u8>,

    /// Base64url-encoded user handle returned from the authenticator
    #[serde(rename = "userHandle")]
    #[serde(deserialize_with = "parsers::non_empty_str")]
    user_handle: Option<String>,

    /// Base64-encode JSON that the client passed to the call
    #[serde(rename = "clientDataJSON", alias = "clientDataJson")]
    #[serde(deserialize_with = "parsers::base64")]
    client_data_json: Vec<u8>,
}

impl GetResponse {
    fn validate<S: Into<String>>(
        &self,
        ty: WebAuthnType,
        cfg: &WebAuthnConfig,
        challenge: S,
        pubkey: Vec<u8>,
    ) -> Result<(), WebAuthnError> {
        // (10 - 14) Verify Client Data
        let client_data: ClientData = serde_json::from_slice(&self.client_data_json)?;
        client_data.validate(ty, cfg, challenge)?;

        let auth_data = AuthData::parse(self.authenticator_data.clone())?;

        // (15 - 17) verify auth data
        auth_data.validate(cfg)?;

        // (18) Verify extensions
        // TODO

        // (19) Compute SHA256 hash of client data
        let hash = digest(&SHA256, &self.client_data_json);

        // (20) Verify signature is a valid signature with the associated public key
        let mut verification_data = vec![];
        verification_data.extend_from_slice(&self.authenticator_data);
        verification_data.extend_from_slice(hash.as_ref());

        signature::verify(
            &signature::ECDSA_P256_SHA256_ASN1,
            Input::from(&pubkey),
            Input::from(&verification_data),
            Input::from(&self.signature),
        )
        .map_err(|_| WebAuthnError::SignatureFailed)?;

        // (21) Verify signedCount
        // TODO
        println!("Sign count: {}", auth_data.count());

        Ok(())
    }
}

/// A `WebAuthnResponse` is the result received from the browser/client
/// after a call to `navigator.credentials.create()` on the client side
/// has been completed.  All fields are required to be present
#[derive(Clone, Debug, Deserialize)]
pub struct WebAuthnResponse {
    /// Base64-encoded id
    id: String,

    /// Base64-encoded id (overriden in the public key response) without padding
    #[serde(alias = "rawId", alias = "rawID")]
    raw_id: String,

    /// The contained response for credential registration
    response: Response,

    /// The type of credential we tried to register
    #[serde(alias = "type")]
    ty: String,
}

impl WebAuthnResponse {
    /// Returns the type of message contained in this response, either a response
    /// to a `create()` call (i.e., register) or a response to a `get()` call
    /// (i.e., authenticate/login)
    pub fn ty(&self) -> WebAuthnType {
        match self.response {
            Response::Create(_) => WebAuthnType::Create,
            Response::Get(_) => WebAuthnType::Get,
        }
    }

    /// Validates a response received after a call to `navigator.credentials.create()` (i.e.,
    /// registering a token).  Returns the id of the credential that was just registered
    /// and the associated public key as (credential_id, pub_key).  In the event the response
    /// contained is not a create response, returns an `IncorrectResponseType` response
    pub fn validate_create<S: Into<String>>(
        &self,
        cfg: &WebAuthnConfig,
        challenge: S,
    ) -> Result<(String, String, u32), WebAuthnError> {
        match self.response {
            Response::Create(ref resp) => resp.validate(WebAuthnType::Create, cfg, challenge),
            _ => Err(WebAuthnError::IncorrectResponseType),
        }
    }

    /// Validates  response recieved after a call to `navigator.credentials.get()` (i.e.,
    /// logging in with a token)
    pub fn validate_get<S: Into<String>>(
        &self,
        cfg: &WebAuthnConfig,
        challenge: S,
        pubkey: String,
    ) -> Result<(), WebAuthnError> {
        match self.response {
            Response::Create(_) => Err(WebAuthnError::IncorrectResponseType),
            Response::Get(ref resp) => {
                // (5) Verify the credential id in the request matches the credential id
                // in the response
                // TODO

                // (6) Verify the credential id in the response is a credential owned by
                // the requesting user
                // TODO

                // (7 / 20.1) Retrieve and covert pubkey into the correct format
                let key_bytes = base64::decode_config(&pubkey, base64::URL_SAFE)?;

                resp.validate(WebAuthnType::Get, cfg, challenge, key_bytes)
            }
        }
    }
}
