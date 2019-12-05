//! FIDO2 responses

mod attestation;
mod client_data;

pub use self::attestation::AttestationError;
pub use self::client_data::ClientDataError;
use crate::webauthn::{WebAuthnConfig, WebAuthnError, WebAuthnType};

use attestation::AttestationData;
use client_data::ClientData;
use ring::digest::{digest, Digest, SHA256};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
struct Response {
    /// Base64-encoded CBOR data representing the attestation result
    #[serde(alias = "attestationData", alias = "attestationObject")]
    attestation_data: String,

    /// Base64-encode JSON that the client passed to the call
    #[serde(alias = "clientDataJson", alias = "clientDataJSON")]
    client_data_json: String,
}

/// A `WebAuthnResponse` is the result received from the browser/client
/// after a call to `navigator.credentials.create()` on the client side
/// has been completed.  All fields are required to be present
#[derive(Clone, Debug, Deserialize)]
pub struct WebAuthnRegisterResponse {
    /// Base64-encoded id
    pub id: String,

    /// Base64-encoded id (overriden in the public key response) without padding
    #[serde(alias = "rawId", alias = "rawID")]
    pub raw_id: String,

    /// The contained response for credential registration
    response: Response,

    /// The type of credential we tried to register
    #[serde(alias = "type")]
    ty: String,
}

impl WebAuthnRegisterResponse {
    /// Returns the client data associated with this response
    fn get_client_data(&self) -> Result<ClientData, WebAuthnError> {
        let decoded = base64::decode_config(&self.response.client_data_json, base64::URL_SAFE)?;
        let data: ClientData = serde_json::from_slice(&decoded)?;
        Ok(data)
    }

    /// Hashes the client data json received
    fn hash_client_data(&self) -> Result<Digest, WebAuthnError> {
        let decoded = base64::decode_config(&self.response.client_data_json, base64::URL_SAFE)?;
        let hash = digest(&SHA256, &decoded);
        Ok(hash)
    }

    /// Returns the attestation data assocated with this response
    fn get_attestation_data(&self) -> Result<AttestationData, WebAuthnError> {
        let decoded = base64::decode_config(&self.response.attestation_data, base64::STANDARD)?;
        let data = AttestationData::parse(decoded)?;
        Ok(data)
    }

    /// Validates this response
    pub fn validate<S: Into<String>>(
        &self,
        ty: WebAuthnType,
        cfg: &WebAuthnConfig,
        challenge: S,
    ) -> Result<(String, String), WebAuthnError> {
        let client_data = self.get_client_data()?;
        let client_data_hash = self.hash_client_data()?;
        let att_data = self.get_attestation_data()?;

        client_data.validate(ty, cfg, challenge)?;
        let (cred_id, cred_pubkey) = att_data.validate(cfg, client_data_hash)?;

        Ok((
            base64::encode_config(&cred_id, base64::STANDARD_NO_PAD),
            base64::encode_config(&cred_pubkey, base64::STANDARD_NO_PAD),
        ))
    }
}
