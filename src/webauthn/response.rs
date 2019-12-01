//! FIDO2 responses

mod attestation;
mod client_data;

pub use self::attestation::AttestationError;
use crate::webauthn::{WebAuthnError, WebAuthnType};

use attestation::AttestationData;
use client_data::ClientData;
use ring::digest::{digest, Digest, SHA256};
use serde::Deserialize;

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

    /// Base64-encoded CBOR data representing the attestation result
    #[serde(alias = "attestationData")]
    attestation_data: String,

    /// Base64-encode JSON that the client passed to the call
    #[serde(alias = "clientDataJson", alias = "clientDataJSON")]
    client_data_json: String,
}

impl WebAuthnRegisterResponse {
    /// Returns the client data associated with this response
    fn get_client_data(&self) -> Result<ClientData, WebAuthnError> {
        let decoded = base64::decode_config(&self.client_data_json, base64::URL_SAFE)?;
        let data: ClientData = serde_json::from_slice(&decoded)?;
        Ok(data)
    }

    /// Hashes the client data json received
    fn hash_client_data(&self) -> Result<Digest, WebAuthnError> {
        let decoded = base64::decode_config(&self.client_data_json, base64::URL_SAFE)?;
        let hash = digest(&SHA256, &decoded);
        Ok(hash)
    }

    /// Returns the attestation data assocated with this response
    fn get_attestation_data(&self) -> Result<AttestationData, WebAuthnError> {
        let decoded = base64::decode_config(&self.attestation_data, base64::STANDARD)?;
        let data = AttestationData::parse(decoded)?;
        Ok(data)
    }

    /// Validates this response
    pub fn validate<S: AsRef<str>, O: AsRef<str>>(
        &self,
        ty: WebAuthnType,
        challenge: S,
        origin: O,
    ) -> Result<(), WebAuthnError> {
        let client_data = self.get_client_data()?;
        let client_data_hash = self.hash_client_data()?;
        let att_data = self.get_attestation_data()?;

        client_data.validate(ty, challenge.as_ref(), origin.as_ref());
        att_data.validate(client_data_hash)?;

        Ok(())
    }
}
