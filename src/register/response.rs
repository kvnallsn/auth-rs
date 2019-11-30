//! FIDO2 responses

mod attestation;
mod client_data;

use attestation::AttestationData;
use client_data::ClientData;
use ring::digest::{digest, Digest, SHA256};
use serde::Deserialize;

/// A `WebAuthnResponse` is the result received from the browser/client
/// after a call to `navigator.credentials.create()` on the client side
/// has been completed.  All fields are required to be present
#[derive(Clone, Debug, Deserialize)]
pub struct WebAuthnResponse {
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

impl WebAuthnResponse {
    /// Returns the client data associated with this response
    pub fn get_client_data(&self) -> Result<(ClientData, Digest), Box<dyn std::error::Error>> {
        let decoded = base64::decode_config(&self.client_data_json, base64::URL_SAFE)?;

        // Hash client data now
        let hash = digest(&SHA256, &decoded);

        let data: ClientData = serde_json::from_slice(&decoded)?;
        Ok((data, hash))
    }

    /// Returns the attestation data assocated with this response
    pub fn get_attestation_data(&self) -> Result<AttestationData, Box<dyn std::error::Error>> {
        let decoded = base64::decode_config(&self.attestation_data, base64::STANDARD)?;
        let data = AttestationData::parse(decoded)?;
        Ok(data)
    }
}
