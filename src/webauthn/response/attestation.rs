//! Attestation Response Code

mod auth_data;
mod error;
mod format;

pub use self::error::AttestationError;
use self::{
    auth_data::{AttestationAuthData, AuthDataFlag},
    format::AttestationFormat,
};
use crate::WebAuthnError;
use ring::digest::{digest, Digest, SHA256};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
struct AttestationResponseInner {
    #[serde(flatten)]
    pub fmt: AttestationFormat,

    #[serde(rename = "authData")]
    #[serde(with = "serde_bytes")]
    pub auth_data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct AttestationData {
    fmt: AttestationFormat,
    auth_data: AttestationAuthData,
}

impl AttestationData {
    fn new(fmt: AttestationFormat, auth_data: AttestationAuthData) -> AttestationData {
        AttestationData { fmt, auth_data }
    }

    /// Decodes a base64-encoded string and returns the parsed AttestationResponse structure
    ///
    /// # Arguments
    /// * `data` - The base64url-decoded attestation_data field
    pub fn parse(data: Vec<u8>) -> Result<AttestationData, WebAuthnError> {
        let inner = serde_cbor::from_slice::<AttestationResponseInner>(&data)?;
        let auth_data = AttestationAuthData::parse(inner.auth_data)?;
        Ok(AttestationData::new(inner.fmt, auth_data))
    }

    /// Validates the data contained in this attestation object
    pub fn validate(self, client_data_hash: Digest) -> Result<(), AttestationError> {
        // Verify `self.auth_data.rp_id_hash` is the SHA256 hash of the expected RP ID
        let rp_id = vec![];
        let rp_id_hash = digest(&SHA256, &rp_id);
        if self.auth_data.rp_id_hash != rp_id_hash.as_ref() {
            panic!("")
        }
        // TODO

        // Verify the `User Present` flag is set in `self.auth_data`
        if !self.auth_data.is_flag_set(AuthDataFlag::UserPresent) {
            panic!("attestion object: user not present");
        }

        // if user verification is required, check for the user verification flag
        // TODO

        // Verify the attestation statement as specified by the attestation format
        let result = match self.fmt {
            AttestationFormat::FidoU2f(fido) => fido.validate(self.auth_data, client_data_hash),
            _ => Err(AttestationError::UnsupportedAttestationFormat),
        };

        if let Err(e) = result {
            panic!("Attestation Failed: {:?}", e);
        }

        // Verify the credentialId is not registered to another user
        // TODO

        Ok(())
    }
}
