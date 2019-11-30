//! Attestation Response Code

mod auth_data;
mod format;

use self::{
    auth_data::{AttestationAuthData, AuthDataFlag},
    format::AttestationFormat,
};
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
    pub fn parse(data: Vec<u8>) -> Result<AttestationData, Box<dyn std::error::Error>> {
        let inner = serde_cbor::from_slice::<AttestationResponseInner>(&data)?;
        let auth_data = AttestationAuthData::parse(inner.auth_data)?;
        Ok(AttestationData::new(inner.fmt, auth_data))
    }

    /// Validates the data contained in this attestation object
    pub fn validate(&self) {
        // Verify `self.auth_data.rp_id_hash` is the SHA256 hash of the expected RP ID
        // TODO

        // Verify the `User Present` flag is set in `self.auth_data`
        if !self.auth_data.is_flag_set(AuthDataFlag::UserPresent) {
            panic!("attestion object: user not present");
        }

        // if user verification is required, check for the user verification flag
        // TODO

        // verify the `alg` parameter in the credential public key matches the
        // alg attribute of one of the items in `options.pubKeyCredParams`
        // TODO
        let _ = self.fmt.get_cert();

        // Verify the attestation statement as specified by the attestation format
        // TODO

        // Verify the credentialId is not registered to another user
        // TODO
    }
}
