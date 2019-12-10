//! Attestation Response Code

mod error;
mod fidou2f;

pub use self::{error::AttestationError, fidou2f::U2fError};
use crate::{webauthn::response::auth_data::AuthData, WebAuthnError};
use serde::Deserialize;

/// Different types of attestation have different ways to authenticate/validate
/// the data.  This enum contains of the various different ways supported by
/// this library.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "fmt", content = "attStmt")]
pub enum AttestationFormat {
    #[serde(alias = "packed")]
    Packed,

    #[serde(alias = "fido-u2f")]
    FidoU2f(fidou2f::FidoU2fAttestation),
}

#[derive(Clone, Debug, Deserialize)]
struct AttestationData {
    #[serde(flatten)]
    pub fmt: AttestationFormat,

    #[serde(rename = "authData")]
    #[serde(with = "serde_bytes")]
    pub auth_data: Vec<u8>,
}

/// Decodes a base64-encoded string and returns the parsed AttestationResponse structure
///
/// # Arguments
/// * `data` - The base64url-decoded attestation_data field
pub fn parse(data: Vec<u8>) -> Result<(AuthData, AttestationFormat), WebAuthnError> {
    let inner = serde_cbor::from_slice::<AttestationData>(&data)?;
    let auth_data = AuthData::parse(inner.auth_data)?;
    Ok((auth_data, inner.fmt))
}
