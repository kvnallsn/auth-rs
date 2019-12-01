//! All the support Attestation formats

pub mod fidou2f;

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
