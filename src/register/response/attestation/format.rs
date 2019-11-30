//! All the support Attestation formats

pub mod fidou2f;

use crate::register::response::attestation::auth_data::AttestationAuthData;
use ring::digest::Digest;
use serde::Deserialize;

#[derive(Clone, Debug)]
pub enum AttestationError {
    /// Occurs when too many X.509 certs are includded in the response
    TooManyX509Certs,

    /// Occurs when the certificate fails to parse
    BadCert,

    /// Occurs when the an unsupported algorithm is encountered
    UnsupportedAlgorithm,

    /// Occurs when converting the credential public key to X9.62 fails
    BadCredentialPublicKey,

    /// Occurs when the attestation fails
    BadSignature(webpki::Error),
}

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

impl AttestationFormat {
    pub fn validate(
        &self,
        auth_data: AttestationAuthData,
        client_data_hash: Digest,
    ) -> Result<(), AttestationError> {
        match self {
            AttestationFormat::Packed => unimplemented!(),
            AttestationFormat::FidoU2f(fmt) => fmt.validate(auth_data, client_data_hash),
        }
    }
}
