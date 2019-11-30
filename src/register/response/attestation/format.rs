//! All the support Attestation formats

pub mod fidou2f;

use openssl::x509::X509;
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

impl AttestationFormat {
    pub fn get_cert(&self) -> Result<X509, Box<dyn std::error::Error>> {
        let cert = match self {
            AttestationFormat::Packed => unimplemented!(),
            AttestationFormat::FidoU2f(fmt) => fmt.get_cert()?,
        };
        Ok(cert)
    }
}
