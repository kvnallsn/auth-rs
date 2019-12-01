//! Attestation Error Code

use crate::common::cose::CoseError;
use std::{error::Error, fmt};

#[derive(Clone, Debug)]
pub enum AttestationError {
    /// Occurs when too many X.509 certs are includded in the response
    TooManyX509Certs,

    /// Occurs when the certificate fails to parse
    BadCert,

    /// Occurs when the an unsupported algorithm is encountered
    UnsupportedAlgorithm,

    /// Occurs when the attestation format specified is not supported.
    /// Current supported formats are: fido-u2f
    UnsupportedAttestationFormat,

    /// Occurs when parsing the COSE public key fails
    InvalidCoseKey,

    /// Occurs when converting the credential public key to X9.62 fails
    BadCredentialPublicKey,

    /// Occurs when the attestation fails
    BadSignature(webpki::Error),
}

impl Error for AttestationError {}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            AttestationError::TooManyX509Certs => format!("Too Many X.509 Certs in Response (> 1)"),
            AttestationError::BadCert => format!("Invalid X.509 Certificate in Response"),
            AttestationError::UnsupportedAlgorithm => format!("Unsupported Algorithm in Response"),
            AttestationError::UnsupportedAttestationFormat => {
                format!("Unsupported Format in Response")
            }
            AttestationError::InvalidCoseKey => format!("Failed to parse COSE public key"),
            AttestationError::BadCredentialPublicKey => {
                format!("Converting public key to X9.62 failed")
            }
            AttestationError::BadSignature(_) => format!("Signature Verification Failed"),
        };

        write!(f, "Attestation Error: {}", msg)
    }
}

impl From<CoseError> for AttestationError {
    fn from(_: CoseError) -> AttestationError {
        AttestationError::InvalidCoseKey
    }
}
