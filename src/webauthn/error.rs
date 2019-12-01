//! Top-Level WebAuthn Error

use crate::webauthn::response::AttestationError;
use base64::DecodeError;
use std::fmt;

#[derive(Debug)]
pub enum WebAuthnError {
    Attestation(AttestationError),
    Base64Error(DecodeError),
    JsonError(serde_json::Error),
    CborError(serde_cbor::Error),
}

impl fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WebAuthnError::Attestation(e) => write!(f, "{}", e),
            WebAuthnError::Base64Error(e) => write!(f, "{}", e),
            WebAuthnError::JsonError(e) => write!(f, "{}", e),
            WebAuthnError::CborError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for WebAuthnError {}

impl From<AttestationError> for WebAuthnError {
    fn from(e: AttestationError) -> WebAuthnError {
        WebAuthnError::Attestation(e)
    }
}

impl From<DecodeError> for WebAuthnError {
    fn from(e: DecodeError) -> WebAuthnError {
        WebAuthnError::Base64Error(e)
    }
}

impl From<serde_json::Error> for WebAuthnError {
    fn from(e: serde_json::Error) -> WebAuthnError {
        WebAuthnError::JsonError(e)
    }
}

impl From<serde_cbor::Error> for WebAuthnError {
    fn from(e: serde_cbor::Error) -> WebAuthnError {
        WebAuthnError::CborError(e)
    }
}
