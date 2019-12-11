//! Top-Level WebAuthn Error

use crate::{
    common::cose::CoseError,
    webauthn::response::{AttestationError, AuthError, ClientDataError},
};
use base64::DecodeError;
use std::fmt;

#[derive(Debug)]
pub enum WebAuthnError {
    IncorrectResponseType,
    InvalidPublicKey,
    SignatureFailed,
    DeviceNotFound,
    AuthenticationError(AuthError),
    ClientData(ClientDataError),
    Attestation(AttestationError),
    Base64Error(DecodeError),
    JsonError(serde_json::Error),
    CborError(serde_cbor::Error),
}

impl fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WebAuthnError::IncorrectResponseType => write!(f, "Incorrect Response Type"),
            WebAuthnError::InvalidPublicKey => write!(f, "Invalid public key"),
            WebAuthnError::SignatureFailed => write!(f, "Signature failed"),
            WebAuthnError::DeviceNotFound => write!(f, "Device not found"),
            WebAuthnError::AuthenticationError(e) => write!(f, "{}", e),
            WebAuthnError::ClientData(e) => write!(f, "{}", e),
            WebAuthnError::Attestation(e) => write!(f, "{}", e),
            WebAuthnError::Base64Error(e) => write!(f, "{}", e),
            WebAuthnError::JsonError(e) => write!(f, "{}", e),
            WebAuthnError::CborError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for WebAuthnError {}

impl From<AuthError> for WebAuthnError {
    fn from(e: AuthError) -> WebAuthnError {
        WebAuthnError::AuthenticationError(e)
    }
}

impl From<CoseError> for WebAuthnError {
    fn from(_: CoseError) -> WebAuthnError {
        WebAuthnError::InvalidPublicKey
    }
}

impl From<ClientDataError> for WebAuthnError {
    fn from(e: ClientDataError) -> WebAuthnError {
        WebAuthnError::ClientData(e)
    }
}

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
