//! Top-Level WebAuthn Error

use crate::{
    common::cose::CoseError,
    webauthn::response::{AttestationError, AuthError, ClientDataError},
};
use base64::DecodeError;
use std::fmt;

#[derive(Debug)]
pub enum Error {
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IncorrectResponseType => write!(f, "Incorrect Response Type"),
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::SignatureFailed => write!(f, "Signature failed"),
            Error::DeviceNotFound => write!(f, "Device not found"),
            Error::AuthenticationError(e) => write!(f, "{}", e),
            Error::ClientData(e) => write!(f, "{}", e),
            Error::Attestation(e) => write!(f, "{}", e),
            Error::Base64Error(e) => write!(f, "{}", e),
            Error::JsonError(e) => write!(f, "{}", e),
            Error::CborError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<AuthError> for Error {
    fn from(e: AuthError) -> Error {
        Error::AuthenticationError(e)
    }
}

impl From<CoseError> for Error {
    fn from(_: CoseError) -> Error {
        Error::InvalidPublicKey
    }
}

impl From<ClientDataError> for Error {
    fn from(e: ClientDataError) -> Error {
        Error::ClientData(e)
    }
}

impl From<AttestationError> for Error {
    fn from(e: AttestationError) -> Error {
        Error::Attestation(e)
    }
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Error {
        Error::Base64Error(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::JsonError(e)
    }
}

impl From<serde_cbor::Error> for Error {
    fn from(e: serde_cbor::Error) -> Error {
        Error::CborError(e)
    }
}
