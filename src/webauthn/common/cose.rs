//! Parses COSE standards data

mod constants;
pub mod key;

pub use self::key::CoseKey;

use serde_cbor::Value;
use std::{collections::BTreeMap, error::Error, fmt};

pub type CoseMap = BTreeMap<i32, Value>;

#[derive(Debug)]
#[allow(dead_code)]
pub enum CoseError {
    /// Occurs when we encounted an unknown or unrecognized key field
    UnknownKey(String),

    /// Occurs when the key is valid, but the valid contained is not
    InvalidField(&'static str, i128),

    /// Occurs when the type we deserialized is not the type we expected
    /// or the type defined in the standard
    InvalidType(&'static str),

    /// Occurs when a required field is missing
    MissingFields,

    /// Occurs when an unsupported algorithm is detected
    UnsupportedAlgorithm,

    /// Occurs when CBOR parsing fails
    ParseError(serde_cbor::Error),
}
impl Error for CoseError {}

impl fmt::Display for CoseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            CoseError::UnknownKey(k) => format!("Unrecognized key: {}", k),
            CoseError::InvalidField(k, v) => format!("Invalid Field: `{}: {}`", k, v),
            CoseError::InvalidType(k) => format!("Unexpected value type: `{}", k),
            CoseError::MissingFields => format!("Some required fields are missing"),
            CoseError::UnsupportedAlgorithm => {
                format!("Unsupported algorithm -- only ES256 (-7) is supported")
            }
            CoseError::ParseError(e) => format!("failed to parse CBOR key structure: {}", e),
        };

        write!(f, "COSE Error: {}", msg)
    }
}

impl From<serde_cbor::Error> for CoseError {
    fn from(e: serde_cbor::Error) -> CoseError {
        CoseError::ParseError(e)
    }
}
