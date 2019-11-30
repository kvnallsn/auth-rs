//! Parses COSE standards data

mod constants;
pub mod key;

pub use self::key::CoseKey;

use serde_cbor::Value;
use std::{collections::BTreeMap, error::Error, fmt};

pub type CoseMap = BTreeMap<i32, Value>;

#[derive(Clone, Debug)]
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
}
impl Error for CoseError {}

impl fmt::Display for CoseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CoseError::UnknownKey(k) => write!(f, "Unrecognized key: {}", k),
            CoseError::InvalidField(k, v) => write!(f, "Invalid Field: `{}: {}`", k, v),
            CoseError::InvalidType(k) => write!(f, "Unexpected value type: `{}", k),
            CoseError::MissingFields => write!(f, "Some required fields are missing"),
            CoseError::UnsupportedAlgorithm => {
                write!(f, "Unsupported algorithm -- only ES256 (-7) is supported")
            }
        }
    }
}
