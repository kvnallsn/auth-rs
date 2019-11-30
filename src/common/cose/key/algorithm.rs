//! COSE Key Algorithms

mod es256;

use self::es256::ES256Params;
use crate::common::cose::{constants::*, CoseError, CoseMap};
use serde::Deserialize;
use serde_cbor::Value;

#[derive(Clone, Debug, Deserialize)]
pub enum CoseKeyAlgorithm {
    #[serde(alias = "-7")]
    ES256(ES256Params),
}

impl CoseKeyAlgorithm {
    /// Parses a COSE Key Algorithm from a CBOR value
    ///
    /// # Argument
    /// * `map` - Map of all values parsed from the CBOR attestation data
    pub fn from_cbor(map: &CoseMap) -> Result<CoseKeyAlgorithm, CoseError> {
        let value = map.get(&COSE_KEY_ALG).ok_or(CoseError::MissingFields)?;
        match value {
            Value::Integer(i) => match *i as i32 {
                COSE_KEY_ALGO_ES256 => Ok(CoseKeyAlgorithm::ES256(ES256Params::from_cbor(map)?)),
                _ => Err(CoseError::UnknownKey(format!("{}", i))),
            },
            _ => Err(CoseError::InvalidType("cose.alg")),
        }
    }
}
