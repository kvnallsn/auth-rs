//! COSE Key Algorithms

mod es256;

use self::es256::ES256Params;
use crate::common::cose::{constants::*, CoseError};
use serde_cbor::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub enum CoseKeyAlgorithm {
    ES256(ES256Params),
}

impl CoseKeyAlgorithm {
    /// Parses a COSE Key Algorithm from a CBOR value
    ///
    /// # Argument
    /// * `map` - Map of all values parsed from the CBOR attestation data
    pub fn from_cbor(map: &BTreeMap<Value, Value>) -> Result<CoseKeyAlgorithm, CoseError> {
        let value = map
            .get(&Value::Integer(COSE_KEY_ALG))
            .ok_or(CoseError::MissingFields)?;
        match value {
            Value::Integer(i) => match i {
                &COSE_KEY_ALGO_ES256 => Ok(CoseKeyAlgorithm::ES256(ES256Params::from_cbor(map)?)),
                _ => Err(CoseError::UnknownKey(format!("{}", i))),
            },
            _ => Err(CoseError::InvalidType("cose.alg")),
        }
    }
}
