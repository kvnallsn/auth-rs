//! ES256 algorithm details

use crate::common::cose::{constants::*, CoseError};
use serde_cbor::Value;
use std::collections::BTreeMap;

/// Different Elliptic Curves that may be represented
#[derive(Clone, Debug)]
pub enum Curve {
    P256,
    P384,
    P512,
    X25519,
    X448,
    Ed25519,
    Ed448,
}

impl Curve {
    pub fn from_cbor(map: &BTreeMap<Value, Value>) -> Result<Curve, CoseError> {
        let crv = map
            .get(&Value::Integer(COSE_KEY_EC2_CRV))
            .ok_or(CoseError::MissingFields)?;

        match crv {
            Value::Integer(i) => match i {
                1 => Ok(Curve::P256),
                2 => Ok(Curve::P384),
                3 => Ok(Curve::P512),
                4 => Ok(Curve::X25519),
                5 => Ok(Curve::X448),
                6 => Ok(Curve::Ed25519),
                7 => Ok(Curve::Ed448),
                _ => Err(CoseError::InvalidField("cose.ec2.crv", *i)),
            },
            _ => Err(CoseError::InvalidType("cose.ec2.crv")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ES256Params {
    pub crv: Curve,
    pub x: Option<Vec<u8>>,
    pub y: Option<Vec<u8>>,
    pub d: Option<Vec<u8>>,
}

impl ES256Params {
    /// Builds the ES256 params by parsing the BTreeMap
    pub fn from_cbor(map: &BTreeMap<Value, Value>) -> Result<ES256Params, CoseError> {
        let crv = Curve::from_cbor(map)?;
        let x = map.get(&Value::Integer(COSE_KEY_EC2_X));
        let y = map.get(&Value::Integer(COSE_KEY_EC2_Y));
        let d = map.get(&Value::Integer(COSE_KEY_EC2_D));

        // Note: we don't use map here because if the value isn't bytes, then we have
        // and invalid type
        let x = match x {
            Some(x) => match x {
                Value::Bytes(b) => Some(b.clone()),
                _ => return Err(CoseError::InvalidType("cose.ec2.x")),
            },
            None => None,
        };

        let y = match y {
            Some(y) => match y {
                Value::Bytes(b) => Some(b.clone()),
                _ => return Err(CoseError::InvalidType("cose.ec2.y")),
            },
            None => None,
        };

        let d = match d {
            Some(d) => match d {
                Value::Bytes(b) => Some(b.clone()),
                _ => return Err(CoseError::InvalidType("cose.ec2.d")),
            },
            None => None,
        };

        Ok(ES256Params { crv, x, y, d })
    }
}
