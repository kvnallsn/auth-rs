//! ES256 algorithm details

use crate::common::cose::{constants::*, CoseError, CoseMap};
use serde::Deserialize;
use serde_cbor::Value;

/// Different Elliptic Curves that may be represented
#[derive(Clone, Debug, Deserialize)]
#[repr(u8)]
pub enum Curve {
    P256 = 1,
    P384 = 2,
    P512 = 3,
    X25519 = 4,
    X448 = 5,
    Ed25519 = 6,
    Ed448 = 7,
}

impl Curve {
    pub fn from_cbor(map: &CoseMap) -> Result<Curve, CoseError> {
        let crv = map.get(&COSE_KEY_EC2_CRV).ok_or(CoseError::MissingFields)?;

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

#[derive(Clone, Debug, Deserialize)]
pub struct ES256Params {
    crv: Curve,
    x: Option<Vec<u8>>,
    y: Option<Vec<u8>>,
    d: Option<Vec<u8>>,
}

#[allow(dead_code)]
impl ES256Params {
    /// Builds the ES256 params by parsing the BTreeMap
    pub fn from_cbor(map: &CoseMap) -> Result<ES256Params, CoseError> {
        let crv = Curve::from_cbor(map)?;
        let x = map.get(&COSE_KEY_EC2_X);
        let y = map.get(&COSE_KEY_EC2_Y);
        let d = map.get(&COSE_KEY_EC2_D);

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

        let is_public = d.is_some();
        let is_private = x.is_some() && y.is_some();

        if !is_public && !is_private {
            // Key has to be at least public or private
            return Err(CoseError::MissingFields);
        }

        Ok(ES256Params { crv, x, y, d })
    }

    /// Converts this public key into a the X9.62 RAW (octet) format
    /// which is defined as `0x04 | x | y` where:
    ///     * `0x04` - Indicates this is a raw (non-compressed) key
    ///     * `x` is the x-coordinate of the public key
    ///     * `y` is the y-coordinate of the public key
    pub fn to_raw(self) -> Option<Vec<u8>> {
        if let Some(mut x) = self.x {
            if let Some(mut y) = self.y {
                let mut raw = vec![0x04];
                raw.append(&mut x);
                raw.append(&mut y);
                return Some(raw);
            }
        }

        None
    }

    /// Returns the public key components (if they exists), else None
    pub fn get_public(&self) -> Option<(&[u8], &[u8])> {
        if let Some(ref x) = self.x {
            if let Some(ref y) = self.y {
                return Some((x, y));
            }
        }

        None
    }

    /// Returns the private key components (if they exists), else None
    pub fn get_private(&self) -> Option<&[u8]> {
        self.d.as_ref().map(|d| d.as_slice())
    }

    /// Returns true if these ES256 parameters contain a private key (i.e., d is not None)
    ///
    /// If this method returns true, then `unwrap()` can be successfully called on d
    pub fn is_private(&self) -> bool {
        self.d.is_some()
    }

    /// Returns true if these ES256 parameters contain a public key (i.e., x and y are not None)
    ///
    /// If this method returns true, then `unwrap()` can be successfully called on x and y
    pub fn is_public(&self) -> bool {
        self.x.is_some() && self.y.is_some()
    }
}
