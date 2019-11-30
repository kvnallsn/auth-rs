//! COSE Key related functions

mod algorithm;

pub use self::algorithm::CoseKeyAlgorithm;
use crate::common::cose::{constants::*, CoseError, CoseMap};
use serde::Deserialize;
use serde_cbor::Value;
use serde_repr::Deserialize_repr;
use std::default::Default;

/// For each of the key types, we define both public and private members.
/// The public members are what is transmitted to others for their usage.
/// Private members allow for the archival of keys by individuals.
/// However, there are some circumstances in which private keys may be
/// distributed to entities in a protocol.  Examples include: entities
/// that have poor random number generation, centralized key creation for
/// multi-cast type operations, and protocols in which a shared secret is
/// used as a bearer token for authorization purposes.
///
/// Key types are identified by the 'kty' member of the COSE_Key object.
/// In this document, we define four values for the member:
#[derive(Clone, Debug, Deserialize_repr)]
#[repr(u8)]
pub enum CoseKeyType {
    Reserved = 0,
    OKP = 1,
    EC2 = 2,
    Symmetric = 4,
}

impl CoseKeyType {
    /// Parses a COSE Key Type from a CBOR value
    ///
    /// # Argument
    /// * `value` - The CBOR encoded value
    pub fn from_cbor(map: &CoseMap) -> Result<CoseKeyType, CoseError> {
        let kty = map.get(&COSE_KEY_KTY).ok_or(CoseError::MissingFields)?;
        match kty {
            Value::Integer(i) => match *i as i32 {
                COSE_KEY_KTY_RESERVED => Ok(CoseKeyType::Reserved),
                COSE_KEY_KTY_OKP => Ok(CoseKeyType::OKP),
                COSE_KEY_KTY_EC2 => Ok(CoseKeyType::EC2),
                COSE_KEY_KTY_SYMMETRIC => Ok(CoseKeyType::Symmetric),
                _ => Err(CoseError::UnknownKey(format!("{}", i))),
            },
            _ => Err(CoseError::InvalidType("cose.kty")),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct CoseKeyBuilder {
    kty: Option<CoseKeyType>,
    kid: Option<i32>,
    alg: Option<CoseKeyAlgorithm>,
    key_ops: Option<i32>,
    iv: Option<i32>,
}

impl CoseKeyBuilder {
    pub fn set_key_type(&mut self, kty: CoseKeyType) {
        self.kty = Some(kty);
    }

    #[allow(dead_code)]
    pub fn set_key_id(&mut self) {}

    #[allow(dead_code)]
    pub fn set_algo(&mut self, alg: CoseKeyAlgorithm) {
        self.alg = Some(alg);
    }

    #[allow(dead_code)]
    pub fn set_key_ops(&mut self) {}

    #[allow(dead_code)]
    pub fn set_iv(&mut self) {}

    pub fn finish(self) -> Result<CoseKey, CoseError> {
        if self.kty.is_none() || self.alg.is_none() {
            Err(CoseError::MissingFields)
        } else {
            Ok(CoseKey {
                kty: self.kty.unwrap(),
                kid: self.kid,
                alg: self.alg.unwrap(),
                key_ops: self.key_ops,
                iv: self.iv,
            })
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct CoseKey {
    pub kty: CoseKeyType,

    pub kid: Option<i32>,

    pub alg: CoseKeyAlgorithm,

    pub key_ops: Option<i32>,

    pub iv: Option<i32>,
}

impl CoseKey {
    pub fn parse(data: &[u8]) -> Result<CoseKey, Box<dyn std::error::Error>> {
        let cose: CoseMap = serde_cbor::from_slice(&data)?;
        let mut builder = CoseKeyBuilder::default();
        builder.set_key_type(CoseKeyType::from_cbor(&cose)?);
        builder.set_algo(CoseKeyAlgorithm::from_cbor(&cose)?);
        Ok(builder.finish()?)
    }
}
