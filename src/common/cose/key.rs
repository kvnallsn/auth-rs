//! COSE Key related functions

mod algorithm;

use self::algorithm::CoseKeyAlgorithm;
use crate::common::cose::{constants::*, CoseError};
use serde_cbor::Value;
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
#[derive(Clone, Debug)]
pub enum CoseKeyType {
    Reserved,
    OKP,
    EC2,
    Symmetric,
}

impl CoseKeyType {
    /// Parses a COSE Key Type from a CBOR value
    ///
    /// # Argument
    /// * `value` - The CBOR encoded value
    pub fn from_cbor(value: &Value) -> Result<CoseKeyType, CoseError> {
        match value {
            Value::Integer(i) => match i {
                &COSE_KEY_KTY_RESERVED => Ok(CoseKeyType::Reserved),
                &COSE_KEY_KTY_OKP => Ok(CoseKeyType::OKP),
                &COSE_KEY_KTY_EC2 => Ok(CoseKeyType::EC2),
                &COSE_KEY_KTY_SYMMETRIC => Ok(CoseKeyType::Symmetric),
                _ => Err(CoseError::UnknownKey(format!("{}", i))),
            },
            _ => Err(CoseError::InvalidType("cose.kty")),
        }
    }
}

#[derive(Clone, Debug, Default)]
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

#[derive(Clone, Debug)]
pub struct CoseKey {
    kty: CoseKeyType,
    kid: Option<i32>,
    alg: CoseKeyAlgorithm,
    key_ops: Option<i32>,
    iv: Option<i32>,
}

impl CoseKey {
    pub fn parse(data: &[u8]) -> Result<CoseKey, Box<dyn std::error::Error>> {
        let mut builder = CoseKeyBuilder::default();
        let cbor = serde_cbor::from_slice::<serde_cbor::Value>(&data)?;
        if let serde_cbor::Value::Map(cose) = cbor {
            // attempt to read key type (KTY) - required field
            let kty = cose
                .get(&Value::Integer(COSE_KEY_KTY))
                .ok_or(CoseError::MissingFields)?;

            builder.set_key_type(CoseKeyType::from_cbor(kty)?);

            builder.set_algo(CoseKeyAlgorithm::from_cbor(&cose)?);
        }
        Ok(builder.finish()?)
    }
}
