//! COSE Key related functions

mod algorithm;

pub use self::algorithm::CoseKeyAlgorithm;
use crate::common::cose::{constants::*, CoseError, CoseMap};
use serde::Deserialize;
use serde_cbor::Value;
use serde_repr::Deserialize_repr;
use std::{
    convert::{TryFrom, TryInto},
    default::Default,
};

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

#[derive(Clone, Debug, Deserialize_repr)]
#[repr(u8)]
pub enum CoseKeyOps {
    Unknown = 0,
    Sign = 1,
    Verify = 2,
    Encrypt = 3,
    Decrypt = 4,
    WrapKey = 5,
    UnwrapKey = 6,
    DeriveKey = 7,
    DeriveBits = 8,
    MacCreate = 9,
    MacVerify = 10,
}

impl CoseKeyOps {
    /// Parses a COSE Key Type from a CBOR value
    ///
    /// # Argument
    /// * `value` - The CBOR encoded value
    pub fn from_cbor(map: &CoseMap) -> Option<Vec<CoseKeyOps>> {
        if let Some(kops) = map.get(&COSE_KEY_KEY_OPS) {
            let mut key_ops: Vec<CoseKeyOps> = vec![];
            if let Value::Array(kops) = kops {
                for kop in kops {
                    if let Value::Integer(kop) = kop {
                        if let Ok(op) = (*kop).try_into() {
                            key_ops.push(op);
                        }
                    }
                }
            }
            Some(key_ops)
        } else {
            None
        }
    }
}

impl TryFrom<i128> for CoseKeyOps {
    type Error = &'static str;

    fn try_from(i: i128) -> Result<Self, Self::Error> {
        match i {
            1 => Ok(CoseKeyOps::Sign),
            2 => Ok(CoseKeyOps::Verify),
            3 => Ok(CoseKeyOps::Encrypt),
            4 => Ok(CoseKeyOps::Decrypt),
            5 => Ok(CoseKeyOps::WrapKey),
            6 => Ok(CoseKeyOps::UnwrapKey),
            7 => Ok(CoseKeyOps::DeriveKey),
            8 => Ok(CoseKeyOps::DeriveBits),
            9 => Ok(CoseKeyOps::MacCreate),
            10 => Ok(CoseKeyOps::MacVerify),
            _ => Err("invalid operation"),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct CoseKeyBuilder {
    /// This parameter is used to identify the family of keys for this
    /// structure and, thus, the set of key-type-specific parameters to be
    /// found.
    kty: Option<CoseKeyType>,

    /// This parameter is used to give an identifier for a key.  The
    /// identifier is not structured and can be anything from a user-
    /// provided string to a value computed on the public portion of the
    /// key.  This field is intended for matching against a 'kid'
    /// parameter in a message in order to filter down the set of keys
    /// that need to be checked.
    kid: Option<Vec<u8>>,

    /// This parameter is used to restrict the algorithm that is used
    /// with the key.  If this parameter is present in the key structure,
    /// the application MUST verify that this algorithm matches the
    /// algorithm for which the key is being used.
    alg: Option<CoseKeyAlgorithm>,

    /// This parameter is defined to restrict the set of operations
    /// that a key is to be used for
    key_ops: Option<Vec<CoseKeyOps>>,

    /// This parameter is defined to carry the base portion of an
    /// IV.  It is designed to be used with the Partial IV header
    /// parameter
    iv: Option<Vec<u8>>,
}

impl CoseKeyBuilder {
    /// Set the key type for the CoseKey being parsed
    ///
    /// # Arguments
    /// * `kty` - What type of key is contained in this structure
    pub fn set_key_type(&mut self, kty: CoseKeyType) {
        self.kty = Some(kty);
    }

    /// Set the key id for the CoseKey being parsed
    ///
    /// # Arguments
    /// * `kid` - User-defined key identifier
    pub fn set_key_id(&mut self, key_id: Vec<u8>) {
        self.kid = Some(key_id);
    }

    /// Set the algorithm to be used with this key
    ///
    /// # Arguments
    /// * `alg` - key algorithm  to use
    pub fn set_algo(&mut self, alg: CoseKeyAlgorithm) {
        self.alg = Some(alg);
    }

    /// Set operations allowed for this key/algorithm pair
    ///
    /// # Arguments
    /// * `key_ops` - Various Key Options that are allowed for this key, or
    ///               None for all operations
    pub fn set_key_ops(&mut self, key_ops: Option<Vec<CoseKeyOps>>) {
        self.key_ops = key_ops;
    }

    /// Set base iv to be used with this key
    ///
    /// # Arguments
    /// * `iv` - Base IV
    pub fn set_iv(&mut self, iv: Vec<u8>) {
        self.iv = Some(iv);
    }

    /// Finish building this CoseKey and generate the resulting structure
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
    /// Identifies the family of keys found in this structure
    pub kty: CoseKeyType,

    /// User-defined identifier for the key
    pub kid: Option<Vec<u8>>,

    /// The algorithm used with this key
    pub alg: CoseKeyAlgorithm,

    /// Set of operations this key supports
    pub key_ops: Option<Vec<CoseKeyOps>>,

    /// Base portion of the IV
    pub iv: Option<Vec<u8>>,
}

impl CoseKey {
    pub fn parse(data: &[u8]) -> Result<CoseKey, CoseError> {
        let cose: CoseMap = serde_cbor::from_slice(&data)?;
        let mut builder = CoseKeyBuilder::default();
        builder.set_key_type(CoseKeyType::from_cbor(&cose)?);
        builder.set_algo(CoseKeyAlgorithm::from_cbor(&cose)?);
        builder.set_key_ops(CoseKeyOps::from_cbor(&cose));

        // Parse key id (kid)
        if let Some(kid) = cose.get(&COSE_KEY_KID) {
            if let Value::Bytes(kid) = kid {
                builder.set_key_id(kid.clone());
            }
        }

        // Parse IV
        if let Some(iv) = cose.get(&COSE_KEY_BASE_IV) {
            if let Value::Bytes(iv) = iv {
                builder.set_iv(iv.clone());
            }
        }

        Ok(builder.finish()?)
    }

    pub fn as_raw(&self) -> Option<Vec<u8>> {
        match self.alg {
            CoseKeyAlgorithm::ES256(ref params) => params.as_raw(),
        }
    }
}
