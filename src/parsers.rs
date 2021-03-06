//! Support for deserializing different types of fields

use serde::{de, Deserialize, Deserializer};

/// Deserializes an optional string, returning `None` of the string is empty
/// instead of `Some("")`
///
/// # Argumnets
/// * `d` - Value to deserialize
#[allow(dead_code)]
pub fn optional_str<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let o: Option<String> = Option::deserialize(d)?;
    Ok(o.filter(|s| !s.is_empty()))
}

#[allow(dead_code)]
pub fn optional_base64<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    let o: Option<String> = Option::deserialize(d)?;
    Ok(match o {
        Some(enc) if enc.is_empty() => None,
        Some(enc) => {
            Some(base64::decode_config(&enc, base64::STANDARD).map_err(de::Error::custom)?)
        }
        None => None,
    })
}

/// Deserializes a base64url-enocded string into the underlying bytes
#[allow(dead_code)]
pub fn base64url<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s: String = String::deserialize(d)?;
    Ok(base64::decode_config(&s, base64::URL_SAFE_NO_PAD).map_err(de::Error::custom)?)
}

/// Deserializes a base64url-enocded string into the underlying bytes
#[allow(dead_code)]
pub fn base64<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s: String = String::deserialize(d)?;
    Ok(base64::decode_config(&s, base64::STANDARD).map_err(de::Error::custom)?)
}
