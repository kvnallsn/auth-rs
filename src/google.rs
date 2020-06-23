//! Validate a Google JWT received when using a Google Login
//!
//! Source: [Google Sign-In for
//! Websites](https://developers.google.com/identity/sign-in/web/sign-in)

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::{collections::HashSet, default::Default};

const TYP_JWT: &str = "jwt";

/// All errors that may occur from using this library
#[derive(Debug)]
pub enum GoogleError {
    /// Occurs when the header fails to decode or if the `typ` field is not JWT (case insenstive)
    BadHeader,

    /// Occurs when the header is missing the `kid` field
    MissingKeyId,

    /// Occurs when attempting the fetch the keys fails
    FetchKeysFailed,

    /// Occurs when was not found in either our cache or from Google
    KeyNotFound,

    /// Occurs if validating the JWT fails
    ValidationFailed,
}

/// A JSON Web Key, returned from Google and used to validate the JWT
#[derive(Deserialize)]
struct JWK {
    /// Key Id corresponding to this key
    pub kid: String,

    /// The public key's modulus
    pub n: String,

    /// The public key's public exponent
    pub e: String,

    /// The key's type (should be RSA)
    pub kty: String,

    /// The use case for this key (renamed due to Rust's keywords)
    /// Should be signature
    #[serde(rename = "use")]
    pub typ: String,

    /// The specific algorithm (should be RS256)
    pub alg: String,
}

/// A container for the response from Google
#[derive(Deserialize)]
struct CertStore {
    /// A list of all valid JWKs that can be used to validate JWTs
    pub keys: Vec<JWK>,
}

impl CertStore {
    /// Fetches the current valid public keys from Google.  As of June 2020, the correct
    /// uri to fetch the keys is `https://www.googleapis.com/oauth2/v1/certs`.
    pub fn fetch() -> Result<CertStore, Box<dyn std::error::Error>> {
        let resp = reqwest::blocking::get("https://www.googleapis.com/oauth2/v3/certs")?;

        // examine the `Cache-Control` header per Google documentation
        // TODO

        let keys = resp.json::<CertStore>()?;
        Ok(keys)
    }

    /// Retrieves a key from the key store, returning a key that can be used
    /// to decode and verify a JWT
    pub fn get(&self, kid: impl AsRef<str>) -> Option<DecodingKey> {
        let mut idx = None;
        for (i, k) in self.keys.iter().enumerate() {
            if k.kid == kid.as_ref() {
                idx = Some(i);
                break;
            }
        }

        idx.map(|i| DecodingKey::from_rsa_components(&self.keys[i].n, &self.keys[1].e))
    }
}

#[derive(Deserialize, Debug)]
pub struct Profile {
    /// User's Google email address
    pub email: String,

    /// True if the user has verified their email address
    pub email_verified: bool,

    /// Name the user goes by (username)
    pub name: String,

    /// Link to profile picture image
    pub picture: String,

    /// Given (or first) name
    pub given_name: String,

    /// Family (or last) name
    pub family_name: String,

    /// Locale
    pub locale: String,
}

/// Verifies a JWT token is valid
///
/// # Arguments
/// * `token` - JWT token (as a base64-encoded string)
pub fn verify(token: impl AsRef<str>) -> Result<Profile, GoogleError> {
    let token = token.as_ref();

    // validate the header
    // Requirements:
    // * alg = RS256
    // * kid = Corresponding key id
    // * typ = JWT
    let header = decode_header(token).map_err(|_| GoogleError::BadHeader)?;

    // verify the type is JWT, fail if this header is missing
    if header.typ.map(|typ| typ.to_ascii_lowercase()).as_deref() != Some(TYP_JWT) {
        return Err(GoogleError::BadHeader);
    }

    // extract the key id used to sign this JWT
    let kid = header.kid.ok_or_else(|| GoogleError::MissingKeyId)?;

    // see if we have the key stored in our cache
    // TODO do this...

    // if we don't have the request key, fetch them
    let keys = CertStore::fetch().map_err(|_| GoogleError::FetchKeysFailed)?;
    let key = keys.get(&kid).ok_or_else(|| GoogleError::KeyNotFound)?;

    let mut aud = HashSet::new();
    aud.insert(
        "561520225764-innm2teqdgtr60n6l1b9dknb261vml3e.apps.googleusercontent.com".to_owned(),
    );

    let validation = Validation {
        leeway: 0,
        validate_exp: true,
        iss: Some("accounts.google.com".to_owned()),
        aud: Some(aud),
        algorithms: vec![Algorithm::RS256],
        ..Default::default()
    };

    let profile: Profile = decode(token, &key, &validation)
        .map_err(|_| GoogleError::ValidationFailed)
        .map(|data| data.claims)?;

    // by default, the token is invalid
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_in() {
        let token = "<SOME TOKEN HERE>";
        let profile = verify(token);
        assert!(profile.is_ok());
    }
}
