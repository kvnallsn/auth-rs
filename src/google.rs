//! Validate a Google JWT received when using a Google Login
//!
//! Source: [Google Sign-In for
//! Websites](https://developers.google.com/identity/sign-in/web/sign-in)

mod store;
pub use store::*;

use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use parking_lot::Mutex;
use serde::Deserialize;
use std::{collections::HashSet, default::Default, sync::Arc};

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

pub struct GoogleAuth<S> {
    store: Arc<Mutex<S>>,
}

impl<S> GoogleAuth<S>
where
    S: CertStore,
{
    pub fn new(store: S) -> GoogleAuth<S> {
        GoogleAuth {
            store: Arc::new(Mutex::new(store)),
        }
    }

    /// Verifies a JWT token is valid
    ///
    /// # Arguments
    /// * `token` - JWT token (as a base64-encoded string)
    pub fn verify(&mut self, token: impl AsRef<str>) -> Result<Profile, GoogleError>
    where
        S: CertStore,
    {
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
        let key;
        {
            let mut store = self.store.lock();
            key = store.get(&kid).ok_or_else(|| GoogleError::KeyNotFound)?;
        }

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
}

/*
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
*/
