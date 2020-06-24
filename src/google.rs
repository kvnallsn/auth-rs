//! Validate a Google JWT received when using a Google Login
//!
//! Source: [Google Sign-In for
//! Websites](https://developers.google.com/identity/sign-in/web/sign-in)

mod key;
pub use key::*;

mod store;
pub use store::*;

use chrono::{prelude::*, Duration};
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use parking_lot::RwLock;
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

/// The response from Google with new keys
#[derive(Deserialize, Debug)]
struct Response {
    pub keys: Vec<Jwk>,
}

#[derive(Clone)]
pub struct GoogleAuth<S> {
    inner: Arc<RwLock<GoogleAuthInner<S>>>,
}

#[derive(Clone)]
struct GoogleAuthInner<S> {
    store: S,
    expire: Option<DateTime<Utc>>,
    validation: Validation
}

impl<S> GoogleAuth<S>
where
    S: CertStore,
{
    pub fn new(store: S, client_id: impl Into<String>) -> GoogleAuth<S> {
        // build the validation struct
        let mut aud = HashSet::new();
        aud.insert(client_id.into());

        let validation = Validation {
            leeway: 0,
            validate_exp: true,
            iss: Some("accounts.google.com".to_owned()),
            aud: Some(aud),
            algorithms: vec![Algorithm::RS256],
            ..Default::default()
        };

        GoogleAuth {
            inner: Arc::new(RwLock::new(GoogleAuthInner {
                store,
                expire: Some(Utc::now()),
                validation,
            }))
        }
    }

    async fn fetch(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let resp = reqwest::get("https://www.googleapis.com/oauth2/v3/certs").await?;

        // examine the `Cache-Control` header per Google documentation
        let mut cache = CacheControl::new();
        let headers = resp.headers().get_all(reqwest::header::CACHE_CONTROL);
        for header in headers {
            cache.update(header.to_str().unwrap());
        }

        if cache.max_age > 0 {
            // set the new expiration time
            if let Ok(duration) = Duration::from_std(std::time::Duration::from_secs(cache.max_age)) {
                let mut inner = self.inner.write();
                inner.expire = Some(Utc::now() + duration);
            }
        }

        let response = resp.json::<Response>().await?;
        let mut inner = self.inner.write();
        inner.store.update(response.keys);
        Ok(())
    }

    /// Returns true of the keys in this store are expired
    fn is_expired(&self) -> bool {
        let inner = self.inner.read();
        if let Some(expire) = inner.expire {
            Utc::now() > expire 
        } else {
            false
        }
    }

    /// Verifies a JWT token is valid
    ///
    /// # Arguments
    /// * `token` - JWT token (as a base64-encoded string)
    pub async fn verify(&mut self, token: impl AsRef<str>) -> Result<Profile, GoogleError>
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

        // check if the store is expired
        if self.is_expired() {
            // if we don't have the request key, fetch them
            self.fetch().await.map_err(|_| GoogleError::FetchKeysFailed)?;
        }

        let inner = self.inner.read();
        let key = inner.store.get(&kid).ok_or_else(|| GoogleError::KeyNotFound)?;

        let profile: Profile = decode(token, &key, &inner.validation)
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
