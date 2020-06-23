//! A trait describing what can be used as a cert store

use chrono::{prelude::*, Duration};
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use std::{collections::HashMap, default::Default};

/// A JSON Web Key, returned from Google and used to validate the JWT
#[derive(Deserialize, Debug)]
pub struct Jwk {
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

#[derive(Deserialize, Debug)]
pub enum Cacheability {
    /// May be stored by any cache, even if the response is normally non-cacheable.
    Public,

    /// May be stored only by a browser's cache, even if the response is normally non-cacheable
    Private,

    /// May be stored by any cache, even if the response is normally non-cacheable. However, the
    /// stored response MUST always go through validation with the origin server first before using
    /// it, therefore, you cannot use no-cache in-conjunction with immutable. If you mean to not
    /// store the response in any cache, use no-store instead
    NoCache,

    /// May not be stored in any cache. Although other directives may be set, this alone is the
    /// only directive you need in preventing cached responses on modern browsers. max-age=0 is
    /// already implied. Setting must-revalidate does not make sense because in order to go through
    /// revalidation you need the response to be stored in a cache, which no-store prevents.
    NoStore,
}

/// Contains the cache control information from the key response
#[derive(Deserialize, Debug)]
pub struct CacheControl {
    cacheability: Cacheability,
    max_age: u64,
}

impl Default for CacheControl {
    fn default() -> CacheControl {
        CacheControl {
            cacheability: Cacheability::Public,
            max_age: 0,
        }
    }
}

impl CacheControl {
    fn new() -> CacheControl {
        Self::default()
    }

    fn update(&mut self, header: impl Into<String>) {
        for directive in header.into().split(",") {
            let directive = directive.trim();
            match directive {
                "public" => self.cacheability = Cacheability::Public,
                "private" => self.cacheability = Cacheability::Private,
                "no-cache" => self.cacheability = Cacheability::NoCache,
                "no-store" => self.cacheability = Cacheability::NoStore,
                _ => {
                    if directive.starts_with("max-age") {
                        if let Some(age) = directive.split("=").last() {
                            self.max_age = age.parse().unwrap_or_else(|_| 0);
                        }
                    }
                }
            }
        }
    }
}

/// The response from Google with new keys
#[derive(Deserialize, Debug)]
pub struct Response {
    pub keys: Vec<Jwk>,

    #[serde(default)]
    pub cache: CacheControl,
}

pub trait CertStore {
    /// Handles updates from fetch
    fn refresh(&mut self);

    /// Returns the key with the specified key id
    fn get(&mut self, kid: impl AsRef<str>) -> Option<DecodingKey>;

    /// Refreshes this store, adding new keys and removing old expired keys
    fn fetch() -> Result<Response, Box<dyn std::error::Error>> {
        let resp = reqwest::blocking::get("https://www.googleapis.com/oauth2/v3/certs")?;

        // examine the `Cache-Control` header per Google documentation
        let mut cache = CacheControl::new();
        let headers = resp.headers().get_all(reqwest::header::CACHE_CONTROL);
        for header in headers {
            cache.update(header.to_str().unwrap());
        }

        let response = resp.json::<Response>()?;
        Ok(response)
    }
}

/// A simple in-memory cert store
///
/// For every instance of this created, each will independantly fetch and store the
/// certificates returned in a Hashmap
#[derive(Debug)]
pub struct MemoryCertStore {
    store: HashMap<String, Jwk>,
    expire: Option<DateTime<Utc>>,
}

impl Default for MemoryCertStore {
    fn default() -> MemoryCertStore {
        MemoryCertStore {
            store: HashMap::new(),
            expire: Some(Utc::now()),
        }
    }
}

impl MemoryCertStore {
    pub fn new() -> MemoryCertStore {
        Self::default()
    }
}

impl CertStore for MemoryCertStore {
    /// Clears the old certificates and Reloads the them from Google
    fn refresh(&mut self) {
        // delete old certs...they've expired
        self.store.clear();

        // fetch new certs then load them into the store
        if let Ok(resp) = Self::fetch() {
            // If an expiration time was present (and it was not zero (or never expire))
            // compute when that will be for us in UTC
            if resp.cache.max_age > 0 {
                let duration = std::time::Duration::from_secs(resp.cache.max_age);
                if let Ok(duration) = Duration::from_std(duration) {
                    self.expire = Some(Utc::now() + duration);
                }
            }

            // Loop over the keys, adding to the store when they are encounted
            for key in resp.keys {
                self.store.insert(key.kid.clone(), key);
            }
        }
    }

    /// Returns the key with the existing id, if one exists
    ///
    /// If the expiration time is set and in the past, then `get` will attempt
    /// to refresh the keys through a call to the Google endpoint
    fn get(&mut self, kid: impl AsRef<str>) -> Option<DecodingKey> {
        // check expiration, if expired, load new certs
        if let Some(expiration) = self.expire {
            if Utc::now() > expiration {
                self.refresh();
            }
        }

        self.store
            .get(kid.as_ref())
            .map(|k| DecodingKey::from_rsa_components(&k.n, &k.e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_store_invalid_key() {
        let mut store = MemoryCertStore::new();
        let res = store.get("invalid-key");
        assert_eq!(res, None);
    }
}
