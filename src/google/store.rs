//! A trait describing what can be used as a cert store

use crate::google::key::*;
use chrono::prelude::*;
use jsonwebtoken::DecodingKey;
use std::{collections::HashMap, default::Default};

pub trait CertStore: Clone {
    /// Handles updates from fetch
    fn update(&mut self, keys: Vec<Jwk>);

    /// Returns the key with the specified key id
    fn get(&self, kid: impl AsRef<str>) -> Option<DecodingKey>;
}

/// A simple in-memory cert store
///
/// For every instance of this created, each will independantly fetch and store the
/// certificates returned in a Hashmap
#[derive(Clone, Debug)]
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
    fn update(&mut self, keys: Vec<Jwk>) {
        // delete old certs...they've expired
        self.store.clear();

        // Loop over the keys, adding to the store when they are encounted
        for key in keys {
            self.store.insert(key.kid.clone(), key);
        }
    }

    /// Returns the key with the existing id, if one exists
    ///
    /// If the expiration time is set and in the past, then `get` will attempt
    /// to refresh the keys through a call to the Google endpoint
    fn get(&self, kid: impl AsRef<str>) -> Option<DecodingKey> {
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
