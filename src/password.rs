//! Password based authentication using argon2

use argon2::{self, Config};
use rand::RngCore;
use std::default::Default;
use thiserror::Error;

// Re-export error type for use downstream
pub use argon2::Variant;

#[derive(Error, Debug)]
pub enum HasherError {
    #[error("password validation failed")]
    ValidationFailed,

    #[error("argon2 backend failure: {0}")]
    Argon2(#[from] argon2::Error),
}

pub enum Hasher {
    Argon2(Config<'static>),
}

impl Hasher {
    pub fn new(lanes: u32, memory: u32, passes: u32, variant: Variant) -> Self {
        let mut argon = Config::default();
        argon.lanes = lanes;
        argon.mem_cost = memory;
        argon.time_cost = passes;
        argon.variant = variant;
        Hasher::Argon2(argon)
    }

    pub fn hash<S: AsRef<str>>(&self, password: S) -> Result<String, HasherError> {
        match self {
            Hasher::Argon2(cfg) => {
                // use a 16-byte salt
                let mut salt = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut salt);

                let hashed = argon2::hash_encoded(password.as_ref().as_bytes(), &salt, cfg)?;
                Ok(hashed)
            }
        }
    }

    pub fn verify<S, H>(&self, password: S, hash: H) -> Result<(), HasherError>
    where
        S: AsRef<str>,
        H: AsRef<str>,
    {
        match self {
            Hasher::Argon2(_) => {
                let result = argon2::verify_encoded(hash.as_ref(), password.as_ref().as_bytes())?;
                if result {
                    Ok(())
                } else {
                    Err(HasherError::ValidationFailed)
                }
            }
        }
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Hasher::Argon2(Config::default())
    }
}
