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

#[cfg(feature = "web-rocket")]
pub mod rocket {
    use super::Hasher;
    use argon2::{Config, Variant};
    use rocket::{
        fairing::{Fairing, Info, Kind},
        Rocket,
    };

    const ARGON2_TABLE: &str = "argon2";

    /// Number of lanes (i.e., threads) to use
    const ARGON2_LANES: &str = "lanes";

    /// Amount of memory used by Argon2, in Kibibytes
    const ARGON2_MEMORY: &str = "memory";

    /// Number of passes (i.e., iterations) over the memory
    const ARGON2_PASSES: &str = "passes";

    /// Variant of Argon2 to use (argon2i argon2d, argon2id)
    const ARGON2_VARIANT: &str = "variant";

    macro_rules! get_int {
        ($field:expr, $table:expr,$rocket:expr) => {
            match $table.get($field) {
                Some(v) => match v {
                    rocket::config::Value::Integer(i) => Some(*i),
                    _ => {
                        log::error!("{}: expected an integer, got something else", $field);
                        return Err($rocket);
                    }
                },
                None => None,
            }
        };
    }

    macro_rules! get_str {
        ($field:expr, $table:expr,$rocket:expr) => {
            match $table.get($field) {
                Some(v) => match v {
                    rocket::config::Value::String(s) => Some(s.as_ref()),
                    _ => {
                        log::error!("{}: expected a string, got something else", $field);
                        return Err($rocket);
                    }
                },
                None => None,
            }
        };
    }

    pub struct PasswordFairing;

    #[rocket::async_trait]
    impl Fairing for PasswordFairing {
        fn info(&self) -> Info {
            Info {
                name: "Auth-rs Password Config",
                kind: Kind::Attach,
            }
        }

        fn on_attach(&self, rocket: Rocket) -> Result<Rocket, Rocket> {
            let mut argon = Config::default();
            let cfg = rocket.config();

            if let Ok(table) = cfg.get_table(ARGON2_TABLE) {
                if let Some(lanes) = get_int!(ARGON2_LANES, table, rocket) {
                    argon.lanes = lanes as u32;
                }

                if let Some(memory) = get_int!(ARGON2_MEMORY, table, rocket) {
                    argon.mem_cost = memory as u32;
                }

                if let Some(passes) = get_int!(ARGON2_PASSES, table, rocket) {
                    argon.time_cost = passes as u32;
                }

                if let Some(variant) = get_str!(ARGON2_VARIANT, table, rocket) {
                    argon.variant = match variant {
                        "argon2i" => Variant::Argon2i,
                        "argon2d" => Variant::Argon2d,
                        "argon2id" => Variant::Argon2id,
                        x => {
                            log::error!("argon2: unrecognized variant `{}`", x);
                            return Err(rocket);
                        }
                    }
                }
            }

            Ok(rocket.manage(Hasher::Argon2(argon)))
        }
    }

    pub fn fairing() -> PasswordFairing {
        PasswordFairing
    }
}
