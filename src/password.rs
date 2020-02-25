//! Password based authentication using argon2

use argon2::{self, Config, Error};
use rand::RngCore;
use rocket::{
    config::Value,
    fairing::{Fairing, Info, Kind},
    Rocket,
};

const ARGON2_TABLE: &str = "argon2";
const ARGON2_LANES: &str = "lanes";

pub struct PasswordConfig;

#[rocket::async_trait]
impl Fairing for PasswordConfig {
    fn info(&self) -> Info {
        Info {
            name: "Auth-rs Password Config",
            kind: Kind::Attach,
        }
    }

    fn on_attach(&self, rocket: Rocket) -> Result<Rocket, Rocket> {
        let argon = Config::default();
        let cfg = rocket.config();

        if let Ok(table) = cfg.get_table(ARGON2_TABLE) {
            //
            println!("{:#?}", table);
        }

        Ok(rocket)
    }
}

pub fn fairing() -> PasswordConfig {
    PasswordConfig
}

pub fn hash<S: AsRef<str>>(password: S, config: &Config) -> Result<String, Error> {
    // use a 16-byte salt
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    argon2::hash_encoded(password.as_ref().as_bytes(), &salt, config)
}

pub fn verify<S, H>(password: S, hash: H) -> Result<bool, Error>
where
    S: AsRef<str>,
    H: AsRef<str>,
{
    argon2::verify_encoded(hash.as_ref(), password.as_ref().as_bytes())
}
