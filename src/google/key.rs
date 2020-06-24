use serde::Deserialize;

/// A JSON Web Key, returned from Google and used to validate the JWT
#[derive(Clone, Deserialize, Debug)]
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
    pub cacheability: Cacheability,
    pub max_age: u64,
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
    pub fn new() -> CacheControl {
        Self::default()
    }

    pub fn update(&mut self, header: impl Into<String>) {
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
