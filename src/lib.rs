//! FIDO2 WebAuthn implementation

pub mod common;
pub mod webauthn;

use crate::webauthn::{
    pk::PublicKeyDescriptor,
    request::{AuthenticateRequest, WebAuthnRegisterRequest},
    response::WebAuthnRegisterResponse,
    User, WebAuthnConfig, WebAuthnError, WebAuthnType,
};

pub struct SecurityDevice {
    id: String,
    pubkey: String,
}

impl SecurityDevice {
    pub fn new<S: Into<String>, T: Into<String>>(id: S, pubkey: T) -> SecurityDevice {
        SecurityDevice {
            id: id.into(),
            pubkey: pubkey.into(),
        }
    }

    /// Creates a request that can be sent to a webauthn api
    ///
    /// # Arguments
    /// * `rp` - The RelyingParty this request represents
    /// * `user` - The user that owns this request
    pub fn register_request<U: Into<User>>(
        cfg: &WebAuthnConfig,
        user: U,
    ) -> WebAuthnRegisterRequest {
        WebAuthnRegisterRequest::new(cfg.as_relying_party(), user)
    }

    /// Parses the response to a register request.  Returns the base64-encoded credential id
    /// and the base64-encoded credential public key
    /// [Spec](https://w3c.github.io/webauthn/#sctn-registering-a-new-credential)
    ///
    /// # Arguments
    /// * `req - The register request to compare data against
    /// * `form` - Form received from the client
    pub fn register<S: Into<String>>(
        cfg: &WebAuthnConfig,
        challenge: S,
        form: WebAuthnRegisterResponse,
    ) -> Result<SecurityDevice, WebAuthnError> {
        let (id, pubkey) = form.validate(WebAuthnType::Create, cfg, challenge)?;
        Ok(SecurityDevice { id, pubkey })
    }

    pub fn authenticate_request(&self, cfg: &WebAuthnConfig) -> AuthenticateRequest {
        let req = AuthenticateRequest::new(cfg, vec![self.as_descriptor()]);
        println!("{:?}", req);
        req
    }

    pub fn as_descriptor(&self) -> PublicKeyDescriptor {
        // decode cred id from base64
        let id = base64::decode_config(&self.id, base64::URL_SAFE_NO_PAD).unwrap();
        PublicKeyDescriptor::new(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::{User, WebAuthnConfig};

    fn setup() -> (WebAuthnConfig, User) {
        let config = WebAuthnConfig::new("https://app.twinscroll.dev");
        let user = User::new(vec![0], "user", "user");
        (config, user)
    }

    /*
    fn read_create_response() -> Result<WebAuthnRegisterResponse, Box<dyn std::error::Error>> {
        let file = File::open("test.json")?;
        let form = serde_json::from_reader(file)?;
        Ok(form)
    }
    */

    #[test]
    fn canary() {
        // If this fails we have a problem...
        assert!(true);
    }

    #[test]
    fn register_device_json() -> Result<(), Box<dyn std::error::Error>> {
        let (cfg, user) = setup();
        let req = SecurityDevice::register_request(&cfg, user).json();
        assert!(req.is_ok());
        Ok(())
    }

    /*
    #[test]
    fn register_device_response() -> Result<(), Box<dyn std::error::Error>> {
        let (cfg, _) = setup();
        let resp = read_create_response()?;
        SecurityDevice::register(&cfg, "challenge", resp)?;
        Ok(())
    }
    */

    #[test]
    fn authenticate_request() {
        let (cfg, _) = setup();
        let dev = SecurityDevice::new("CWzOsf1w1zo84JXBj-2qgAQ-VSAURyqsEYirJAuMr3wIqq45K-q8XyyJB_wNTA2IeEOVlFrdDoZTQCDq9J955w", "BDNovyJSkd92ctlHTVuoBFFDgKaZz9V6xZdnlHG9sWYZZ1W31famIP16_qRohLQhUQL2klPufvH-EAhNzro67k0");
        let req = dev.authenticate_request(&cfg);
        println!("{:?}", req);
    }
}
