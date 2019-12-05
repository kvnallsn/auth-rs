//! FIDO2 WebAuthn implementation

pub mod common;
pub mod webauthn;

use crate::webauthn::{
    request::WebAuthnRegisterRequest, response::WebAuthnRegisterResponse, User, WebAuthnConfig,
    WebAuthnError, WebAuthnType,
};

pub struct SecurityDevice;

impl SecurityDevice {
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
    pub fn register(
        cfg: &WebAuthnConfig,
        req: &WebAuthnRegisterRequest,
        form: WebAuthnRegisterResponse,
    ) -> Result<(String, String), WebAuthnError> {
        let (id, pubkey) = form.validate(
            WebAuthnType::Create,
            cfg,
            req.challenge()
            //"s0Tnjjv67CzQxIdneKXRPrUYGyUjuZQJr17fRPkvdoA",
            //"https://app.twinscroll.dev",
        )?;

        Ok((id, pubkey))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::{User, WebAuthnConfig};
    use std::fs::File;

    fn setup() -> (WebAuthnConfig, User) {
        let config = WebAuthnConfig::new("https://app.twinscroll.dev");
        let user = User::new(vec![0], "user", "user");
        (config, user)
    }

    fn read_create_response() -> Result<WebAuthnRegisterResponse, Box<dyn std::error::Error>> {
        let file = File::open("test.json")?;
        let form = serde_json::from_reader(file)?;
        Ok(form)
    }

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

    #[test]
    fn register_device_response() -> Result<(), Box<dyn std::error::Error>> {
        let (cfg, user) = setup();
        let req = SecurityDevice::register_request(&cfg, user);
        let resp = read_create_response()?;
        SecurityDevice::register(&cfg, &req, resp)?;
        Ok(())
    }
}
