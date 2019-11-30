//! FIDO-U2F Attestation Support

use openssl::x509::X509;
use serde::Deserialize;
use std::ops::Deref;

#[derive(Clone, Debug, Deserialize)]
#[serde(transparent)]
pub struct Buffer {
    #[serde(flatten)]
    #[serde(with = "serde_bytes")]
    pub cert: Vec<u8>,
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.cert
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct FidoU2fAttestation {
    pub x5c: Vec<Buffer>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl FidoU2fAttestation {
    pub fn get_cert(&self) -> Result<X509, Box<dyn std::error::Error>> {
        if self.x5c.len() != 1 {
            // TODO change to error
            panic!("fido-u2f: x5c: too many certs");
        }
        // TODO fix unwrap() call
        //let cert = EndEntityCert::from(Input::from(&self.x5c[0])).unwrap();
        //let (_, cert) = x509_parser::parse_x509_der(&self.x5c[0]).unwrap();
        let cert = X509::from_der(&self.x5c[0]).unwrap();
        //println!("{}", cert.signature_algorithm().object());
        Ok(cert)
    }
}
