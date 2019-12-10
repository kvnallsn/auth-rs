//! FIDO-U2F Attestation Support

use crate::webauthn::response::{AuthData, AuthError};
use ring::digest::Digest;
use serde::Deserialize;
use std::{fmt, ops::Deref};
use untrusted::Input;
use webpki::{EndEntityCert, ECDSA_P256_SHA256};

#[derive(Clone, Debug)]
pub enum U2fError {
    /// Occurs when too many X.509 certs are includded in the response
    TooManyX509Certificates,

    /// Occurs when the certificate fails to parse
    BadX509Certificate,
}

impl std::error::Error for U2fError {}

impl fmt::Display for U2fError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            U2fError::TooManyX509Certificates => {
                format!("too many X.509 certificates in u2f statement")
            }
            U2fError::BadX509Certificate => format!("failed to parse x.509 certificate"),
        };

        write!(f, "{}", msg)
    }
}

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
    /// Parses the X.509 certificate stored in the attestation data
    fn get_cert(&self) -> Result<EndEntityCert, U2fError> {
        if self.x5c.len() != 1 {
            return Err(U2fError::TooManyX509Certificates);
        }

        EndEntityCert::from(Input::from(&self.x5c[0])).map_err(|_| U2fError::BadX509Certificate)
    }

    pub fn validate(
        &self,
        auth_data: &AuthData,
        client_data_hash: Digest,
    ) -> Result<(Vec<u8>, Vec<u8>), AuthError> {
        // Check that x5c has exactly one element and let attCert be that element.
        // Let certificate public key be the public key conveyed by attCert. If certificate
        // public key is not an Elliptic Curve (EC) public key over the P-256 curve, terminate
        // this algorithm and return an appropriate error.
        let cert = self.get_cert()?;

        // Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to
        // Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in Section 3.6.2 Public Key
        // Representation Formats of [FIDO-Registry]).
        let pubkey = auth_data.public_key()?;
        let cred_id = auth_data.credential_id()?;

        // Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash ||
        // credentialId || publicKeyU2F) (see Section 4.3 of [FIDO-U2F-Message-Formats]).
        let mut verification_data = vec![0x00];
        verification_data.extend_from_slice(auth_data.rp_id_hash());
        verification_data.extend_from_slice(client_data_hash.as_ref());
        verification_data.extend_from_slice(&cred_id);
        verification_data.extend_from_slice(&pubkey);

        // 6. Verify the sig using verificationData and the certificate public key per section 4.1.4
        // of [SEC1] with SHA-256 as the hash function used in step two.
        cert.verify_signature(
            &ECDSA_P256_SHA256,
            Input::from(verification_data.as_slice()),
            Input::from(self.sig.as_slice()),
        )?;

        // 7. Optionally, inspect x5c and consult externally provided knowledge to determine whether
        // attStmt conveys a Basic or AttCA attestation.
        //TODO

        // 8.If successful, return implementation-specific values representing attestation
        // type Basic, AttCA or uncertainty, and attestation trust path x5c.
        //TODO

        Ok((cred_id.to_vec(), pubkey))
    }
}
