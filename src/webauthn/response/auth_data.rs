//! Authentication Data contained in the Attestation Response

use crate::{
    common::cose::CoseKey,
    webauthn::response::{attestation::U2fError, AttestationError, WebAuthnConfig},
};
use ring::digest::{digest, SHA256};
use std::fmt;

#[derive(Clone, Debug)]
pub struct CredentialData {
    pub aa_guid: [u8; 16],
    pub length: u16,
    pub cred_id: Vec<u8>,
    pub cred_pub_key: CoseKey,
}

impl CredentialData {
    pub fn parse(data: &[u8]) -> Result<Self, AttestationError> {
        let mut aa_guid = [0; 16];
        aa_guid.copy_from_slice(&data[..16]);

        let mut length = [0; 2];
        length.copy_from_slice(&data[16..18]);
        let length = u16::from_be_bytes(length);

        let cred_id_end: usize = 18 + length as usize;
        let mut cred_id: Vec<u8> = Vec::new();
        cred_id.extend_from_slice(&data[18..cred_id_end]);

        let cred_pub_key = CoseKey::parse(&data[cred_id_end..])?;

        Ok(CredentialData {
            aa_guid,
            length,
            cred_id,
            cred_pub_key,
        })
    }
}

#[derive(Clone, Debug)]
pub enum AuthError {
    /// Occurs when the RP ID hash in the attestation auth data does not match
    /// the value supplied with the creation request. (Potentially MitM!)
    RpIdHashMismatch,

    /// Occurs when the UserFlag is not set in the auth data flags
    UserNotPresent,

    /// Occurs when the UserVerified is not set in auth data and flags
    /// and user verification has been specifically requested
    UserNotVerified,

    /// Occurs when the credential data is missing from the response
    CredDataMissing,

    /// Occurs when the public key components are not present in this key
    PublicKeyMissing,

    /// Occurs when the private key components are not present in this key
    PrivateKeyMissing,

    /// Occurs when an error occurs during fido-u2f attestation
    U2fError(U2fError),

    /// Occurs when the message built fails to validate against the
    /// signature provided
    SignatureVerificationFailed(webpki::Error),
}

impl std::error::Error for AuthError {}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            AuthError::RpIdHashMismatch => format!("Relying Party id mismatch"),
            AuthError::UserNotPresent => format!("User not found but required"),
            AuthError::UserNotVerified => format!("User not verified but verification is required"),
            AuthError::CredDataMissing => format!("Credential data missing but requred"),
            AuthError::PublicKeyMissing => format!("public key components missing"),
            AuthError::PrivateKeyMissing => format!("private key components missing"),
            AuthError::U2fError(e) => format!("fido-u2f failed attestation: {}", e),
            AuthError::SignatureVerificationFailed(e) => {
                format!("failed to verify messate with x.509 certificate: {:?}", e)
            }
        };

        write!(f, "Authentication Error: {}", msg)
    }
}

impl From<webpki::Error> for AuthError {
    fn from(e: webpki::Error) -> AuthError {
        AuthError::SignatureVerificationFailed(e)
    }
}

impl From<U2fError> for AuthError {
    fn from(e: U2fError) -> AuthError {
        AuthError::U2fError(e)
    }
}

#[derive(Clone, Debug)]
pub struct AuthData {
    rp_id_hash: [u8; 32],
    flags: u8,
    counter: u32,
    cred_data: Option<CredentialData>,
}

#[allow(dead_code)]
pub enum AuthDataFlag {
    /// Indicates if the user is present
    UserPresent,

    /// Indicates if the user is verified
    UserVerified,

    /// Indicates whether the authenticator added attested credential data
    AttestedCredentialData,

    /// Indiciates if the authenticator data has extensions
    ExtensionData,
}

#[allow(dead_code)]
impl AuthData {
    /// Parse the authentication data from a raw byte vector / slice
    ///
    /// # Arguments
    /// * `data` - Data to parse into an AuthData
    pub fn parse(data: Vec<u8>) -> Result<Self, AttestationError> {
        let mut rp_id_hash = [0; 32];
        rp_id_hash.copy_from_slice(&data[..32]);

        let mut counter = [0; 4];
        counter.copy_from_slice(&data[33..37]);

        let cred_data = match data.len() > 37 {
            true => Some(CredentialData::parse(&data[37..])?),
            false => None,
        };

        Ok(AuthData {
            rp_id_hash,
            flags: data[32],
            counter: u32::from_be_bytes(counter),
            cred_data,
        })
    }

    /// Verify this data
    pub fn validate(&self, cfg: &WebAuthnConfig) -> Result<(), AuthError> {
        // Verify the relying party's id matches what we configured
        let rp_id_hash = digest(&SHA256, cfg.id().as_bytes());
        if self.rp_id_hash != rp_id_hash.as_ref() {
            return Err(AuthError::RpIdHashMismatch);
        }

        // Verify that the User Present bit of the flags in authData is set.
        if !self.is_user_present() {
            return Err(AuthError::UserNotPresent);
        }

        // if user verification is required, check for the user verification flag
        // TODO

        Ok(())
    }

    /// Returns a reference to the hash of the relying party's id
    pub fn rp_id_hash(&self) -> &[u8; 32] {
        &self.rp_id_hash
    }

    /// Return a copy of the credential data
    pub fn credential_data(&self) -> Option<&CredentialData> {
        self.cred_data.as_ref()
    }

    /// Returns the public key in raw format
    pub fn public_key(&self) -> Result<Vec<u8>, AuthError> {
        let data = self.cred_data.as_ref().ok_or(AuthError::CredDataMissing)?;
        data.cred_pub_key
            .as_raw()
            .ok_or(AuthError::PublicKeyMissing)
    }

    /// Returns the bytes of the credential id stored in the credential data
    pub fn credential_id(&self) -> Result<&[u8], AuthError> {
        let data = self.cred_data.as_ref().ok_or(AuthError::CredDataMissing)?;
        Ok(data.cred_id.as_slice())
    }

    /// Checks if a flags is set in the auth data's flag field.  A return value
    /// of `true` indicates the flag is set; a return value of `false` indicates
    /// the flag was not set
    ///
    /// # Arguments
    /// * `flag` - Flag to check
    pub fn is_flag_set(&self, flag: AuthDataFlag) -> bool {
        match flag {
            AuthDataFlag::UserPresent => (self.flags & 0x01) == 0x01,
            AuthDataFlag::UserVerified => (self.flags & 0x04) == 0x04,
            AuthDataFlag::AttestedCredentialData => (self.flags & 0x40) == 0x40,
            AuthDataFlag::ExtensionData => (self.flags & 0x80) == 0x80,
        }
    }

    /// Returns true if the user present flag is set in the response
    /// Returns false otherwise
    pub fn is_user_present(&self) -> bool {
        self.is_flag_set(AuthDataFlag::UserPresent)
    }

    /// Returns true if the user verified flag is set in the response
    /// Returns false otherwise
    pub fn is_user_verified(&self) -> bool {
        self.is_flag_set(AuthDataFlag::UserVerified)
    }

    /// Returns true if the response has additional attested credential data
    /// Returns false otherwise
    pub fn has_credential(&self) -> bool {
        self.is_flag_set(AuthDataFlag::AttestedCredentialData)
    }

    /// Returns true if the response has extensions
    /// Returns false otherwise
    pub fn has_extensions(&self) -> bool {
        self.is_flag_set(AuthDataFlag::ExtensionData)
    }
}
