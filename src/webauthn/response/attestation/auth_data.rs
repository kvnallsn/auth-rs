//! Authentication Data contained in the Attestation Response

use crate::{common::cose::CoseKey, webauthn::response::AttestationError};

#[derive(Clone, Debug)]
pub struct AttestationAuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub counter: u32,
    pub aa_guid: [u8; 16],
    pub length: u16,
    pub cred_id: Vec<u8>,
    pub key: CoseKey,
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

impl AttestationAuthData {
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
}

impl AttestationAuthData {
    pub fn parse(data: Vec<u8>) -> Result<AttestationAuthData, AttestationError> {
        let mut rp_id_hash = [0; 32];
        rp_id_hash.copy_from_slice(&data[..32]);

        let mut counter = [0; 4];
        counter.copy_from_slice(&data[33..37]);

        let mut aa_guid = [0; 16];
        aa_guid.copy_from_slice(&data[37..53]);

        let mut length = [0; 2];
        length.copy_from_slice(&data[53..55]);
        let length = u16::from_be_bytes(length);

        let cred_id_end: usize = 55 + length as usize;
        let mut cred_id: Vec<u8> = Vec::new();
        cred_id.extend_from_slice(&data[55..cred_id_end]);

        let key = CoseKey::parse(&data[cred_id_end..])?;

        Ok(AttestationAuthData {
            rp_id_hash,
            flags: data[32],
            counter: u32::from_be_bytes(counter),
            aa_guid,
            length,
            cred_id,
            key,
        })
    }
}
