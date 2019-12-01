//! Public Key related items

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// A COSEAlgorithmIdentifier's value is a number identifying a cryptographic algorithm.
/// The algorithm identifiers SHOULD be values registered in the [IANA COSE Algorithms
/// registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms), for instance,
/// -7 for "ES256" and -257 for "RS256".
#[derive(Copy, Clone, Debug, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum PublicKeyAlgorithm {
    /// RSASSA-PKCS1-v1_5 w/ SHA-256
    RS256 = -257,

    /// ECDSA w/ SHA-512
    ES512 = -36,

    /// ECDSA w/ SHA-384
    ES384 = -35,

    /// ECDSA w/ SHA-256
    ES256 = -7,
}

/// Represents the different types of Public Key Credentials we can create.
/// For now, only PublicKey is supported/exists.  In the future, this may
/// expand to include more types.
/// [WebAuthn Spec](https://www.w3.org/TR/webauthn/#enumdef-publickeycredentialtype)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PublicKeyCredentialType {
    /// A Public Key credential
    #[serde(rename = "public-key")]
    PublicKey,
}

/// Parameters used to specify different Public Key algorithms possible
/// [WebAuthn Spec](https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialparameters)
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyParams {
    /// Type of credential to be created
    #[serde(rename = "type")]
    pub ty: PublicKeyCredentialType,

    /// Cryptographic signature algorithm of the newly-generated credential to be used.
    /// Also specifies the type of asymmetric key-pair to generate (e.g., RSA, Elliptic Curve, etc.)
    ///
    /// Default: ES256
    pub alg: PublicKeyAlgorithm,
}

impl Default for PublicKeyParams {
    fn default() -> PublicKeyParams {
        PublicKeyParams {
            ty: PublicKeyCredentialType::PublicKey,
            alg: PublicKeyAlgorithm::ES256,
        }
    }
}
/// Describes a Public Key used by FIDO2
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeyCredential {
    /// Type of Public Key referred to
    #[serde(rename = "type")]
    pub ty: PublicKeyCredentialType,

    /// Credential Id of the public key credential
    pub id: Vec<u8>,
}

impl PublicKeyCredential {
    /// Creates a new public key credential from a returned response
    ///
    /// # Arguments
    /// * `id` - The id of the public key
    pub fn new(id: Vec<u8>) -> PublicKeyCredential {
        PublicKeyCredential {
            ty: PublicKeyCredentialType::PublicKey,
            id,
        }
    }
}
