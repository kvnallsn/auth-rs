//! Defined COSE constants

/// COSE_Key Parameters
pub const COSE_KEY_KTY: i128 = 1;
pub const COSE_KEY_KID: i128 = 2;
pub const COSE_KEY_ALG: i128 = 3;
pub const COSE_KEY_KEY_OPS: i128 = 4;
pub const COSE_KEY_BASE_IV: i128 = 5;

/// COSE_Key Types (KTY)
pub const COSE_KEY_KTY_RESERVED: i128 = 0;
pub const COSE_KEY_KTY_OKP: i128 = 1;
pub const COSE_KEY_KTY_EC2: i128 = 2;
pub const COSE_KEY_KTY_SYMMETRIC: i128 = 4;

/// COSE Key Algorithms (ALG)
pub const COSE_KEY_ALGO_ES256: i128 = -7;

/// COSE EC2 Key Parameters
pub const COSE_KEY_EC2_CRV: i128 = -1;
pub const COSE_KEY_EC2_X: i128 = -2;
pub const COSE_KEY_EC2_Y: i128 = -3;
pub const COSE_KEY_EC2_D: i128 = -4;
