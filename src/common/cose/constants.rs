//! Defined COSE constants

/// COSE_Key Parameters
pub const COSE_KEY_KTY: i32 = 1;
pub const COSE_KEY_KID: i32 = 2;
pub const COSE_KEY_ALG: i32 = 3;
pub const COSE_KEY_KEY_OPS: i32 = 4;
pub const COSE_KEY_BASE_IV: i32 = 5;

/// COSE_Key Types (KTY)
pub const COSE_KEY_KTY_RESERVED: i32 = 0;
pub const COSE_KEY_KTY_OKP: i32 = 1;
pub const COSE_KEY_KTY_EC2: i32 = 2;
pub const COSE_KEY_KTY_SYMMETRIC: i32 = 4;

/// COSE Key Algorithms (ALG)
pub const COSE_KEY_ALGO_ES256: i32 = -7;

/// COSE EC2 Key Parameters
pub const COSE_KEY_EC2_CRV: i32 = -1;
pub const COSE_KEY_EC2_X: i32 = -2;
pub const COSE_KEY_EC2_Y: i32 = -3;
pub const COSE_KEY_EC2_D: i32 = -4;
