#![forbid(unsafe_code)]

//! Umbrella re-exports for the independent Wycheproof NG crates.
//!
//! Prefer depending on a family crate such as `wycheproof-ng-ecdsa` when
//! dependency bulkheading matters. This crate intentionally imports every
//! family crate and has no algorithm-selection features.

pub use wycheproof_ng_aead as aead;
pub use wycheproof_ng_bls as bls;
pub use wycheproof_ng_dh as dh;
pub use wycheproof_ng_dsa as dsa;
pub use wycheproof_ng_ecdsa as ecdsa;
pub use wycheproof_ng_eddsa as eddsa;
pub use wycheproof_ng_fpe as fpe;
pub use wycheproof_ng_kdf_jose as kdf_jose;
pub use wycheproof_ng_mldsa as mldsa;
pub use wycheproof_ng_mlkem as mlkem;
pub use wycheproof_ng_rsa_encryption as rsa_encryption;
pub use wycheproof_ng_rsa_signature as rsa_signature;
pub use wycheproof_ng_symmetric as symmetric;
