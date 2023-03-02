//! AEAD tests

use super::*;

define_test_set!("AEAD", "aead_test_schema.json");

define_test_set_names!(
    Aegis128 => "aegis128",
    Aegis128L => "aegis128L",
    Aegis256 => "aegis256",
    Aes128CbcHmacSha256 => "a128cbc_hs256",
    Aes192CbcHmacSha384 => "a192cbc_hs384",
    Aes256CbcHmacSha512 => "a256cbc_hs512",
    AesCcm => "aes_ccm",
    AesEax => "aes_eax",
    AesGcm => "aes_gcm",
    AesGcmSiv => "aes_gcm_siv",
    AesSivCmac => "aead_aes_siv_cmac",
    AriaCcm => "aria_ccm",
    AriaGcm => "aria_gcm",
    Ascon128 => "ascon128",
    Ascon128a => "ascon128a",
    Ascon80pq => "ascon80pq",
    CamelliaCcm => "camellia_ccm",
    ChaCha20Poly1305 => "chacha20_poly1305",
    Morus1280 => "morus1280",
    Morus640 => "morus640",
    SeedCcm => "seed_ccm",
    SeedGcm => "seed_gcm",
    Sm4Ccm => "sm4_ccm",
    Sm4Gcm => "sm4_gcm",
    XChaCha20Poly1305 => "xchacha20_poly1305",
);

define_algorithm_map!(
    "A128CBC-HS256" => Aes128CbcHmacSha256,
    "A192CBC-HS384" => Aes192CbcHmacSha384,
    "A256CBC-HS512" => Aes256CbcHmacSha512,
    "AEAD-AES-SIV-CMAC" => AesSivCmac,
    "AEGIS128" => Aegis128,
    "AEGIS128L" => Aegis128L,
    "AEGIS256" => Aegis256,
    "AES-CCM" => AesCcm,
    "AES-EAX" => AesEax,
    "AES-GCM" => AesGcm,
    "AES-GCM-SIV" => AesGcmSiv,
    "ARIA-CCM" => AriaCcm,
    "ARIA-GCM" => AriaGcm,
    "ASCON128" => Ascon128,
    "ASCON128A" => Ascon128a,
    "ASCON80PQ" => Ascon80pq,
    "CAMELLIA-CCM" => CamelliaCcm,
    "CAMELLIA-GCM" => CamelliaGcm,
    "CHACHA20-POLY1305" => ChaCha20Poly1305,
    "MORUS1280" => Morus1280,
    "MORUS640" => Morus640,
    "SEED-CCM" => SeedCcm,
    "SEED-GCM" => SeedGcm,
    "SM4-CCM" => Sm4Ccm,
    "SM4-GCM" => Sm4Gcm,
    "XCHACHA20-POLY1305" => XChaCha20Poly1305,
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    #[serde(rename = "Ktv")]
    KnownTestVector,
    #[serde(rename = "TagCollision_1")]
    TagCollisionPtext,
    #[serde(rename = "TagCollision_2")]
    TagCollisionAad,
    #[serde(rename = "CVE-2017-18330")]
    LongNonce,
    CounterWrap,
    EdgeCaseCiphertext,
    EdgeCasePoly1305,
    EdgeCasePolyKey,
    EdgeCaseSiv,
    EdgeCaseTag,
    InsecureTagSize,
    InvalidNonceSize,
    InvalidTagSize,
    LongIv,
    ModifiedTag,
    OldVersion,
    Pseudorandom,
    SmallIv,
    SpecialCase,
    SpecialCaseIv,
    WrappedIv,
    ZeroLengthIv,
}

define_typeid!(TestGroupTypeId => "AeadTest");

define_test_group!(
    "ivSize" => nonce_size: usize,
    "keySize" => key_size: usize,
    "tagSize" => tag_size: usize,
);

define_test!(
    key: Vec<u8>,
    "iv" => nonce: Vec<u8>,
    aad: Vec<u8>,
    "msg" => pt: Vec<u8>,
    ct: Vec<u8>,
    tag: Vec<u8>,
);
