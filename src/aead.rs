use super::*;

define_test_set!("AEAD", "aead_test_schema.json");

define_test_set_names!(
    Aegis128 => "aegis128",
    Aegis128L => "aegis128L",
    Aegis256 => "aegis256",
    AesCcm => "aes_ccm",
    AesEax => "aes_eax",
    AesGcm => "aes_gcm",
    AesGcmSiv => "aes_gcm_siv",
    AesSivCmac => "aead_aes_siv_cmac",
    ChaCha20Poly1305 => "chacha20_poly1305",
    XChaCha20Poly1305 => "xchacha20_poly1305"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    BadPadding,
    ConstructedIv,
    CounterWrap,
    EdgeCaseSiv,
    InvalidNonceSize,
    InvalidTagSize,
    LongIv,
    OldVersion,
    SmallIv,
    ZeroLengthIv,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    #[serde(rename = "ivSize")]
    pub nonce_size: usize,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(rename = "tagSize")]
    pub tag_size: usize,
    #[serde(rename = "type")]
    typ: String,
    pub tests: Vec<Test>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Test {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "iv")]
    pub nonce: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub aad: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "msg")]
    pub pt: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub ct: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub tag: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<TestFlag>,
}
