use super::*;

define_test_set!(
    "MAC",
    "mac_test_schema.json",
    "mac_with_iv_test_schema.json"
);

define_test_set_names!(
    AesCmac => "aes_cmac",
    HmacSha1 => "hmac_sha1",
    HmacSha224 => "hmac_sha224",
    HmacSha256 => "hmac_sha256",
    HmacSha384 => "hmac_sha384",
    HmacSha512 => "hmac_sha512",
    HmacSha3_224 => "hmac_sha3_224",
    HmacSha3_256 => "hmac_sha3_256",
    HmacSha3_384 => "hmac_sha3_384",
    HmacSha3_512 => "hmac_sha3_512",
    Gmac => "gmac",
    Vmac64 => "vmac_64",
    Vmac128 => "vmac_128"
);

define_typeid!(TestGroupTypeId => "MacTest", "MacWithIvTest");

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    InvalidNonce,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(rename = "tagSize")]
    pub tag_size: usize,
    #[serde(rename = "ivSize")]
    pub nonce_size: Option<usize>,
    #[serde(rename = "type")]
    typ: TestGroupTypeId,
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
    #[serde(deserialize_with = "opt_vec_from_hex", default, rename = "iv")]
    pub nonce: Option<Vec<u8>>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub tag: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<TestFlag>,
}
