use super::*;

define_test_set!("Cipher", "ind_cpa_test_schema.json");

define_test_set_names!(
    AesCbcPkcs5 => "aes_cbc_pkcs5"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    BadPadding,
}

define_typeid!(TestGroupTypeId => "IndCpaTest");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    #[serde(rename = "ivSize")]
    pub nonce_size: usize,
    #[serde(rename = "keySize")]
    pub key_size: usize,
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
    pub iv: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "msg")]
    pub pt: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub ct: Vec<u8>,
    pub result: TestResult,
    #[serde(default)]
    pub flags: Vec<TestFlag>,
}
