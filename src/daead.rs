use super::*;

define_test_set!("DAEAD", "daead_test_schema.json");

define_test_set_names!(
    AesGcmSiv => "aes_siv_cmac"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    EdgeCaseSiv,
}

define_typeid!(TestGroupTypeId => "DaeadTest");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
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
    pub key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub aad: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "msg")]
    pub pt: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub ct: Vec<u8>,
    pub result: TestResult,
    #[serde(default)]
    pub flags: Vec<TestFlag>,
}
