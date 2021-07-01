use super::*;

define_test_set_names!(
    KeyWrap => "kw",
    KeyWrapWithPadding => "kwp"
);

define_test_set!("Keywrap", "keywrap_test_schema.json");

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    SmallKey,
    WeakWrapping,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(rename = "type")]
    typ: String, // todo enum/check
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
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub ct: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<TestFlag>,
}
