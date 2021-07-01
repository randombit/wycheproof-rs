use super::*;

define_test_set!("HKDF", "hkdf_test_schema.json");

define_test_set_names!(
    HkdfSha1 => "hkdf_sha1",
    HkdfSha256 => "hkdf_sha256",
    HkdfSha384 => "hkdf_sha384",
    HkdfSha512 => "hkdf_sha512"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    EmptySalt,
    SizeTooLarge,
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
    pub ikm: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub salt: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub info: Vec<u8>,
    pub size: usize,
    #[serde(deserialize_with = "vec_from_hex")]
    pub okm: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<TestFlag>,
}
