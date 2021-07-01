use super::*;

define_test_set!("xDH", "xdh_comp_schema.json");

define_test_set_names!(
    X25519 => "x25519",
    X448 => "x448"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    LowOrderPublic,
    NonCanonicalPublic,
    SmallPublicKey,
    Twist,
    ZeroSharedSecret,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    pub curve: MontgomeryCurve,
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
    #[serde(deserialize_with = "vec_from_hex", rename = "public")]
    pub public_key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "private")]
    pub private_key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "shared")]
    pub shared_secret: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<TestFlag>,
}
