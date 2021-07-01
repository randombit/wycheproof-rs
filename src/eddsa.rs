use super::*;

define_test_set!("EdDSA verify", "eddsa_verify_schema.json");

define_test_set_names!(
    Ed25519 => "eddsa",
    Ed448 => "ed448"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    SignatureMalleability,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestKey {
    pub curve: EdwardsCurve,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(deserialize_with = "vec_from_hex")]
    pub pk: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub sk: Vec<u8>,
    #[serde(rename = "type")]
    typ: String, // check this
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestKeyJwk {
    #[serde(rename = "crv")]
    pub curve: EdwardsCurve,
    #[serde(deserialize_with = "vec_from_base64")]
    pub d: Vec<u8>,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "vec_from_base64")]
    pub x: Vec<u8>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    pub jwk: Option<TestKeyJwk>,
    pub key: TestKey,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyDer")]
    pub der: Vec<u8>,
    #[serde(rename = "keyPem")]
    pub pem: String,
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
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub sig: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<TestFlag>,
}
