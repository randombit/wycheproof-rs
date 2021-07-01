use super::*;

define_test_set!(
    "DSA verify",
    "dsa_verify_schema.json",
    "dsa_p1363_verify_schema.json"
);

define_test_set_names!(
    Dsa2048_224Sha224 => "dsa_2048_224_sha224",
    Dsa2048_224Sha256 => "dsa_2048_224_sha256",
    Dsa2048_256Sha256 => "dsa_2048_256_sha256",
    Dsa3072_256Sha256 => "dsa_3072_256_sha256",
    Dsa2048_224Sha224P1363 => "dsa_2048_224_sha224_p1363",
    Dsa2048_224Sha256P1363 => "dsa_2048_224_sha256_p1363",
    Dsa2048_256Sha256P1363 => "dsa_2048_256_sha256_p1363",
    Dsa3072_256Sha256P1363 => "dsa_3072_256_sha256_p1363",
    DsaMisc => "dsa"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    EdgeCase,
    NoLeadingZero,
}

define_typeid!(TestKeyTypeId => "DsaPublicKey");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestKey {
    #[serde(deserialize_with = "vec_from_hex")]
    pub g: Vec<u8>,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(deserialize_with = "vec_from_hex")]
    pub p: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub q: Vec<u8>,
    #[serde(rename = "type")]
    typ: TestKeyTypeId,
    #[serde(deserialize_with = "vec_from_hex")]
    pub y: Vec<u8>,
}

define_typeid!(TestGroupTypeId => "DsaVerify", "DsaP1363Verify");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    pub key: TestKey,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyDer")]
    pub der: Vec<u8>,
    #[serde(rename = "keyPem")]
    pub pem: String,
    #[serde(rename = "sha")]
    pub hash: HashFunction,
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
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub sig: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<TestFlag>,
}
