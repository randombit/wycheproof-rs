use super::*;

define_test_set!("RSA PKCS1 verify", "rsassa_pss_verify_schema.json");

define_test_set_names!(
    RsaPss2048Sha1Mgf1_20 => "rsa_pss_2048_sha1_mgf1_20",
    RsaPss2048Sha256Mgf1_0 => "rsa_pss_2048_sha256_mgf1_0",
    RsaPss2048Sha256Mgf1_32 => "rsa_pss_2048_sha256_mgf1_32",
    RsaPss2048Sha512_256Mgf1_28 => "rsa_pss_2048_sha512_256_mgf1_28",
    RsaPss2048Sha512_256Mgf1_32 => "rsa_pss_2048_sha512_256_mgf1_32",
    RsaPss3072Sha256Mgf1_32 => "rsa_pss_3072_sha256_mgf1_32",
    RsaPss4096Sha256Mgf1_32 => "rsa_pss_4096_sha256_mgf1_32",
    RsaPss4096Sha512Mgf1_32 => "rsa_pss_4096_sha512_mgf1_32",
    RsaPssmisc => "rsa_pss_misc"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    WeakHash,
}

define_typeid!(TestGroupTypeId => "RsassaPssVerify");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    #[serde(deserialize_with = "vec_from_hex")]
    pub e: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyAsn")]
    pub asn_key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyDer")]
    pub der: Vec<u8>,
    #[serde(rename = "keyPem")]
    pub pem: String,
    #[serde(rename = "keysize")]
    pub key_size: usize,
    pub mgf: Mgf,
    #[serde(rename = "mgfSha")]
    pub mgf_hash: HashFunction,
    #[serde(deserialize_with = "vec_from_hex")]
    pub n: Vec<u8>,
    #[serde(rename = "sLen")]
    pub salt_length: usize,
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
