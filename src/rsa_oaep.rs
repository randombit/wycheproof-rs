use super::*;

define_test_set!("RSA OAEP decrypt", "rsaes_oaep_decrypt_schema.json");

define_test_set_names!(
    Rsa2048Sha1Mgf1Sha1 => "rsa_oaep_2048_sha1_mgf1sha1",
    Rsa2048Sha224Mgf1Sha1 => "rsa_oaep_2048_sha224_mgf1sha1",
    Rsa2048Sha224Mgf1Sha224 => "rsa_oaep_2048_sha224_mgf1sha224",
    Rsa2048Sha256Mgf1Sha1 => "rsa_oaep_2048_sha256_mgf1sha1",
    Rsa2048Sha256Mgf1Sha256 => "rsa_oaep_2048_sha256_mgf1sha256",
    Rsa2048Sha384Mgf1Sha1 => "rsa_oaep_2048_sha384_mgf1sha1",
    Rsa2048Sha384Mgf1Sha384 => "rsa_oaep_2048_sha384_mgf1sha384",
    Rsa2048Sha512Mgf1Sha1 => "rsa_oaep_2048_sha512_mgf1sha1",
    Rsa2048Sha512Mgf1Sha512 => "rsa_oaep_2048_sha512_mgf1sha512",
    Rsa3072Sha256Mgf1Sha1 => "rsa_oaep_3072_sha256_mgf1sha1",
    Rsa3072Sha256Mgf1Sha256 => "rsa_oaep_3072_sha256_mgf1sha256",
    Rsa3072Sha512Mgf1Sha1 => "rsa_oaep_3072_sha512_mgf1sha1",
    Rsa3072Sha512Mgf1Sha512 => "rsa_oaep_3072_sha512_mgf1sha512",
    Rsa4096Sha256Mgf1Sha1 => "rsa_oaep_4096_sha256_mgf1sha1",
    Rsa4096Sha256Mgf1Sha256 => "rsa_oaep_4096_sha256_mgf1sha256",
    Rsa4096Sha512Mgf1Sha1 => "rsa_oaep_4096_sha512_mgf1sha1",
    Rsa4096Sha512Mgf1Sha512 => "rsa_oaep_4096_sha512_mgf1sha512",
    RsaMisc => "rsa_oaep_misc"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    Constructed,
    InvalidOaepPadding,
    SmallModulus,
}

define_typeid!(TestGroupTypeId => "RsaesOaepDecrypt");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    #[serde(deserialize_with = "vec_from_hex")]
    pub d: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub e: Vec<u8>,
    #[serde(rename = "keysize")]
    pub key_size: usize,
    pub mgf: Mgf,
    #[serde(rename = "mgfSha")]
    pub mgf_hash: HashFunction,
    #[serde(deserialize_with = "vec_from_hex")]
    pub n: Vec<u8>,
    #[serde(rename = "privateKeyJwk")]
    pub jwk: Option<RsaPrivateJwk>,
    #[serde(deserialize_with = "vec_from_hex", rename = "privateKeyPkcs8")]
    pub pkcs8: Vec<u8>,
    #[serde(rename = "privateKeyPem")]
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
    pub ct: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub label: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<TestFlag>,
}
