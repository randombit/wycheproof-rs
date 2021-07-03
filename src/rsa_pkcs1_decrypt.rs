//! RSA PKCS1v1.5 decryption tests

use super::*;

define_test_set!("RSA PKCS1 decrypt", "rsaes_pkcs1_decrypt_schema.json");

define_algorithm_map!("RSAES-PKCS1-v1_5" => RsaPkcs1v15Encryption);

define_test_set_names!(
    Rsa2048 => "rsa_pkcs1_2048",
    Rsa3072 => "rsa_pkcs1_3072",
    Rsa4096 => "rsa_pkcs1_4096"
);

define_test_flags!(InvalidPkcs1Padding);

define_typeid!(TestGroupTypeId => "RsaesPkcs1Decrypt");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    #[serde(deserialize_with = "vec_from_hex")]
    pub d: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub e: Vec<u8>,
    #[serde(rename = "keysize")]
    pub key_size: usize,
    #[serde(deserialize_with = "vec_from_hex")]
    pub n: Vec<u8>,
    #[serde(rename = "privateKeyJwk")]
    pub jwk: Option<RsaPrivateJwk>,
    #[serde(deserialize_with = "vec_from_hex", rename = "privateKeyPkcs8")]
    pub pkcs8: Vec<u8>,
    #[serde(rename = "privateKeyPem")]
    pub pem: String,
    #[serde(rename = "type")]
    typ: TestGroupTypeId,
    pub tests: Vec<Test>,
}

define_test!(msg: Vec<u8>, ct: Vec<u8>);
