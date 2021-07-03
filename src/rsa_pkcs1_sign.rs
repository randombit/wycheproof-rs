//! RSA PKCS1v1.5 signature generation tests

use super::*;

define_test_set!("RSA PKCS1 sign", "rsassa_pkcs1_generate_schema.json");

define_test_set_names!(RsaMisc => "rsa_sig_gen_misc");

define_algorithm_map!("RSASSA-PKCS1-v1_5" => RsaPkcs1v15);

define_test_flags!(SmallPublicKey, SmallModulus, WeakHash);

define_typeid!(TestGroupTypeId => "RsassaPkcs1Generate");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    #[serde(deserialize_with = "vec_from_hex")]
    pub d: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub e: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyAsn")]
    pub asn_key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyDer")]
    pub der: Vec<u8>,
    #[serde(rename = "keyJwk")]
    pub public_jwk: Option<RsaPublicJwk>,
    #[serde(rename = "privateKeyJwk")]
    pub private_jwk: Option<RsaPrivateJwk>,
    #[serde(rename = "keyPem")]
    pub public_pem: String,
    #[serde(rename = "privateKeyPem")]
    pub private_pem: String,
    #[serde(rename = "privateKeyPkcs8")]
    pub private_pkcs8: String,
    #[serde(rename = "keysize")]
    pub key_size: usize,
    #[serde(deserialize_with = "vec_from_hex")]
    pub n: Vec<u8>,
    #[serde(rename = "sha")]
    pub hash: HashFunction,
    #[serde(rename = "type")]
    typ: TestGroupTypeId,
    pub tests: Vec<Test>,
}

define_test!(msg: Vec<u8>, sig: Vec<u8>);
