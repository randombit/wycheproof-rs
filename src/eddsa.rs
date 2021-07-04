//! EdDSA verification tests

use super::*;

define_test_set!("EdDSA verify", "eddsa_verify_schema.json");

define_test_set_names!(
    Ed25519 => "eddsa",
    Ed448 => "ed448"
);

define_algorithm_map!("EDDSA" => EdDsa);

define_test_flags!(SignatureMalleability);

define_typeid!(TestKeyTypeId => "EDDSAKeyPair");

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
    typ: TestKeyTypeId,
}

define_typeid!(TestGroupTypeId => "EddsaVerify");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    pub jwk: Option<EddsaJwk>,
    pub key: TestKey,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyDer")]
    pub der: Vec<u8>,
    #[serde(rename = "keyPem")]
    pub pem: String,
    #[serde(rename = "type")]
    typ: TestGroupTypeId,
    pub tests: Vec<Test>,
}

define_test!(msg: Vec<u8>, sig: Vec<u8>);
