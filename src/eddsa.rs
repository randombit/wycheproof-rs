//! EdDSA verification tests

use super::*;

define_test_set!("EdDSA verify", "eddsa_verify_schema.json");

define_test_set_names!(
    Ed25519 => "ed25519",
    Ed448 => "ed448",
);

define_algorithm_map!("EDDSA" => EdDsa);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    CompressedSignature,
    InvalidEncoding,
    InvalidSignature,
    #[serde(rename = "Ktv")]
    KnownTestVector,
    #[serde(rename = "InvalidKtv")]
    InvalidKnownTestVector,
    SignatureMalleability,
    SignatureWithGarbage,
    TinkOverflow,
    TruncatedSignature,
    Valid,
}

define_typeid!(TestKeyTypeId => "EDDSAPublicKey");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestKey {
    pub curve: EdwardsCurve,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(deserialize_with = "vec_from_hex")]
    pub pk: Vec<u8>,
    #[serde(rename = "type")]
    typ: TestKeyTypeId,
}

define_typeid!(TestGroupTypeId => "EddsaVerify");

define_test_group!(
    "publicKeyJwk" => jwk: EddsaPublicJwk,
    "publicKey" => key: TestKey,
    "publicKeyDer" => der: Vec<u8> | "vec_from_hex",
    "publicKeyPem" => pem: String,
);

define_test!(msg: Vec<u8>, sig: Vec<u8>);
