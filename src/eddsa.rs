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

define_test_group_type_id!(
    "EddsaVerify" => Eddsa,
);

define_test_group!(
    "publicKeyJwk" => jwk: EddsaPublicJwk,
    "publicKey" => key: EddsaPublic,
    "publicKeyDer" => der: ByteString,
    "publicKeyPem" => pem: String,
);

define_test!(msg: ByteString, sig: ByteString);
