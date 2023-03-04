//! DSA verification tests

use super::*;

define_test_set!(
    "DSA verify",
    "dsa_verify_schema.json",
    "dsa_p1363_verify_schema.json"
);

define_algorithm_map!("DSA" => Dsa);

define_test_set_names!(
    Dsa2048_224Sha224 => "dsa_2048_224_sha224",
    Dsa2048_224Sha256 => "dsa_2048_224_sha256",
    Dsa2048_256Sha256 => "dsa_2048_256_sha256",
    Dsa3072_256Sha256 => "dsa_3072_256_sha256",
    Dsa2048_224Sha224P1363 => "dsa_2048_224_sha224_p1363",
    Dsa2048_224Sha256P1363 => "dsa_2048_224_sha256_p1363",
    Dsa2048_256Sha256P1363 => "dsa_2048_256_sha256_p1363",
    Dsa3072_256Sha256P1363 => "dsa_3072_256_sha256_p1363",
);

define_test_flags!(
    ArithmeticError,
    BerEncodedSignature,
    IntegerOverflow,
    InvalidEncoding,
    InvalidSignature,
    InvalidTypesInSignature,
    MissingZero,
    ModifiedInteger,
    ModifiedSignature,
    ModularInverse,
    Normal,
    RangeCheck,
    SmallRandS,
    SpecialCaseHash,
);

define_typeid!(TestKeyTypeId => "DsaPublicKey");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestKey {
    pub g: LargeInteger,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    pub p: LargeInteger,
    pub q: LargeInteger,
    #[serde(rename = "type")]
    typ: TestKeyTypeId,
    pub y: LargeInteger,
}

define_test_group_type_id!(
    "DsaVerify" => DsaVerify,
    "DsaP1363Verify" => DsaVerifyP1363,
);

define_test_group!(
    "publicKey" => key: TestKey,
    "publicKeyDer" => der: ByteString,
    "publicKeyPem" => pem: String,
    "sha" => hash: HashFunction,
);

define_test!(msg: ByteString, sig: ByteString);
