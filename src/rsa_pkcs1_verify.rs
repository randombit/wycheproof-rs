//! RSA PKCS1v1.5 verification tests

use super::*;

define_test_set!("RSA PKCS1 verify", "rsassa_pkcs1_verify_schema.json");

define_algorithm_map!("RSASSA-PKCS1-v1_5" => RsaPkcs1v15);

define_test_set_names!(
    Rsa2048Sha224 => "rsa_signature_2048_sha224",
    Rsa2048Sha256 => "rsa_signature_2048_sha256",
    Rsa2048Sha3_224 => "rsa_signature_2048_sha3_224",
    Rsa2048Sha3_256 => "rsa_signature_2048_sha3_256",
    Rsa2048Sha3_384 => "rsa_signature_2048_sha3_384",
    Rsa2048Sha3_512 => "rsa_signature_2048_sha3_512",
    Rsa2048Sha384 => "rsa_signature_2048_sha384",
    Rsa2048Sha512_224 => "rsa_signature_2048_sha512_224",
    Rsa2048Sha512_256 => "rsa_signature_2048_sha512_256",
    Rsa2048Sha512 => "rsa_signature_2048_sha512",
    Rsa3072Sha256 => "rsa_signature_3072_sha256",
    Rsa3072Sha3_256 => "rsa_signature_3072_sha3_256",
    Rsa3072Sha3_384 => "rsa_signature_3072_sha3_384",
    Rsa3072Sha3_512 => "rsa_signature_3072_sha3_512",
    Rsa3072Sha384 => "rsa_signature_3072_sha384",
    Rsa3072Sha512_256 => "rsa_signature_3072_sha512_256",
    Rsa3072Sha512 => "rsa_signature_3072_sha512",
    Rsa4096Sha384 => "rsa_signature_4096_sha384",
    Rsa4096Sha512_256 => "rsa_signature_4096_sha512_256",
    Rsa4096Sha512 => "rsa_signature_4096_sha512",
    RsaMisc => "rsa_signature"
);

define_test_flags!(MissingNull, SmallPublicKey, SmallModulus);

define_typeid!(TestGroupTypeId => "RsassaPkcs1Verify");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    #[serde(deserialize_with = "vec_from_hex")]
    pub e: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyAsn")]
    pub asn_key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyDer")]
    pub der: Vec<u8>,
    #[serde(rename = "keyJwk")]
    pub jwk: Option<RsaPublicJwk>,
    #[serde(rename = "keyPem")]
    pub pem: String,
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
