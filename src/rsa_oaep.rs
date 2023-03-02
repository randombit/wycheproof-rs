//! RSA OAEP decryption tests

use super::*;

define_test_set!("RSA OAEP decrypt", "rsaes_oaep_decrypt_schema.json");

/*
Currently skips:

rsa_three_primes_oaep_2048_sha1_mgf1sha1_test.json
rsa_three_primes_oaep_3072_sha224_mgf1sha224_test.json
rsa_three_primes_oaep_4096_sha256_mgf1sha256_test.json
*/
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
    Rsa2048Sha512_224Mgf1Sha1 => "rsa_oaep_2048_sha512_224_mgf1sha1",
    Rsa2048Sha512_224Mgf1Sha512_224 => "rsa_oaep_2048_sha512_224_mgf1sha512_224",
    Rsa3072Sha256Mgf1Sha1 => "rsa_oaep_3072_sha256_mgf1sha1",
    Rsa3072Sha256Mgf1Sha256 => "rsa_oaep_3072_sha256_mgf1sha256",
    Rsa3072Sha512Mgf1Sha1 => "rsa_oaep_3072_sha512_mgf1sha1",
    Rsa3072Sha512Mgf1Sha512 => "rsa_oaep_3072_sha512_mgf1sha512",
    Rsa3072Sha512_256Mgf1Sha1 => "rsa_oaep_3072_sha512_256_mgf1sha1",
    Rsa3072Sha512_256Mgf1Sha512_256 => "rsa_oaep_3072_sha512_256_mgf1sha512_256",
    Rsa4096Sha256Mgf1Sha1 => "rsa_oaep_4096_sha256_mgf1sha1",
    Rsa4096Sha256Mgf1Sha256 => "rsa_oaep_4096_sha256_mgf1sha256",
    Rsa4096Sha512Mgf1Sha1 => "rsa_oaep_4096_sha512_mgf1sha1",
    Rsa4096Sha512Mgf1Sha512 => "rsa_oaep_4096_sha512_mgf1sha512",
    RsaMisc => "rsa_oaep_misc",
);

define_algorithm_map!("RSAES-OAEP" => RsaOaep);

define_test_flags!(
    Constructed,
    EncryptionWithLabel,
    InvalidCiphertext,
    InvalidOaepPadding,
    Normal,
    SmallModulus,
);

define_typeid!(TestGroupTypeId => "RsaesOaepDecrypt");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestKey {
    #[serde(rename = "publicExponent")]
    e: LargeInteger,
    #[serde(rename = "privateExponent")]
    d: LargeInteger,
    #[serde(rename = "modulus")]
    n: LargeInteger,
    #[serde(rename = "prime1")]
    p: LargeInteger,
    #[serde(rename = "prime2")]
    q: LargeInteger,
    #[serde(rename = "exponent1")]
    d1: LargeInteger,
    #[serde(rename = "exponent2")]
    d2: LargeInteger,
    #[serde(rename = "coefficient")]
    c: LargeInteger,
}

define_test_group!(
    "privateKey" => key: TestKey,
    "keySize" => key_size: usize,
    mgf: Mgf,
    "mgfSha" => mgf_hash: HashFunction,
    "privateKeyJwk" => jwk: Option<RsaPrivateJwk>,
    "privateKeyPkcs8" => pkcs8: ByteString,
    "privateKeyPem" => pem: String,
    "sha" => hash: HashFunction,
);

define_test!(msg: ByteString, ct: ByteString, label: ByteString);
