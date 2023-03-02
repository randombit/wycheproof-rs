//! RSA PSS verification tests

use super::*;

define_test_set!(
    "RSA PKCS1 verify",
    "rsassa_pss_verify_schema.json",
    "rsassa_pss_with_parameters_verify_schema.json"
);

define_test_set_names!(
    RsaPss2048Sha1Mgf1SaltLen20WithParams => "rsa_pss_2048_sha1_mgf1_20_params",
    RsaPss2048Sha1Mgf1SaltLen20 => "rsa_pss_2048_sha1_mgf1_20",
    RsaPss2048Sha256Mgf1SaltLen0WithParams => "rsa_pss_2048_sha256_mgf1_0_params",
    RsaPss2048Sha256Mgf1SaltLen0 => "rsa_pss_2048_sha256_mgf1_0",
    RsaPss2048Sha256Mgf1SaltLen32WithParams => "rsa_pss_2048_sha256_mgf1_32_params",
    RsaPss2048Sha256Mgf1SaltLen32 => "rsa_pss_2048_sha256_mgf1_32",
    RsaPss2048Sha256Mgf1Sha1_20 => "rsa_pss_2048_sha256_mgf1sha1_20",
    RsaPss2048Sha384Mgf1SaltLen48 => "rsa_pss_2048_sha384_mgf1_48",
    RsaPss2048Sha512_224Mgf1SaltLen28 => "rsa_pss_2048_sha512_224_mgf1_28",
    RsaPss2048Sha512_256Mgf1SaltLen32 => "rsa_pss_2048_sha512_256_mgf1_32",
    RsaPss2048Sha512Mgf1Sha256SaltLen32WithParams => "rsa_pss_2048_sha512_mgf1sha256_32_params",
    RsaPss2048Shake128WithParams => "rsa_pss_2048_shake128_params",
    RsaPss2048Shake128 => "rsa_pss_2048_shake128",
    RsaPss2048Shake256 => "rsa_pss_2048_shake256",
    RsaPss3072Sha256Mgf1SaltLen32WithParams => "rsa_pss_3072_sha256_mgf1_32_params",
    RsaPss3072Sha256Mgf1SaltLen32 => "rsa_pss_3072_sha256_mgf1_32",
    RsaPss3072Shake128WithParams => "rsa_pss_3072_shake128_params",
    RsaPss3072Shake128 => "rsa_pss_3072_shake128",
    RsaPss3072Shake256WithParams => "rsa_pss_3072_shake256_params",
    RsaPss3072Shake256 => "rsa_pss_3072_shake256",
    RsaPss4096Sha256Mgf1SaltLen32 => "rsa_pss_4096_sha256_mgf1_32",
    RsaPss4096Sha384Mgf1SaltLen48 => "rsa_pss_4096_sha384_mgf1_48",
    RsaPss4096Sha512Mgf1SaltLen32WithParams => "rsa_pss_4096_sha512_mgf1_32_params",
    RsaPss4096Sha512Mgf1SaltLen32 => "rsa_pss_4096_sha512_mgf1_32",
    RsaPss4096Sha512Mgf1SaltLen64WithParams => "rsa_pss_4096_sha512_mgf1_64_params",
    RsaPss4096Sha512Mgf1SaltLen64 => "rsa_pss_4096_sha512_mgf1_64",
    RsaPss4096Shake256WithParams => "rsa_pss_4096_shake256_params",
    RsaPss4096Shake256 => "rsa_pss_4096_shake256",
    RsaPssmiscWithParams => "rsa_pss_misc_params",
    RsaPssmisc => "rsa_pss_misc",
);

define_algorithm_map!("RSASSA-PSS" => RsaPss);

define_test_flags!(
    DistinctHash,
    ModifiedSignature,
    Mgf1Sha1,
    Normal,
    ParameterTest,
    SpecialCaseHash,
    SpecifyPkcs1Algorithm,
    WeakHash,
    WrongPrimitive,
);

define_typeid!(TestGroupTypeId => "RsassaPssVerify", "RsassaPssWithParametersVerify");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestKey {
    #[serde(rename = "publicExponent")]
    e: LargeInteger,
    #[serde(rename = "modulus")]
    n: LargeInteger,
}

define_test_group!(
    "publicKey" => key: TestKey,
    "publicKeyAsn" => asn_key: ByteString,
    "publicKeyDer" => der: ByteString,
    "publicKeyPem" => pem: String,
    "publicKeyJwk" => jwk: Option<RsaPublicJwk>,
    "keySize" => key_size: usize,
    mgf: Mgf,
    "mgfSha" => mgf_hash: HashFunction,
    "sLen" => salt_length: usize,
    "sha" => hash: HashFunction,
);

define_test!(msg: ByteString, sig: ByteString);
