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

define_test_group_type_id!(
    "RsassaPssVerify" => RsaPssVerify,
    "RsassaPssWithParametersVerify" => RsaPssVerifyWithParam,
);

fn deser_mgf_hash<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<HashFunction>, D::Error> {
    let s: &str = Deserialize::deserialize(deserializer)?;
    match s {
        "" => Ok(None),
        "SHA-1" => Ok(Some(HashFunction::Sha1)),
        "SHA-224" => Ok(Some(HashFunction::Sha2_224)),
        "SHA-256" => Ok(Some(HashFunction::Sha2_256)),
        "SHA-384" => Ok(Some(HashFunction::Sha2_384)),
        "SHA-512" => Ok(Some(HashFunction::Sha2_512)),
        "SHA-512/224" => Ok(Some(HashFunction::Sha2_512_224)),
        "SHA-512/256" => Ok(Some(HashFunction::Sha2_512_256)),
        h => panic!("Unknown hash {}", h),
    }
}

define_test_group!(
    "publicKey" => key: RsaPublic,
    "publicKeyAsn" => asn_key: ByteString,
    "publicKeyDer" => der: ByteString,
    "publicKeyPem" => pem: String,
    "publicKeyJwk" => jwk: Option<RsaPublicJwk>,
    "keySize" => key_size: usize,
    mgf: Mgf,
    "mgfSha" => mgf_hash: Option<HashFunction> | "deser_mgf_hash",
    "sLen" => salt_size: usize,
    "sha" => hash: HashFunction,
);

define_test!(msg: ByteString, sig: ByteString);
