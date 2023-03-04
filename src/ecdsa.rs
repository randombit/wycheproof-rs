//! ECDSA tests

use super::*;

define_test_set!(
    "ECDSA verify",
    "ecdsa_verify_schema.json",
    "ecdsa_p1363_verify_schema.json",
    "ecdsa_bitcoin_verify_schema.json"
);

define_algorithm_map!("ECDSA" => Ecdsa);

define_test_set_names!(
    EcdsaBrainpool224r1Sha224P1363 => "ecdsa_brainpoolP224r1_sha224_p1363",
    EcdsaBrainpool224r1Sha224 => "ecdsa_brainpoolP224r1_sha224",
    EcdsaBrainpool224r1Sha3_224 => "ecdsa_brainpoolP224r1_sha3_224",
    EcdsaBrainpool256r1Sha256P1363 => "ecdsa_brainpoolP256r1_sha256_p1363",
    EcdsaBrainpool256r1Sha256 => "ecdsa_brainpoolP256r1_sha256",
    EcdsaBrainpool256r1Sha3_256 => "ecdsa_brainpoolP256r1_sha3_256",
    EcdsaBrainpool320r1Sha3_384 => "ecdsa_brainpoolP320r1_sha3_384",
    EcdsaBrainpool320r1Sha384P1363 => "ecdsa_brainpoolP320r1_sha384_p1363",
    EcdsaBrainpool320r1Sha384 => "ecdsa_brainpoolP320r1_sha384",
    EcdsaBrainpool384r1Sha3_384 => "ecdsa_brainpoolP384r1_sha3_384",
    EcdsaBrainpool384r1Sha384P1363 => "ecdsa_brainpoolP384r1_sha384_p1363",
    EcdsaBrainpool384r1Sha384 => "ecdsa_brainpoolP384r1_sha384",
    EcdsaBrainpool512r1Sha3_512 => "ecdsa_brainpoolP512r1_sha3_512",
    EcdsaBrainpool512r1Sha512P1363 => "ecdsa_brainpoolP512r1_sha512_p1363",
    EcdsaBrainpool512r1Sha512 => "ecdsa_brainpoolP512r1_sha512",
    EcdsaSecp160k1Sha256P1363 => "ecdsa_secp160k1_sha256_p1363",
    EcdsaSecp160k1Sha256 => "ecdsa_secp160k1_sha256",
    EcdsaSecp160r1Sha256P1363 => "ecdsa_secp160r1_sha256_p1363",
    EcdsaSecp160r1Sha256 => "ecdsa_secp160r1_sha256",
    EcdsaSecp160r2Sha256P1363 => "ecdsa_secp160r2_sha256_p1363",
    EcdsaSecp160r2Sha256 => "ecdsa_secp160r2_sha256",
    EcdsaSecp192k1Sha256P1363 => "ecdsa_secp192k1_sha256_p1363",
    EcdsaSecp192k1Sha256 => "ecdsa_secp192k1_sha256",
    EcdsaSecp192r1Sha256P1363 => "ecdsa_secp192r1_sha256_p1363",
    EcdsaSecp192r1Sha256 => "ecdsa_secp192r1_sha256",
    EcdsaSecp224k1Sha224P1363 => "ecdsa_secp224k1_sha224_p1363",
    EcdsaSecp224k1Sha224 => "ecdsa_secp224k1_sha224",
    EcdsaSecp224k1Sha256P1363 => "ecdsa_secp224k1_sha256_p1363",
    EcdsaSecp224k1Sha256 => "ecdsa_secp224k1_sha256",
    EcdsaSecp224r1Sha224P1363 => "ecdsa_secp224r1_sha224_p1363",
    EcdsaSecp224r1Sha224 => "ecdsa_secp224r1_sha224",
    EcdsaSecp224r1Sha256P1363 => "ecdsa_secp224r1_sha256_p1363",
    EcdsaSecp224r1Sha256 => "ecdsa_secp224r1_sha256",
    EcdsaSecp224r1Sha3_224 => "ecdsa_secp224r1_sha3_224",
    EcdsaSecp224r1Sha3_256 => "ecdsa_secp224r1_sha3_256",
    EcdsaSecp224r1Sha3_512 => "ecdsa_secp224r1_sha3_512",
    EcdsaSecp224r1Sha512P1363 => "ecdsa_secp224r1_sha512_p1363",
    EcdsaSecp224r1Sha512 => "ecdsa_secp224r1_sha512",
    EcdsaSecp224r1Shake128P1363 => "ecdsa_secp224r1_shake128_p1363",
    EcdsaSecp224r1Shake128 => "ecdsa_secp224r1_shake128",
    EcdsaSecp256k1Sha256Bitcoin => "ecdsa_secp256k1_sha256_bitcoin",
    EcdsaSecp256k1Sha256P1363 => "ecdsa_secp256k1_sha256_p1363",
    EcdsaSecp256k1Sha256 => "ecdsa_secp256k1_sha256",
    EcdsaSecp256k1Sha3_256 => "ecdsa_secp256k1_sha3_256",
    EcdsaSecp256k1Sha3_512 => "ecdsa_secp256k1_sha3_512",
    EcdsaSecp256k1Sha512P1363 => "ecdsa_secp256k1_sha512_p1363",
    EcdsaSecp256k1Sha512 => "ecdsa_secp256k1_sha512",
    EcdsaSecp256k1Shake128P1363 => "ecdsa_secp256k1_shake128_p1363",
    EcdsaSecp256k1Shake128 => "ecdsa_secp256k1_shake128",
    EcdsaSecp256k1Shake256P1363 => "ecdsa_secp256k1_shake256_p1363",
    EcdsaSecp256k1Shake256 => "ecdsa_secp256k1_shake256",
    EcdsaSecp256r1Sha256P1363 => "ecdsa_secp256r1_sha256_p1363",
    EcdsaSecp256r1Sha256 => "ecdsa_secp256r1_sha256",
    EcdsaSecp256r1Sha3_256 => "ecdsa_secp256r1_sha3_256",
    EcdsaSecp256r1Sha3_512 => "ecdsa_secp256r1_sha3_512",
    EcdsaSecp256r1Sha512P1363 => "ecdsa_secp256r1_sha512_p1363",
    EcdsaSecp256r1Sha512 => "ecdsa_secp256r1_sha512",
    EcdsaSecp256r1Shake128P1363 => "ecdsa_secp256r1_shake128_p1363",
    EcdsaSecp256r1Shake128 => "ecdsa_secp256r1_shake128",
    EcdsaSecp256r1Webcrypto => "ecdsa_secp256r1_webcrypto",
    EcdsaSecp384r1Sha256 => "ecdsa_secp384r1_sha256",
    EcdsaSecp384r1Sha3_384 => "ecdsa_secp384r1_sha3_384",
    EcdsaSecp384r1Sha3_512 => "ecdsa_secp384r1_sha3_512",
    EcdsaSecp384r1Sha384P1363 => "ecdsa_secp384r1_sha384_p1363",
    EcdsaSecp384r1Sha384 => "ecdsa_secp384r1_sha384",
    EcdsaSecp384r1Sha512P1363 => "ecdsa_secp384r1_sha512_p1363",
    EcdsaSecp384r1Sha512 => "ecdsa_secp384r1_sha512",
    EcdsaSecp384r1Shake256P1363 => "ecdsa_secp384r1_shake256_p1363",
    EcdsaSecp384r1Shake256 => "ecdsa_secp384r1_shake256",
    EcdsaSecp384r1Webcrypto => "ecdsa_secp384r1_webcrypto",
    EcdsaSecp521r1Sha3_512 => "ecdsa_secp521r1_sha3_512",
    EcdsaSecp521r1Sha512P1363 => "ecdsa_secp521r1_sha512_p1363",
    EcdsaSecp521r1Sha512 => "ecdsa_secp521r1_sha512",
    EcdsaSecp521r1Shake256P1363 => "ecdsa_secp521r1_shake256_p1363",
    EcdsaSecp521r1Shake256 => "ecdsa_secp521r1_shake256",
    EcdsaSecp521r1Webcrypto => "ecdsa_secp521r1_webcrypto",
);

define_test_flags!(
    ArithmeticError,
    BerEncodedSignature,
    EdgeCasePublicKey,
    EdgeCaseShamirMultiplication,
    GroupIsomorphism,
    IntegerOverflow,
    InvalidEncoding,
    InvalidSignature,
    InvalidTypesInSignature,
    MissingZero,
    ModifiedInteger,
    ModifiedSignature,
    ModularInverse,
    PointDuplication,
    RangeCheck,
    SignatureSize,
    SignatureMalleabilityBitcoin,
    SmallRandS,
    SpecialCaseHash,
    Untruncatedhash,
    ValidSignature,
);

define_typeid!(TestKeyTypeId => "EcPublicKey");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestKey {
    pub curve: EllipticCurve,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(rename = "type")]
    typ: TestKeyTypeId,
    #[serde(rename = "uncompressed")]
    pub key: ByteString,
    #[serde(rename = "wx")]
    pub affine_x: LargeInteger,
    #[serde(rename = "wy")]
    pub affine_y: LargeInteger,
}

define_test_group_type_id!(
    "EcdsaVerify" => Ecdsa,
    "EcdsaP1363Verify" => EcdsaP1363,
    "EcdsaBitcoinVerify" => EcdsaBitcoin,
);

define_test_group!(
    "publicKeyJwk" => jwk: Option<EcdsaPublicJwk>,
    "publicKey" => key: TestKey,
    "publicKeyDer" => der: ByteString,
    "publicKeyPem" => pem: String,
    "sha" => hash: HashFunction,
);

define_test!(msg: ByteString, sig: ByteString);
