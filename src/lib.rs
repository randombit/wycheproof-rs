use serde::{de::Error, Deserialize, Deserializer};

use base64::{decode_config as base64_decode, URL_SAFE};
use hex::decode as hex_decode;
use std::collections::HashMap;

mod datafiles;

/// The error type
#[derive(Debug)]
pub enum WycheproofError {
    NoDataSet,
    InvalidData,
    ParsingFailed(Box<dyn std::error::Error>),
}

fn vec_from_hex<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s: &str = Deserialize::deserialize(deserializer)?;
    hex_decode(s).map_err(D::Error::custom)
}

#[derive(Debug, Deserialize)]
struct WrappedHexVec(#[serde(deserialize_with = "vec_from_hex")] Vec<u8>);

fn opt_vec_from_hex<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    let owv = Option::<WrappedHexVec>::deserialize(deserializer);
    owv.map(|ow: Option<WrappedHexVec>| ow.map(|w: WrappedHexVec| w.0))
}

fn vec_from_base64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s: &str = Deserialize::deserialize(deserializer)?;
    base64_decode(s, URL_SAFE).map_err(D::Error::custom)
}

macro_rules! define_schema {
    ( $enum_name:ident, $schema_type:expr, $( $schema_name:expr ),* ) => {
        #[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
        struct $enum_name {}

        impl<'de> Deserialize<'de> for $enum_name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s: &str = Deserialize::deserialize(deserializer)?;

                match s {
                    $(
                    $schema_name => Ok($enum_name {}),
                    )*
                    unknown => Err(D::Error::custom(format!("unknown {} schema {}", $schema_type, unknown))),
                }
            }
        }
    }
}

macro_rules! define_test_set {
    ( $test_set_type:ident, $schema_type:ident, $flag_type:ident, $test_group_type:ident) => {
        #[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $test_set_type {
            pub algorithm: String,
            #[serde(rename = "generatorVersion")]
            pub generator_version: String,
            #[serde(rename = "numberOfTests")]
            pub number_of_tests: usize,
            pub header: Vec<String>,
            pub notes: HashMap<$flag_type, String>,
            schema: $schema_type,
            #[serde(rename = "testGroups")]
            pub test_groups: Vec<$test_group_type>,
        }

        impl $test_set_type {
            fn check(obj: Self) -> Result<Self, WycheproofError> {
                let actual_number_of_tests: usize =
                    obj.test_groups.iter().map(|tg| tg.tests.len()).sum();
                if obj.number_of_tests != actual_number_of_tests {
                    return Err(WycheproofError::InvalidData);
                }
                Ok(obj)
            }

            pub fn load(name: &str) -> Result<Self, WycheproofError> {
                match datafiles::wycheproof_data_set(name) {
                    Some(data) => {
                        let set = serde_json::from_str(data);
                        match set {
                            Ok(set) => Self::check(set),
                            Err(e) => Err(WycheproofError::ParsingFailed(Box::new(e))),
                        }
                    }
                    None => Err(WycheproofError::NoDataSet),
                }
            }
        }
    };
}

/// The expected result of a Wycheproof test
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestResult {
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "invalid")]
    Invalid,
    #[serde(rename = "acceptable")]
    Acceptable,
}

impl TestResult {
    pub fn must_fail(&self) -> bool {
        match self {
            Self::Valid => false,
            Self::Acceptable => false,
            Self::Invalid => true,
        }
    }
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum EllipticCurve {
    #[serde(rename = "secp224r1")]
    Secp224r1,
    #[serde(rename = "secp256r1", alias = "P-256")]
    Secp256r1,
    #[serde(rename = "secp384r1", alias = "P-384")]
    Secp384r1,
    #[serde(rename = "secp521r1", alias = "P-521")]
    Secp521r1,

    #[serde(rename = "secp224k1")]
    Secp224k1,
    #[serde(rename = "secp256k1", alias = "P-256K")]
    Secp256k1,

    #[serde(rename = "brainpoolP224r1")]
    Brainpool224r1,
    #[serde(rename = "brainpoolP256r1")]
    Brainpool256r1,
    #[serde(rename = "brainpoolP320r1")]
    Brainpool320r1,
    #[serde(rename = "brainpoolP384r1")]
    Brainpool384r1,
    #[serde(rename = "brainpoolP512r1")]
    Brainpool512r1,

    #[serde(rename = "brainpoolP224t1")]
    Brainpool224t1,
    #[serde(rename = "brainpoolP256t1")]
    Brainpool256t1,
    #[serde(rename = "brainpoolP320t1")]
    Brainpool320t1,
    #[serde(rename = "brainpoolP384t1")]
    Brainpool384t1,
    #[serde(rename = "brainpoolP512t1")]
    Brainpool512t1,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum HashFunction {
    #[serde(rename = "SHA-1")]
    Sha1,

    #[serde(rename = "SHA-224")]
    Sha2_224,
    #[serde(rename = "SHA-256")]
    Sha2_256,
    #[serde(rename = "SHA-384")]
    Sha2_384,
    #[serde(rename = "SHA-512")]
    Sha2_512,

    #[serde(rename = "SHA-512/224")]
    Sha2_512_224,

    #[serde(rename = "SHA-512/256")]
    Sha2_512_256,

    #[serde(rename = "SHA3-224")]
    Sha3_224,
    #[serde(rename = "SHA3-256")]
    Sha3_256,
    #[serde(rename = "SHA3-384")]
    Sha3_384,
    #[serde(rename = "SHA3-512")]
    Sha3_512,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum Mgf {
    #[serde(rename = "MGF1")]
    Mgf1,
}

//*** AEAD ***

define_test_set!(AeadTestSet, AeadTestSchema, AeadTestFlag, AeadTestGroup);
define_schema!(AeadTestSchema, "AEAD", "aead_test_schema.json");

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum AeadTestFlag {
    BadPadding,
    ConstructedIv,
    CounterWrap,
    EdgeCaseSiv,
    InvalidNonceSize,
    InvalidTagSize,
    LongIv,
    OldVersion,
    SmallIv,
    ZeroLengthIv,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AeadTestGroup {
    #[serde(rename = "ivSize")]
    pub nonce_size: usize,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(rename = "tagSize")]
    pub tag_size: usize,
    #[serde(rename = "type")]
    typ: String,
    pub tests: Vec<AeadTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AeadTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "iv")]
    pub nonce: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub aad: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "msg")]
    pub pt: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub ct: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub tag: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<AeadTestFlag>,
}

//*** DAEAD ***

define_test_set!(DaeadTestSet, DaeadTestSchema, DaeadTestFlag, DaeadTestGroup);
define_schema!(DaeadTestSchema, "DAEAD", "daead_test_schema.json");

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum DaeadTestFlag {
    EdgeCaseSiv,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaeadTestGroup {
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(rename = "type")]
    typ: String,
    pub tests: Vec<DaeadTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaeadTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub aad: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "msg")]
    pub pt: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub ct: Vec<u8>,
    pub result: TestResult,
    #[serde(default)]
    pub flags: Vec<DaeadTestFlag>,
}

//*** Cipher ***

define_test_set!(
    CipherTestSet,
    CipherTestSchema,
    CipherTestFlag,
    CipherTestGroup
);
define_schema!(CipherTestSchema, "Cipher", "ind_cpa_test_schema.json");

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum CipherTestFlag {
    BadPadding,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherTestGroup {
    #[serde(rename = "ivSize")]
    pub nonce_size: usize,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(rename = "type")]
    typ: String,
    pub tests: Vec<CipherTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub iv: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "msg")]
    pub pt: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub ct: Vec<u8>,
    pub result: TestResult,
    #[serde(default)]
    pub flags: Vec<CipherTestFlag>,
}

//*** ECDSA verify ***

define_test_set!(
    EcdsaVerifyTestSet,
    EcdsaVerifyTestSchema,
    EcdsaVerifyTestFlag,
    EcdsaVerifyTestGroup
);

define_schema!(
    EcdsaVerifyTestSchema,
    "ECDSA verify",
    "ecdsa_verify_schema.json",
    "ecdsa_p1363_verify_schema.json"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum EcdsaVerifyTestFlag {
    BER,
    EdgeCase,
    GroupIsomorphism,
    MissingZero,
    PointDuplication,
    SigSize,
    WeakHash,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaVerifyTestKey {
    pub curve: EllipticCurve,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(rename = "type")]
    typ: String, // check this
    #[serde(deserialize_with = "vec_from_hex", rename = "uncompressed")]
    key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "wx")]
    affine_x: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "wy")]
    affine_y: Vec<u8>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaVerifyJwk {
    #[serde(rename = "crv")]
    pub curve: EllipticCurve,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "vec_from_base64", rename = "x")]
    pub affine_x: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64", rename = "y")]
    pub affine_y: Vec<u8>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaVerifyTestGroup {
    pub jwk: Option<EcdsaVerifyJwk>,
    pub key: EcdsaVerifyTestKey,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyDer")]
    pub der: Vec<u8>,
    #[serde(rename = "keyPem")]
    pub pem: String,
    #[serde(rename = "sha")]
    pub hash: HashFunction,
    #[serde(rename = "type")]
    typ: String, // todo enum/check
    pub tests: Vec<EcdsaVerifyTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaVerifyTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub sig: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<EcdsaVerifyTestFlag>,
}

//*** EdDSA verify ***

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum EdwardsCurve {
    #[serde(alias = "edwards25519")]
    Ed25519,
    #[serde(alias = "edwards448")]
    Ed448,
}

define_test_set!(
    EddsaVerifyTestSet,
    EddsaVerifyTestSchema,
    EddsaVerifyTestFlag,
    EddsaVerifyTestGroup
);

define_schema!(
    EddsaVerifyTestSchema,
    "EdDSA verify",
    "eddsa_verify_schema.json"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum EddsaVerifyTestFlag {
    SignatureMalleability,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EddsaVerifyTestKey {
    pub curve: EdwardsCurve,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(deserialize_with = "vec_from_hex")]
    pub pk: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub sk: Vec<u8>,
    #[serde(rename = "type")]
    typ: String, // check this
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EddsaVerifyJwk {
    #[serde(rename = "crv")]
    pub curve: EdwardsCurve,
    #[serde(deserialize_with = "vec_from_base64")]
    pub d: Vec<u8>,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "vec_from_base64")]
    pub x: Vec<u8>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EddsaVerifyTestGroup {
    pub jwk: Option<EddsaVerifyJwk>,
    pub key: EddsaVerifyTestKey,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyDer")]
    pub der: Vec<u8>,
    #[serde(rename = "keyPem")]
    pub pem: String,
    #[serde(rename = "type")]
    typ: String, // todo enum/check
    pub tests: Vec<EddsaVerifyTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EddsaVerifyTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub sig: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<EddsaVerifyTestFlag>,
}

//*** RSA PKCS1 verify ***

define_test_set!(
    RsaPkcs1VerifyTestSet,
    RsaPkcs1VerifyTestSchema,
    RsaPkcs1VerifyTestFlag,
    RsaPkcs1VerifyTestGroup
);

define_schema!(
    RsaPkcs1VerifyTestSchema,
    "RSA PKCS1 verify",
    "rsassa_pkcs1_verify_schema.json"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum RsaPkcs1VerifyTestFlag {
    MissingNull,
    SmallPublicKey,
    SmallModulus,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPublicJwk {
    pub alg: String,
    #[serde(deserialize_with = "vec_from_base64")]
    pub e: Vec<u8>,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "vec_from_base64")]
    n: Vec<u8>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPkcs1VerifyTestGroup {
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
    typ: String, // todo enum/check
    pub tests: Vec<RsaPkcs1VerifyTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPkcs1VerifyTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub sig: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<RsaPkcs1VerifyTestFlag>,
}

//*** RSA PKCS1 sign ***

define_test_set!(
    RsaPkcs1SignTestSet,
    RsaPkcs1SignTestSchema,
    RsaPkcs1SignTestFlag,
    RsaPkcs1SignTestGroup
);

define_schema!(
    RsaPkcs1SignTestSchema,
    "RSA PKCS1 sign",
    "rsassa_pkcs1_generate_schema.json"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum RsaPkcs1SignTestFlag {
    SmallPublicKey,
    SmallModulus,
    WeakHash,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPkcs1SignTestGroup {
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
    typ: String, // todo enum/check
    pub tests: Vec<RsaPkcs1SignTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPkcs1SignTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub sig: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<RsaPkcs1SignTestFlag>,
}

//*** RSA PSS verify ***

define_test_set!(
    RsaPssVerifyTestSet,
    RsaPssVerifyTestSchema,
    RsaPssVerifyTestFlag,
    RsaPssVerifyTestGroup
);

define_schema!(
    RsaPssVerifyTestSchema,
    "RSA PKCS1 verify",
    "rsassa_pss_verify_schema.json"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum RsaPssVerifyTestFlag {
    WeakHash,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPssVerifyTestGroup {
    #[serde(deserialize_with = "vec_from_hex")]
    pub e: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyAsn")]
    pub asn_key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyDer")]
    pub der: Vec<u8>,
    #[serde(rename = "keyPem")]
    pub pem: String,
    #[serde(rename = "keysize")]
    pub key_size: usize,
    mgf: Mgf,
    #[serde(rename = "mgfSha")]
    mgf_hash: HashFunction,
    #[serde(deserialize_with = "vec_from_hex")]
    pub n: Vec<u8>,
    #[serde(rename = "sLen")]
    pub salt_length: usize,
    #[serde(rename = "sha")]
    pub hash: HashFunction,
    #[serde(rename = "type")]
    typ: String, // todo enum/check
    pub tests: Vec<RsaPssVerifyTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPssVerifyTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub sig: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<RsaPssVerifyTestFlag>,
}

//*** RSA OAEP decrypt ***

define_test_set!(
    RsaOaepDecryptTestSet,
    RsaOaepDecryptTestSchema,
    RsaOaepDecryptTestFlag,
    RsaOaepDecryptTestGroup
);

define_schema!(
    RsaOaepDecryptTestSchema,
    "RSA OAEP decrypt",
    "rsaes_oaep_decrypt_schema.json"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum RsaOaepDecryptTestFlag {
    Constructed,
    InvalidOaepPadding,
    SmallModulus,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPrivateJwk {
    pub alg: String,
    #[serde(deserialize_with = "vec_from_base64")]
    pub d: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64")]
    pub dp: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64")]
    pub dq: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64")]
    pub e: Vec<u8>,
    pub kid: String,
    pub kty: String,
    #[serde(deserialize_with = "vec_from_base64")]
    pub n: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64")]
    pub p: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64")]
    pub q: Vec<u8>,
    #[serde(deserialize_with = "vec_from_base64")]
    pub qi: Vec<u8>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaOaepDecryptTestGroup {
    #[serde(deserialize_with = "vec_from_hex")]
    pub d: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub e: Vec<u8>,
    #[serde(rename = "keysize")]
    pub key_size: usize,
    mgf: Mgf,
    #[serde(rename = "mgfSha")]
    mgf_hash: HashFunction,
    #[serde(deserialize_with = "vec_from_hex")]
    pub n: Vec<u8>,
    #[serde(rename = "privateKeyJwk")]
    pub jwk: Option<RsaPrivateJwk>,
    #[serde(deserialize_with = "vec_from_hex", rename = "privateKeyPkcs8")]
    pub pkcs8: Vec<u8>,
    #[serde(rename = "privateKeyPem")]
    pub pem: String,
    #[serde(rename = "sha")]
    pub hash: HashFunction,
    #[serde(rename = "type")]
    typ: String, // todo enum/check
    pub tests: Vec<RsaOaepDecryptTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaOaepDecryptTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub ct: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    label: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<RsaOaepDecryptTestFlag>,
}

//*** RSA PKCS1 decrypt ***

define_test_set!(
    RsaPkcs1DecryptTestSet,
    RsaPkcs1DecryptTestSchema,
    RsaPkcs1DecryptTestFlag,
    RsaPkcs1DecryptTestGroup
);

define_schema!(
    RsaPkcs1DecryptTestSchema,
    "RSA PKCS1 decrypt",
    "rsaes_pkcs1_decrypt_schema.json"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum RsaPkcs1DecryptTestFlag {
    InvalidPkcs1Padding,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPkcs1DecryptTestGroup {
    #[serde(deserialize_with = "vec_from_hex")]
    pub d: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub e: Vec<u8>,
    #[serde(rename = "keysize")]
    pub key_size: usize,
    #[serde(deserialize_with = "vec_from_hex")]
    pub n: Vec<u8>,
    #[serde(rename = "privateKeyJwk")]
    pub jwk: Option<RsaPrivateJwk>,
    #[serde(deserialize_with = "vec_from_hex", rename = "privateKeyPkcs8")]
    pub pkcs8: Vec<u8>,
    #[serde(rename = "privateKeyPem")]
    pub pem: String,
    #[serde(rename = "type")]
    typ: String, // todo enum/check
    pub tests: Vec<RsaPkcs1DecryptTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPkcs1DecryptTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub ct: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<RsaPkcs1DecryptTestFlag>,
}

//*** ECDH ***

define_test_set!(EcdhTestSet, EcdhTestSchema, EcdhTestFlag, EcdhTestGroup);

define_schema!(
    EcdhTestSchema,
    "ECDH",
    "ecdh_test_schema.json",
    "ecdh_ecpoint_test_schema.json"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum EcdhTestFlag {
    AddSubChain,
    #[allow(non_camel_case_types)]
    CVE_2017_10176,
    CompressedPoint,
    GroupIsomorphism,
    InvalidAsn,
    InvalidPublic,
    IsomorphicPublicKey,
    ModifiedPrime,
    UnnamedCurve,
    UnusedParam,
    WeakPublicKey,
    WrongOrder,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum EcdhEncoding {
    #[serde(rename = "asn")]
    Asn1,
    #[serde(rename = "ecpoint")]
    EcPoint,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdhTestGroup {
    pub curve: EllipticCurve,
    pub encoding: EcdhEncoding,
    #[serde(rename = "type")]
    typ: String, // todo enum/check
    pub tests: Vec<EcdhTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdhTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex", rename = "public")]
    pub public_key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "private")]
    pub private_key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "shared")]
    pub shared_secret: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<EcdhTestFlag>,
}

//*** xDH ***

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum MontgomeryCurve {
    #[serde(alias = "curve25519")]
    X25519,
    #[serde(alias = "curve448")]
    X448,
}

define_test_set!(XdhTestSet, XdhTestSchema, XdhTestFlag, XdhTestGroup);

define_schema!(XdhTestSchema, "xDH", "xdh_comp_schema.json");

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum XdhTestFlag {
    LowOrderPublic,
    NonCanonicalPublic,
    SmallPublicKey,
    Twist,
    ZeroSharedSecret,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdhTestGroup {
    pub curve: MontgomeryCurve,
    #[serde(rename = "type")]
    typ: String, // todo enum/check
    pub tests: Vec<XdhTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdhTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex", rename = "public")]
    pub public_key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "private")]
    pub private_key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "shared")]
    pub shared_secret: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<XdhTestFlag>,
}

//*** DSA verify ***

define_test_set!(
    DsaVerifyTestSet,
    DsaVerifyTestSchema,
    DsaVerifyTestFlag,
    DsaVerifyTestGroup
);

define_schema!(
    DsaVerifyTestSchema,
    "DSA verify",
    "dsa_verify_schema.json",
    "dsa_p1363_verify_schema.json"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum DsaVerifyTestFlag {
    EdgeCase,
    NoLeadingZero,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsaVerifyTestKey {
    #[serde(deserialize_with = "vec_from_hex")]
    pub g: Vec<u8>,
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(deserialize_with = "vec_from_hex")]
    pub p: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub q: Vec<u8>,
    #[serde(rename = "type")]
    typ: String, // check this
    #[serde(deserialize_with = "vec_from_hex")]
    pub y: Vec<u8>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsaVerifyTestGroup {
    pub key: DsaVerifyTestKey,
    #[serde(deserialize_with = "vec_from_hex", rename = "keyDer")]
    pub der: Vec<u8>,
    #[serde(rename = "keyPem")]
    pub pem: String,
    #[serde(rename = "sha")]
    pub hash: HashFunction,
    #[serde(rename = "type")]
    typ: String, // todo enum/check
    pub tests: Vec<DsaVerifyTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsaVerifyTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub sig: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<DsaVerifyTestFlag>,
}

//*** MAC ***

define_test_set!(MacTestSet, MacTestSchema, MacTestFlag, MacTestGroup);

define_schema!(
    MacTestSchema,
    "MAC",
    "mac_test_schema.json",
    "mac_with_iv_test_schema.json"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum MacTestFlag {
    InvalidNonce,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacTestGroup {
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(rename = "tagSize")]
    pub tag_size: usize,
    #[serde(rename = "ivSize")]
    pub nonce_size: Option<usize>,
    #[serde(rename = "type")]
    typ: String, // todo enum/check
    pub tests: Vec<MacTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "opt_vec_from_hex", default, rename = "iv")]
    pub nonce: Option<Vec<u8>>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub tag: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<MacTestFlag>,
}

//*** HKDF ***

define_test_set!(HkdfTestSet, HkdfTestSchema, HkdfTestFlag, HkdfTestGroup);

define_schema!(HkdfTestSchema, "HKDF", "hkdf_test_schema.json");

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum HkdfTestFlag {
    EmptySalt,
    SizeTooLarge,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HkdfTestGroup {
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(rename = "type")]
    typ: String, // todo enum/check
    pub tests: Vec<HkdfTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HkdfTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub ikm: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub salt: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub info: Vec<u8>,
    pub size: usize,
    #[serde(deserialize_with = "vec_from_hex")]
    pub okm: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<HkdfTestFlag>,
}

//*** Primality ***

define_test_set!(
    PrimalityTestSet,
    PrimalityTestSchema,
    PrimalityTestFlag,
    PrimalityTestGroup
);

define_schema!(
    PrimalityTestSchema,
    "Primality",
    "primality_test_schema.json"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum PrimalityTestFlag {
    CarmichaelNumber,
    NegativeOfPrime,
    WorstCaseMillerRabin,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrimalityTestGroup {
    #[serde(rename = "type")]
    typ: String, // todo enum/check
    pub tests: Vec<PrimalityTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrimalityTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub value: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<PrimalityTestFlag>,
}

//*** Keywrap ***

define_test_set!(
    KeywrapTestSet,
    KeywrapTestSchema,
    KeywrapTestFlag,
    KeywrapTestGroup
);

define_schema!(KeywrapTestSchema, "Keywrap", "keywrap_test_schema.json");

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum KeywrapTestFlag {
    SmallKey,
    WeakWrapping,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeywrapTestGroup {
    #[serde(rename = "keySize")]
    pub key_size: usize,
    #[serde(rename = "type")]
    typ: String, // todo enum/check
    pub tests: Vec<KeywrapTest>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeywrapTest {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex")]
    pub key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub msg: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    pub ct: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<KeywrapTestFlag>,
}
