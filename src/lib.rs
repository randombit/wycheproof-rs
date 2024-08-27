//! # Wycheproof test vectors
//!
//! Wycheproof is a set of cryptographic tests created by a team at Google which
//! checks for common bugs and corner cases in cryptographic code.
//!
//! This crate is a convenient repacking of the Wycheproof JSON-formatted test
//! data with deserialization to easily usable structs.
//!
//! Hex and base64 encoded data is decoded to binary in the `BinaryString`
//! struct which is a light wrapper around `Vec<u8>`.
//!
//! Large integers (such as those used in the RSA test data) are decoded as
//! big-endian byte arrays into a `LargeInteger` struct, which is again a light
//! wrapper around `Vec<u8>`. Additionally if the `num-bigint` feature is enabled,
//! this type also gains a conversion function to `num_bigint::BigUint`.
//!
//! Each submodule of this crate includes a set of structs: a `TestName` which
//! specifies which individual test is desired, a `TestSet` which is the set of
//! data associated with the `TestName`. Each `TestSet` contains one or more
//! `TestGroups`, which in turn contain some amount of test-specific
//! configuration information along with a list of `Test` which are the actual
//! tests.
//!
//! Each test has an expected result which is either `Valid`, `Invalid`, or
//! `Acceptable`. `Acceptable` just means that the test is technically valid but
//! might still be rejected for various reasons, for instance because the hash
//! function that was used is too weak for proper security.
//!
//! # Examples
//!
//! ```
//! fn print_gcm() {
//!     // Print all AES-GCM test vector data
//!     let test_set = wycheproof::aead::TestSet::load(wycheproof::aead::TestName::AesGcm).unwrap();
//!
//!     for test_group in test_set.test_groups {
//!         println!(
//!             "* Group key size:{} tag size:{} nonce size:{}",
//!             test_group.key_size, test_group.tag_size, test_group.nonce_size,
//!         );
//!         for test in test_group.tests {
//!             println!(
//!                 "Test:{} Key:{} AAD:{} PT:{} CT:{} Tag:{}",
//!                 test.tc_id,
//!                 data_encoding::HEXLOWER.encode(&test.key),
//!                 data_encoding::HEXLOWER.encode(&test.aad),
//!                 data_encoding::HEXLOWER.encode(&test.pt),
//!                 data_encoding::HEXLOWER.encode(&test.ct),
//!                 data_encoding::HEXLOWER.encode(&test.tag)
//!             );
//!         }
//!     }
//! }
//! ```
//!
//! ```
//! // Iterate over all of the AEAD tests
//! for aead in wycheproof::aead::TestName::all() {
//!    println!("{:?}", aead);
//! }
//! ```

#![forbid(unsafe_code)]

use serde::{de::Error, Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt;

/// The error type
#[derive(Debug)]
pub enum WycheproofError {
    /// Named data set was not found
    NoDataSet,
    /// The JSON parsed but was found to be invalid somehow
    InvalidData,
    /// The JSON parsing failed
    ParsingFailed(Box<dyn std::error::Error>),
}

impl std::fmt::Display for WycheproofError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::NoDataSet => write!(f, "No data set matches provided name"),
            Self::InvalidData => write!(f, "Data set seems to be invalid"),
            Self::ParsingFailed(e) => write!(f, "Parsing JSON failed {}", e),
        }
    }
}

impl std::error::Error for WycheproofError {}

fn vec_from_hex<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s: &str = Deserialize::deserialize(deserializer)?;
    data_encoding::HEXLOWER
        .decode(s.as_bytes())
        .map_err(D::Error::custom)
}

fn combine_header<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let h: Vec<String> = Deserialize::deserialize(deserializer)?;
    let combined = h.join(" ");
    Ok(combined)
}

macro_rules! define_typeid {
    ( $name:ident => $( $tag:expr ),* ) => {
        #[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
        struct $name {}

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s: &str = Deserialize::deserialize(deserializer)?;

                match s {
                    $(
                        $tag => Ok(Self {}),
                    )*
                    unknown => Err(D::Error::custom(format!("unexpected type {} for {}", unknown, stringify!($name)))),
                }
            }
        }
    }
}

macro_rules! define_test_group_type_id {
    ( $( $json_str:expr => $enum_elem:ident ),* $(,)?) => {
        #[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
        #[allow(non_camel_case_types)]
        pub enum TestGroupTypeId {
            $(
                #[serde(rename = $json_str)]
                $enum_elem,
            )*
        }
    }
}

macro_rules! define_algorithm_map {
    ( $( $json_str:expr => $enum_elem:ident ),* $(,)?) => {
        #[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
        #[allow(non_camel_case_types)]
        pub enum Algorithm {
            $(
                #[serde(rename = $json_str)]
                $enum_elem,
            )*
        }
    }
}

macro_rules! define_test_set_names {
    ( $( $enum_name:ident => $test_name:expr ),* $(,)?) => {
        #[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
        #[allow(non_camel_case_types)]
        pub enum TestName {
            $(
                $enum_name,
            )*
        }

        impl TestName {
            #[inline(never)]
            pub fn json_data(&self) -> &'static str {
                match self {
                    $(
                        Self::$enum_name => include_str!(concat!("data/", $test_name, "_test.json")),
                    )*
                }
            }

            pub fn all() -> Vec<TestName> {
                vec![
                    $(
                        Self::$enum_name,
                    )*
                ]
            }
        }

        impl std::str::FromStr for TestName {
            type Err = WycheproofError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $(
                        $test_name => Ok(Self::$enum_name),
                    )*
                        _ => Err(WycheproofError::NoDataSet),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BugType {
    AuthBypass,
    Basic,
    BerEncoding,
    CanOfWorms,
    Confidentiality,
    Defined,
    EdgeCase,
    Functionality,
    KnownBug,
    Legacy,
    Malleability,
    MissingStep,
    ModifiedParameter,
    SignatureMalleability,
    Unknown,
    WeakParams,
    WrongPrimitive,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
pub struct CVE(pub String);

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
pub struct URL(pub String);

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestFlagInfo {
    #[serde(rename = "bugType")]
    pub bug_type: BugType,
    pub description: Option<String>,
    pub effect: Option<String>,
    pub cves: Option<Vec<CVE>>,
    pub links: Option<Vec<URL>>,
}

macro_rules! define_test_flags {
    ( $( $($json_name:literal =>)? $flag:ident ),* $(,)?) => {
        #[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
        pub enum TestFlag {
            $(
                $(#[serde(rename = $json_name)])?
                $flag,
            )*
        }
    }
}

macro_rules! define_test_group {
    ( $( $($json_name:literal =>)? $field_name:ident: $type:ty $(| $deser_fn:expr)? ),* $(,)?) => {
        #[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct TestGroup {
            $(
            $(#[serde(deserialize_with = $deser_fn)])?
            $(#[serde(rename = $json_name)])?
            pub $field_name: $type,
            )*
            #[serde(rename = "type")]
            pub test_type: TestGroupTypeId,
            pub tests: Vec<Test>,
        }
    }
}

macro_rules! define_test {
    ( $( $($json_name:literal =>)? $field_name:ident: $type:ty ),* $(,)?) => {
        #[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct Test {
            #[serde(rename = "tcId")]
            pub tc_id: usize,
            pub comment: String,
            $(
            $(#[serde(rename = $json_name)])?
            pub $field_name: $type,
            )*
            pub result: TestResult,
            #[serde(default)]
            pub flags: Vec<TestFlag>,
        }
    }
}

macro_rules! define_test_set {
    ( $schema_type:expr, $( $schema_name:expr ),* ) => {

        #[derive(Debug, Clone, Hash, Eq, PartialEq)]
        struct TestSchema {
            pub schema: String,
        }

        impl<'de> Deserialize<'de> for TestSchema {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s: &str = Deserialize::deserialize(deserializer)?;

                match s {
                    $(
                        $schema_name => Ok(Self { schema: s.to_string() }),
                    )*
                        unknown => Err(D::Error::custom(format!("unknown {} schema {}", $schema_type, unknown))),
                }
            }
        }

        #[doc = "A group of "]
        #[doc = $schema_type]
        #[doc = " tests."]
        #[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct TestSet {
            pub algorithm: Algorithm,
            #[serde(rename = "generatorVersion")]
            pub generator_version: String,
            #[serde(rename = "numberOfTests")]
            pub number_of_tests: usize,
            #[serde(deserialize_with = "combine_header")]
            pub header: String,
            pub notes: HashMap<TestFlag, TestFlagInfo>,
            schema: TestSchema,
            #[serde(rename = "testGroups")]
            pub test_groups: Vec<TestGroup>,
        }

        impl TestSet {
            fn check(obj: Self) -> Result<Self, WycheproofError> {
                let actual_number_of_tests: usize =
                    obj.test_groups.iter().map(|tg| tg.tests.len()).sum();
                if obj.number_of_tests != actual_number_of_tests {
                    return Err(WycheproofError::InvalidData);
                }
                Ok(obj)
            }

            pub fn load(test: TestName) -> Result<Self, WycheproofError> {
                match serde_json::from_str(test.json_data()) {
                    Ok(set) => Self::check(set),
                    Err(e) => Err(WycheproofError::ParsingFailed(Box::new(e))),
                }
            }
        }
    };
}

/// The expected result of a Wycheproof test
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestResult {
    /// The test is expected to pass
    #[serde(rename = "valid")]
    Valid,
    /// The test is expected to fail
    #[serde(rename = "invalid")]
    Invalid,
    /// The test is allowed to pass but may reasonably fail for policy reasons
    /// (eg for a valid signature when the hash function used is too weak)
    #[serde(rename = "acceptable")]
    Acceptable,
}

impl TestResult {
    /// Return true if this test *must* fail
    pub fn must_fail(&self) -> bool {
        match self {
            Self::Valid => false,
            Self::Acceptable => false,
            Self::Invalid => true,
        }
    }
}

/// Prime order elliptic curves
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum EllipticCurve {
    #[serde(rename = "secp160r1")]
    Secp160r1,
    #[serde(rename = "secp160r2")]
    Secp160r2,
    #[serde(rename = "secp160k1")]
    Secp160k1,
    #[serde(rename = "secp192r1")]
    Secp192r1,
    #[serde(rename = "secp192k1")]
    Secp192k1,
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

/// Hash Function identifiers
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

    #[serde(rename = "SHAKE128")]
    Shake128,

    #[serde(rename = "SHAKE256")]
    Shake256,
}

/// MGF identifiers
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum Mgf {
    #[serde(rename = "MGF1")]
    Mgf1,
    #[serde(rename = "SHAKE128")]
    Shake128,
    #[serde(rename = "SHAKE256")]
    Shake256,
}

/// Edwards curves
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum EdwardsCurve {
    #[serde(alias = "edwards25519")]
    Ed25519,
    #[serde(alias = "edwards448")]
    Ed448,
}

/// Montgomery curves
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum MontgomeryCurve {
    #[serde(alias = "curve25519")]
    X25519,
    #[serde(alias = "curve448")]
    X448,
}

#[derive(Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(transparent)]
pub struct ByteString {
    #[serde(deserialize_with = "vec_from_hex")]
    value: Vec<u8>,
}

impl ByteString {
    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl fmt::Debug for ByteString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", data_encoding::HEXLOWER.encode(&self.value))
    }
}

impl std::ops::Deref for ByteString {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl AsRef<[u8]> for ByteString {
    fn as_ref(&self) -> &[u8] {
        &self.value
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(transparent)]
pub struct LargeInteger {
    #[serde(deserialize_with = "vec_from_hex")]
    value: Vec<u8>,
}

impl std::ops::Deref for LargeInteger {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl AsRef<[u8]> for LargeInteger {
    fn as_ref(&self) -> &[u8] {
        &self.value
    }
}

impl LargeInteger {
    fn new(value: Vec<u8>) -> Self {
        Self { value }
    }

    #[cfg(feature = "num-bigint")]
    pub fn as_num_bigint(&self) -> num_bigint::BigUint {
        num_bigint::BigUint::from_bytes_be(&self.value)
    }
}

mod test_keys;
pub use test_keys::*;

pub mod aead;
pub mod cipher;
pub mod dsa;
pub mod ec_curve;
pub mod ecdh;
pub mod ecdsa;
pub mod eddsa;
pub mod fpe_list;
pub mod fpe_str;
pub mod hkdf;
pub mod keywrap;
pub mod mac;
pub mod mac_with_nonce;
pub mod primality;
pub mod rsa_oaep;
pub mod rsa_pkcs1_decrypt;
pub mod rsa_pkcs1_verify;
pub mod rsa_pss_verify;
pub mod xdh;
