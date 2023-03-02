//! Format Preseverving Encryption

use super::*;

define_test_set!("FPE_str", "fpe_str_test_schema.json");

define_test_set_names!(
    AesFf1Base10 => "aes_ff1_base10",
    AesFf1Base16 => "aes_ff1_base16",
    AesFf1Base26 => "aes_ff1_base26",
    AesFf1Base32 => "aes_ff1_base32",
    AesFf1Base36 => "aes_ff1_base36",
    AesFf1Base45 => "aes_ff1_base45",
    AesFf1Base62 => "aes_ff1_base62",
    AesFf1Base64 => "aes_ff1_base64",
    AesFf1Base85 => "aes_ff1_base85",
);

define_algorithm_map!(
    "AES-FF1" => AesFf1
);

define_test_flags!(
    EdgeCasePrf,
    EdgeCaseState,
    InvalidKeySize,
    InvalidMessageSize,
    InvalidPlaintext,
    LargeMessageSize,
    NormalMessageSize,
    SmallMessageSize,
);

define_typeid!(TestGroupTypeId => "FpeStrTest");

define_test_group!(
    alphabet: String,
    "keySize" => key_size: usize,
    "msgSize" => msg_size: usize,
    radix: usize,
);

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Test {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    pub result: TestResult,
    #[serde(deserialize_with = "vec_from_hex")]
    key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    tweak: Vec<u8>,
    msg: String,
    ct: String,
    #[serde(default)]
    pub flags: Vec<TestFlag>,
}
