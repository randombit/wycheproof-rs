//! Format Preseverving Encryption

use super::*;

define_test_set!("FPE_list", "fpe_list_test_schema.json");

define_test_set_names!(
    AesFf1Radix10 => "aes_ff1_radix10",
    AesFf1Radix16 => "aes_ff1_radix16",
    AesFf1Radix255 => "aes_ff1_radix255",
    AesFf1Radix256 => "aes_ff1_radix256",
    AesFf1Radix26 => "aes_ff1_radix26",
    AesFf1Radix32 => "aes_ff1_radix32",
    AesFf1Radix36 => "aes_ff1_radix36",
    AesFf1Radix45 => "aes_ff1_radix45",
    AesFf1Radix62 => "aes_ff1_radix62",
    AesFf1Radix64 => "aes_ff1_radix64",
    AesFf1Radix65535 => "aes_ff1_radix65535",
    AesFf1Radix65536 => "aes_ff1_radix65536",
    AesFf1Radix85 => "aes_ff1_radix85",
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

define_test_group_type_id!(
    "FpeListTest" => FpeList,
);

define_test_group!(
    "keySize" => key_size: usize,
    "msgSize" => msg_size: usize,
    radix: usize,
);

define_test!(
    key: ByteString,
    tweak: ByteString,
    "msg" => pt: Vec<isize>,
    ct: Vec<usize>,
);
