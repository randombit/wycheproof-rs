//! Message Authentication Code tests

use super::*;

define_test_set!("MAC with IV", "mac_with_iv_test_schema.json");

define_test_set_names!(
    Gmac => "aes_gmac",
    Vmac64 => "vmac_64",
    Vmac128 => "vmac_128",
);

define_algorithm_map!(
    "AES-GMAC" => AesGmac,
    "VMAC-AES" => VmacAes,
);

define_test_group_type_id!(
    "MacWithIvTest" => MacWithIv,
);

define_test_flags!(
    EdgeCase,
    InvalidNonce,
    "Ktv" => KnownTestVector,
    ModifiedTag,
    Pseudorandom,
    SpecialCaseTag,
    TagCollision,
);

define_test_group!(
    "keySize" => key_size: usize,
    "tagSize" => tag_size: usize,
    "ivSize" => nonce_size: usize,
);

define_test!(
    key: ByteString,
    "iv" => nonce: ByteString,
    msg: ByteString,
    tag: ByteString,
);
