//! NIST keywrapping tests

use super::*;

define_test_set!("Keywrap", "keywrap_test_schema.json");

define_test_set_names!(
    AesKeyWrap => "aes_wrap",
    AesKeyWrapWithPadding => "aes_kwp",
    AriaKeyWrap => "aria_wrap",
    AriaKeyWrapWithPadding => "aria_kwp",
    CamelliaKeyWrap => "camellia_wrap",
    SeedKeyWrap => "seed_wrap",
);

define_algorithm_map!(
    "AES-KWP" => AesKeyWrapWithPadding,
    "AES-WRAP" => AesKeyWrap,
    "ARIA-KWP" => AriaKeyWrapWithPadding,
    "ARIA-WRAP" => AriaKeyWrap,
    "CAMELLIA-WRAP" => CamelliaKeyWrap,
    "SEED-WRAP" => SeedKeyWrap,
);

define_test_flags!(
    CounterOverflow,
    EmptyKey,
    InvalidWrappingSize,
    ModifiedIv,
    ModifiedPadding,
    Normal,
    ShortKey,
    SmallKey,
    WrongDataSize,
);

define_test_group_type_id!(
    "KeywrapTest" => Keywrap
);

define_test_group!(
    "keySize" => key_size: usize,
);

define_test!(
    key: ByteString,
    "msg" => pt: ByteString,
    ct: ByteString
);
