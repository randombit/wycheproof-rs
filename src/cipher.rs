//! IND-CPA cipher tests

use super::*;

define_test_set!("Cipher", "ind_cpa_test_schema.json");

define_test_set_names!(
    AesCbcPkcs5 => "aes_cbc_pkcs5",
    AesXts => "aes_xts",
    AriaCbcPkcs5 => "aria_cbc_pkcs5",
    CamelliaCbcPkcs5 => "camellia_cbc_pkcs5",
);

define_algorithm_map!(
    "AES-CBC-PKCS5" => AesCbcPkcs5,
    "AES-XTS" => AesXts,
    "ARIA-CBC-PKCS5" => AriaCbcPkcs5,
    "CAMELLIA-CBC-PKCS5" => CamelliaCbcPkcs5,
);

define_test_flags!(BadPadding, NoPadding, Pseudorandom);

define_typeid!(TestGroupTypeId => "IndCpaTest");

define_test_group!(
    "ivSize" => nonce_size: usize,
    "keySize" => key_size: usize,
);

define_test!(
    iv: ByteString,
    key: ByteString,
    "msg" => pt: ByteString,
    ct: ByteString,
);
