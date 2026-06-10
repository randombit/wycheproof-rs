//! PBES2 tests

use super::*;

define_test_set!("PBES2", "pbe_test_schema.json");

define_test_set_names!(
    PbeWithHmacSha1AndAes128 => "pbes2_hmacsha1_aes_128",
    PbeWithHmacSha1AndAes192 => "pbes2_hmacsha1_aes_192",
    PbeWithHmacSha1AndAes256 => "pbes2_hmacsha1_aes_256",
    PbeWithHmacSha224AndAes128 => "pbes2_hmacsha224_aes_128",
    PbeWithHmacSha224AndAes192 => "pbes2_hmacsha224_aes_192",
    PbeWithHmacSha224AndAes256 => "pbes2_hmacsha224_aes_256",
    PbeWithHmacSha256AndAes128 => "pbes2_hmacsha256_aes_128",
    PbeWithHmacSha256AndAes192 => "pbes2_hmacsha256_aes_192",
    PbeWithHmacSha256AndAes256 => "pbes2_hmacsha256_aes_256",
    PbeWithHmacSha384AndAes128 => "pbes2_hmacsha384_aes_128",
    PbeWithHmacSha384AndAes192 => "pbes2_hmacsha384_aes_192",
    PbeWithHmacSha384AndAes256 => "pbes2_hmacsha384_aes_256",
    PbeWithHmacSha512AndAes128 => "pbes2_hmacsha512_aes_128",
    PbeWithHmacSha512AndAes192 => "pbes2_hmacsha512_aes_192",
    PbeWithHmacSha512AndAes256 => "pbes2_hmacsha512_aes_256",
);

define_algorithm_map!(
    "PbeWithHmacSha1AndAes_128" => PbeWithHmacSha1AndAes128,
    "PbeWithHmacSha1AndAes_192" => PbeWithHmacSha1AndAes192,
    "PbeWithHmacSha1AndAes_256" => PbeWithHmacSha1AndAes256,
    "PbeWithHmacSha224AndAes_128" => PbeWithHmacSha224AndAes128,
    "PbeWithHmacSha224AndAes_192" => PbeWithHmacSha224AndAes192,
    "PbeWithHmacSha224AndAes_256" => PbeWithHmacSha224AndAes256,
    "PbeWithHmacSha256AndAes_128" => PbeWithHmacSha256AndAes128,
    "PbeWithHmacSha256AndAes_192" => PbeWithHmacSha256AndAes192,
    "PbeWithHmacSha256AndAes_256" => PbeWithHmacSha256AndAes256,
    "PbeWithHmacSha384AndAes_128" => PbeWithHmacSha384AndAes128,
    "PbeWithHmacSha384AndAes_192" => PbeWithHmacSha384AndAes192,
    "PbeWithHmacSha384AndAes_256" => PbeWithHmacSha384AndAes256,
    "PbeWithHmacSha512AndAes_128" => PbeWithHmacSha512AndAes128,
    "PbeWithHmacSha512AndAes_192" => PbeWithHmacSha512AndAes192,
    "PbeWithHmacSha512AndAes_256" => PbeWithHmacSha512AndAes256,
);

define_test_flags!(Ascii, BmpString, NonUtf8, Printable, Utf8,);

define_test_group_type_id!(
    "PbeTest" => Pbe,
);

define_test_group!();

define_test!(
    password: ByteString,
    salt: ByteString,
    "iterationCount" => iteration_count: usize,
    iv: ByteString,
    msg: ByteString,
    ct: ByteString,
);
