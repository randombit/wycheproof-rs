//! Password-Based Encryption Scheme 2 (PBES2) tests

use super::*;

define_test_set!("PBES2", "pbe_test_schema.json");

define_test_set_names!(
    Pbes2HmacSha1Aes128 => "pbes2_hmacsha1_aes_128",
    Pbes2HmacSha1Aes192 => "pbes2_hmacsha1_aes_192",
    Pbes2HmacSha1Aes256 => "pbes2_hmacsha1_aes_256",
    Pbes2HmacSha224Aes128 => "pbes2_hmacsha224_aes_128",
    Pbes2HmacSha224Aes192 => "pbes2_hmacsha224_aes_192",
    Pbes2HmacSha224Aes256 => "pbes2_hmacsha224_aes_256",
    Pbes2HmacSha256Aes128 => "pbes2_hmacsha256_aes_128",
    Pbes2HmacSha256Aes192 => "pbes2_hmacsha256_aes_192",
    Pbes2HmacSha256Aes256 => "pbes2_hmacsha256_aes_256",
    Pbes2HmacSha384Aes128 => "pbes2_hmacsha384_aes_128",
    Pbes2HmacSha384Aes192 => "pbes2_hmacsha384_aes_192",
    Pbes2HmacSha384Aes256 => "pbes2_hmacsha384_aes_256",
    Pbes2HmacSha512Aes128 => "pbes2_hmacsha512_aes_128",
    Pbes2HmacSha512Aes192 => "pbes2_hmacsha512_aes_192",
    Pbes2HmacSha512Aes256 => "pbes2_hmacsha512_aes_256",
);

define_algorithm_map!(
    "PbeWithHmacSha1AndAes_128" => Pbes2HmacSha1Aes128,
    "PbeWithHmacSha1AndAes_192" => Pbes2HmacSha1Aes192,
    "PbeWithHmacSha1AndAes_256" => Pbes2HmacSha1Aes256,
    "PbeWithHmacSha224AndAes_128" => Pbes2HmacSha224Aes128,
    "PbeWithHmacSha224AndAes_192" => Pbes2HmacSha224Aes192,
    "PbeWithHmacSha224AndAes_256" => Pbes2HmacSha224Aes256,
    "PbeWithHmacSha256AndAes_128" => Pbes2HmacSha256Aes128,
    "PbeWithHmacSha256AndAes_192" => Pbes2HmacSha256Aes192,
    "PbeWithHmacSha256AndAes_256" => Pbes2HmacSha256Aes256,
    "PbeWithHmacSha384AndAes_128" => Pbes2HmacSha384Aes128,
    "PbeWithHmacSha384AndAes_192" => Pbes2HmacSha384Aes192,
    "PbeWithHmacSha384AndAes_256" => Pbes2HmacSha384Aes256,
    "PbeWithHmacSha512AndAes_128" => Pbes2HmacSha512Aes128,
    "PbeWithHmacSha512AndAes_192" => Pbes2HmacSha512Aes192,
    "PbeWithHmacSha512AndAes_256" => Pbes2HmacSha512Aes256,
);

define_test_flags!(Ascii, BmpString, NonUtf8, Printable, Utf8,);

define_test_group_type_id!(
    "PbeTest" => PbeTest,
);

define_test_group!();

define_test!(
    "msg" => pt: ByteString,
    ct: ByteString,
    password: ByteString,
    salt: ByteString,
    "iv" => nonce: ByteString,
    "iterationCount" => iteration_count: usize,
);
