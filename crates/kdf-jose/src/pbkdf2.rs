//! PBKDF2 tests

use wycheproof_ng_core::*;

define_test_set!("PBKDF2", "pbkdf_test_schema.json");

define_test_set_names!(
    Pbkdf2HmacSha1 => "pbkdf2_hmacsha1",
    Pbkdf2HmacSha224 => "pbkdf2_hmacsha224",
    Pbkdf2HmacSha256 => "pbkdf2_hmacsha256",
    Pbkdf2HmacSha384 => "pbkdf2_hmacsha384",
    Pbkdf2HmacSha512 => "pbkdf2_hmacsha512",
);

define_algorithm_map!(
    "PBKDF2-HMACSHA1" => Pbkdf2HmacSha1,
    "PBKDF2-HMACSHA224" => Pbkdf2HmacSha224,
    "PBKDF2-HMACSHA256" => Pbkdf2HmacSha256,
    "PBKDF2-HMACSHA384" => Pbkdf2HmacSha384,
    "PBKDF2-HMACSHA512" => Pbkdf2HmacSha512,
);

define_test_flags!(
    Ascii,
    LargeIterationCount,
    NonUtf8,
    Printable,
    Pseudorandom,
    Rfc6070,
    Rfc7914,
    Utf8,
);

define_test_group_type_id!(
    "PbkdfTest" => PbkdfTest,
);

define_test_group!();

define_test!(
    password: ByteString,
    salt: ByteString,
    "iterationCount" => iteration_count: usize,
    "dkLen" => dk_len: usize,
    "dk" => dk: ByteString,
);
