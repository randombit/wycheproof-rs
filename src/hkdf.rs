//! HKDF tests

use super::*;

define_test_set!("HKDF", "hkdf_test_schema.json");

define_test_set_names!(
    HkdfSha1 => "hkdf_sha1",
    HkdfSha256 => "hkdf_sha256",
    HkdfSha384 => "hkdf_sha384",
    HkdfSha512 => "hkdf_sha512",
);

define_algorithm_map!(
    "HKDF-SHA-1" => HkdfSha1,
    "HKDF-SHA-256" => HkdfSha256,
    "HKDF-SHA-384" => HkdfSha384,
    "HKDF-SHA-512" => HkdfSha512,
);

define_test_flags!(
    EmptySalt,
    MaximalOutputSize,
    Normal,
    OutputCollision,
    SizeTooLarge,
);

define_test_group_type_id!(
    "HkdfTest" => KDF,
);

define_test_group!(
    "keySize" => key_size: usize,
);

define_test!(
    ikm: ByteString,
    salt: ByteString,
    info: ByteString,
    size: usize,
    okm: ByteString,
);
