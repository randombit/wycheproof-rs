//! Message Authentication Code tests

use super::*;

define_test_set!("MAC", "mac_test_schema.json");

define_test_set_names!(
    AesCmac => "aes_cmac",
    AriaCmac => "aria_cmac",
    CamelliaCmac => "camellia_cmac",
    HmacSha1 => "hmac_sha1",
    HmacSha224 => "hmac_sha224",
    HmacSha256 => "hmac_sha256",
    HmacSha384 => "hmac_sha384",
    HmacSha3_224 => "hmac_sha3_224",
    HmacSha3_256 => "hmac_sha3_256",
    HmacSha3_384 => "hmac_sha3_384",
    HmacSha3_512 => "hmac_sha3_512",
    HmacSha512 => "hmac_sha512",
    HmacSha512_224 => "hmac_sha512_224",
    HmacSha512_256 => "hmac_sha512_256",
    HmacSm3 => "hmac_sm3",
    Kmac128 => "kmac128_no_customization",
    Kmac256 => "kmac256_no_customization",
    SipHash_1_3 => "siphash_1_3",
    SipHash_2_4 => "siphash_2_4",
    SipHash_4_8 => "siphash_4_8",
    SipHashx_2_4 => "siphashx_2_4",
    SipHashx_4_8 => "siphashx_4_8",
);

define_algorithm_map!(
    "AES-CMAC" => AesCmac,
    "ARIA-CMAC" => AriaCmac,
    "CAMELLIA-CMAC" => CamelliaCmac,
    "HMACSHA1" => HmacSha1,
    "HMACSHA224" => HmacSha224,
    "HMACSHA256" => HmacSha256,
    "HMACSHA3-224" => HmacSha3_224,
    "HMACSHA3-256" => HmacSha3_256,
    "HMACSHA3-384" => HmacSha3_384,
    "HMACSHA3-512" => HmacSha3_512,
    "HMACSHA384" => HmacSha384,
    "HMACSHA512" => HmacSha512,
    "HMACSHA512/224" => HmacSha512_224,
    "HMACSHA512/256" => HmacSha512_256,
    "HMACSM3" => HmacSm3,
    "KMAC128" => Kmac128,
    "KMAC256" => Kmac256,
    "SipHash-1-3" => Siphash_1_3,
    "SipHash-2-4" => Siphash_2_4,
    "SipHash-4-8" => Siphash_4_8,
    "SipHashX-2-4" => Siphashx_2_4,
    "SipHashX-4-8" => Siphashx_4_8,
);

define_test_group_type_id!(
    "MacTest" => Mac,
);

define_test_flags!(InvalidKeySize, ModifiedTag, Pseudorandom, TruncatedHmac,);

define_test_group!(
    "keySize" => key_size: usize,
    "tagSize" => tag_size: usize,
);

define_test!(key: ByteString, msg: ByteString, tag: ByteString,);
