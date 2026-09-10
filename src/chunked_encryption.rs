//! Chunked encryption tests
//!
//! These test vectors cover the C2SP chunked encryption construction
//! ("Cobblestone", see <https://c2sp.org/chunked-encryption>).
//!
//! Note that the `ct` field holds the ciphertext zlib-compressed and then
//! hex-encoded upstream; the [`ByteString`] decodes the hex layer, so it holds
//! the still-zlib-compressed ciphertext bytes.

use super::*;

define_test_set!("Chunked Encryption", "c2sp_chunked_encryption_schema.json");

define_test_set_names!(
    Cobblestone128 => "c2sp_chunked_encryption_aes_128_gcm",
    Cobblestone256 => "c2sp_chunked_encryption_aes_256_gcm",
);

define_algorithm_map!(
    "Cobblestone-128" => Cobblestone128,
    "Cobblestone-256" => Cobblestone256,
);

define_test_flags!(
    ChunkReordering,
    CounterRollover,
    HeaderFailure,
    InvalidKeySize,
    ModifiedCiphertext,
    PartialPlaintext,
    TrailingData,
    Truncation,
    ValidFinalChunk,
    WrongContext,
    WrongKey,
);

/// The underlying AEAD, identified by its IANA registry name
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
pub enum ChunkedEncryptionAead {
    #[serde(rename = "AEAD_AES_128_GCM")]
    Aes128Gcm,
    #[serde(rename = "AEAD_AES_256_GCM")]
    Aes256Gcm,
}

define_test_group_type_id!(
    "ChunkedEncryption" => ChunkedEncryption,
);

define_test_group!(
    aead: ChunkedEncryptionAead,
    "sha" => hash: HashFunction,
);

define_test!(
    key: ByteString,
    ctx: ByteString,
    ct: ByteString,
    "aeadKey" => aead_key: Option<ByteString>,
    "baseNonce" => base_nonce: Option<ByteString>,
    "msgLength" => msg_length: Option<usize>,
    "msgSha512" => msg_sha512: Option<ByteString>,
);
