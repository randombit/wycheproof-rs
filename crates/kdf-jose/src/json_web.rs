//! JSON Web tests (JWS, JWE, JWK, JWCrypto)

use wycheproof_ng_core::*;

define_test_set!(
    "JSON Web",
    "json_web_crypto_schema_v1.json",
    "json_web_encryption_schema_v1.json",
    "json_web_key_schema_v1.json",
    "json_web_signature_schema_v1.json"
);

define_test_set_names!(
    JsonWebCrypto => "json_web_crypto",
    JsonWebEncryption => "json_web_encryption",
    JsonWebKey => "json_web_key",
    JsonWebSignature => "json_web_signature",
);

define_algorithm_map!();

define_test_flags!(
    AlgIsNone,
    Ambiguous,
    CompressedPlaintext,
    DuplicateKid,
    JsonSerialization,
    JsonWebKeyset,
    MixedKeySet,
    ModifiedPadding,
    ModifiedPkcs15Padding,
    ModifiedSignature,
    Normal,
    Pkcs15WithOaepKey,
    Pkcs5Padding,
    WrongCipher,
    WrongPrimitive,
);

define_test_group_type_id!(
    "JsonWebCrypto" => JsonWebCrypto,
    "JsonWebEncryption" => JsonWebEncryption,
    "JsonWebKey" => JsonWebKey,
    "JsonWebSignature" => JsonWebSignature,
);

define_test_group!(
    "comment" => group_comment: String,
    "private" => private_key: Option<serde_json::Value>,
    "public" => public_key: Option<serde_json::Value>,
);

define_test!(
    jws: Option<serde_json::Value>,
    jwe: Option<serde_json::Value>,
    "pt" => pt: Option<String>,
    "enc" => enc: Option<String>,
);
