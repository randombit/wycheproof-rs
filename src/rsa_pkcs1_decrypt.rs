//! RSA PKCS1v1.5 decryption tests

use super::*;

define_test_set!("RSA PKCS1 decrypt", "rsaes_pkcs1_decrypt_schema.json");

define_algorithm_map!("RSAES-PKCS1-v1_5" => RsaPkcs1v15Encryption);

define_test_set_names!(
    Rsa2048 => "rsa_pkcs1_2048",
    Rsa3072 => "rsa_pkcs1_3072",
    Rsa4096 => "rsa_pkcs1_4096"
);

define_test_flags!(
    "CVE 2020-14967" => LeadingZerosOnCiphertext,
    "CVE 2021-3580" => CiphertextTooLarge,
    InvalidCiphertextFormat,
    InvalidPkcs1Padding,
    Normal,
    SpecialCase,
    SpecialCasePadding,
    Sslv23Padding,
);

define_test_group_type_id!(
    "RsaesPkcs1Decrypt" => RsaPkcs1Decrypt,
);

define_test_group!(
    "privateKey" => key: RsaPrivate,
    "keySize" => key_size: usize,
    "privateKeyJwk" => jwk: Option<RsaPrivateJwk>,
    "privateKeyPkcs8" => pkcs8: ByteString,
    "privateKeyPem" => pem: String,
);

define_test!("msg" => pt: ByteString, ct: ByteString);
