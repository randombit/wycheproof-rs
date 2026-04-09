//! RSA PKCS1v1.5 signature generation tests

use super::*;

define_test_set!("RSA PKCS1 sig gen", "rsassa_pkcs1_generate_schema_v1.json");

define_algorithm_map!("RSASSA-PKCS1-v1_5" => RsaPkcs1v15);

define_test_set_names!(
    RsaSigGen1024 => "rsa_pkcs1_1024_sig_gen",
    RsaSigGen1536 => "rsa_pkcs1_1536_sig_gen",
    RsaSigGen2048 => "rsa_pkcs1_2048_sig_gen",
    RsaSigGen3072 => "rsa_pkcs1_3072_sig_gen",
    RsaSigGen4096 => "rsa_pkcs1_4096_sig_gen",
);

define_test_flags!(
    BerEncodedPadding,
    SmallModulus,
    SmallPublicKey,
    ValidSignature,
    WeakHash,
);

define_test_group_type_id!(
    "RsassaPkcs1Generate" => RsaPkcs1SigGen,
);

define_test_group!(
    "keySize" => key_size: usize,
    "sha" => hash: HashFunction,
    "privateKey" => private_key: RsaPrivate,
    "privateKeyJwk" => private_key_jwk: Option<RsaPrivateJwk>,
    "privateKeyPem" => private_key_pem: String,
    "privateKeyPkcs8" => private_key_pkcs8: ByteString,
    "keyAsn" => key_asn: ByteString,
    "keyDer" => key_der: ByteString,
    "keyJwk" => key_jwk: Option<RsaPublicJwk>,
    "keyPem" => key_pem: String,
);

define_test!(msg: ByteString, sig: ByteString);
