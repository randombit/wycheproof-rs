//! Montgomery curve ECDH tests

use super::*;

define_test_set!(
    "xDH",
    "xdh_comp_schema_v1.json",
    "xdh_asn_comp_schema_v1.json",
    "xdh_jwk_comp_schema_v1.json",
    "xdh_pem_comp_schema_v1.json"
);

define_test_set_names!(
    X25519 => "x25519",
    X448 => "x448",
    X25519Asn => "x25519_asn",
    X448Asn => "x448_asn",
    X25519Jwk => "x25519_jwk",
    X448Jwk => "x448_jwk",
    X25519Pem => "x25519_pem",
    X448Pem => "x448_pem",
);

define_algorithm_map!("XDH" => Xdh);

define_test_flags!(
    EdgeCaseMultiplication,
    EdgeCasePrivateKey,
    EdgeCaseShared,
    InvalidPublic,
    "Ktv" => KnownTestVector,
    LowOrderPublic,
    MissingOctetString,
    NonCanonicalPublic,
    Normal,
    PublicKeyTooLong,
    SmallPublicKey,
    SpecialPublicKey,
    Twist,
    ZeroSharedSecret,
);

define_test_group_type_id!(
    "XdhComp" => KeyAgreement,
    "XdhAsnComp" => KeyAgreementAsn,
    "XdhJwkComp" => KeyAgreementJwk,
    "XdhPemComp" => KeyAgreementPem,
);

define_test_group!(curve: MontgomeryCurve);

define_test!(
    "public" => public_key: serde_json::Value,
    "private" => private_key: serde_json::Value,
    "shared" => shared_secret: ByteString,
);
