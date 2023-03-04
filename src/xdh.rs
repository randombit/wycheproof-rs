//! Montgomery curve ECDH tests

use super::*;

define_test_set!("xDH", "xdh_comp_schema.json");

define_test_set_names!(
    X25519 => "x25519",
    X448 => "x448",
);

define_algorithm_map!("XDH" => Xdh);

define_test_flags!(
    EdgeCaseMultiplication,
    EdgeCasePrivateKey,
    EdgeCaseShared,
    Ktv,
    LowOrderPublic,
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
);

define_test_group!(curve: MontgomeryCurve);

define_test!(
    "public" => public_key: ByteString,
    "private" => private_key: ByteString,
    "shared" => shared_secret: ByteString,
);
