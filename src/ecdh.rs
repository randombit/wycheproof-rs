//! ECDH key agreement tests

use super::*;

define_test_set!(
    "ECDH",
    "ecdh_test_schema.json",
    "ecdh_ecpoint_test_schema.json"
);

define_algorithm_map!("ECDH" => Ecdh);

define_test_set_names!(
    EcdhBrainpool224r1 => "ecdh_brainpoolP224r1",
    EcdhBrainpool256r1 => "ecdh_brainpoolP256r1",
    EcdhBrainpool320r1 => "ecdh_brainpoolP320r1",
    EcdhBrainpool384r1 => "ecdh_brainpoolP384r1",
    EcdhBrainpool512r1 => "ecdh_brainpoolP512r1",
    EcdhSecp224r1 => "ecdh_secp224r1",
    EcdhSecp256k1 => "ecdh_secp256k1",
    EcdhSecp256r1 => "ecdh_secp256r1",
    EcdhSecp384r1 => "ecdh_secp384r1",
    EcdhSecp521r1 => "ecdh_secp521r1",
    EcdhSecp224r1Ecpoint => "ecdh_secp224r1_ecpoint",
    EcdhSecp256r1Ecpoint => "ecdh_secp256r1_ecpoint",
    EcdhSecp384r1Ecpoint => "ecdh_secp384r1_ecpoint",
    EcdhSecp521r1Ecpoint => "ecdh_secp521r1_ecpoint",
);

define_test_flags!(
    AdditionChain,
    "CVE-2017-8932" => GolangScalarmulBug,
    "CVE_2017_10176" => JavaAdditionChainBug,
    CompressedPoint,
    CompressedPublic,
    EdgeCaseDoubling,
    EdgeCaseEphemeralKey,
    EdgeCaseSharedSecret,
    InvalidAsn,
    InvalidCompressedPublic,
    InvalidCurveAttack,
    InvalidEncoding,
    InvalidPublic,
    InvalidPem,
    IsomorphicPublicKey,
    GroupIsomorphism,
    LargeCofactor,
    "Modified curve parameter" => ModifiedCurveParameter,
    ModifiedCofactor,
    ModifiedGenerator,
    ModifiedGroup,
    ModifiedPrime,
    ModifiedPublicPoint,
    NegativeCofactor,
    Normal,
    UnnamedCurve,
    UnusedParam,
    WeakPublicKey,
    WrongCurve,
    WrongOrder,
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
pub enum EcdhEncoding {
    #[serde(rename = "asn")]
    Asn1,
    #[serde(rename = "ecpoint")]
    EcPoint,
}

define_test_group_type_id!(
    "EcdhTest" => Ecdh,
    "EcdhEcpointTest" => EcdhEcpoint,
);

define_test_group!(curve: EllipticCurve, encoding: EcdhEncoding);

define_test!(
    "public" => public_key: ByteString,
    "private" => private_key: ByteString,
    "shared" => shared_secret: ByteString,
);
