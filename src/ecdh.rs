//! ECDH key agreement tests

use super::*;

define_test_set!(
    "ECDH",
    "ecdh_test_schema_v1.json",
    "ecdh_ecpoint_test_schema_v1.json",
    "ecdh_pem_test_schema_v1.json",
    "ecdh_webcrypto_test_schema_v1.json"
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
    EcdhSecp224r1Pem => "ecdh_secp224r1_pem",
    EcdhSecp256r1Pem => "ecdh_secp256r1_pem",
    EcdhSecp384r1Pem => "ecdh_secp384r1_pem",
    EcdhSecp521r1Pem => "ecdh_secp521r1_pem",
    EcdhSecp256k1Webcrypto => "ecdh_secp256k1_webcrypto",
    EcdhSecp256r1Webcrypto => "ecdh_secp256r1_webcrypto",
    EcdhSecp384r1Webcrypto => "ecdh_secp384r1_webcrypto",
    EcdhSecp521r1Webcrypto => "ecdh_secp521r1_webcrypto",
    EcdhSect283k1 => "ecdh_sect283k1",
    EcdhSect283r1 => "ecdh_sect283r1",
    EcdhSect409k1 => "ecdh_sect409k1",
    EcdhSect409r1 => "ecdh_sect409r1",
    EcdhSect571k1 => "ecdh_sect571k1",
    EcdhSect571r1 => "ecdh_sect571r1",
);

define_test_flags!(
    AddSubChain,
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
    LowOrderPublic,
    "ModifiedCurveParameter" => ModifiedCurveParameter,
    ModifiedCofactor,
    ModifiedGenerator,
    ModifiedGroup,
    ModifiedPrime,
    ModifiedPublicPoint,
    NegativeCofactor,
    NoCofactor,
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
    #[serde(rename = "pem")]
    Pem,
    #[serde(rename = "webcrypto")]
    Webcrypto,
}

define_test_group_type_id!(
    "EcdhTest" => Ecdh,
    "EcdhEcpointTest" => EcdhEcpoint,
    "EcdhPemTest" => EcdhPem,
    "EcdhWebcryptoTest" => EcdhWebcrypto,
);

define_test_group!(curve: EllipticCurve, encoding: EcdhEncoding);

define_test!(
    "public" => public_key: serde_json::Value,
    "private" => private_key: serde_json::Value,
    "shared" => shared_secret: ByteString,
);
