use super::*;

define_test_set!(
    "ECDH",
    "ecdh_test_schema.json",
    "ecdh_ecpoint_test_schema.json"
);

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
    EcdhMisc => "ecdh"
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    AddSubChain,
    #[allow(non_camel_case_types)]
    CVE_2017_10176,
    CompressedPoint,
    GroupIsomorphism,
    InvalidAsn,
    InvalidPublic,
    IsomorphicPublicKey,
    ModifiedPrime,
    UnnamedCurve,
    UnusedParam,
    WeakPublicKey,
    WrongOrder,
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum EcdhEncoding {
    #[serde(rename = "asn")]
    Asn1,
    #[serde(rename = "ecpoint")]
    EcPoint,
}

define_typeid!(TestGroupTypeId => "EcdhTest", "EcdhEcpointTest");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
    pub curve: EllipticCurve,
    pub encoding: EcdhEncoding,
    #[serde(rename = "type")]
    typ: TestGroupTypeId,
    pub tests: Vec<Test>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Test {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub comment: String,
    #[serde(deserialize_with = "vec_from_hex", rename = "public")]
    pub public_key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "private")]
    pub private_key: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex", rename = "shared")]
    pub shared_secret: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<TestFlag>,
}
