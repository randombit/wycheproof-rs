//! ML-KEM tests

use wycheproof_ng_core::*;

define_test_set!(
    "ML-KEM",
    "mlkem_test_schema.json",
    "mlkem_encaps_test_schema.json",
    "mlkem_keygen_seed_test_schema.json",
    "mlkem_semi_expanded_decaps_test_schema.json"
);

define_test_set_names!(
    MlKem512 => "mlkem_512",
    MlKem768 => "mlkem_768",
    MlKem1024 => "mlkem_1024",
    MlKem512Encaps => "mlkem_512_encaps",
    MlKem768Encaps => "mlkem_768_encaps",
    MlKem1024Encaps => "mlkem_1024_encaps",
    MlKem512KeygenSeed => "mlkem_512_keygen_seed",
    MlKem768KeygenSeed => "mlkem_768_keygen_seed",
    MlKem1024KeygenSeed => "mlkem_1024_keygen_seed",
    MlKem512SemiExpandedDecaps => "mlkem_512_semi_expanded_decaps",
    MlKem768SemiExpandedDecaps => "mlkem_768_semi_expanded_decaps",
    MlKem1024SemiExpandedDecaps => "mlkem_1024_semi_expanded_decaps",
);

define_algorithm_map!(
    "ML-KEM" => MlKem,
);

define_test_flags!(
    DecapsulationFailure,
    IncorrectCiphertextLength,
    IncorrectDecapsulationKeyLength,
    InvalidCipherText,
    InvalidDecapsulationKey,
    ModulusOverflow,
    Strcmp,
);

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, serde_derive::Deserialize)]
pub enum MlKemParameterSet {
    #[serde(rename = "ML-KEM-512")]
    MlKem512,
    #[serde(rename = "ML-KEM-768")]
    MlKem768,
    #[serde(rename = "ML-KEM-1024")]
    MlKem1024,
}

define_test_group_type_id!(
    "MLKEMTest" => MlKemTest,
    "MLKEMEncapsTest" => MlKemEncapsTest,
    "MLKEMKeyGen" => MlKemKeygenSeedTest,
    "MLKEMDecapsValidationTest" => MlKemSemiExpandedDecapsTest,
);

define_test_group!(
    "parameterSet" => parameter_set: MlKemParameterSet,
);

define_test!(
    "K" => k: Option<ByteString>,
    "c" => ct: Option<ByteString>,
    "ek" => ek: Option<ByteString>,
    "dk" => dk: Option<ByteString>,
    seed: Option<ByteString>,
    "m" => m: Option<ByteString>,
);
