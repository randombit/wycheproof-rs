//! ML-KEM tests

use super::*;

define_test_set!(
    "ML-KEM",
    "mlkem_test_schema.json",
    "mlkem_encaps_test_schema.json",
    "mlkem_keygen_seed_test_schema.json",
    "mlkem_semi_expanded_decaps_test_schema.json"
);

define_test_set_names!(
    MlKem512 => "mlkem_512",
    MlKem512Encaps => "mlkem_512_encaps",
    MlKem512KeyGenSeed => "mlkem_512_keygen_seed",
    MlKem512SemiExpandedDecaps => "mlkem_512_semi_expanded_decaps",
    MlKem768 => "mlkem_768",
    MlKem768Encaps => "mlkem_768_encaps",
    MlKem768KeyGenSeed => "mlkem_768_keygen_seed",
    MlKem768SemiExpandedDecaps => "mlkem_768_semi_expanded_decaps",
    MlKem1024 => "mlkem_1024",
    MlKem1024Encaps => "mlkem_1024_encaps",
    MlKem1024KeyGenSeed => "mlkem_1024_keygen_seed",
    MlKem1024SemiExpandedDecaps => "mlkem_1024_semi_expanded_decaps",
);

define_algorithm_map!("ML-KEM" => MlKem);

define_test_flags!(
    IncorrectCiphertextLength,
    IncorrectDecapsulationKeyLength,
    InvalidDecapsulationKey,
    ModulusOverflow,
    Strcmp,
);

/// ML-KEM parameter sets
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
    "MLKEMTest" => MlKem,
    "MLKEMEncapsTest" => MlKemEncaps,
    "MLKEMKeyGen" => MlKemKeyGen,
    "MLKEMDecapsValidationTest" => MlKemDecapsValidation,
);

define_test_group!(
    "parameterSet" => parameter_set: MlKemParameterSet,
);

define_test!(
    seed: Option<ByteString>,
    "ek" => encaps_key: Option<ByteString>,
    "dk" => decaps_key: Option<ByteString>,
    "m" => msg: Option<ByteString>,
    "c" => ct: Option<ByteString>,
    "K" => shared_secret: Option<ByteString>,
);
