//! MLDSA-Verify tests

use super::*;

define_test_set!("MLDSA Verify", "mldsa_verify_schema.json");

define_test_set_names!(
    MlDsa44Verify => "mldsa_44_verify",
    MlDsa65Verify => "mldsa_65_verify",
    MlDsa87Verify => "mldsa_87_verify",
);

define_algorithm_map!(
    "ML-DSA-44" => MlDsa44,
    "ML-DSA-65" => MlDsa65,
    "ML-DSA-87" => MlDsa87,
);

define_test_flags!(
    BoundaryCondition,
    IncorrectPublicKeyLength,
    IncorrectSignatureLength,
    InvalidHintsEncoding,
    InvalidPrivateKey,
    InvalidContext,
    ManySteps,
    ModifiedSignature,
    ValidSignature,
    ZeroPublicKey,
);

define_test_group_type_id!(
    "MlDsaVerify" => MlDsaVerify,
);

define_test_group!(
    "publicKey" => pubkey: ByteString,
);

define_test!(msg: ByteString, sig: ByteString, ctx: Option<ByteString>);
