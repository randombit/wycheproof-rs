//! MLDSA-Sign tests

use wycheproof_ng_core::*;

define_test_set!(
    "MLDSA Sign",
    "mldsa_sign_noseed_schema.json",
    "mldsa_sign_seed_schema.json"
);

define_test_set_names!(
    MlDsa44SignNoSeed => "mldsa_44_sign_noseed",
    MlDsa44SignSeed => "mldsa_44_sign_seed",
    MlDsa65SignNoSeed => "mldsa_65_sign_noseed",
    MlDsa65SignSeed => "mldsa_65_sign_seed",
    MlDsa87SignNoSeed => "mldsa_87_sign_noseed",
    MlDsa87SignSeed => "mldsa_87_sign_seed",
);

define_algorithm_map!(
    "ML-DSA-44" => MlDsa44,
    "ML-DSA-65" => MlDsa65,
    "ML-DSA-87" => MlDsa87,
);

define_test_flags!(
    BoundaryCondition,
    IncorrectPrivateKeyLength,
    IncorrectSignatureLength,
    Internal,
    InvalidContext,
    InvalidHintsEncoding,
    InvalidPrivateKey,
    ManySteps,
    MissingMessage,
    NoCofactor,
    SampleNttEdgeCase,
    ValidSignature,
    WrongSizedSeed,
);

define_test_group_type_id!(
    "MlDsaSign" => MlDsaSign,
);

define_test_group!(
    "privateKey" => privkey: Option<ByteString>,
    "privateKeyPkcs8" => privkey_pkcs8: Option<ByteString>,
    "privateSeed" => privseed: Option<ByteString>,
    "publicKey" => pubkey: Option<ByteString>,
);

define_test!(
    "msg" => msg: Option<ByteString>,
    mu: Option<ByteString>,
    sig: ByteString,
    ctx: Option<ByteString>,
);
