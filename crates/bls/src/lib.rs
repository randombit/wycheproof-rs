//! BLS-12-381 tests

use wycheproof_ng_core::*;

define_test_set!(
    "BLS",
    "bls_sig_verify_schema.json",
    "bls_hash_to_g2_schema.json",
    "bls_aggregate_verify_schema.json"
);

define_test_set_names!(
    BlsSigG2BasicVerify => "bls_sig_g2_basic_verify",
    BlsSigG2PopVerify => "bls_sig_g2_pop_verify",
    BlsHashToG2 => "bls_hash_to_g2",
    BlsSigG2AggregateVerify => "bls_sig_g2_aggregate_verify",
);

define_algorithm_map!("BLS" => Bls);

define_test_flags!(
    EmptyAggregate,
    EmptyMessage,
    FieldBoundary,
    HashToG2,
    IdentityPoint,
    InvalidEncoding,
    InvalidFlags,
    InvalidSignature,
    LargeMessage,
    MinimalInput,
    MismatchedCount,
    NotInSubgroup,
    NotOnCurve,
    SignatureMalleability,
    TruncatedSignature,
    Valid,
    ValidAggregate,
    WrongDST,
    WrongKey,
    WrongMessage,
);

define_test_group_type_id!(
    "BlsSigVerify" => BlsSigVerify,
    "BlsHashToG2" => BlsHashToG2,
    "BlsAggregateVerify" => BlsAggregateVerify,
);

define_test_group!(
    "publicKey" => public_key: Option<serde_json::Value>,
    ciphersuite: Option<String>,
    dst: Option<String>,
);

define_test!(
    msg: Option<ByteString>,
    sig: Option<ByteString>,
    expected: Option<ByteString>,
    "pubkeys" => pubkeys: Option<Vec<ByteString>>,
    "messages" => messages: Option<Vec<ByteString>>,
);
