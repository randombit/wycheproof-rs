//! Elliptic Curve Information

use super::*;

define_test_set!("EC Curve", "ec_curve_test_schema.json");

define_test_set_names!(
    EcCurveInfo => "ec_prime_order_curves"
);

define_test_flags!();

define_test_group_type_id!(
    "EcCurveTest" => EcCurve,
);

define_algorithm_map!(
    "EcCurveTest" => EcCurve
);

define_test_group!();

define_test!(
    name: String,
    oid: String,
    "ref" => reference: String,
    p: LargeInteger,
    n: LargeInteger,
    a: LargeInteger,
    b: LargeInteger,
    gx: LargeInteger,
    gy: LargeInteger,
    h: usize,
);
