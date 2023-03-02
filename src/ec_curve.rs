//! Elliptic Curve Information

use super::*;

define_test_set!("EC Curve", "ec_curve_test_schema.json");

define_test_set_names!(
    EcCurveInfo => "ec_prime_order_curves"
);

define_test_flags!();

define_typeid!(TestGroupTypeId => "EcCurveTest");

define_algorithm_map!(
    "EcCurveTest" => EcCurve
);

define_test_group!();

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Test {
    #[serde(rename = "tcId")]
    pub tc_id: usize,
    pub name: String,
    pub oid: String,
    pub comment: Option<String>,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(deserialize_with = "vec_from_hex")]
    p: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    n: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    a: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    b: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    gx: Vec<u8>,
    #[serde(deserialize_with = "vec_from_hex")]
    gy: Vec<u8>,
    h: usize,
    #[serde(default)]
    pub flags: Vec<TestFlag>,
    pub result: TestResult,
}
