use super::*;

define_test_set_names!(
    Primality => "primality"
);

define_test_set!("Primality", "primality_test_schema.json");

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Deserialize)]
pub enum TestFlag {
    CarmichaelNumber,
    NegativeOfPrime,
    WorstCaseMillerRabin,
}

define_typeid!(TestGroupTypeId => "PrimalityTest");

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestGroup {
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
    #[serde(deserialize_with = "vec_from_hex")]
    pub value: Vec<u8>,
    pub result: TestResult,
    pub flags: Vec<TestFlag>,
}
