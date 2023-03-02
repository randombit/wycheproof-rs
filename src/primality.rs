//! Primality checking tests

use super::*;

define_test_set!("Primality", "primality_test_schema.json");

define_test_set_names!(
    Primality => "primality"
);

define_algorithm_map!("PrimalityTest" => Primality);

define_test_flags!(
    AndDub00,
    Arnault96,
    Bleichen05,
    BoundDeterministic,
    CarmichaelNumber,
    FermatTest,
    FixedMillerRabinBasis,
    GaMaPa19,
    Howe98,
    Jaeschke93,
    Mueller,
    NegativeOfPrime,
    Pinch06,
    Pinch93,
    Prime,
    SmallInteger,
    SmallNumberOfMillerRabinTests,
    SorWeb15,
    Stephan20,
);

define_typeid!(TestGroupTypeId => "PrimalityTest");

define_test_group!();

define_test!(value: Vec<u8>);
