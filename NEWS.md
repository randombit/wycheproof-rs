## 0.5.1 Not Yet Released

* Update base64 dependency from 0.13 to 0.21

## 0.5.0 2023-03-04

* Update the Wycheproof test data to the new set released on
  2023-02-27. This set removes the daead and pkcs1_sign tests.
* Several small structure changes which reflect changes in the
  Wycheproof data.
* Various types within the tests that were Vec<u8> are now
  wrapped in LargeInteger or ByteString types
* Add num-bigint feature for converting LargeInteger into
  a num_bigint::BigUint
* Previously no MSRV was set for this crate. It is now 1.57.0
* Use 2021 Edition

## 0.4.0 2021-07-11

* Split the `mac` tests into `mac` and `mac_with_iv` to better
  match the Wycheproof schema.
* Some macro helper improvements

## 0.3.0 2021-07-04

* `TestSet::algorithm` is now an enumeration
* `TestSet::header` is now a `String` instead of a `Vec<String>`
* Add many macros to reduce code duplication

## 0.2.0 2021-07-01

* Add `TestName` enums to allow better typechecking
* Split up into several modules; now everything is of the form
  `wycheproof::foo::{TestName, TestSet, TestGroup, Test, TestFlag}`
* Some data was inadvertantly not `pub`

## 0.1.0 2021-06-26

* First release

