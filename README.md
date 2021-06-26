Wycheproof (Deserialized)
===========================

[![crates.io](https://img.shields.io/crates/v/wycheproof.svg)](https://crates.io/crates/wycheproof)
[![docs.rs](https://docs.rs/wycheproof/badge.svg)](https://docs.rs/wycheproof)

Google's [Wycheproof](https://github.com/google/wycheproof) project is an
immensely useful set of tests which cover common corner cases in cryptographic
code.

The author is currently on their third job in a row where he had to write code
in Rust to deserialize the JSON formatted Wycheproof tests so they can be used
to test some code. This crate was born out of a desire to never ever have to do
this again. This crate is also a lot nicer than the previous iterations (mine
anyway) as this crate decodes the hex and base64 during deserialization, uses
enums for aiding type checking, covers the entire test suite, etc.

Wycheproof uses a general schema where "test sets" in turn contain "test groups"
and each group has a list of tests along with some amount of configuration
information specific to that group of tests. By calling
`FooTestSet::load("...")` you can request the named test set. For example to
iterate over the GCM tests and print the data

```
use hex::encode as hex_encode;

fn print_gcm() {
    let test_set = wycheproof::AeadTestSet::load("aes_gcm").unwrap();

    for test_group in test_set.test_groups {
        println!(
            "* Group key size:{} tag size:{} nonce size:{}",
            test_group.key_size, test_group.tag_size, test_group.nonce_size,
        );
        for test in test_group.tests {
            println!(
                "Test:{} Key:{} AAD:{} PT:{} CT:{} Tag:{}",
                test.tc_id,
                hex_encode(test.key),
                hex_encode(test.aad),
                hex_encode(test.pt),
                hex_encode(test.ct),
                hex_encode(test.tag)
            );
        }
    }
}
```

You get the idea.

Comments and patches are welcome. Since the intent of this crate is to be just a
deserializion of the Wycheproof tests, the possible scope for changes seems
limited.

One issue I'd like to fix is that discoverability of test sets is nil; you just
have to somehow know that say "ecdsa_secp224r1_sha3_512" is a valid name for a
test set. Also you have to just somehow know which TestSet type is associated
with that name, and this is not always obvious. Perhaps naming every test using
test-type specific enums is the correct approach.

Further macro magic to reduce code duplication would be nice as well.

This crate is licensed Apache 2.0-only, just as Wycheproof itself is.  The files
in `src/data` are taken from
[the latest Wycheproof commit](https://github.com/google/wycheproof/commit/2196000605e45d91097147c9c71f26b72af58003)
