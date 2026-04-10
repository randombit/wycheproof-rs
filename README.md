Wycheproof (Deserialized)
===========================

[![crates.io](https://img.shields.io/crates/v/wycheproof.svg)](https://crates.io/crates/wycheproof)
[![docs.rs](https://docs.rs/wycheproof/badge.svg)](https://docs.rs/wycheproof)

Google's [Wycheproof](https://github.com/C2SP/wycheproof) project is an
immensely useful set of tests which cover common corner cases in cryptographic
code.

The author is currently on their third job in a row where he had to write code
in Rust to deserialize the JSON formatted Wycheproof tests so they can be used
to test some code. This crate was born out of a desire to never ever have to do
this again. It also does all the nice things I wanted but didn't have the time
to do on previous attempts, like decoding the hex and base64 during
deserialization, using enums to aid type checking, verifying that schemas match
the expected one, etc.

The minimum supported Rust version (MSRV) of this crate is currently Rust 1.57.0.
If the MSRV increases in the future, this will be accompanied by an increment to
the minor version number.

Comments and patches are welcome.

This crate is licensed Apache 2.0-only, just as Wycheproof itself is.  The files
in `src/data` are taken from
[the latest Wycheproof commit](https://github.com/C2SP/wycheproof/commit/75ede73a39b8517b2a06c8115dfbcd364479796c)

By default all available tests are compiled in. If you only need to test a few
specific algorithms, you can do so with `no-default-features` plus one or more
feature flags

* `aead`
* `bls`
* `cipher`
* `daead`
* `dsa`
* `ec`
* `ecdh`
* `ecdsa`
* `eddsa`
* `fpe`
* `hkdf`
* `json_web`
* `keywrap`
* `mac`
* `mlkem`
* `pbes2`
* `pbkdf2`
* `primality`
* `rsa_enc`
* `rsa_sig`
* `rsa_sig_gen`
* `xdh`
* `mldsa-sign`
* `mldsa-verify`
