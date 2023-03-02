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
[the latest Wycheproof commit](https://github.com/google/wycheproof/commit/b063b4aedae951c69df014cd25fa6d69ae9e8cb9)
