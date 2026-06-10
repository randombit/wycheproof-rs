# Wycheproof NG

`wycheproof-ng-rs` is a maintained fork of Jack Lloyd's
[`wycheproof`](https://crates.io/crates/wycheproof) Rust crate. It deserializes
the C2SP Wycheproof JSON test vectors into typed Rust structures so
cryptographic implementations can consume the vectors without hand-written JSON
plumbing.

The fork starts from the `updates` branch of
[`randombit/wycheproof-rs`](https://github.com/randombit/wycheproof-rs), not
from the last published `wycheproof` crate. Its first releases track C2SP
Wycheproof v1 test vectors from commit
`75ede73a39b8517b2a06c8115dfbcd364479796c`.

This repository keeps the Apache-2.0 license. See [NOTICE.md](NOTICE.md) for
attribution to the original crate author and upstream vector source.

## Crates

The original crate used Cargo features to select algorithm families. This fork
publishes independent crates instead, so projects can import only the vector
families they need and avoid additive feature-resolution surprises.

| Crate | Contents |
|---|---|
| `wycheproof-ng-core` | Shared result types, decoded byte wrappers, errors, and deserialization helpers. |
| `wycheproof-ng-aead` | AEAD and DAEAD vectors. |
| `wycheproof-ng-symmetric` | Block cipher, key wrap, MAC, and MAC-with-nonce vectors. |
| `wycheproof-ng-fpe` | Format-preserving encryption vectors. |
| `wycheproof-ng-ecdsa` | ECDSA vectors. |
| `wycheproof-ng-dh` | ECDH, XDH, and EC curve vectors. |
| `wycheproof-ng-dsa` | DSA vectors. |
| `wycheproof-ng-eddsa` | Ed25519 and Ed448 vectors. |
| `wycheproof-ng-bls` | BLS vectors. |
| `wycheproof-ng-rsa-encryption` | RSA OAEP and PKCS#1 decryption vectors. |
| `wycheproof-ng-rsa-signature` | RSA PKCS#1 signature and RSA-PSS vectors. |
| `wycheproof-ng-mlkem` | ML-KEM vectors. |
| `wycheproof-ng-mldsa` | ML-DSA vectors. |
| `wycheproof-ng-kdf-jose` | HKDF, PBKDF2, PBES2, JSON Web, and primality vectors. |
| `wycheproof-ng` | Umbrella crate that re-exports every family crate. |

Use a family crate when dependency bulkheading matters:

```rust
use wycheproof_ng_ecdsa::{TestName, TestSet};

let set = TestSet::load(TestName::EcdsaSecp256r1Sha256)?;
```

Use the umbrella crate only when importing every family is acceptable:

```rust
let set = wycheproof_ng::ecdsa::TestSet::load(
    wycheproof_ng::ecdsa::TestName::EcdsaSecp256r1Sha256,
)?;
```

## Vector Provenance

The vector files are committed to the repository and included in each crate at
publish time. Builds do not fetch data from the network.

The repository records the pinned upstream source in
`scripts/wycheproof-source.env`, the crate assignment in
`scripts/wycheproof-data-manifest.tsv`, and the offline content hashes in
`scripts/wycheproof-data-sha256.tsv`.

Run the provenance checks with:

```bash
scripts/verify-wycheproof-data.sh
scripts/verify-wycheproof-data-offline.sh
```

The networked check compares local committed vectors against the pinned C2SP
Wycheproof commit. The offline check verifies the committed files against the
checked-in SHA-256 manifest.

## Minimum Supported Rust Version

The minimum supported Rust version for the forked crate family is Rust 1.85.0.
Any future MSRV increase should be accompanied by a minor version bump.

## Maintenance

The fork tracks C2SP Wycheproof updates quarterly, or sooner when
security-relevant vector changes land upstream. Every data refresh should be a
pull request that runs:

```bash
scripts/sync-wycheproof-data.sh
scripts/verify-minimal-imports.sh
scripts/verify-package-sizes.sh
scripts/publish-workspace.sh --dry-run
```

Each published crate should stay below an `8 MiB` compressed `.crate` budget. If
a family approaches that budget, split that family before publishing the next
upstream refresh.

## Releases

All crates are versioned together for the initial release train. The first
version is `0.1.0`.

The first crates.io release must be bootstrapped manually, or with a temporary
local token and:

```bash
scripts/publish-workspace.sh --publish
```

After the first release, configure crates.io trusted publishing for every crate:

- owner: `huitseeker`;
- repository: `huitseeker/wycheproof-ng-rs`;
- workflow: `release.yml`;
- environment: `crates-io`.

Subsequent releases should use the protected GitHub Actions release workflow.

## Migration

For the old all-in-one crate:

```toml
wycheproof = "0.6"
```

use the umbrella crate:

```toml
wycheproof-ng = "0.1"
```

For one vector family, depend directly on that family crate:

```toml
wycheproof-ng-ecdsa = "0.1"
```

This avoids additive feature resolution. Depending on ECDSA vectors will not
cause ML-KEM, RSA, or FPE vectors to be compiled.
