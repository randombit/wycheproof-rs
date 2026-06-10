#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
work_dir="${repo_root}/target/minimal-imports"

families=(
  aead
  bls
  dh
  dsa
  ecdsa
  eddsa
  fpe
  kdf-jose
  mldsa
  mlkem
  rsa-encryption
  rsa-signature
  symmetric
)

rm -rf "${work_dir}"
mkdir -p "${work_dir}"

for family in "${families[@]}"; do
  package="wycheproof-ng-${family}"
  crate_ident="${package//-/_}"
  crate_dir="${repo_root}/crates/${family}"
  test_dir="${work_dir}/${package}"

  mkdir -p "${test_dir}/src"
  cat > "${test_dir}/Cargo.toml" <<EOF
[package]
name = "minimal-import-${package}"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
${package} = { path = "${crate_dir}" }

[workspace]
EOF

  cat > "${test_dir}/src/lib.rs" <<EOF
use ${crate_ident} as _;

pub fn smoke() {}
EOF

  cargo check --manifest-path "${test_dir}/Cargo.toml"
  cargo doc --manifest-path "${crate_dir}/Cargo.toml" --no-deps

  tree="$(cargo tree --manifest-path "${test_dir}/Cargo.toml" --prefix none)"
  while IFS= read -r dep; do
    [[ "${dep}" == "${package} "* ]] && continue
    [[ "${dep}" == "wycheproof-ng-core "* ]] && continue
    if [[ "${dep}" == wycheproof-ng-* ]]; then
      echo "${package} unexpectedly pulls ${dep}" >&2
      exit 1
    fi
  done <<< "${tree}"
done
