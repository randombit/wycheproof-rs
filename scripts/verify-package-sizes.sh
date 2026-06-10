#!/usr/bin/env bash
set -euo pipefail

readonly LIMIT_BYTES="${LIMIT_BYTES:-8388608}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

packages=(
  wycheproof-ng-core
  wycheproof-ng-aead
  wycheproof-ng-bls
  wycheproof-ng-dh
  wycheproof-ng-dsa
  wycheproof-ng-ecdsa
  wycheproof-ng-eddsa
  wycheproof-ng-fpe
  wycheproof-ng-kdf-jose
  wycheproof-ng-mldsa
  wycheproof-ng-mlkem
  wycheproof-ng-rsa-encryption
  wycheproof-ng-rsa-signature
  wycheproof-ng-symmetric
  wycheproof-ng
)

cd "${repo_root}"

for package in "${packages[@]}"; do
  rm -f "target/package/${package}-"*.crate
done

cargo package --workspace --exclude xtask --allow-dirty --no-verify >/dev/null

failed=0
sizes_file="$(mktemp)"
cleanup() {
  rm -f "${sizes_file}"
}
trap cleanup EXIT

for package in "${packages[@]}"; do
  version="$(cargo pkgid -p "${package}" | sed 's/.*@//')"
  crate_file="target/package/${package}-${version}.crate"
  if [[ -z "${crate_file}" ]]; then
    echo "missing packaged crate for ${package}" >&2
    failed=1
    continue
  fi
  if [[ ! -f "${crate_file}" ]]; then
    echo "missing packaged crate for ${package}: ${crate_file}" >&2
    failed=1
    continue
  fi

  size="$(wc -c < "${crate_file}" | tr -d ' ')"
  printf '%s\t%s\n' "${package}" "${size}" >> "${sizes_file}"
  if (( size > LIMIT_BYTES )); then
    echo "${package} exceeds ${LIMIT_BYTES} byte package budget" >&2
    failed=1
  fi
done

{
  printf '%-34s %10s\n' "package" "bytes"
  LC_ALL=C sort -t $'\t' -k2,2n "${sizes_file}" | while IFS=$'\t' read -r package size; do
    printf '%-34s %10d\n' "${package}" "${size}"
  done
} | tee "${sizes_file}.table"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Package sizes"
    echo
    echo "| Package | Bytes |"
    echo "|---|---:|"
    LC_ALL=C sort -t $'\t' -k2,2n "${sizes_file}" | while IFS=$'\t' read -r package size; do
      echo "| \`${package}\` | ${size} |"
    done
  } >> "${GITHUB_STEP_SUMMARY}"
fi

exit "${failed}"
