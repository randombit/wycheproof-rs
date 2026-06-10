#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

source "${script_dir}/wycheproof-source.env"

readonly upstream_repo_url="${UPSTREAM_REPO_URL}"
readonly upstream_ref="${UPSTREAM_REF}"
readonly upstream_data_dir="${UPSTREAM_DATA_DIR}"
readonly manifest="${script_dir}/wycheproof-data-manifest.tsv"
readonly hashes="${script_dir}/wycheproof-data-sha256.tsv"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

cd "${repo_root}"

if [[ -n "${WYCHEPROOF_CHECKOUT:-}" ]]; then
  upstream_root="${WYCHEPROOF_CHECKOUT}"
else
  archive="${tmp_dir}/wycheproof.tar.gz"
  extract_dir="${tmp_dir}/extract"
  mkdir -p "${extract_dir}"
  curl -fsSL --retry 3 --connect-timeout 15 --max-time 180 \
    "${upstream_repo_url}/archive/${upstream_ref}.tar.gz" \
    -o "${archive}"
  tar -xzf "${archive}" -C "${extract_dir}"
  upstream_root="$(find "${extract_dir}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
fi

upstream_vectors="${upstream_root}/${upstream_data_dir}"
if [[ ! -d "${upstream_vectors}" ]]; then
  echo "missing upstream data directory: ${upstream_vectors}" >&2
  exit 1
fi

manifest_files="${tmp_dir}/manifest-files.txt"
upstream_files="${tmp_dir}/upstream-files.txt"

awk -F '\t' 'NF == 2 && $1 !~ /^#/ { print $1 }' "${manifest}" | LC_ALL=C sort > "${manifest_files}"
find "${upstream_vectors}" -maxdepth 1 -type f -name '*.json' -exec basename {} \; | LC_ALL=C sort > "${upstream_files}"

if ! diff -u "${upstream_files}" "${manifest_files}"; then
  echo "manifest does not exactly cover ${upstream_repo_url}@${upstream_ref}:${upstream_data_dir}" >&2
  exit 1
fi

while IFS=$'\t' read -r file_name local_dir; do
  [[ -z "${file_name}" || "${file_name}" == \#* ]] && continue
  mkdir -p "${local_dir}"
  cp "${upstream_vectors}/${file_name}" "${local_dir}/${file_name}"
done < "${manifest}"

if command -v sha256sum >/dev/null 2>&1; then
  find crates -path '*/src/data/*.json' -type f | LC_ALL=C sort | xargs sha256sum | awk '{print $1 "\t" $2}' > "${hashes}"
else
  find crates -path '*/src/data/*.json' -type f | LC_ALL=C sort | xargs shasum -a 256 | awk '{print $1 "\t" $2}' > "${hashes}"
fi

scripts/verify-wycheproof-data.sh
scripts/verify-wycheproof-data-offline.sh
cargo test --workspace
