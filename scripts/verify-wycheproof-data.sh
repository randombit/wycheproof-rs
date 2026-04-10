#!/usr/bin/env bash
set -euo pipefail

readonly UPSTREAM_REPO_URL="${UPSTREAM_REPO_URL:-https://github.com/C2SP/wycheproof}"
readonly UPSTREAM_REF="${UPSTREAM_REF:-75ede73a39b8517b2a06c8115dfbcd364479796c}"
readonly UPSTREAM_DATA_DIR="${UPSTREAM_DATA_DIR:-testvectors_v1}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
readonly LOCAL_DATA_DIR="${LOCAL_DATA_DIR:-${repo_root}/src/data}"

tmp_dir="$(mktemp -d)"
cleanup() {
    rm -rf "${tmp_dir}"
}
trap cleanup EXIT

archive="${tmp_dir}/wycheproof.tar.gz"
extract_dir="${tmp_dir}/extract"
mkdir -p "${extract_dir}"

curl -fsSL "${UPSTREAM_REPO_URL}/archive/${UPSTREAM_REF}.tar.gz" -o "${archive}"
tar -xzf "${archive}" -C "${extract_dir}"

upstream_root="$(find "${extract_dir}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
upstream_data_dir="${upstream_root}/${UPSTREAM_DATA_DIR}"

if [[ ! -d "${upstream_data_dir}" ]]; then
    echo "missing upstream data directory: ${UPSTREAM_DATA_DIR}" >&2
    exit 1
fi

if [[ ! -d "${LOCAL_DATA_DIR}" ]]; then
    echo "missing local data directory: ${LOCAL_DATA_DIR}" >&2
    exit 1
fi

local_files="${tmp_dir}/local-files.txt"
upstream_files="${tmp_dir}/upstream-files.txt"

find "${LOCAL_DATA_DIR}" -maxdepth 1 -type f -exec basename {} \; | LC_ALL=C sort > "${local_files}"
find "${upstream_data_dir}" -maxdepth 1 -type f -exec basename {} \; | LC_ALL=C sort > "${upstream_files}"

if ! diff -u "${upstream_files}" "${local_files}"; then
    echo "src/data file list does not match ${UPSTREAM_REPO_URL}@${UPSTREAM_REF}:${UPSTREAM_DATA_DIR}" >&2
    exit 1
fi

if ! diff -ru "${upstream_data_dir}" "${LOCAL_DATA_DIR}"; then
    echo "src/data file contents do not match ${UPSTREAM_REPO_URL}@${UPSTREAM_REF}:${UPSTREAM_DATA_DIR}" >&2
    exit 1
fi

file_count="$(wc -l < "${local_files}" | tr -d ' ')"
echo "src/data matches ${UPSTREAM_REPO_URL}@${UPSTREAM_REF}:${UPSTREAM_DATA_DIR} (${file_count} files)"
