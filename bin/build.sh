#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
bridge_dir="${repo_root}/bridge"
output_dir="${repo_root}/build"
output_path="${output_dir}/localdraft-bridge"

mkdir -p "${output_dir}"

(
  cd "${bridge_dir}"
  CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w" \
    -o "${output_path}" \
    ./cmd/localdraft-bridge
)

printf 'Built LocalDraft Bridge: %s\n' "${output_path}"
