#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
bridge_path="${repo_root}/build/localdraft-bridge"

if [[ ! -x "${bridge_path}" ]]; then
  "${script_dir}/build.sh"
fi

exec "${bridge_path}" serve "$@" --web-root "${repo_root}"
