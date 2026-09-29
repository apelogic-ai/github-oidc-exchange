#!/usr/bin/env bash
set -euo pipefail

destination="${1:?usage: stage-release-contract-assets.sh DESTINATION}"
[[ -d "$destination" ]] || {
  printf 'release contract destination is not a directory: %s\n' "$destination" >&2
  exit 1
}

assets=(
  docs/policy-contract.schema.json
  docs/policy-contract.example.json
  docs/policy-contract-v6.schema.json
  docs/policy-contract-v6.example.json
  docs/workload-policy-contract.example.json
)

for asset in "${assets[@]}"; do
  jq empty "$asset"
  cp "$asset" "$destination/${asset##*/}"
done
