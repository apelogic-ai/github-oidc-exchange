#!/usr/bin/env bash
set -euo pipefail

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

bash scripts/stage-release-contract-assets.sh "$scratch"

assets=(
  policy-contract.schema.json
  policy-contract.example.json
  policy-contract-v6.schema.json
  policy-contract-v6.example.json
  workload-policy-contract.example.json
)

for asset in "${assets[@]}"; do
  cmp "docs/$asset" "$scratch/$asset"
  jq empty "$scratch/$asset"
done

staged=("$scratch"/*)
[[ "${#staged[@]}" == "${#assets[@]}" ]]
