#!/usr/bin/env bash
set -euo pipefail

workflow=".github/workflows/release.yml"

required=(
  'workflow_dispatch:'
  'cosign-release: v3.1.2'
  '--registry-referrers-mode=oci-1-1'
  '--new-bundle-format=true'
  '--experimental-oci11=true'
  '--type spdxjson'
  '--type slsaprovenance1'
  'CANDIDATE_TAG=candidate-'
  'Promote verified image candidate'
  'gh release create "v$VERSION"'
)

for contract in "${required[@]}"; do
  rg --fixed-strings --quiet -- "$contract" "$workflow"
done

if rg --fixed-strings --quiet -- '--fulcio-auth-flow=device' "$workflow"; then
  printf 'device-flow authentication is forbidden\n' >&2
  exit 1
fi

candidate_line="$(rg --line-number 'Build and publish unique image candidate' "$workflow" | cut -d: -f1)"
promotion_line="$(rg --line-number 'Promote verified image candidate' "$workflow" | cut -d: -f1)"
release_line="$(rg --line-number 'gh release create' "$workflow" | cut -d: -f1)"
[[ "$candidate_line" -lt "$promotion_line" ]]
[[ "$promotion_line" -lt "$release_line" ]]
