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
  grep -Fq -- "$contract" "$workflow"
done

package_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
chart_version="$(sed -n 's/^version: //p' charts/github-oidc-exchange/Chart.yaml | head -1)"
chart_app_version="$(sed -n 's/^appVersion: "\([^"]*\)"/\1/p' charts/github-oidc-exchange/Chart.yaml | head -1)"
[[ -n "$package_version" ]]
[[ "$chart_version" == "$package_version" ]]
[[ "$chart_app_version" == "$package_version" ]]

if grep -Fq -- '--fulcio-auth-flow=device' "$workflow"; then
  printf 'device-flow authentication is forbidden\n' >&2
  exit 1
fi

candidate_line="$(grep -n 'Build and publish unique image candidate' "$workflow" | cut -d: -f1)"
promotion_line="$(grep -n 'Promote verified image candidate' "$workflow" | cut -d: -f1)"
release_line="$(grep -n 'gh release create' "$workflow" | cut -d: -f1)"
[[ "$candidate_line" -lt "$promotion_line" ]]
[[ "$promotion_line" -lt "$release_line" ]]
