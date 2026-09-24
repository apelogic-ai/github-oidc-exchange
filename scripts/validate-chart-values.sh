#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s VALUES_FILE\n' "$0" >&2
  exit 2
fi

values_file=$1
chart=charts/github-oidc-exchange
if [[ ! -f "$values_file" ]]; then
  printf 'values file not found: %s\n' "$values_file" >&2
  exit 2
fi

# Run chart-owned semantic checks first so sentinel failures explain the exact
# values path and recovery. The following strict lint remains authoritative for
# the complete published JSON schema.
helm template values-preflight "$chart" -f "$values_file" \
  --skip-schema-validation >/dev/null
helm lint "$chart" -f "$values_file" --strict
