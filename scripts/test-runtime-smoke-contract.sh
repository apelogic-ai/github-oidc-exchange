#!/usr/bin/env bash
set -euo pipefail

if ((BASH_VERSINFO[0] < 5)); then
  printf 'test-runtime-smoke-contract.sh requires Bash 5 or newer (found %s)\n' \
    "$BASH_VERSION" >&2
  exit 2
fi

fixture_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir"' EXIT

cp .github/workflows/release.yml "$fixture_dir/release.yml"
sed -i.bak \
  's/name: Publish signed version tags/name: Publish immutable version aliases/' \
  "$fixture_dir/release.yml"

if output="$(RELEASE_WORKFLOW="$fixture_dir/release.yml" \
  bash scripts/validate-runtime-smoke.sh 2>&1)"; then
  printf 'runtime smoke validator accepted a missing workflow anchor\n' >&2
  exit 1
fi

grep -Fq "anchor 'name: Publish signed version tags' not found" <<<"$output"
