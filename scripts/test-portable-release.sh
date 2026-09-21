#!/usr/bin/env bash
set -euo pipefail

workflow=.github/workflows/portable-release.yml
[[ -f "$workflow" ]]
if grep -Ei 'aws|ecr|secretsmanager|qemu|binfmt' "$workflow"; then
  printf 'portable release must not depend on AWS or emulated images\n' >&2
  exit 1
fi
for expected in 'workflow_dispatch:' 'packages: write' 'ubuntu-24.04-arm' \
  'linux/amd64' 'linux/arm64' 'scripts/smoke-release-container.sh' \
  'helm package' 'helm push' 'docker buildx imagetools create' \
  'gh release create'; do
  grep -Fq "$expected" "$workflow"
done
