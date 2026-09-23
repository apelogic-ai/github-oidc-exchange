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
  'gh release create' 'aquasecurity/trivy-action@' 'anchore/sbom-action@' \
  'cosign attest' 'cosign sign-blob' 'release-manifest.sigstore.json' \
  '--notes-file "docs/releases/v$VERSION.md"' 'image_platforms:' \
  '[[ -s "docs/releases/v$VERSION.md" ]]' 'policy_contract:' \
  'identity_contract:' 'release_url:' 'workflow_run_url:' \
  'slsaprovenance1' 'spdxjson'; do
  grep -Fq -- "$expected" "$workflow"
done
