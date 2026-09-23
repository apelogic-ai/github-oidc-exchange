#!/usr/bin/env bash
set -euo pipefail

version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
[[ -n "$version" ]]
lock_version="$(awk '
  /^name = "github-oidc-exchange"$/ { package = 1; next }
  package && /^version = "/ { gsub(/^version = "|"$/, ""); print; exit }
' Cargo.lock)"
[[ "$lock_version" == "$version" ]]
[[ "$(sed -n 's/^version: //p' charts/github-oidc-exchange/Chart.yaml | head -1)" == "$version" ]]
[[ "$(sed -n 's/^appVersion: "\([^"]*\)"/\1/p' charts/github-oidc-exchange/Chart.yaml | head -1)" == "$version" ]]
for document in README.md THIRD_PARTY_NOTICES.md docs/installation.md docs/quickstart.md \
  docs/integration.md docs/consumer-contract-v1.md charts/github-oidc-exchange/README.md \
  charts/github-oidc-exchange/examples/production-values.yaml \
  "docs/releases/v$version.md"; do
  grep -Fq "$version" "$document"
done
grep -Fq "## [$version]" CHANGELOG.md
grep -Fq '](docs/installation.md)' README.md
grep -Fq '](THIRD_PARTY_NOTICES.md)' README.md
grep -Fq '](docs/upgrade-v0.5.0.md)' README.md
grep -Fq '](../../docs/installation.md)' charts/github-oidc-exchange/README.md

policy_version="$(sed -n 's/^pub const POLICY_VERSION: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
[[ "$policy_version" == 'github-oidc-exchange.apelogic.io/v5' ]]
for policy_surface in docs/policy-contract.schema.json docs/policy-contract.example.json \
  scripts/smoke-release-container.sh docs/upgrade-v0.5.0.md "docs/releases/v$version.md"; do
  grep -Fq "$policy_version" "$policy_surface"
done
release_notes="docs/releases/v$version.md"
for expected in 'Service Envelope bootstrap identity' 'Normal governed-task behavior is unchanged' \
  'unsupported policy version' '0.4.0 application/chart plus v4 policy pair' \
  'release-manifest.json' 'native amd64 and arm64 container' 'SPDX SBOM' \
  'SLSA provenance' 'cosign verify-blob' 'cosign verify-attestation' \
  'ecr_image' 'ecr_chart' '/README.md)' '/CHANGELOG.md)' \
  '/docs/policy-contract.schema.json)' '/docs/policy-contract.example.json)' \
  '/docs/upgrade-v0.5.0.md)'; do
  grep -Fq "$expected" "$release_notes"
done
jq -e --arg version "$policy_version" '.properties.version.const == $version' \
  docs/policy-contract.schema.json >/dev/null
jq -e --arg version "$policy_version" '.version == $version' \
  docs/policy-contract.example.json >/dev/null

current_surfaces=(
  src
  README.md
  docs/installation.md
  docs/quickstart.md
  docs/integration.md
  docs/consumer-contract-v1.md
  docs/policy-contract.schema.json
  docs/policy-contract.example.json
  charts/github-oidc-exchange/README.md
  charts/github-oidc-exchange/examples/production-values.yaml
)
# Negative regression fixtures in tests/security.rs and the release-container
# smoke intentionally contain the retired v4 fields to prove rejection.
if grep -R -n -E \
  'bootstrap_group|service-envelope-bootstrap|workflow_refs|job_workflow_refs|IdentityProfile|BOOTSTRAP_PREFIX' \
  "${current_surfaces[@]}"; then
  printf 'current code, policy fixtures, and operator docs must not retain bootstrap-contract fields\n' >&2
  exit 1
fi

for name in github-oidc-exchange-keyring github-oidc-exchange-policy \
  github-oidc-exchange-workload-rsa-keyring github-oidc-exchange-workload-policy \
  github-oidc-exchange-server-tls; do
  grep -Fq "$name" docs/installation.md
  grep -Fq "$name" charts/github-oidc-exchange/values.example.yaml
done
for key in keyring.json policy.json rsa-keyring.json workload-policy.json tls.crt tls.key; do
  grep -Fq "$key" docs/installation.md
  grep -Fq "$key" charts/github-oidc-exchange/templates/deployment.yaml
done
for route in /.well-known/openid-configuration /jwks.json /v1/exchange /v1/workload/exchange; do
  grep -Fq "$route" docs/consumer-contract-v1.md
done
for expected in 'id-token: write' 'delivery test checklist' 'rollback identity PREVIOUS_REVISION' \
  'check-install-inputs.sh' 'generate-es256' 'generate-rsa' \
  'cert-manager' 'customer-PKI' 'TokenReview' 'GitHub OAuth App'; do
  grep -Fqi "$expected" docs/installation.md
done
grep -Fq 'resourceVersion' docs/installation.md
grep -Fq 'test-install-rotation.sh' docs/installation.md
grep -Fq 'steward-run/issues/43' docs/installation.md

for document in docs/installation.md docs/consumer-contract-v1.md; do
  grep -Fq 'customer reusable workflow requires both exchange inputs' "$document"
  grep -Fq '`identity-exchange-url` and `identity-exchange-audience`' "$document"
  grep -Fq 'direct-action fallback' "$document"
  grep -Fq 'not the customer handoff' "$document"
done
! grep -Fq 'binds its GitHub input audience to' docs/installation.md docs/consumer-contract-v1.md
