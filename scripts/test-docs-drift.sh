#!/usr/bin/env bash
set -euo pipefail

version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
[[ -n "$version" ]]
[[ "$(sed -n 's/^version: //p' charts/github-oidc-exchange/Chart.yaml | head -1)" == "$version" ]]
[[ "$(sed -n 's/^appVersion: "\([^"]*\)"/\1/p' charts/github-oidc-exchange/Chart.yaml | head -1)" == "$version" ]]
for document in README.md docs/installation.md docs/consumer-contract-v1.md charts/github-oidc-exchange/README.md; do
  grep -Fq "$version" "$document"
done
grep -Fq '](docs/installation.md)' README.md
grep -Fq '](THIRD_PARTY_NOTICES.md)' README.md
grep -Fq '](../../docs/installation.md)' charts/github-oidc-exchange/README.md

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
