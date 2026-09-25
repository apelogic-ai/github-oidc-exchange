#!/usr/bin/env bash
set -euo pipefail

version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
lock_version="$(awk '
  /^name = "github-oidc-exchange"$/ { package = 1; next }
  package && /^version = "/ { gsub(/^version = "|"$/, ""); print; exit }
' Cargo.lock)"
chart_version="$(sed -n 's/^version: //p' charts/github-oidc-exchange/Chart.yaml | head -1)"
app_version="$(sed -n 's/^appVersion: "\([^"]*\)"/\1/p' charts/github-oidc-exchange/Chart.yaml | head -1)"
[[ "$version" == "0.6.0" ]]
[[ "$lock_version" == "$version" ]]
[[ "$chart_version" == "$version" ]]
[[ "$app_version" == "$version" ]]

current_docs=(
  README.md
  THIRD_PARTY_NOTICES.md
  docs/installation.md
  docs/quickstart.md
  docs/integration.md
  docs/consumer-contract-v1.md
  docs/upgrade-v0.6.0.md
  docs/source-authentication-documentation-inventory.md
  docs/releases/v0.6.0.md
  charts/github-oidc-exchange/README.md
  charts/github-oidc-exchange/examples/production-values.yaml
)
for document in "${current_docs[@]}"; do
  grep -Fq "$version" "$document"
done
grep -Fq "## [$version]" CHANGELOG.md

v5_policy="$(sed -n 's/^pub const POLICY_VERSION: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
v6_policy="$(sed -n 's/^pub const SOURCE_AUTH_POLICY_VERSION: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
v2_identity="$(sed -n 's/^pub const IDENTITY_CONTRACT: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
v3_identity="$(sed -n 's/^pub const SOURCE_AUTH_IDENTITY_CONTRACT: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
[[ "$v5_policy" == 'github-oidc-exchange.apelogic.io/v5' ]]
[[ "$v6_policy" == 'github-oidc-exchange.apelogic.io/v6' ]]
[[ "$v2_identity" == 'steward-task-v2' ]]
[[ "$v3_identity" == 'steward-task-v3' ]]

jq -e --arg version "$v5_policy" '.properties.version.const == $version' \
  docs/policy-contract.schema.json >/dev/null
jq -e --arg version "$v5_policy" '.version == $version' \
  docs/policy-contract.example.json >/dev/null
jq -e --arg version "$v6_policy" '.properties.version.const == $version' \
  docs/policy-contract-v6.schema.json >/dev/null
jq -e --arg version "$v6_policy" '.version == $version' \
  docs/policy-contract-v6.example.json >/dev/null

# v5 remains strict; v6 requires only the repository boundary and represents
# actor compatibility dependencies in the schema.
jq -e '
  (.required | index("actors")) and
  (.properties.repositories.items["$ref"] == "#/$defs/repository") and
  (."$defs".repository.required | index("subjects")) and
  (."$defs".repository.required | index("events")) and
  (."$defs".repository.required | index("refs"))
' docs/policy-contract.schema.json >/dev/null
jq -e '
  .required == ["version", "service_group", "repositories"] and
  .properties.repositories.items.required == ["owner_id", "repository_id"] and
  (.properties.repositories.items.required | index("subjects") | not) and
  (.properties.repositories.items.required | index("events") | not) and
  (.properties.repositories.items.required | index("refs") | not) and
  (.allOf | length > 0)
' docs/policy-contract-v6.schema.json >/dev/null

for document in README.md docs/installation.md docs/integration.md \
  docs/consumer-contract-v1.md docs/upgrade-v0.6.0.md \
  docs/releases/v0.6.0.md charts/github-oidc-exchange/README.md; do
  grep -Fq "$v5_policy" "$document"
  grep -Fq "$v6_policy" "$document"
  grep -Fq "$v2_identity" "$document"
  grep -Fq "$v3_identity" "$document"
done

for expected in \
  'github_oidc_exchange_endpoint' \
  'github_oidc_audience' \
  'identity_contracts_supported' \
  'policy_versions_supported'; do
  grep -Fq "$expected" src/http.rs
  grep -Fq "$expected" docs/consumer-contract-v1.md
done

for phrase in \
  'chart defaults to v5' \
  'separately named' \
  'atomic rollback' \
  'Identity does not decide' \
  'Steward performs any user binding' \
  'Task authority'; do
  grep -Fqi "$phrase" README.md docs/installation.md docs/integration.md \
    docs/consumer-contract-v1.md docs/upgrade-v0.6.0.md
done

grep -Fq 'policyContract: github-oidc-exchange.apelogic.io/v5' \
  charts/github-oidc-exchange/values.yaml
grep -Fq 'policyContract: github-oidc-exchange.apelogic.io/v5' \
  charts/github-oidc-exchange/values.example.yaml
grep -Fq 'name: EXPECTED_POLICY_VERSION' \
  charts/github-oidc-exchange/templates/deployment.yaml
grep -Fq 'github-oidc-exchange-policy` (v5)' docs/upgrade-v0.6.0.md
grep -Fq 'github-oidc-exchange-policy-v6' docs/upgrade-v0.6.0.md

release_notes="docs/releases/v$version.md"
for expected in \
  'continues to issue the unchanged' \
  'Explicit values plus separate policy object' \
  'supported_policy_contracts' \
  'supported_identity_contracts' \
  'github_oidc_audience' \
  'manifest-preserving mirror' \
  'release-manifest.json' \
  'native amd64 and arm64 container' \
  'SPDX SBOM' \
  'SLSA provenance' \
  'cosign verify-blob' \
  'cosign verify-attestation' \
  'ecr_image' \
  'ecr_chart' \
  '/README.md)' \
  '/charts/github-oidc-exchange/values.schema.json)' \
  '../upgrade-v0.6.0.md)'; do
  grep -Fq "$expected" "$release_notes"
done

# Historical guides keep their historical contract and point to current docs.
for document in docs/upgrade-v0.5.0.md docs/upgrade-v0.5.1.md \
  docs/releases/v0.5.0.md docs/releases/v0.5.1.md; do
  grep -Fq 'Historical' "$document"
  grep -Fq 'consumer-contract-v1.md' "$document" || \
    grep -Fq 'upgrade-v0.6.0.md' "$document"
done

# Current relative Markdown links must resolve. URL, mail, and page-only links
# are outside this local-file check.
for document in "${current_docs[@]}"; do
  while IFS= read -r target; do
    target="${target#](}"
    target="${target%)}"
    target="${target%%#*}"
    case "$target" in
      ''|'#'*|http://*|https://*|mailto:*) continue ;;
    esac
    [[ -e "$(dirname "$document")/$target" ]] || {
      printf 'broken relative link in %s: %s\n' "$document" "$target" >&2
      exit 1
    }
  done < <(grep -oE ']\([^)]+\)' "$document" || true)
done

for name in github-oidc-exchange-keyring github-oidc-exchange-policy \
  github-oidc-exchange-policy-v6 github-oidc-exchange-workload-rsa-keyring \
  github-oidc-exchange-workload-policy github-oidc-exchange-server-tls; do
  grep -Fq "$name" docs/installation.md
done
for route in /.well-known/openid-configuration /jwks.json /v1/exchange \
  /v1/workload/exchange; do
  grep -Fq "$route" docs/consumer-contract-v1.md
done

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
for expected in 'id-token: write' 'delivery test checklist' \
  'rollback identity PREVIOUS_REVISION' 'check-install-inputs.sh' \
  'generate-es256' 'generate-rsa' 'cert-manager' 'operator-PKI' \
  'TokenReview' 'GitHub OAuth App'; do
  grep -Fqi "$expected" docs/installation.md
done
grep -Fq 'resourceVersion' docs/installation.md
grep -Fq 'test-install-rotation.sh' docs/installation.md
grep -Fq 'steward-run/issues/43' docs/installation.md

for document in docs/installation.md docs/consumer-contract-v1.md; do
  grep -Fq 'reusable workflow requires both exchange inputs' "$document"
  grep -Fq '`identity-exchange-url` and `identity-exchange-audience`' "$document"
  grep -Fq 'direct-action fallback' "$document"
  grep -Fq 'not the supported handoff' "$document"
done
! grep -Fq 'binds its GitHub input audience to' \
  docs/installation.md docs/consumer-contract-v1.md

# Negative source files in tests intentionally contain retired contract fields.
current_surfaces=(
  src
  README.md
  docs/installation.md
  docs/quickstart.md
  docs/integration.md
  docs/consumer-contract-v1.md
  docs/policy-contract.schema.json
  docs/policy-contract.example.json
  docs/policy-contract-v6.schema.json
  docs/policy-contract-v6.example.json
  charts/github-oidc-exchange/README.md
  charts/github-oidc-exchange/examples/production-values.yaml
)
if grep -R -n -E \
  'bootstrap_group|service-envelope-bootstrap|workflow_refs|job_workflow_refs|IdentityProfile|BOOTSTRAP_PREFIX' \
  "${current_surfaces[@]}"; then
  printf 'current code and docs retain retired contract fields\n' >&2
  exit 1
fi
