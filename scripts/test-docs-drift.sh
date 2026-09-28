#!/usr/bin/env bash
set -euo pipefail

version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
released_version="0.7.2"
lock_version="$(awk '
  /^name = "github-oidc-exchange"$/ { package = 1; next }
  package && /^version = "/ { gsub(/^version = "|"$/, ""); print; exit }
' Cargo.lock)"
chart_version="$(sed -n 's/^version: //p' charts/github-oidc-exchange/Chart.yaml | head -1)"
app_version="$(sed -n 's/^appVersion: "\([^"]*\)"/\1/p' charts/github-oidc-exchange/Chart.yaml | head -1)"
[[ "$version" == "0.7.3-dev" ]]
[[ "$lock_version" == "$version" ]]
[[ "$chart_version" == "$version" ]]
[[ "$app_version" == "$version" ]]
grep -Fq 'kubeVersion: ">=1.32.0-0"' charts/github-oidc-exchange/Chart.yaml
grep -Fq 'Kubernetes >=1.32' README.md
grep -Fq 'Kubernetes >=1.32' docs/installation.md
! grep -Fq 'Kubernetes >=1.30' README.md docs/installation.md
! grep -Fq 'Kubernetes >=1.31' README.md docs/installation.md

current_docs=(
  README.md
  THIRD_PARTY_NOTICES.md
  docs/installation.md
  docs/quickstart.md
  docs/integration.md
  docs/consumer-contract-v1.md
  docs/steward-openshell-workload-pairing.md
  docs/upgrade-v0.7.2.md
  docs/source-authentication-documentation-inventory.md
  docs/releases/v0.7.2.md
  charts/github-oidc-exchange/README.md
)
for document in "${current_docs[@]}"; do
  grep -Fq "$released_version" "$document"
done
grep -Fq "## [$released_version]" CHANGELOG.md
production_example=charts/github-oidc-exchange/examples/production-values.yaml
grep -Fq 'repository: replace-with-release-image-repository' "$production_example"
grep -Fq 'digest: replace-with-release-image-digest' "$production_example"
grep -Fq 'release-manifest.json' "$production_example"
for document in docs/installation.md charts/github-oidc-exchange/README.md; do
  grep -Fq 'networkPolicy.metricsNamespaceSelector' "$document"
  grep -Fq 'networkPolicy.metricsPodSelector' "$document"
  grep -Fq 'networkPolicy.apiServerCidrs' "$document"
  grep -Fq 'networkPolicy.apiServerPorts' "$document"
  grep -Fq 'networkPolicy.dnsIpBlocks' "$document"
  grep -Fq 'networkPolicy.extraEgress' "$document"
done
for expected in 'rolloutAutomation.reloader.enabled' \
  'configmap.reloader.stakater.com/reload' \
  'secret.reloader.stakater.com/reload'; do
  grep -Fq "$expected" charts/github-oidc-exchange/templates/deployment.yaml \
    docs/installation.md charts/github-oidc-exchange/README.md
done
grep -Fq 'githubPolicy: rev-1' charts/github-oidc-exchange/values.yaml
grep -Fq 'githubKeyring: rev-1' charts/github-oidc-exchange/values.yaml

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
  (.oneOf | length == 2) and
  (.properties.repositories.items.properties.owner_id.pattern == "^[1-9][0-9]{0,19}$") and
  (.properties.actors.patternProperties | has("^[1-9][0-9]{0,19}$"))
' docs/policy-contract-v6.schema.json >/dev/null
jq -e '
  .identity_contract == "steward-task-v3" and
  .sub == "github-actions:actor:12345" and
  .actor_login == "alice" and
  .source_provenance.actor == "alice" and
  (has("email") | not) and
  (has("email_verified") | not) and
  (has("groups") | not) and
  (has("github_actor") | not)
' docs/steward-task-v3.example.json >/dev/null
jq -e '
  .method == "GET" and
  .url == "https://identity.example.invalid/.well-known/oauth-authorization-server" and
  .headers.accept == "application/json" and
  .redirect == "manual"
' tests/fixtures/steward-run-authorization-server-request.json >/dev/null
jq -e '
  .properties.config.properties.issuerUrl.pattern == "^https://[^/?#]+/?$"
' charts/github-oidc-exchange/values.schema.json >/dev/null
grep -Fq "!authority.contains('/')" src/config.rs
for document in README.md docs/installation.md docs/quickstart.md \
  docs/integration.md docs/consumer-contract-v1.md \
  charts/github-oidc-exchange/README.md; do
  grep -Fqi 'origin' "$document"
done
for expected in \
  'KEY_EXPIRY_READINESS_THRESHOLD_SECONDS' \
  'github_oidc_exchange_signing_key_seconds_until_expiry' \
  'github_oidc_exchange_workload_signing_key_seconds_until_expiry'; do
  grep -Fq "$expected" src/http.rs src/config.rs docs/installation.md \
    charts/github-oidc-exchange/templates/deployment.yaml
done
grep -Fq -- '--valid-for-days' docs/installation.md src/bin/keyring-tool.rs
grep -Fq 'export-jwks' docs/installation.md src/bin/keyring-tool.rs
grep -Fq '/usr/local/bin/keyring-tool' Dockerfile README.md docs/installation.md
grep -Fq -- '--entrypoint /usr/local/bin/keyring-tool' docs/installation.md
for expected in 'static verifier' 'mounted JWKS' 'before Identity activates' \
  'Identity does not call'; do
  grep -Fq "$expected" docs/installation.md docs/consumer-contract-v1.md
done

for document in README.md docs/installation.md docs/integration.md \
  docs/consumer-contract-v1.md docs/upgrade-v0.7.2.md \
  docs/releases/v0.7.2.md charts/github-oidc-exchange/README.md; do
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

for route in /.well-known/oauth-authorization-server \
  /.well-known/openid-configuration; do
  grep -Fq "$route" src/http.rs
  grep -Fq "$route" docs/consumer-contract-v1.md
  grep -Fq "$route" charts/github-oidc-exchange/templates/ingress.yaml
  grep -Fq "$route" charts/github-oidc-exchange/templates/httproute.yaml
done

for phrase in \
  'chart defaults to v5' \
  'separately named' \
  'atomic rollback' \
  'Identity does not decide' \
  'Steward performs any user binding' \
  'Task authority'; do
  grep -Fqi "$phrase" README.md docs/installation.md docs/integration.md \
    docs/consumer-contract-v1.md docs/upgrade-v0.7.2.md
done

grep -Fq 'policyContract: github-oidc-exchange.apelogic.io/v5' \
  charts/github-oidc-exchange/values.yaml
grep -Fq 'policyContract: github-oidc-exchange.apelogic.io/v5' \
  charts/github-oidc-exchange/values.example.yaml
grep -Fq 'name: EXPECTED_POLICY_VERSION' \
  charts/github-oidc-exchange/templates/deployment.yaml
grep -Fq 'github-oidc-exchange-policy` (v5)' docs/upgrade-v0.7.2.md
grep -Fq 'github-oidc-exchange-policy-v6' docs/upgrade-v0.7.2.md

release_notes="docs/releases/v$released_version.md"
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
  'public GitHub release assets no longer contain private-registry' \
  'It contains no `ecr_*` fields' \
  '/README.md)' \
  '/charts/github-oidc-exchange/values.schema.json)' \
  '../upgrade-v0.7.2.md)'; do
  grep -Fq "$expected" "$release_notes"
done
! grep -Eq '"?ecr_(image|chart|image_digest|chart_digest)"?[[:space:]]*:' \
  "$release_notes"

# Historical guides keep their historical contract and point to current docs.
for document in docs/upgrade-v0.5.0.md docs/upgrade-v0.5.1.md \
  docs/upgrade-v0.6.0.md docs/upgrade-v0.7.0.md docs/upgrade-v0.7.1.md \
  docs/releases/v0.5.0.md docs/releases/v0.5.1.md \
  docs/releases/v0.6.0.md docs/releases/v0.7.0.md \
  docs/releases/v0.7.1.md; do
  grep -Fq 'Historical' "$document"
  grep -Fq 'consumer-contract-v1.md' "$document" || \
    grep -Fq 'upgrade-v0.7.2.md' "$document"
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
for route in /.well-known/oauth-authorization-server \
  /.well-known/openid-configuration /jwks.json /v1/exchange \
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

for document in docs/installation.md docs/integration.md \
  docs/consumer-contract-v1.md; do
  grep -Fq 'steward-api-url' "$document"
  grep -Fqi 'discovery' "$document"
  grep -Fq 'identity-exchange-url' "$document"
  grep -Fq 'identity-exchange-audience' "$document"
  grep -Fqi 'deprecated compatibility' "$document"
done
! grep -Fq 'reusable workflow requires both exchange inputs' \
  docs/installation.md docs/integration.md docs/consumer-contract-v1.md

workload_pairing=docs/steward-openshell-workload-pairing.md
for expected in \
  'apelogic-workload-exchange' \
  'system:serviceaccount:steward:steward-controller' \
  'kubernetes:serviceaccount:steward:steward-controller' \
  'openshell-api' \
  'openshell-admin' \
  'openshell-user' \
  'server.oidc.audience' \
  'rolloutRevisions.workloadPolicy'; do
  grep -Fq "$expected" "$workload_pairing"
done
jq -e '
  .version == "github-oidc-exchange.apelogic.io/workload-policy-v1" and
  .identities == [{
    username: "system:serviceaccount:steward:steward-controller",
    subject: "kubernetes:serviceaccount:steward:steward-controller",
    roles: ["openshell-admin", "openshell-user"]
  }]
' docs/workload-policy-contract.example.json >/dev/null
for document in docs/installation.md docs/integration.md \
  docs/consumer-contract-v1.md charts/github-oidc-exchange/README.md; do
  grep -Fq 'steward-openshell-workload-pairing.md' "$document"
done

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
  docs/steward-task-v3.example.json
  charts/github-oidc-exchange/README.md
  charts/github-oidc-exchange/examples/production-values.yaml
)
if grep -R -n -E \
  'bootstrap_group|service-envelope-bootstrap|workflow_refs|job_workflow_refs|IdentityProfile|BOOTSTRAP_PREFIX' \
  "${current_surfaces[@]}"; then
  printf 'current code and docs retain retired contract fields\n' >&2
  exit 1
fi
