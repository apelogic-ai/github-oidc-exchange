#!/usr/bin/env bash
set -euo pipefail

bash scripts/validate-ci-tools.sh

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
  'CHART_CANDIDATE_TAG=candidate-'
  'oras push --image-spec v1.0'
  'aws ecr describe-images'
  'Promote verified image candidate'
  'Promote verified chart candidate'
  'oras tag "$CHART_REFERENCE@${{ steps.chart.outputs.digest }}" "$VERSION"'
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

grep -Fq -- '.Chart.Version | replace "+" "_"' \
  charts/github-oidc-exchange/templates/_helpers.tpl

render_dir="$(mktemp -d)"
trap 'rm -rf "$render_dir"' EXIT
cp -R charts/github-oidc-exchange "$render_dir/chart"
sed -i.bak \
  "s/^version: .*/version: ${package_version}+flux.test/" \
  "$render_dir/chart/Chart.yaml"
helm template test "$render_dir/chart" \
  -f charts/github-oidc-exchange/ci/test-values.yaml >"$render_dir/rendered.yaml"
grep -Fq -- \
  "helm.sh/chart: \"github-oidc-exchange-${package_version}_flux.test\"" \
  "$render_dir/rendered.yaml"

helm template workload "$render_dir/chart" \
  --namespace github-oidc-exchange \
  -f charts/github-oidc-exchange/ci/workload-values.yaml >"$render_dir/workload.yaml"
helm template workload "$render_dir/chart" \
  --namespace github-oidc-exchange \
  -f charts/github-oidc-exchange/ci/workload-values.yaml >"$render_dir/workload-repeat.yaml"
helm template workload "$render_dir/chart" \
  --namespace github-oidc-exchange \
  -f charts/github-oidc-exchange/ci/workload-values.yaml \
  --set-string rolloutRevisions.workloadRsaKeyring=rev-2 \
  >"$render_dir/workload-changed.yaml"

for annotation in github-policy github-keyring workload-policy workload-rsa-keyring workload-tls; do
  original="$(grep -F -- "checksum/$annotation:" "$render_dir/workload.yaml")"
  repeated="$(grep -F -- "checksum/$annotation:" "$render_dir/workload-repeat.yaml")"
  [[ -n "$original" ]]
  [[ "$original" == "$repeated" ]]
done

original_rsa="$(grep -F -- 'checksum/workload-rsa-keyring:' "$render_dir/workload.yaml")"
changed_rsa="$(grep -F -- 'checksum/workload-rsa-keyring:' "$render_dir/workload-changed.yaml")"
[[ "$original_rsa" != "$changed_rsa" ]]
for annotation in github-policy github-keyring workload-policy workload-tls; do
  original="$(grep -F -- "checksum/$annotation:" "$render_dir/workload.yaml")"
  changed="$(grep -F -- "checksum/$annotation:" "$render_dir/workload-changed.yaml")"
  [[ "$original" == "$changed" ]]
done

if helm template missing-workload-checksum "$render_dir/chart" \
  --namespace github-oidc-exchange \
  -f charts/github-oidc-exchange/ci/workload-values.yaml \
  --set-string rolloutRevisions.workloadTls= \
  >/dev/null 2>&1; then
  printf 'workload profile must require all rollout revisions\n' >&2
  exit 1
fi

workload_contracts=(
  'name: WORKLOAD_EXCHANGE_ENABLED'
  'name: WORKLOAD_INPUT_AUDIENCE'
  'name: WORKLOAD_RSA_KEYRING_FILE'
  'name: WORKLOAD_LISTEN_ADDRESS'
  'name: TLS_CERTIFICATE_FILE'
  'name: TLS_PRIVATE_KEY_FILE'
  'name: http'
  'containerPort: 8080'
  'name: workload-https'
  'containerPort: 8443'
  'port: 8443'
  'resources: ["tokenreviews"]'
  'verbs: ["create"]'
  'scheme: http'
  'checksum/github-policy:'
  'checksum/github-keyring:'
  'checksum/workload-policy:'
  'checksum/workload-rsa-keyring:'
  'checksum/workload-tls:'
)
for contract in "${workload_contracts[@]}"; do
  grep -Fq -- "$contract" "$render_dir/workload.yaml"
done

awk '
  /^kind: NetworkPolicy$/ { capture = 1 }
  capture { print }
  capture && /^---$/ { exit }
' "$render_dir/workload.yaml" > "$render_dir/networkpolicy.yaml"

awk '
  /^  ingress:/ { ingress = 1; next }
  /^  egress:/ { ingress = 0 }
  ingress && /^    - from:/ { rule += 1 }
  ingress && rule == 1 && /cidr: 10[.]0[.]0[.]0\/16/ { public_source = 1 }
  ingress && rule == 1 && /port: 8080/ { public_port = 1 }
  ingress && rule == 1 && /port: 8443/ { bad = 1 }
  ingress && rule == 2 && /kubernetes[.]io\/metadata[.]name: example-caller/ { caller_namespace = 1 }
  ingress && rule == 2 && /app[.]kubernetes[.]io\/name: example-caller/ { caller_pod = 1 }
  ingress && rule == 2 && /port: 8443/ { workload_port = 1 }
  ingress && rule == 2 && /port: 8080/ { bad = 1 }
  END {
    if (!(public_source && public_port && caller_namespace && caller_pod && workload_port) || bad) {
      exit 1
    }
  }
' "$render_dir/networkpolicy.yaml"

awk '
  /^kind: ServiceMonitor$/ { capture = 1 }
  capture { print }
  capture && /^---$/ { exit }
' "$render_dir/workload.yaml" > "$render_dir/servicemonitor.yaml"
grep -Fq -- 'port: http' "$render_dir/servicemonitor.yaml"
grep -Fq -- 'scheme: http' "$render_dir/servicemonitor.yaml"

if grep -Fq -- 'path: /v1/workload/exchange' "$render_dir/workload.yaml"; then
  printf 'workload exchange must not be exposed through Ingress\n' >&2
  exit 1
fi

if grep -Fq -- 'resources: ["tokenreviews"]' "$render_dir/rendered.yaml"; then
  printf 'TokenReview RBAC must be absent when workload exchange is disabled\n' >&2
  exit 1
fi

if grep -Fq -- '$1 == "Digest:"' "$workflow"; then
  printf 'release digest must come from the registry API, not formatted CLI output\n' >&2
  exit 1
fi

if grep -Fq -- '--fulcio-auth-flow=device' "$workflow"; then
  printf 'device-flow authentication is forbidden\n' >&2
  exit 1
fi

if grep -Fq -- 'helm push' "$workflow"; then
  printf 'chart must use a unique candidate tag before semantic promotion\n' >&2
  exit 1
fi

if grep -Fq -- 'aws ecr put-image' "$workflow" ||
  grep -Fq -- '--output text > /tmp/chart-manifest.json' "$workflow"; then
  printf 'chart promotion must preserve the verified OCI manifest digest\n' >&2
  exit 1
fi

image_candidate_line="$(grep -n 'Build and publish unique image candidate' "$workflow" | cut -d: -f1)"
chart_candidate_line="$(grep -n 'Publish unique immutable chart candidate' "$workflow" | cut -d: -f1)"
verification_line="$(grep -n 'Sign, attest, and verify immutable candidate artifacts' "$workflow" | cut -d: -f1)"
image_promotion_line="$(grep -n 'Promote verified image candidate' "$workflow" | cut -d: -f1)"
chart_promotion_line="$(grep -n 'Promote verified chart candidate' "$workflow" | cut -d: -f1)"
release_line="$(grep -n 'gh release create' "$workflow" | cut -d: -f1)"
[[ "$image_candidate_line" -lt "$verification_line" ]]
[[ "$chart_candidate_line" -lt "$verification_line" ]]
[[ "$verification_line" -lt "$image_promotion_line" ]]
[[ "$verification_line" -lt "$chart_promotion_line" ]]
[[ "$image_promotion_line" -lt "$release_line" ]]
[[ "$chart_promotion_line" -lt "$release_line" ]]
