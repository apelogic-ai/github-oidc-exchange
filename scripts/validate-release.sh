#!/usr/bin/env bash
set -euo pipefail

bash scripts/validate-ci-tools.sh
bash scripts/test-portable-release.sh
bash scripts/test-docs-drift.sh

# The published source, package, and chart must advertise the same license.
[[ -f LICENSE ]]
grep -Fq 'MIT License' LICENSE
grep -Fq 'license = "MIT"' Cargo.toml
grep -Fq 'artifacthub.io/license: MIT' charts/github-oidc-exchange/Chart.yaml

grep -Fq -- \
  'cargo build --locked --release --bin github-oidc-exchange' Dockerfile
if grep -Fq -- 'test-support' Dockerfile ||
  grep -R -n -E 'integration-fixture|MemoryReplayLedger' Cargo.toml src Dockerfile; then
  printf 'release image must exclude fixture-only replay implementations\n' >&2
  exit 1
fi

if grep -R -n -E 'Dynamo|dynamodb|REPLAY_TABLE|AWS_ENDPOINT_URL_DYNAMODB' \
  Cargo.toml src charts docs README.md scripts/smoke-release-container.sh; then
  printf 'normal release must not retain a DynamoDB replay dependency\n' >&2
  exit 1
fi
if grep -n -E 'aws-(config|sdk-dynamodb)' Cargo.toml Cargo.lock; then
  printf 'normal release must not retain an AWS SDK replay dependency\n' >&2
  exit 1
fi

workflow=".github/workflows/release.yml"

required=(
  'workflow_dispatch:'
  'packages: write'
  'runs-on: ubuntu-24.04-arm'
  'Build and publish native amd64 image candidate'
  'Build and publish native arm64 image candidate'
  'Compose native multi-platform image candidate'
  'platforms: linux/amd64'
  'platforms: linux/arm64'
  'needs.build-amd64.outputs.digest'
  'needs.build-arm64.outputs.digest'
  'SMOKE_PLATFORM=linux/amd64 bash scripts/smoke-release-container.sh'
  'SMOKE_PLATFORM=linux/arm64 bash scripts/smoke-release-container.sh'
  'cosign-release: v3.1.2'
  '--registry-referrers-mode=oci-1-1'
  '--new-bundle-format=true'
  '--experimental-oci11=true'
  '--type spdxjson'
  '--type slsaprovenance1'
  'CANDIDATE_TAG: candidate-'
  'CHART_CANDIDATE_TAG: candidate-'
  'oras push --image-spec v1.0'
  'org.opencontainers.image.source=https://github.com/$GITHUB_REPOSITORY'
  'aws ecr describe-images'
  'Promote verified image candidate'
  'Promote verified chart candidate'
  'oras tag "$CHART_REFERENCE@${{ steps.chart.outputs.digest }}" "$VERSION"'
  'PUBLIC_IMAGE_REFERENCE=ghcr.io/'
  'PUBLIC_CHART_REFERENCE=ghcr.io/'
  'Authenticate to GitHub Container Registry'
  'Mirror verified immutable ECR artifacts to GHCR'
  'Verify mirrored GHCR packages remain public'
  'Sign, attest, and verify public GHCR artifacts'
  'Verify anonymous exact-digest GHCR pulls'
  'oras cp "$source_image" "$PUBLIC_IMAGE_REFERENCE:$VERSION"'
  'oras cp "$source_chart" "$PUBLIC_CHART_REFERENCE:$VERSION"'
  'docker logout ghcr.io || true'
  'helm registry logout ghcr.io || true'
  'oras logout ghcr.io || true'
  'ecr_image:$ecr_image'
  'ecr_chart:$ecr_chart'
  'public_image_digest:$public_image_digest'
  'public_chart_digest:$public_chart_digest'
  'ecr_image_digest:$ecr_image_digest'
  'ecr_chart_digest:$ecr_chart_digest'
  'anonymous_pull_verified:true'
  'byte_identical_to_ecr:true'
  'image_platforms:$platforms[0]'
  'release_url:$release_url'
  'workflow_run_url:$workflow_run_url'
  '[[ -s "docs/releases/v$REQUESTED_VERSION.md" ]]'
  'gh release create "v$VERSION"'
  '--notes-file "docs/releases/v$VERSION.md"'
  '--arg policy_contract "$policy_contract"'
  '--arg identity_contract "$identity_contract"'
  'policy_contract:$policy_contract'
  'identity_contract:$identity_contract'
)

for contract in "${required[@]}"; do
  grep -Fq -- "$contract" "$workflow"
done

if grep -R -n -i -E 'qemu|binfmt' .github/workflows; then
  printf 'emulated image builds are forbidden; use native architecture runners\n' >&2
  exit 1
fi

for architecture in amd64 arm64; do
  grep -Fq -- "image-platform-$architecture.digest" "$workflow"
  grep -Fq -- "architecture == \$architecture" "$workflow"
done
grep -Fq -- 'image.ecr-scan-$architecture.json' "$workflow"

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
grep -Fq -- 'kind: Role' "$render_dir/rendered.yaml"
grep -Fq -- 'apiGroups: ["coordination.k8s.io"]' "$render_dir/rendered.yaml"
grep -Fq -- 'resources: ["leases"]' "$render_dir/rendered.yaml"
grep -Fq -- 'verbs: ["create", "get", "update", "list", "delete"]' "$render_dir/rendered.yaml"
grep -Fq -- 'kind: RoleBinding' "$render_dir/rendered.yaml"
grep -Fq -- 'name: REPLAY_LEASE_NAMESPACE' "$render_dir/rendered.yaml"
if grep -Fq -- 'REPLAY_TABLE' "$render_dir/rendered.yaml"; then
  printf 'chart must not render a replay table setting\n' >&2
  exit 1
fi

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

# An empty selector in either dimension would make port 8443 reachable from
# more workloads than the operator intended. Keep the schema guard executable.
for selector in callerNamespaceSelector callerPodSelector; do
  if helm template empty-workload-caller "$render_dir/chart" \
    --namespace github-oidc-exchange \
    -f charts/github-oidc-exchange/ci/workload-values.yaml \
    --set-json "workloadExchange.networkPolicy.${selector}={}" \
    >/dev/null 2>&1; then
    printf 'workload profile must reject an empty %s\n' "$selector" >&2
    exit 1
  fi
done

helm template tagged "$render_dir/chart" \
  -f charts/github-oidc-exchange/examples/production-values.yaml \
  >"$render_dir/tagged.yaml"
grep -Fq -- \
  "image: ghcr.io/apelogic-ai/github-oidc-exchange:0.5.0@sha256:ef41cf1cf5d7f8b182e985f609884f6409d9d49ebc8a5164f7b76faf8f806dc1" \
  "$render_dir/tagged.yaml"
if helm template malformed-tag "$render_dir/chart" \
  -f charts/github-oidc-exchange/examples/production-values.yaml \
  --set-string image.tag=not/a/tag \
  >/dev/null 2>&1; then
  printf 'image tag must remain a single registry tag component\n' >&2
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

amd64_candidate_line="$(grep -n 'Build and publish native amd64 image candidate' "$workflow" | cut -d: -f1)"
arm64_candidate_line="$(grep -n 'Build and publish native arm64 image candidate' "$workflow" | cut -d: -f1)"
image_candidate_line="$(grep -n 'Compose native multi-platform image candidate' "$workflow" | cut -d: -f1)"
chart_candidate_line="$(grep -n 'Publish unique immutable chart candidate' "$workflow" | cut -d: -f1)"
verification_line="$(grep -n 'Sign, attest, and verify immutable candidate artifacts' "$workflow" | cut -d: -f1)"
image_promotion_line="$(grep -n 'Promote verified image candidate' "$workflow" | cut -d: -f1)"
chart_promotion_line="$(grep -n 'Promote verified chart candidate' "$workflow" | cut -d: -f1)"
public_mirror_line="$(grep -n 'Mirror verified immutable ECR artifacts to GHCR' "$workflow" | cut -d: -f1)"
public_visibility_line="$(grep -n 'Verify mirrored GHCR packages remain public' "$workflow" | cut -d: -f1)"
public_sign_line="$(grep -n 'Sign, attest, and verify public GHCR artifacts' "$workflow" | cut -d: -f1)"
anonymous_verify_line="$(grep -n 'Verify anonymous exact-digest GHCR pulls' "$workflow" | cut -d: -f1)"
release_line="$(grep -n 'gh release create' "$workflow" | cut -d: -f1)"
[[ "$image_candidate_line" -lt "$verification_line" ]]
[[ "$amd64_candidate_line" -lt "$image_candidate_line" ]]
[[ "$arm64_candidate_line" -lt "$image_candidate_line" ]]
[[ "$chart_candidate_line" -lt "$verification_line" ]]
[[ "$verification_line" -lt "$image_promotion_line" ]]
[[ "$verification_line" -lt "$chart_promotion_line" ]]
[[ "$image_promotion_line" -lt "$release_line" ]]
[[ "$chart_promotion_line" -lt "$release_line" ]]
[[ "$image_promotion_line" -lt "$public_mirror_line" ]]
[[ "$chart_promotion_line" -lt "$public_mirror_line" ]]
[[ "$public_mirror_line" -lt "$public_visibility_line" ]]
[[ "$public_visibility_line" -lt "$public_sign_line" ]]
[[ "$public_sign_line" -lt "$anonymous_verify_line" ]]
[[ "$anonymous_verify_line" -lt "$release_line" ]]
