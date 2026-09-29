#!/usr/bin/env bash
set -euo pipefail

if ((BASH_VERSINFO[0] < 5)); then
  printf 'test-public-release-boundary.sh requires Bash 5 or newer (found %s)\n' \
    "$BASH_VERSION" >&2
  exit 2
fi

fixture_dir="$(mktemp -d)"
trap 'rm -rf "$fixture_dir"' EXIT

mkdir -p "$fixture_dir/workflows"
cp .github/workflows/ci.yml "$fixture_dir/workflows/ci.yml"
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
[[ -n "$version" ]]
release_notes="docs/releases/v$version.md"
[[ -s "$release_notes" ]]
printf '%s\n' \
  '{"image":"ghcr.io/apelogic-ai/github-oidc-exchange@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","public_distribution":{"registry":"ghcr.io"}}' \
  > "$fixture_dir/release-manifest.json"
printf '%s\n' \
  'Source: https://github.com/apelogic-ai/github-oidc-exchange' \
  'Image: `ghcr.io/apelogic-ai/github-oidc-exchange@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`' \
  "Version $version supports Kubernetes 1.36; see README.md and release-manifest.json." \
  > "$fixture_dir/release-notes.md"

bash scripts/check-public-release-boundary.sh \
  --workflows "$fixture_dir/workflows" \
  --evidence "$fixture_dir/release-manifest.json" \
  --evidence "$fixture_dir/release-notes.md"

image_digest=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
chart_digest=sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
release_url="https://github.com/apelogic-ai/github-oidc-exchange/releases/tag/v$version"
workflow_run_url="https://github.com/apelogic-ai/github-oidc-exchange/actions/runs/123456789"
image="ghcr.io/apelogic-ai/github-oidc-exchange@$image_digest"
chart="ghcr.io/apelogic-ai/charts/github-oidc-exchange@$chart_digest"
policy_contract="$(sed -n 's/^pub const POLICY_VERSION: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
identity_contract="$(sed -n 's/^pub const IDENTITY_CONTRACT: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
source_auth_policy_contract="$(sed -n 's/^pub const SOURCE_AUTH_POLICY_VERSION: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
source_auth_identity_contract="$(sed -n 's/^pub const SOURCE_AUTH_IDENTITY_CONTRACT: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
printf '%s\n' \
  '{"linux":{"amd64":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","arm64":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}' \
  > "$fixture_dir/image-platforms.json"
jq -n --arg version "$version" --arg commit 0123456789abcdef0123456789abcdef01234567 \
  --arg release_url "$release_url" --arg workflow_run_url "$workflow_run_url" \
  --arg image "$image" --arg chart "$chart" \
  --arg public_image_digest "$image_digest" --arg public_chart_digest "$chart_digest" \
  --arg policy_contract "$policy_contract" --arg identity_contract "$identity_contract" \
  --arg source_auth_policy_contract "$source_auth_policy_contract" \
  --arg source_auth_identity_contract "$source_auth_identity_contract" \
  --slurpfile platforms "$fixture_dir/image-platforms.json" \
  '{version:$version,commit:$commit,release_url:$release_url,workflow_run_url:$workflow_run_url,image:$image,chart:$chart,public_image_digest:$public_image_digest,public_chart_digest:$public_chart_digest,image_platforms:$platforms[0],public_distribution:{registry:"ghcr.io",anonymous_pull_verified:true,direct_publish:true},policy_contract:$policy_contract,identity_contract:$identity_contract,supported_policy_contracts:[$policy_contract,$source_auth_policy_contract],supported_identity_contracts:[$identity_contract,$source_auth_identity_contract]}' \
  > "$fixture_dir/workflow-release-manifest.json"

jq -n \
  --arg source https://github.com/apelogic-ai/github-oidc-exchange \
  --arg commit 0123456789abcdef0123456789abcdef01234567 \
  --arg workflow https://github.com/apelogic-ai/github-oidc-exchange/.github/workflows/release.yml@refs/heads/main \
  --arg invocation 123456789/1 --arg version "$version" \
  '{buildDefinition:{buildType:"https://apelogic.ai/build-types/github-actions-release/v1",externalParameters:{source:$source,commit:$commit,version:$version}},runDetails:{builder:{id:$workflow},metadata:{invocationId:$invocation}}}' \
  > "$fixture_dir/workflow-release.slsa.json"

bash scripts/check-public-release-boundary.sh \
  --workflows .github/workflows \
  --evidence "$release_notes" \
  --evidence "$fixture_dir/workflow-release-manifest.json" \
  --evidence "$fixture_dir/workflow-release.slsa.json"

plant=0
for planted in \
  '${{ vars.ECR_PLANTED }}' \
  '${{ vars.aws_planted }}' \
  '${{ secrets.ECR_PLANTED }}' \
  'uses: aws-actions/amazon-ecr-login@0000000000000000000000000000000000000000' \
  'run: aws ecr get-login-password' \
  '000000000000.dkr.example.amazonaws.com/example' \
  'uses: aws-actions/configure-aws-credentials@0000000000000000000000000000000000000000'; do
  plant=$((plant + 1))
  printf 'name: planted\nenv:\n  REGISTRY: %s\n' "$planted" \
    > "$fixture_dir/workflows/planted-$plant.txt"
  if bash scripts/check-public-release-boundary.sh \
    --workflows "$fixture_dir/workflows" >/dev/null 2>&1; then
    printf 'release boundary guard accepted a planted workflow reference\n' >&2
    exit 1
  fi
  rm "$fixture_dir/workflows/planted-$plant.txt"
done

printf '%s\n' \
  '{"image":"quay.io"}' \
  > "$fixture_dir/planted-manifest.json"
if bash scripts/check-public-release-boundary.sh \
  --workflows "$fixture_dir/workflows" \
  --evidence "$fixture_dir/planted-manifest.json" >/dev/null 2>&1; then
  printf 'release boundary guard accepted a planted evidence reference\n' >&2
  exit 1
fi

printf '%s\n' \
  '{"documentation":"https://unapproved.example.invalid"}' \
  > "$fixture_dir/planted-host.json"
if bash scripts/check-public-release-boundary.sh \
  --workflows "$fixture_dir/workflows" \
  --evidence "$fixture_dir/planted-host.json" >/dev/null 2>&1; then
  printf 'release boundary guard accepted an unapproved HTTPS host\n' >&2
  exit 1
fi

printf '%s\n' 'Image: `quay.io/example/image`' > "$fixture_dir/planted-notes.md"
if bash scripts/check-public-release-boundary.sh \
  --workflows "$fixture_dir/workflows" \
  --evidence "$fixture_dir/planted-notes.md" >/dev/null 2>&1; then
  printf 'release boundary guard accepted a planted release-note reference\n' >&2
  exit 1
fi
