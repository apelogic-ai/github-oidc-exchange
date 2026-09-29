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

printf '%s\n' \
  '{"linux":{"amd64":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","arm64":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}' \
  > "$fixture_dir/image-platforms.json"
RELEASE_VERSION="$version" \
RELEASE_COMMIT=0123456789abcdef0123456789abcdef01234567 \
RELEASE_REPOSITORY=apelogic-ai/github-oidc-exchange \
RELEASE_WORKFLOW_REF=refs/heads/main \
RELEASE_RUN_ID=123456789 \
RELEASE_RUN_ATTEMPT=1 \
RELEASE_IMAGE=ghcr.io/apelogic-ai/github-oidc-exchange@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
RELEASE_CHART=ghcr.io/apelogic-ai/charts/github-oidc-exchange@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 \
RELEASE_IMAGE_DIGEST=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
RELEASE_CHART_DIGEST=sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 \
RELEASE_PLATFORMS_FILE="$fixture_dir/image-platforms.json" \
  bash scripts/generate-release-evidence.sh "$fixture_dir"

bash scripts/check-public-release-boundary.sh \
  --workflows .github/workflows \
  --evidence "$release_notes" \
  --evidence "$fixture_dir/release-manifest.json" \
  --evidence "$fixture_dir/release.slsa.json"

plant=0
for planted in \
  '${{ vars.ECR_PLANTED }}' \
  '${{ vars.aws_planted }}' \
  '${{ secrets.ECR_PLANTED }}' \
  '${{ vars['"'"'ECR_PLANTED'"'"'] }}' \
  '${{ secrets["AWS_PLANTED"] }}' \
  'uses: aws-actions/amazon-ecr-login@0000000000000000000000000000000000000000' \
  'run: aws ecr get-login-password' \
  'run: $(aws ecr get-login-password)' \
  'run: aws --region us-east-1 ecr get-login-password' \
  'run: "aws" ecr get-login-password' \
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

for planted_host in \
  'Private registry: registry.private.invalid' \
  '{"note":"registry.private.invalid"}'; do
  printf '%s\n' "$planted_host" > "$fixture_dir/planted-bare-host.txt"
  if bash scripts/check-public-release-boundary.sh \
    --workflows "$fixture_dir/workflows" \
    --evidence "$fixture_dir/planted-bare-host.txt" >/dev/null 2>&1; then
    printf 'release boundary guard accepted a planted bare host\n' >&2
    exit 1
  fi
done

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
