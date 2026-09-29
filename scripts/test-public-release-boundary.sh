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
printf '%s\n' \
  '{"image":"ghcr.io/apelogic-ai/github-oidc-exchange@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","public_distribution":{"registry":"ghcr.io"}}' \
  > "$fixture_dir/release-manifest.json"
printf '%s\n' \
  'Source: https://github.com/apelogic-ai/github-oidc-exchange' \
  'Image: `ghcr.io/apelogic-ai/github-oidc-exchange@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`' \
  > "$fixture_dir/release-notes.md"

bash scripts/check-public-release-boundary.sh \
  --workflows "$fixture_dir/workflows" \
  --evidence "$fixture_dir/release-manifest.json" \
  --evidence "$fixture_dir/release-notes.md"

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
  '{"image":"quay.io/example/image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}' \
  > "$fixture_dir/planted-manifest.json"
if bash scripts/check-public-release-boundary.sh \
  --workflows "$fixture_dir/workflows" \
  --evidence "$fixture_dir/planted-manifest.json" >/dev/null 2>&1; then
  printf 'release boundary guard accepted a planted evidence reference\n' >&2
  exit 1
fi

printf '%s\n' \
  '{"documentation":"https://unapproved.example.invalid/release/v1"}' \
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
