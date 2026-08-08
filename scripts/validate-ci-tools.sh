#!/usr/bin/env bash
set -euo pipefail

validator="scripts/validate-release.sh"
required_tools=(
  awk
  bash
  cp
  cut
  grep
  head
  helm
  mktemp
  sed
)

for tool in "${required_tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'release validator requires unavailable tool: %s\n' "$tool" >&2
    exit 1
  fi
done

if grep -En '(^|[;&|[:space:]])(rg|ripgrep)([;&|[:space:]]|$)' "$validator"; then
  printf 'release validator must use the declared portable grep dependency\n' >&2
  exit 1
fi
