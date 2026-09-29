#!/usr/bin/env bash
set -euo pipefail

if ((BASH_VERSINFO[0] < 5)); then
  printf 'check-public-release-boundary.sh requires Bash 5 or newer (found %s)\n' \
    "$BASH_VERSION" >&2
  exit 2
fi

workflow_root=.github/workflows
evidence_files=()

while (($# > 0)); do
  case "$1" in
    --workflows)
      workflow_root=${2:?--workflows requires a path}
      shift 2
      ;;
    --evidence)
      evidence_files+=("${2:?--evidence requires a path}")
      shift 2
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "$workflow_root" ]]; then
  printf 'workflow directory does not exist: %s\n' "$workflow_root" >&2
  exit 2
fi

for forbidden in \
  '(^|[^[:alnum:]_])(vars|secrets)[.](ecr|aws)_' \
  'amazonaws[.]com' \
  'configure-aws-credentials' \
  'amazon-ecr-login' \
  '(^|[[:space:]])aws[[:space:]]+ecr([[:space:]]|$)'; do
  if grep -R -n -i -E "$forbidden" "$workflow_root"; then
    printf 'workflow contains a forbidden registry dependency matching: %s\n' \
      "$forbidden" >&2
    exit 1
  fi
done

check_public_reference() {
  local file=$1
  local reference=$2
  local host

  case "$reference" in
    http://*)
      printf 'release evidence contains a non-HTTPS host reference in %s: %s\n' \
        "$file" "$reference" >&2
      return 1
      ;;
  esac
  reference=${reference#https://}
  reference=${reference#oci://}
  host=${reference%%/*}
  host=${host%%:*}
  case "$host" in
    ghcr.io | github.com | api.github.com | token.actions.githubusercontent.com | apelogic.ai | github-oidc-exchange.apelogic.io)
      return 0
      ;;
    *)
      printf 'release evidence names a host outside the allowlist in %s: %s\n' \
      "$file" "$reference" >&2
      return 1
      ;;
  esac
}

if ((${#evidence_files[@]} == 0)); then
  exit 0
fi

for file in "${evidence_files[@]}"; do
  if [[ ! -f "$file" ]]; then
    printf 'release evidence does not exist: %s\n' "$file" >&2
    exit 2
  fi

  if [[ "$file" == *.json ]] && jq -e . "$file" >/dev/null 2>&1; then
    while IFS=$'\t' read -r key reference; do
      [[ -n "$reference" ]] || continue
      if [[ "$key" == registry && "$reference" != ghcr.io ]]; then
        printf 'release evidence names a non-GHCR registry in %s: %s\n' \
          "$file" "$reference" >&2
        exit 1
      fi
      check_public_reference "$file" "$reference"
    done < <(jq -r '
      .. | objects | to_entries[] |
      select(.key | test("(^|_)(registry|image|chart|reference)$"; "i")) |
      select(.value | type == "string") |
      [.key, .value] | @tsv
    ' "$file")
  fi

  while IFS= read -r reference; do
    [[ -n "$reference" ]] || continue
    check_public_reference "$file" "$reference"
  done < <(grep -Eo '(https?://|oci://)?([[:alnum:]-]+\.)+[[:alnum:]-]+(:[0-9]+)?(/[[:alnum:]_.:@+?=&%/-]+)?' "$file" || true)
done
