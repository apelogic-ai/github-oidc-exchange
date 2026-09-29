#!/usr/bin/env bash
set -euo pipefail

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

for forbidden in 'vars.ECR_' 'amazonaws.com' 'configure-aws-credentials'; do
  if grep -R -n -F --include='*.yml' --include='*.yaml' "$forbidden" "$workflow_root"; then
    printf 'workflow contains a forbidden registry dependency: %s\n' "$forbidden" >&2
    exit 1
  fi
done

check_registry_reference() {
  local file=$1
  local reference=$2

  reference=${reference#oci://}
  case "$reference" in
    ghcr.io | ghcr.io/*)
      return 0
      ;;
    github-oidc-exchange.apelogic.io/*)
      return 0
      ;;
    http://* | https://*)
      return 0
      ;;
  esac

  if [[ "$reference" =~ ^([[:alnum:]-]+\.)+[[:alnum:]-]+(:[0-9]+)?(/|$) ]]; then
    printf 'release evidence names a non-GHCR registry in %s: %s\n' \
      "$file" "$reference" >&2
    return 1
  fi
}

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
      check_registry_reference "$file" "$reference"
    done < <(jq -r '
      .. | objects | to_entries[] |
      select(.key | test("(^|_)(registry|image|chart|reference)$"; "i")) |
      select(.value | type == "string") |
      [.key, .value] | @tsv
    ' "$file")
  fi

  while IFS= read -r reference; do
    [[ -n "$reference" ]] || continue
    case "$reference" in
      ghcr.io/*)
        continue
        ;;
    esac
    if grep -Fq "https://$reference" "$file" || grep -Fq "http://$reference" "$file"; then
      continue
    fi
    check_registry_reference "$file" "$reference"
  done < <(grep -Eo '([[:alnum:]-]+\.)+[[:alnum:]-]+(:[0-9]+)?(/[[:alnum:]_.:@+-]+)+' "$file" || true)
done
