#!/usr/bin/env bash
# Print only Kubernetes object metadata and data-key names, never data values.
set -euo pipefail

if [[ $# -lt 3 ]]; then
  printf 'usage: %s KUBECONFIG CONTEXT NAMESPACE [--workload] [--skip-workload-tls] [--public-tls NAME]\n' "$0" >&2
  exit 2
fi
kubeconfig=$1
context=$2
namespace=$3
shift 3
workload=false
skip_workload_tls=false
public_tls=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --workload) workload=true; shift ;;
    --skip-workload-tls) skip_workload_tls=true; shift ;;
    --public-tls)
      [[ $# -ge 2 ]] || exit 2
      public_tls=$2
      shift 2 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done
[[ -f "$kubeconfig" && -n "$context" && -n "$namespace" ]]
kubectl_args=(--kubeconfig "$kubeconfig" --context "$context" -n "$namespace")

check_object() {
  local kind=$1 name=$2 expected_type=$3
  shift 3
  local actual_kind actual_namespace actual_name actual_type keys
  # Go template expands only map *keys*. Secret bytes never reach stdout or
  # shell variables. Do not replace this with -o json or a .data JSONPath.
  read -r actual_kind actual_namespace actual_name actual_type keys <<<"$(
    kubectl "${kubectl_args[@]}" get "$kind" "$name" \
      -o go-template='{{.kind}} {{.metadata.namespace}} {{.metadata.name}} {{.type}} {{range $key, $_ := .data}}{{$key}},{{end}}'
  )"
  if [[ "$actual_kind" != "$kind" || "$actual_namespace" != "$namespace" || "$actual_name" != "$name" ]]; then
    printf 'object identity mismatch for %s/%s\n' "$kind" "$name" >&2
    return 1
  fi
  if [[ "$kind" == Secret ]]; then
    if [[ "$actual_type" != "$expected_type" ]]; then
      printf 'object type mismatch for %s/%s\n' "$kind" "$name" >&2
      return 1
    fi
  fi
  for required_key in "$@"; do
    if [[ ",$keys" != *",$required_key,"* ]]; then
      printf 'required key missing from %s/%s: %s\n' "$kind" "$name" "$required_key" >&2
      return 1
    fi
  done
  printf 'verified %s/%s in %s (type and key presence only)\n' "$kind" "$name" "$namespace"
}

check_object ConfigMap github-oidc-exchange-policy ConfigMap policy.json || exit 1
check_object Secret github-oidc-exchange-keyring Opaque keyring.json || exit 1
if [[ "$workload" == true ]]; then
  check_object ConfigMap github-oidc-exchange-workload-policy ConfigMap workload-policy.json || exit 1
  check_object Secret github-oidc-exchange-workload-rsa-keyring Opaque rsa-keyring.json || exit 1
  if [[ "$skip_workload_tls" != true ]]; then
    check_object Secret github-oidc-exchange-server-tls kubernetes.io/tls tls.crt tls.key || exit 1
  fi
fi
if [[ -n "$public_tls" ]]; then
  check_object Secret "$public_tls" kubernetes.io/tls tls.crt tls.key || exit 1
fi
