#!/usr/bin/env bash
# Exercises the guide's create -> version-checked file replacement in a disposable namespace.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  printf 'usage: %s KUBECONFIG CONTEXT NAMESPACE\n' "$0" >&2
  exit 2
fi
identity_kubeconfig=$1
identity_context=$2
identity_namespace=$3
identity_name=identity-install-rotation-test
kubectl_args=(--kubeconfig "$identity_kubeconfig" --context "$identity_context" -n "$identity_namespace")
created=false
cleanup() {
  if [[ "$created" == true ]]; then
    kubectl "${kubectl_args[@]}" delete secret "$identity_name" --ignore-not-found >/dev/null
  fi
}
trap cleanup EXIT

kubectl "${kubectl_args[@]}" create secret generic "$identity_name" --type=Opaque \
  --from-file=keyring.json=docs/keyring-contract.example.json >/dev/null
created=true
identity_old_rv="$(kubectl "${kubectl_args[@]}" get secret "$identity_name" -o jsonpath='{.metadata.resourceVersion}')"
[[ -n "$identity_old_rv" ]]

kubectl "${kubectl_args[@]}" create secret generic "$identity_name" --type=Opaque \
  --from-file=keyring.json=docs/rsa-keyring-contract.example.json \
  --dry-run=client -o json | jq --arg rv "$identity_old_rv" '.metadata.resourceVersion=$rv' | \
  kubectl "${kubectl_args[@]}" replace -f - >/dev/null

identity_new_rv="$(kubectl "${kubectl_args[@]}" get secret "$identity_name" -o jsonpath='{.metadata.resourceVersion}')"
[[ -n "$identity_new_rv" && "$identity_new_rv" != "$identity_old_rv" ]]
if kubectl "${kubectl_args[@]}" create secret generic "$identity_name" --type=Opaque \
  --from-file=keyring.json=docs/keyring-contract.example.json \
  --dry-run=client -o json | jq --arg rv "$identity_old_rv" '.metadata.resourceVersion=$rv' | \
  kubectl "${kubectl_args[@]}" replace -f - >/dev/null 2>&1; then
  printf 'stale resourceVersion replacement unexpectedly succeeded\n' >&2
  exit 1
fi
[[ "$(kubectl "${kubectl_args[@]}" get secret "$identity_name" -o jsonpath='{.metadata.resourceVersion}')" == "$identity_new_rv" ]]
identity_annotation_state="$(kubectl "${kubectl_args[@]}" get secret "$identity_name" \
  -o go-template='{{with .metadata.annotations}}{{if index . "kubectl.kubernetes.io/last-applied-configuration"}}present{{else}}absent{{end}}{{else}}absent{{end}}')"
if [[ "$identity_annotation_state" != absent ]]; then
  printf 'rotation must not add a last-applied annotation\n' >&2
  exit 1
fi
printf 'file-based rotation: create, version-checked replace, stale-write denial, and no last-applied annotation passed\n'
