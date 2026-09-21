#!/usr/bin/env bash
set -euo pipefail

# All source files here are public examples or throwaway test certificates.
# The output template exposes only type, namespace, name and key names.
template='{{.kind}} {{.metadata.namespace}} {{.metadata.name}} {{.type}} {{range $key, $_ := .data}}{{$key}},{{end}}'
policy="$(kubectl -n identity create configmap github-oidc-exchange-policy \
  --from-file=policy.json=docs/policy-contract.example.json \
  --dry-run=client -o "go-template=$template")"
[[ "$policy" == 'ConfigMap identity github-oidc-exchange-policy <no value> policy.json,' ]]
issuer="$(kubectl -n identity create secret generic github-oidc-exchange-keyring \
  --type=Opaque --from-file=keyring.json=docs/keyring-contract.example.json \
  --dry-run=client -o "go-template=$template")"
[[ "$issuer" == 'Secret identity github-oidc-exchange-keyring Opaque keyring.json,' ]]
workload_policy="$(kubectl -n identity create configmap github-oidc-exchange-workload-policy \
  --from-file=workload-policy.json=docs/workload-policy-contract.example.json \
  --dry-run=client -o "go-template=$template")"
[[ "$workload_policy" == 'ConfigMap identity github-oidc-exchange-workload-policy <no value> workload-policy.json,' ]]
workload_key="$(kubectl -n identity create secret generic github-oidc-exchange-workload-rsa-keyring \
  --type=Opaque --from-file=rsa-keyring.json=docs/rsa-keyring-contract.example.json \
  --dry-run=client -o "go-template=$template")"
[[ "$workload_key" == 'Secret identity github-oidc-exchange-workload-rsa-keyring Opaque rsa-keyring.json,' ]]

scratch="$(mktemp -d)"
trap 'rm -f "$scratch/server.crt" "$scratch/server.key"; rmdir "$scratch"' EXIT
openssl req -x509 -newkey rsa:2048 -noenc -days 1 \
  -keyout "$scratch/server.key" -out "$scratch/server.crt" \
  -subj '/CN=github-oidc-exchange.identity.svc.cluster.local' >/dev/null 2>&1
tls="$(kubectl -n identity create secret tls github-oidc-exchange-server-tls \
  --cert="$scratch/server.crt" --key="$scratch/server.key" \
  --dry-run=client -o "go-template=$template")"
[[ "$tls" == 'Secret identity github-oidc-exchange-server-tls kubernetes.io/tls tls.crt,tls.key,' ||
  "$tls" == 'Secret identity github-oidc-exchange-server-tls kubernetes.io/tls tls.key,tls.crt,' ]]
