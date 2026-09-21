#!/usr/bin/env bash
set -euo pipefail

# No cluster, credentials, or Secret data are used in this contract test.
kubectl() {
  while [[ $# -gt 0 && "$1" != get ]]; do shift; done
  [[ "$1" == get ]]
  local kind=$2 name=$3
  case "$kind/$name" in
    ConfigMap/github-oidc-exchange-policy) printf 'ConfigMap identity %s - policy.json,\n' "$name" ;;
    Secret/github-oidc-exchange-keyring) printf 'Secret identity %s Opaque keyring.json,\n' "$name" ;;
    ConfigMap/github-oidc-exchange-workload-policy) printf 'ConfigMap identity %s - workload-policy.json,\n' "$name" ;;
    Secret/github-oidc-exchange-workload-rsa-keyring) printf 'Secret identity %s Opaque rsa-keyring.json,\n' "$name" ;;
    Secret/github-oidc-exchange-server-tls|Secret/identity-public-tls)
      printf 'Secret identity %s kubernetes.io/tls tls.crt,tls.key,\n' "$name" ;;
    *) return 1 ;;
  esac
}
export -f kubectl

bash scripts/check-install-inputs.sh Cargo.toml test-context identity >/dev/null
bash scripts/check-install-inputs.sh Cargo.toml test-context identity --workload \
  --public-tls identity-public-tls >/dev/null
if bash scripts/check-install-inputs.sh Cargo.toml test-context wrong-namespace \
  >/dev/null 2>&1; then
  printf 'object namespace mismatch must fail\n' >&2
  exit 1
fi
