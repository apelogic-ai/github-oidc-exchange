#!/usr/bin/env bash
set -euo pipefail

for tool in kind kubectl cargo python3 curl; do
  command -v "$tool" >/dev/null || {
    printf '%s is required for the Kubernetes Lease integration test\n' "$tool" >&2
    exit 1
  }
done

run_dir="$(mktemp -d)"
cluster="identity-lease-$RANDOM-$RANDOM"
namespace="identity-lease-test"
kubeconfig="$run_dir/kubeconfig"
token_file="$run_dir/service-account-token"
proxy_pid=""

cleanup() {
  if [[ -n "$proxy_pid" ]]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
  fi
  kind delete cluster --name "$cluster" --kubeconfig "$kubeconfig" >/dev/null 2>&1 || true
  rm -rf "$run_dir"
}
trap cleanup EXIT

kind create cluster --name "$cluster" --kubeconfig "$kubeconfig" --wait 90s >/dev/null
kubectl --kubeconfig "$kubeconfig" create namespace "$namespace" >/dev/null
kubectl --kubeconfig "$kubeconfig" -n "$namespace" apply -f - >/dev/null <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: lease-test
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: lease-test
rules:
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["create", "get", "update", "list", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: lease-test
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: lease-test
subjects:
  - kind: ServiceAccount
    name: lease-test
    namespace: identity-lease-test
EOF

umask 077
kubectl --kubeconfig "$kubeconfig" -n "$namespace" create token lease-test >"$token_file"
case "$(uname -s)" in
  Darwin) token_mode="$(stat -f '%Lp' "$token_file")" ;;
  Linux) token_mode="$(stat -c '%a' "$token_file")" ;;
  *)
    printf 'cannot verify token-file mode on this operating system\n' >&2
    exit 1
    ;;
esac
[[ "$token_mode" == 600 ]]

proxy_port="$(python3 -c 'import socket; sock = socket.socket(); sock.bind(("127.0.0.1", 0)); print(sock.getsockname()[1]); sock.close()')"
kubectl --kubeconfig "$kubeconfig" proxy --address=127.0.0.1 --accept-hosts='^127\.0\.0\.1$' --port="$proxy_port" >"$run_dir/proxy.log" 2>&1 &
proxy_pid="$!"
for _ in $(seq 1 50); do
  if curl --fail --silent "http://127.0.0.1:$proxy_port/healthz" >/dev/null; then
    break
  fi
  kill -0 "$proxy_pid"
  sleep 0.1
done
curl --fail --silent "http://127.0.0.1:$proxy_port/healthz" >/dev/null

KUBE_LEASE_TEST_COLLECTION_URL="http://127.0.0.1:$proxy_port/apis/coordination.k8s.io/v1/namespaces/$namespace/leases" \
  KUBE_LEASE_TEST_TOKEN_FILE="$token_file" \
  cargo test --locked --features test-support --test kubernetes_lease_kind
