#!/usr/bin/env bash
set -euo pipefail

for tool in kind kubectl helm cargo python3 curl; do
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
api_server_service_ip=""
kind_node_image="${KIND_NODE_IMAGE:-kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed}"
probe_image="registry.k8s.io/e2e-test-images/agnhost:2.54@sha256:e729df863cf62ba0363b611302784bc4b2fa79effcd057e7342bd22658ccb71d"

cleanup() {
  if [[ -n "$proxy_pid" ]]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
  fi
  kind delete cluster --name "$cluster" --kubeconfig "$kubeconfig" >/dev/null 2>&1 || true
  rm -rf "$run_dir"
}
trap cleanup EXIT

probe_api_server() {
  local endpoint=${1:-$api_server_service_ip}
  python3 - "$kubeconfig" "$namespace" "$endpoint" <<'PY'
import subprocess
import sys

command = [
    "kubectl",
    "--kubeconfig",
    sys.argv[1],
    "-n",
    sys.argv[2],
    "exec",
    "network-policy-probe",
    "--",
    "/agnhost",
    "connect",
    "--timeout=2s",
    "--protocol=tcp",
    f"{sys.argv[3]}:443",
]
try:
    completed = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
except subprocess.TimeoutExpired:
    sys.exit(124)
sys.exit(completed.returncode)
PY
}

printf 'disposable cluster=%s kubeconfig=%s context=kind-%s state=%s node=%s\n' \
  "$cluster" "$kubeconfig" "$cluster" "$run_dir" "$kind_node_image"
kind create cluster --name "$cluster" --kubeconfig "$kubeconfig" \
  --image "$kind_node_image" --wait 90s >/dev/null
api_server_service_ip="$(kubectl --kubeconfig "$kubeconfig" \
  get service kubernetes -o jsonpath='{.spec.clusterIP}')"
[[ -n "$api_server_service_ip" ]]
bash scripts/test-install-rotation.sh "$kubeconfig" "kind-$cluster" default
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

# Current kindnetd evaluates this connection after the kubernetes Service is
# translated to the control-plane endpoint on 6443. First prove that the old
# 443-only policy blocks it, then apply the chart default and prove it works.
kubectl --kubeconfig "$kubeconfig" -n "$namespace" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: network-policy-probe
  labels:
    app.kubernetes.io/name: github-oidc-exchange
    app.kubernetes.io/instance: network-policy-probe
spec:
  serviceAccountName: lease-test
  containers:
    - name: agnhost
      image: $probe_image
      imagePullPolicy: IfNotPresent
      args: ["pause"]
  restartPolicy: Never
EOF
kubectl --kubeconfig "$kubeconfig" -n "$namespace" wait \
  --for=condition=Ready pod/network-policy-probe --timeout=90s >/dev/null

helm template network-policy-probe charts/github-oidc-exchange \
  --namespace "$namespace" \
  -f charts/github-oidc-exchange/ci/test-values.yaml \
  --set-json 'networkPolicy.apiServerPorts=[443]' \
  --show-only templates/networkpolicy.yaml |
  kubectl --kubeconfig "$kubeconfig" -n "$namespace" apply -f - >/dev/null
sleep 2
if probe_api_server; then
  printf '443-only policy unexpectedly reached the post-DNAT API-server endpoint\n' >&2
  exit 1
fi

helm template network-policy-probe charts/github-oidc-exchange \
  --namespace "$namespace" \
  -f charts/github-oidc-exchange/ci/test-values.yaml \
  --show-only templates/networkpolicy.yaml |
  kubectl --kubeconfig "$kubeconfig" -n "$namespace" apply -f - >/dev/null
for _ in $(seq 1 12); do
  if probe_api_server; then
    api_server_reachable=1
    break
  fi
  sleep 1
done
if [[ "${api_server_reachable:-0}" != 1 ]]; then
  printf 'default policy did not reach the post-DNAT API-server endpoint on 6443\n' >&2
  exit 1
fi

# Exercise the same API path by Service DNS name. On kind/Kubernetes 1.36 this
# regresses if the ingress half of the policy drops DNS replies.
for _ in $(seq 1 12); do
  if probe_api_server kubernetes.default.svc.cluster.local; then
    dns_api_server_reachable=1
    break
  fi
  sleep 1
done
if [[ "${dns_api_server_reachable:-0}" != 1 ]]; then
  printf 'default policy did not admit DNS replies for the Kubernetes Service name\n' >&2
  exit 1
fi

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
