#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: smoke-release-container.sh IMAGE}"
smoke_platform="${SMOKE_PLATFORM:-linux/amd64}"
[[ "${smoke_platform}" == linux/amd64 || "${smoke_platform}" == linux/arm64 ]] || {
  printf 'unsupported release smoke platform: %s\n' "${smoke_platform}" >&2
  exit 64
}
tmp="$(mktemp -d)"
app_dir="$tmp/app"
container="github-oidc-exchange-smoke-$$"
mock_pid=""
mkdir -p "$app_dir"

cleanup() {
  if [[ -n "$mock_pid" ]]; then
    kill "$mock_pid" 2>/dev/null || true
    wait "$mock_pid" 2>/dev/null || true
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

diagnose() {
  printf '%s\n' 'mock diagnostics:' >&2
  if [[ -f "$tmp/mock-events" ]]; then
    sed -n '1,80p' "$tmp/mock-events" >&2
  else
    printf '%s\n' 'no mock requests recorded' >&2
  fi
  printf '%s\n' 'container diagnostics:' >&2
  docker logs "$container" >&2 || true
}

openssl req -x509 -newkey rsa:3072 -nodes -days 1 \
  -subj /CN=github-oidc-exchange-smoke-ca \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign \
  -keyout "$tmp/ca.key" -out "$tmp/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:3072 -nodes \
  -subj /CN=host.docker.internal \
  -keyout "$app_dir/tls.key" -out "$tmp/tls.csr" >/dev/null 2>&1
printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' \
  'subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1' \
  > "$tmp/tls.ext"
openssl x509 -req -days 1 \
  -in "$tmp/tls.csr" \
  -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" -CAcreateserial \
  -extfile "$tmp/tls.ext" \
  -out "$app_dir/tls.crt" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "$tmp/workload-signing.pem" >/dev/null 2>&1
printf '%s' projected-service-account-token > "$app_dir/service-account-token"

python3 -c '
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import ssl
import sys
import threading

diagnostics = sys.argv[3]
coordination = sys.argv[4]

def record(event):
    with open(diagnostics, "a", encoding="utf-8") as output:
        output.write(event + "\n")

class BaseHandler(BaseHTTPRequestHandler):
    def reply(self, document):
        body = json.dumps(document).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

class TokenReviewHandler(BaseHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(length))
        checks = {
            "path": self.path == "/apis/authentication.k8s.io/v1/tokenreviews",
            "authorization": self.headers.get("authorization") == "Bearer projected-service-account-token",
            "apiVersion": request.get("apiVersion") == "authentication.k8s.io/v1",
            "kind": request.get("kind") == "TokenReview",
            "source_token": request.get("spec", {}).get("token") == "projected-source-token",
            "audience": request.get("spec", {}).get("audiences") == ["apelogic-workload-exchange"],
        }
        record("tokenreview request " + " ".join(f"{name}={str(value).lower()}" for name, value in checks.items()))
        if not all(checks.values()):
            self.send_error(400)
            return
        self.reply({"status": {
            "authenticated": True,
            "audiences": ["apelogic-workload-exchange"],
            "user": {"username": "system:serviceaccount:steward:steward-controller"}
        }})
        record("tokenreview response authenticated=true audience=exact username=mapped")

token_review = ThreadingHTTPServer(("127.0.0.1", 0), TokenReviewHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
token_review.socket = context.wrap_socket(token_review.socket, server_side=True)
temporary = coordination + ".tmp"
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as output:
    output.write(f"tokenreview={token_review.server_port}\n")
os.replace(temporary, coordination)
token_review.serve_forever()
' "$app_dir/tls.crt" "$app_dir/tls.key" "$tmp/mock-events" "$tmp/mock-ports" &
mock_pid="$!"

for _ in $(seq 1 50); do
  [[ -s "$tmp/mock-ports" ]] && break
  kill -0 "$mock_pid"
  sleep 0.1
done
coordination_mode="$(python3 -c 'import os, stat, sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode))[2:])' "$tmp/mock-ports")"
[[ "$coordination_mode" == 600 ]]
token_review_port="$(sed -n 's/^tokenreview=//p' "$tmp/mock-ports")"
[[ "$token_review_port" =~ ^[0-9]+$ ]]

jq -n '{
  version: "github-oidc-exchange.apelogic.io/v4",
  service_group: "agents.apelogic.ai/service-principal:steward-run",
  acting_group_prefix: "agents.apelogic.ai/acting-user:",
  bootstrap_group: "agents.apelogic.ai/service-envelope-bootstrap:steward-run",
  allowed_email_domains: ["apelogic.ai"],
  repositories: [{
    profile: "task",
    owner_id: "227278099",
    repository_id: "1320906141",
    subjects: ["repo:apelogic-ai@227278099/steward-run@1320906141:ref:refs/heads/main"],
    events: ["workflow_dispatch"],
    refs: ["refs/heads/main"]
  }],
  actors: {"16106037": {email: "leo@apelogic.ai", canonical_user_id: "usr_0123456789abcdef0123456789abcdef", verified: true}}
}' > "$app_dir/policy.json"

jq -n '{
  version: "github-oidc-exchange.apelogic.io/keyring-v1",
  current_kid: "smoke-ec",
  keys: [{
    kid: "smoke-ec",
    seed: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=",
    not_before: "2020-01-01T00:00:00Z",
    not_after: "2099-01-01T00:00:00Z"
  }]
}' > "$app_dir/keyring.json"

jq -n '{
  version: "github-oidc-exchange.apelogic.io/workload-policy-v1",
  identities: [{
    username: "system:serviceaccount:steward:steward-controller",
    subject: "kubernetes:serviceaccount:steward:steward-controller",
    roles: ["openshell-admin", "openshell-user"]
  }]
}' > "$app_dir/workload-policy.json"

jq -n --rawfile key "$tmp/workload-signing.pem" '{
  version: "github-oidc-exchange.apelogic.io/rsa-keyring-v1",
  current_kid: "smoke-rsa",
  keys: [{
    kid: "smoke-rsa",
    private_key_pkcs8_pem: $key,
    not_before: "2020-01-01T00:00:00Z",
    not_after: "2099-01-01T00:00:00Z"
  }]
}' > "$app_dir/rsa-keyring.json"

cp "$tmp/ca.crt" "$app_dir/kubernetes-ca.crt"
chmod 0755 "$app_dir"
chmod 0444 "$app_dir"/*

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

case "$(uname -s)" in
  Linux)
    public_port="$(free_port)"
    workload_port="$(free_port)"
    while [[ "$public_port" == "$workload_port" \
      || "$public_port" == "$token_review_port" \
      || "$workload_port" == "$token_review_port" ]]; do
      public_port="$(free_port)"
      workload_port="$(free_port)"
    done
    docker_network=(--network host)
    mock_host=127.0.0.1
    public_listen="127.0.0.1:$public_port"
    workload_listen="127.0.0.1:$workload_port"
    ;;
  Darwin)
    docker_network=(
      --add-host host.docker.internal:host-gateway
      --publish 127.0.0.1::8080
      --publish 127.0.0.1::8443
    )
    mock_host=host.docker.internal
    public_listen=0.0.0.0:8080
    workload_listen=0.0.0.0:8443
    ;;
  *)
    printf 'unsupported smoke-test host: %s\n' "$(uname -s)" >&2
    exit 1
    ;;
esac

docker run --detach --name "$container" \
  --platform "${smoke_platform}" \
  "${docker_network[@]}" \
  --volume "$app_dir:/smoke:ro" \
  --env ISSUER_URL=https://identity.dev.apelogic.io \
  --env GITHUB_EXCHANGE_AUDIENCE=apelogic-github-exchange \
  --env OUTPUT_AUDIENCE=steward-task-api \
  --env POLICY_FILE=/smoke/policy.json \
  --env KEYRING_FILE=/smoke/keyring.json \
  --env REPLAY_LEASE_NAMESPACE=smoke \
  --env LISTEN_ADDRESS="$public_listen" \
  --env WORKLOAD_EXCHANGE_ENABLED=true \
  --env WORKLOAD_LISTEN_ADDRESS="$workload_listen" \
  --env WORKLOAD_INPUT_AUDIENCE=apelogic-workload-exchange \
  --env WORKLOAD_OUTPUT_AUDIENCE=openshell-api \
  --env WORKLOAD_POLICY_FILE=/smoke/workload-policy.json \
  --env WORKLOAD_RSA_KEYRING_FILE=/smoke/rsa-keyring.json \
  --env TLS_CERTIFICATE_FILE=/smoke/tls.crt \
  --env TLS_PRIVATE_KEY_FILE=/smoke/tls.key \
  --env KUBERNETES_SERVICE_HOST="$mock_host" \
  --env KUBERNETES_SERVICE_PORT_HTTPS="$token_review_port" \
  --env KUBERNETES_CA_CERTIFICATE_FILE=/smoke/kubernetes-ca.crt \
  --env KUBERNETES_SERVICE_ACCOUNT_TOKEN_FILE=/smoke/service-account-token \
  "$image" >/dev/null

if [[ "$(uname -s)" == Darwin ]]; then
  public_port="$(docker port "$container" 8080/tcp)"
  public_port="${public_port##*:}"
  workload_port="$(docker port "$container" 8443/tcp)"
  workload_port="${workload_port##*:}"
fi
[[ "$public_port" =~ ^[0-9]+$ ]]
[[ "$workload_port" =~ ^[0-9]+$ ]]

for _ in $(seq 1 60); do
  if [[ "$(docker inspect --format '{{.State.Running}}' "$container")" != true ]]; then
    docker logs "$container" >&2
    exit 1
  fi
  if curl --fail --silent --show-error "http://127.0.0.1:$public_port/readyz" >/dev/null \
    && curl --fail --silent --show-error --cacert "$tmp/ca.crt" \
      "https://127.0.0.1:$workload_port/readyz" >/dev/null; then
    if ! response="$(curl --fail --silent --show-error --cacert "$tmp/ca.crt" \
      --request POST \
      --header 'Authorization: Bearer projected-source-token' \
      "https://127.0.0.1:$workload_port/v1/workload/exchange")"; then
      diagnose
      exit 1
    fi
    token="$(jq -er '.access_token' <<< "$response")"
    python3 -c '
import base64
import json
import sys

def decode(segment):
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))

header, claims = map(decode, sys.stdin.read().strip().split(".")[:2])
assert header["alg"] == "RS256"
assert claims["sub"] == "kubernetes:serviceaccount:steward:steward-controller"
assert claims["aud"] == ["openshell-api"]
assert claims["roles"] == ["openshell-admin", "openshell-user"]
assert claims["identity_contract"] == "openshell-workload-v1"
' <<< "$token"
    [[ "$(docker inspect --format '{{.State.Running}}' "$container")" == true ]]
    docker stop --time 10 "$container" >/dev/null
    [[ "$(docker inspect --format '{{.State.ExitCode}}' "$container")" == 0 ]]
    exit 0
  fi
  sleep 1
done

docker logs "$container" >&2
diagnose
exit 1
