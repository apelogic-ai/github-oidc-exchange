# Steward and OpenShell workload-exchange pairing

This guide pairs Identity's optional Kubernetes workload exchange with the
Steward controller and OpenShell. It is a cross-product configuration map, not
a runtime dependency from Identity to Steward: Steward presents a Kubernetes
credential to Identity, Identity validates it with TokenReview and issues a
bounded token, and OpenShell verifies that token. Identity 0.7.5 and later
support this contract.

The standard contract has these exact joins:

| Producer | Consumer | Exact value |
| --- | --- | --- |
| Steward projected ServiceAccount token | Identity `workloadExchange.inputAudience` | `apelogic-workload-exchange` |
| Kubernetes TokenReview username | Identity workload policy `username` | `system:serviceaccount:steward:steward-controller` |
| Identity workload policy `subject` | OpenShell token subject | `kubernetes:serviceaccount:steward:steward-controller` |
| Identity `workloadExchange.outputAudience` | OpenShell `server.oidc.audience` | `openshell-api` |
| Identity workload policy `roles` claim | OpenShell role configuration | `openshell-admin` and `openshell-user` |
| Identity `config.issuerUrl` | OpenShell `server.oidc.issuer` | The same exact HTTPS issuer origin |

The `steward` namespace in this example is an installation input. If Steward
is installed elsewhere, replace `steward` in the namespace selector,
`username`, and `subject` together. The chart-owned controller ServiceAccount
name remains `steward-controller`. Do not use wildcards.

## Identity values and policy

Use this additive Identity values overlay after the baseline installation is
healthy. Keep the existing image, public exchange, policy, keyring, and
network settings in the deployment-owned values file.

```yaml
workloadExchange:
  enabled: true
  inputAudience: apelogic-workload-exchange
  outputAudience: openshell-api
  policyConfigMapName: github-oidc-exchange-workload-policy
  policyConfigMapKey: workload-policy.json
  rsaKeyringSecretName: github-oidc-exchange-workload-rsa-keyring
  rsaKeyringSecretKey: rsa-keyring.json
  tls:
    secretName: github-oidc-exchange-server-tls
    certificateKey: tls.crt
    privateKeyKey: tls.key
  networkPolicy:
    callerNamespaceSelector:
      kubernetes.io/metadata.name: steward
    callerPodSelector:
      app.kubernetes.io/name: steward
      app.kubernetes.io/component: controller

rolloutRevisions:
  workloadPolicy: workload-policy-rev-1
  workloadRsaKeyring: workload-rsa-rev-1
  workloadTls: workload-tls-rev-1
```

The referenced `workload-policy.json` must contain the exact admitted
ServiceAccount and the exact OpenShell role strings:

```json
{
  "version": "github-oidc-exchange.apelogic.io/workload-policy-v1",
  "identities": [
    {
      "username": "system:serviceaccount:steward:steward-controller",
      "subject": "kubernetes:serviceaccount:steward:steward-controller",
      "roles": ["openshell-admin", "openshell-user"]
    }
  ]
}
```

This exact document is checked in as
[`workload-policy-contract.example.json`](workload-policy-contract.example.json).
Add other admitted identities as separate exact entries; do not replace an
existing policy when another workload still depends on it. After changing the
referenced ConfigMap, change `rolloutRevisions.workloadPolicy` and wait for the
Identity Deployment rollout because projected policy content is not
hot-reloaded.

## Steward values

Steward projects the fixed `apelogic-workload-exchange` audience into the
`steward-controller` Pod. Point that controller at Identity's internal TLS
listener and pin the certificate DNS name:

```yaml
execution:
  enabled: true

config:
  controller:
    workloadExchangeEndpoint: https://github-oidc-exchange.identity.svc.cluster.local:8443/v1/workload/exchange
    workloadExchangeServerName: github-oidc-exchange.identity.svc.cluster.local

networkPolicy:
  identityExchangeNamespace: identity

workloadExchangeTrust:
  kind: ConfigMap
  name: steward-workload-exchange-ca
  caCertificate: ca.crt
```

Here `identity` is the Identity namespace. It must match both the Service DNS
name and Steward's `networkPolicy.identityExchangeNamespace`; otherwise the
controller egress policy blocks port 8443. The serving certificate selected
by Identity's `workloadExchange.tls.secretName` must cover the exact
`workloadExchangeServerName`, and Steward's public CA ConfigMap must validate
that chain. The workload endpoint stays cluster-internal and must not be added
to Ingress or HTTPRoute. See the pinned
[Steward 0.3.2 values contract](https://github.com/apelogic-ai/steward/blob/v0.3.2/charts/steward/values.yaml)
for the paired namespace setting.

## OpenShell values

OpenShell must verify the issuer, output audience, and role claim that Identity
selects. Pair its values with the Identity configuration above:

```yaml
server:
  auth:
    allowUnauthenticatedUsers: false
  oidc:
    issuer: https://identity.example.org
    audience: openshell-api
    rolesClaim: roles
    adminRole: openshell-admin
    userRole: openshell-user
```

Replace the issuer with the exact origin-only `config.issuerUrl` used by
Identity. If different role names are deliberately selected in OpenShell,
change the Identity workload-policy roles to those exact strings in the same
rollout. Identity fixes the claim name to `roles`, the token contract to
`openshell-workload-v1`, the algorithm to RS256, and the lifetime to at most
120 seconds; callers cannot override them.

OpenShell caches the issuer JWKS for up to one hour. Prefer enabling the
Identity workload exchange before OpenShell first starts. If OpenShell is
already running when the exchange is enabled or its RSA key set changes,
restart OpenShell so it loads the current keys before testing tokens (or wait
for the full configured `jwksTtl`, 3600 seconds by default):

```sh
kubectl --kubeconfig "$OPENSHELL_KUBECONFIG" \
  --context "$OPENSHELL_CONTEXT" \
  -n "$OPENSHELL_NAMESPACE" rollout restart statefulset/openshell
kubectl --kubeconfig "$OPENSHELL_KUBECONFIG" \
  --context "$OPENSHELL_CONTEXT" \
  -n "$OPENSHELL_NAMESPACE" rollout status statefulset/openshell --timeout=10m
```

Wait for the configured replica count to become ready. A successful rollout,
not a ConfigMap or Secret update alone, proves the cached JWKS was replaced.

## Operator CLI authentication when Identity is the only provider

Use a dedicated, least-privilege ServiceAccount for interactive administration;
do not reuse Steward's controller identity. Add this exact entry alongside the
controller entry in Identity's workload policy, then advance
`rolloutRevisions.workloadPolicy` and wait for Identity to roll out:

```json
{
  "username": "system:serviceaccount:openshell:openshell-operator",
  "subject": "kubernetes:serviceaccount:openshell:openshell-operator",
  "roles": ["openshell-admin", "openshell-user"]
}
```

`openshell-admin` is required for the global setup operations below;
`openshell-user` permits the same short-lived identity to exercise ordinary
CLI operations. Remove either role only after verifying the intended command
set against the deployed OpenShell authorization policy.

Create the ServiceAccount in the namespace named by that entry:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: openshell-operator
  namespace: openshell
automountServiceAccountToken: false
```

Save that manifest as `openshell-operator-serviceaccount.yaml` and apply it to
the explicit cluster target:

```sh
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" \
  --context "$IDENTITY_CONTEXT" apply \
  -f openshell-operator-serviceaccount.yaml
```

The person running the procedure needs RBAC only to request a bound token for
that ServiceAccount and to port-forward the Identity Service. The
ServiceAccount is the TokenReview identity; NetworkPolicy separately governs
the connection path. A helper Pod must match Identity's configured caller
namespace and Pod selectors. A direct port-forward must be permitted by the
cluster and CNI policy. Create a short-lived
projected token for the exact input audience, exchange it over the internal TLS
name, and keep bearer material in a mode-0700 temporary directory:

```sh
umask 077
operator_tmp="$(mktemp -d)"
cleanup_operator_auth() {
  if [ -n "${identity_port_forward_pid:-}" ]; then
    kill "$identity_port_forward_pid" 2>/dev/null || true
  fi
  rm -rf "$operator_tmp"
}
trap cleanup_operator_auth EXIT HUP INT TERM

kubectl --kubeconfig "$IDENTITY_KUBECONFIG" \
  --context "$IDENTITY_CONTEXT" -n openshell \
  create token openshell-operator \
  --audience=apelogic-workload-exchange --duration=10m \
  >"$operator_tmp/projected.jwt"

kubectl --kubeconfig "$IDENTITY_KUBECONFIG" \
  --context "$IDENTITY_CONTEXT" -n identity \
  port-forward service/github-oidc-exchange 18443:8443 \
  >"$operator_tmp/port-forward.log" 2>&1 &
identity_port_forward_pid=$!

attempt=0
until grep -Fq 'Forwarding from' "$operator_tmp/port-forward.log"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 40 ] || ! kill -0 "$identity_port_forward_pid" 2>/dev/null; then
    printf 'Identity port-forward did not become ready\n' >&2
    exit 1
  fi
  sleep 0.25
done

printf 'Authorization: Bearer %s\n' "$(tr -d '\n' <"$operator_tmp/projected.jwt")" \
  >"$operator_tmp/authorization.header"
curl --fail --silent --show-error \
  --cacert /absolute/path/to/workload-ca.crt \
  --resolve github-oidc-exchange.identity.svc.cluster.local:18443:127.0.0.1 \
  --header @"$operator_tmp/authorization.header" \
  --request POST \
  https://github-oidc-exchange.identity.svc.cluster.local:18443/v1/workload/exchange \
  >"$operator_tmp/exchange.json"
jq -er '.token_type == "Bearer" and .expires_in <= 120' \
  "$operator_tmp/exchange.json" >/dev/null
jq -er .access_token "$operator_tmp/exchange.json" >"$operator_tmp/openshell.jwt"
```

Register the gateway in a temporary OpenShell configuration root. With browser
launch disabled, the initial authentication attempt may stop after preserving
the gateway registration; verify the directory before installing the
short-lived token bundle:

```sh
export OPENSHELL_GATEWAY_ENDPOINT=https://openshell.example.org
export IDENTITY_ISSUER=https://identity.example.org
export XDG_CONFIG_HOME="$operator_tmp/config"
OPENSHELL_NO_BROWSER=1 openshell gateway add "$OPENSHELL_GATEWAY_ENDPOINT" \
  --name governed \
  --oidc-issuer "$IDENTITY_ISSUER" \
  --oidc-client-id openshell-cli \
  --oidc-audience openshell-api || true
test -d "$XDG_CONFIG_HOME/openshell/gateways/governed"

jq -n --rawfile access_token "$operator_tmp/openshell.jwt" \
  --arg issuer "$IDENTITY_ISSUER" \
  '{access_token:($access_token | gsub("\\n"; "")), issuer:$issuer, client_id:"openshell-cli"}' \
  >"$XDG_CONFIG_HOME/openshell/gateways/governed/oidc_token.json"
chmod 0600 "$XDG_CONFIG_HOME/openshell/gateways/governed/oidc_token.json"

# Run the governed setup operations while the <=120-second token is valid.
openshell settings set --global SETTING_NAME SETTING_VALUE
openshell provider profile import --global /absolute/path/to/reviewed-profile.yaml
```

The `EXIT` trap deletes the CLI configuration, projected token, exchanged
token, headers, and response. Do not copy this temporary bundle into a normal
user profile. Each later session requests and exchanges a new bound token.
Identity audits a successful exchange as `workload_exchange_issued` with only
a truncated hash of the reviewed ServiceAccount username; it never logs either
bearer token. Denials and dependency failures use the stable reasons in the
[operator observability contract](operator-observability-contract-v1.md).

## Verification

From the selected Steward controller Pod, verify the source credential has the
projected audience without printing the token, then exercise the empty-body
exchange through the configured TLS trust. A successful response must verify
against Identity's JWKS with:

- `iss` equal to the configured Identity issuer;
- `aud` equal to `openshell-api`;
- `sub` equal to `kubernetes:serviceaccount:steward:steward-controller`;
- `roles` equal to the reviewed policy roles; and
- `identity_contract` equal to `openshell-workload-v1`.

Also prove that a token for the Kubernetes API audience, an unlisted
ServiceAccount, a Pod outside both NetworkPolicy selectors, and the wrong CA or
server name fail. Record only status, timestamps, revisions, and public key
IDs; never record either source or exchanged bearer token.
