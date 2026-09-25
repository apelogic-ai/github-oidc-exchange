# Baseline deployment quickstart — github-oidc-exchange 0.6.0

This path installs the 0.6.0 chart with the unchanged v5 policy and
`steward-task-v2` output. It assumes an existing Kubernetes cluster, HTTPS
Gateway, DNS/certificate, and a published immutable image/chart handoff.
Use the [installation guide](installation.md) for other exposure modes,
private registries, rotation, optional workload exchange, and uninstall.

The v6 source-authentication policy is not enabled by this quickstart. After a
v5 deployment passes, use the [0.6.0 upgrade guide](upgrade-v0.6.0.md) to opt
in with a separate v6 ConfigMap and atomic rollback plan.

## 1. Pin the environment and artifacts

Required tools: Rust 1.95, Helm 3.17+, `kubectl`, `jq`, `oras`, and an explicit
kubeconfig/context. Start from the reviewed 0.6.0 source.

```sh
export IDENTITY_VERSION=0.6.0
export IDENTITY_KUBECONFIG=/absolute/path/to/cluster-kubeconfig
export IDENTITY_CONTEXT=platform-context
export IDENTITY_NAMESPACE=identity
export IDENTITY_ISSUER=https://identity.example.org
export IDENTITY_FORK=ORG/github-oidc-exchange

kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  get namespace "$IDENTITY_NAMESPACE" >/dev/null 2>&1 || \
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  create namespace "$IDENTITY_NAMESPACE"
```

Download the release handoff and resolve immutable references:

```sh
umask 077
install -d -m 0700 ./private ./dist
gh release download "v$IDENTITY_VERSION" --repo "$IDENTITY_FORK" \
  --pattern release-manifest.json --dir ./dist
export IDENTITY_IMAGE_REFERENCE="$(jq -er .image ./dist/release-manifest.json)"
export IDENTITY_CHART_REFERENCE="$(jq -er .chart ./dist/release-manifest.json)"
export IDENTITY_IMAGE_REPOSITORY="${IDENTITY_IMAGE_REFERENCE%@*}"
export IDENTITY_IMAGE_DIGEST="${IDENTITY_IMAGE_REFERENCE#*@}"
export IDENTITY_CHART_REPOSITORY="${IDENTITY_CHART_REFERENCE%@*}"

test "$(oras manifest fetch --descriptor \
  "$IDENTITY_IMAGE_REPOSITORY:$IDENTITY_VERSION" | jq -er .digest)" \
  = "$IDENTITY_IMAGE_DIGEST"
```

Both handoff references must contain `@sha256:`. Do not replace a digest with
a mutable tag.

## 2. Create the v5 policy and issuer key

The example is schema-valid but not an approved deployment policy. Replace all
identity values with claims observed from the real workflow as described in
the [integration guide](integration.md).

```sh
install -m 0600 docs/policy-contract.example.json ./private/policy-v5.json
cargo run --locked --bin keyring-tool -- generate-es256 \
  ./private/issuer-keyring.json issuer-0.6.0-a
cargo run --locked --bin keyring-tool -- validate-es256 \
  ./private/issuer-keyring.json
jq -e '.version == "github-oidc-exchange.apelogic.io/v5"' \
  ./private/policy-v5.json >/dev/null

kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" create configmap github-oidc-exchange-policy \
  --from-file=policy.json=./private/policy-v5.json
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" create secret generic github-oidc-exchange-keyring \
  --type=Opaque --from-file=keyring.json=./private/issuer-keyring.json
```

Keep both files outside Git in encrypted, access-controlled storage.

## 3. Configure and validate values

```sh
cp charts/github-oidc-exchange/values.example.yaml ./private/values.yaml
```

Set:

- `image.repository` and exact `image.digest` from the handoff;
- `config.issuerUrl` to `IDENTITY_ISSUER`;
- `config.githubExchangeAudience` to a dedicated bounded value;
- `config.policyContract: github-oidc-exchange.apelogic.io/v5`;
- `config.policyConfigMapName: github-oidc-exchange-policy`;
- the existing ES256 keyring Secret name;
- `httpRoute.enabled: true`, the existing HTTPS Gateway parent, and issuer
  hostname; and
- exact ingress source CIDRs.

Leave workload exchange, browser HOP-1, and Ingress disabled for baseline.

```sh
bash scripts/validate-chart-values.sh ./private/values.yaml
helm lint charts/github-oidc-exchange -f ./private/values.yaml --strict
helm template identity charts/github-oidc-exchange \
  --namespace "$IDENTITY_NAMESPACE" -f ./private/values.yaml \
  > ./dist/identity-rendered.yaml
grep -F 'EXPECTED_POLICY_VERSION' ./dist/identity-rendered.yaml
grep -F 'github-oidc-exchange.apelogic.io/v5' ./dist/identity-rendered.yaml
```

## 4. Install and verify

```sh
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  upgrade --install identity "oci://$IDENTITY_CHART_REPOSITORY" \
  --version "$IDENTITY_VERSION" --namespace "$IDENTITY_NAMESPACE" \
  --values ./private/values.yaml --wait --timeout 10m
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" rollout status \
  deployment/github-oidc-exchange --timeout=5m
```

Validate both equivalent metadata endpoints without hard-coding the input
audience:

```sh
issuer_location="${IDENTITY_ISSUER#https://}"
issuer_authority="${issuer_location%%/*}"
issuer_path=""
if [ "$issuer_location" != "$issuer_authority" ]; then
  issuer_path="/${issuer_location#*/}"
fi
identity_origin="https://$issuer_authority"
for metadata_url in \
  "$identity_origin/.well-known/oauth-authorization-server$issuer_path" \
  "$identity_origin/.well-known/openid-configuration"; do
  curl -fsS "$metadata_url" | \
    jq -e --arg issuer "$IDENTITY_ISSUER" '
      .issuer == $issuer and
      .jwks_uri == ($issuer + "/jwks.json") and
      .github_oidc_exchange_endpoint == ($issuer + "/v1/exchange") and
      (.github_oidc_audience | type == "string" and length > 0) and
      (.identity_contracts_supported | index("steward-task-v2")) and
      (.identity_contracts_supported | index("steward-task-v3")) and
      (.policy_versions_supported | index("github-oidc-exchange.apelogic.io/v5")) and
      (.policy_versions_supported | index("github-oidc-exchange.apelogic.io/v6"))
    ' >/dev/null
done
curl -fsS "$IDENTITY_ISSUER/jwks.json" | \
  jq -e '[.keys[] | select(.alg == "ES256" and .kty == "EC")] | length > 0' \
  >/dev/null
```

Finish with the integration guide's real positive, replay, negative, and
consumer-verification cases. Baseline v5 must reject wrong repository, subject,
event, ref, actor, and audience. Helm rendering alone is not acceptance.
