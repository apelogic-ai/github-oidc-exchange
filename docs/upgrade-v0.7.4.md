# Upgrade to 0.7.4 — release boundary, diagnostics, and DNS replies

Application/chart 0.7.4 is a patch release. It preserves all public routes,
audiences, token lifetimes, policy contracts, and output identity contracts.
The chart still defaults to policy v5 and `steward-task-v2`; v6 and
`steward-task-v3` remain an explicit coordinated activation.

## Compatibility matrix

| Application/chart | Policy object | Output | Supported |
| --- | --- | --- | --- |
| 0.7.4 / 0.7.4 | `github-oidc-exchange-policy` (`github-oidc-exchange.apelogic.io/v5`) | `steward-task-v2` | Yes; chart default |
| 0.7.4 / 0.7.4 | `github-oidc-exchange-policy-v6` (`github-oidc-exchange.apelogic.io/v6`) | `steward-task-v3` | Yes; explicit opt-in |
| 0.7.3 / 0.7.3 | matching v5 or v6 object | matching v2 or v3 token | Rollback pair |

Do not combine an application from one row with a chart from another. Keep the
v5 and v6 ConfigMaps separately named through activation and rollback.

## Preflight

Use an explicit kubeconfig and context for every cluster command:

```sh
export IDENTITY_VERSION=0.7.4
export IDENTITY_RELEASE=identity
export IDENTITY_NAMESPACE=identity
export IDENTITY_KUBECONFIG=/absolute/path/to/cluster-kubeconfig
export IDENTITY_CONTEXT=platform-context

gh release download "v$IDENTITY_VERSION" \
  --repo apelogic-ai/github-oidc-exchange \
  --pattern release-manifest.json \
  --pattern release-manifest.sigstore.json \
  --dir ./dist

cosign verify-blob \
  --bundle ./dist/release-manifest.sigstore.json \
  --certificate-identity \
    https://github.com/apelogic-ai/github-oidc-exchange/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ./dist/release-manifest.json

export IDENTITY_IMAGE="$(jq -er .image ./dist/release-manifest.json)"
export IDENTITY_CHART="$(jq -er .chart ./dist/release-manifest.json)"

for artifact in "$IDENTITY_IMAGE" "$IDENTITY_CHART"; do
  cosign verify-attestation \
    --certificate-identity \
      https://github.com/apelogic-ai/github-oidc-exchange/.github/workflows/release.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --experimental-oci11=true \
    --new-bundle-format=true \
    --type slsaprovenance1 \
    "$artifact" >/dev/null
done
```

Verify the image and chart signatures plus their SPDX and SLSA attestations at
the exact manifest digests. The attached `release.slsa.json` is a predicate for
inspection; the verified OCI SLSA attestation is the authoritative statement.

Before rollout, confirm:

- the installed application and chart are the same prior version;
- the selected policy ConfigMap matches `config.policyContract`;
- `networkPolicy.dnsNamespaceSelector`, `dnsPodSelector`, and optional
  `dnsIpBlocks` select only the actual DNS responders;
- Kubernetes API CIDRs and ports cover both pre- and post-DNAT endpoints;
- the current signing key remains outside the readiness expiry window.

## Upgrade

Populate a reviewed values file with the verified image repository and digest,
then render and upgrade using the same explicit cluster target:

```sh
bash scripts/validate-chart-values.sh /path/to/identity-values.yaml
helm lint charts/github-oidc-exchange \
  -f /path/to/identity-values.yaml --strict
helm template "$IDENTITY_RELEASE" charts/github-oidc-exchange \
  --namespace "$IDENTITY_NAMESPACE" \
  -f /path/to/identity-values.yaml >/tmp/identity-0.7.4.yaml

helm upgrade --install "$IDENTITY_RELEASE" charts/github-oidc-exchange \
  --version "$IDENTITY_VERSION" \
  --namespace "$IDENTITY_NAMESPACE" \
  --kubeconfig "$IDENTITY_KUBECONFIG" \
  --kube-context "$IDENTITY_CONTEXT" \
  -f /path/to/identity-values.yaml \
  --atomic --wait --timeout 10m
```

The NetworkPolicy adds a peer-scoped ingress rule for DNS replies without a
destination-port restriction because replies target ephemeral client ports.
It does not admit arbitrary sources: it reuses the configured DNS
namespace/Pod selectors and literal DNS IP blocks.

## Verification

```sh
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" \
  --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" rollout status \
  deployment/github-oidc-exchange --timeout=10m

kubectl --kubeconfig "$IDENTITY_KUBECONFIG" \
  --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" get pods,networkpolicy
```

Verify `/livez`, `/readyz`, both discovery routes, JWKS, one accepted exchange,
wrong-audience denial, and replay denial. Confirm Pod logs contain no token or
private key material. When testing a JWKS outage, expect an `exchange_failed`
event with the failing JWKS stage and cause, plus HTTP 503
`temporarily_unavailable`.

From an admitted Pod, resolve `kubernetes.default.svc.cluster.local` and reach
the Kubernetes API through that name. This proves the DNS reply and API-server
egress paths together.

## Rollback

List revisions and restore the previously accepted 0.7.3 revision with the
same explicit cluster target:

```sh
helm history "$IDENTITY_RELEASE" \
  --namespace "$IDENTITY_NAMESPACE" \
  --kubeconfig "$IDENTITY_KUBECONFIG" \
  --kube-context "$IDENTITY_CONTEXT"

helm rollback "$IDENTITY_RELEASE" PREVIOUS_REVISION \
  --namespace "$IDENTITY_NAMESPACE" \
  --kubeconfig "$IDENTITY_KUBECONFIG" \
  --kube-context "$IDENTITY_CONTEXT" \
  --wait --timeout 10m
```

Rollback the application/chart and policy reference as one unit. Do not delete
the newer signing keys or policy object until all retained tokens and rollback
windows have expired.
