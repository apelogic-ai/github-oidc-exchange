# Upgrade to 0.7.6 — optional issuers, workload tasks, and chart delivery

Application/chart 0.7.6 is a default-preserving update. Existing GitHub v5/v6
exchange, OpenShell workload role bindings, routes, audiences, token lifetimes,
OCI coordinates, signer identity, and signature filenames remain unchanged.
Generic OIDC, workload task bindings, tag-only images, and a chart-owned GitHub
policy ConfigMap each require an explicit operator choice.

## Compatibility matrix

| Application/chart | Policy object | Output | Supported |
| --- | --- | --- | --- |
| 0.7.6 / 0.7.6 | `github-oidc-exchange.apelogic.io/v5` object | `steward-task-v2` | Yes; chart default |
| 0.7.6 / 0.7.6 | `github-oidc-exchange.apelogic.io/v6` object | `steward-task-v3` | Yes; explicit opt-in |
| 0.7.5 / 0.7.5 | matching v5 or v6 object | matching v2 or v3 | Rollback pair |

Keep application, chart, and GitHub policy selection together. There is no
database migration; retain the namespace so replay Leases remain intact.

## Preflight and upgrade

Download and verify the v0.7.6 release manifest and OCI attestations as
described in the [installation guide](installation.md). Set explicit cluster
coordinates, populate the verified image digest in the reviewed values file,
then render and upgrade:

```sh
export IDENTITY_VERSION=0.7.6
export IDENTITY_RELEASE=identity
export IDENTITY_NAMESPACE=identity
export IDENTITY_KUBECONFIG=/absolute/path/to/cluster-kubeconfig
export IDENTITY_CONTEXT=platform-context

bash scripts/validate-chart-values.sh /path/to/identity-values.yaml
helm lint charts/github-oidc-exchange \
  -f /path/to/identity-values.yaml --strict
helm template "$IDENTITY_RELEASE" charts/github-oidc-exchange \
  --namespace "$IDENTITY_NAMESPACE" \
  -f /path/to/identity-values.yaml >/tmp/identity-0.7.6.yaml

helm upgrade --install "$IDENTITY_RELEASE" charts/github-oidc-exchange \
  --version "$IDENTITY_VERSION" \
  --namespace "$IDENTITY_NAMESPACE" \
  --kubeconfig "$IDENTITY_KUBECONFIG" \
  --kube-context "$IDENTITY_CONTEXT" \
  -f /path/to/identity-values.yaml \
  --atomic --wait --timeout 10m
```

For an unchanged deployment, leave `genericOidc.enabled=false`, keep existing
workload role bindings, retain `image.requireDigest=true`, and leave
`policyConfigMap.create=false`.

To enable generic OIDC, create the exact-binding policy ConfigMap, configure
its rollout revision and issuer HTTPS egress, and test every accepted and
refused claim combination. If the issuer uses a private CA, configure only its
public certificates through `genericOidc.additionalCaSecret`; never place a
private key there. The complete Jenkins-compatible profile is in the
[integration guide](integration.md#jenkins-oidc-provider-profile).

To issue a pure-service task token from workload exchange, replace the selected
identity's role binding with one exact `task` binding and verify wrong audience,
expired projected token, unmapped identity, replay, and unavailable-ledger
refusals. Do not add both `roles` and `task` to one identity.

Use `image.requireDigest=false` only when the delivery platform enforces tag
immutability. Use `policyConfigMap.create=true` only for public authorization
data that passes the chart's complete v5/v6 validation; private keys, TLS
material, registry credentials, and generic/workload policies remain external.

## Verification

```sh
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" \
  --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" rollout status \
  deployment/github-oidc-exchange --timeout=10m
```

Verify `/healthz`, `/readyz`, discovery, JWKS, one accepted GitHub exchange,
wrong audience, policy denial, and replay. When generic OIDC is enabled, verify
that discovery advertises `/v1/oidc/exchange`, each configured provider can
recover independently, an unavailable provider returns 503 without changing
global readiness, and request bodies cannot select identity. When a workload
`task` binding is enabled, verify the issued token is ES256 with
`aud=["steward-task-api"]`, contains only the policy-bound pure-service groups,
and has no acting-user group or source provenance.

## Rollback

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

Restore the prior application/chart and policy references as one unit. Disable
generic OIDC or workload `task` bindings before rolling back to 0.7.5, which
does not implement those profiles. Preserve key overlap, policy objects, and
replay Leases until token and rollback windows have expired.
