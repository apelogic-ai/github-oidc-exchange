# Upgrade to 0.7.7 — chart-owned workload policy

Application/chart 0.7.7 is a default-preserving update. Existing GitHub v5/v6
exchange, generic OIDC, workload exchange, routes, audiences, token lifetimes,
OCI coordinates, signer identity, and signature filenames remain unchanged.
A chart-owned workload-policy ConfigMap requires an explicit operator choice.

## Compatibility matrix

| Application/chart | Policy object | Output | Supported |
| --- | --- | --- | --- |
| 0.7.7 / 0.7.7 | `github-oidc-exchange.apelogic.io/v5` object | `steward-task-v2` | Yes; chart default |
| 0.7.7 / 0.7.7 | `github-oidc-exchange.apelogic.io/v6` object | `steward-task-v3` | Yes; explicit opt-in |
| 0.7.6 / 0.7.6 | matching v5 or v6 object | matching v2 or v3 | Rollback pair |

Keep application, chart, and GitHub policy selection together. There is no
database migration; retain the namespace so replay Leases remain intact.

## Preflight and upgrade

Download and verify the v0.7.7 release manifest and OCI attestations as
described in the [installation guide](installation.md). Set explicit cluster
coordinates, populate the verified image digest in the reviewed values file,
then render and upgrade:

```sh
export IDENTITY_VERSION=0.7.7
export IDENTITY_RELEASE=identity
export IDENTITY_NAMESPACE=identity
export IDENTITY_KUBECONFIG=/absolute/path/to/cluster-kubeconfig
export IDENTITY_CONTEXT=platform-context

bash scripts/validate-chart-values.sh /path/to/identity-values.yaml
helm lint charts/github-oidc-exchange \
  -f /path/to/identity-values.yaml --strict
helm template "$IDENTITY_RELEASE" charts/github-oidc-exchange \
  --namespace "$IDENTITY_NAMESPACE" \
  -f /path/to/identity-values.yaml >/tmp/identity-0.7.7.yaml

helm upgrade --install "$IDENTITY_RELEASE" charts/github-oidc-exchange \
  --version "$IDENTITY_VERSION" \
  --namespace "$IDENTITY_NAMESPACE" \
  --kubeconfig "$IDENTITY_KUBECONFIG" \
  --kube-context "$IDENTITY_CONTEXT" \
  -f /path/to/identity-values.yaml \
  --atomic --wait --timeout 10m
```

For an unchanged deployment, leave `workloadExchange.policy.create=false`. The
chart keeps using the existing workload-policy ConfigMap name and key without
rendering that object.

To let the chart own the workload policy, set
`workloadExchange.policy.create=true` and put the validated public policy object
in `workloadExchange.policy.document`. The chart validates the document, creates
`workloadExchange.policyConfigMapName` under
`workloadExchange.policyConfigMapKey`, and rolls the Deployment when the
document changes. Never put the workload RSA keyring or TLS private key in
chart values.

Helm refuses to create a ConfigMap that already exists outside the release.
When switching an existing installation to the chart-owned policy, either
delete the operator-managed ConfigMap in the same change window, or prepare it
for adoption by adding the label `app.kubernetes.io/managed-by=Helm` and the
annotations `meta.helm.sh/release-name=$IDENTITY_RELEASE` and
`meta.helm.sh/release-namespace=$IDENTITY_NAMESPACE` before the upgrade.

## Verification

```sh
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" \
  --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" rollout status \
  deployment/github-oidc-exchange --timeout=10m
```

Verify `/healthz`, `/readyz`, discovery, JWKS, one accepted GitHub exchange,
wrong audience, policy denial, and replay. When the chart owns the workload
policy, verify the rendered ConfigMap matches the reviewed document, the new
pods start (startup refuses an invalid workload policy), and one admitted and
one unmapped workload identity are accepted and refused as expected.

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

Restore the prior application/chart and policy references as one unit. A 0.7.6
revision does not render the workload policy, so rolling back from a
chart-owned policy removes that ConfigMap. Keep a copy of the reviewed document
and recreate the operator-managed workload policy ConfigMap with the same name
and key immediately after the rollback, then verify workload readiness. Preserve
key overlap, policy objects, and replay Leases until token and rollback windows
have expired.
