# Upgrade to 0.7.5 — owner scope and operator observability

Application/chart 0.7.5 is non-breaking. It adds no required value and keeps
the public routes, audiences, token lifetimes, policy versions, output
contracts, OCI coordinates, signer identity, and signature filenames.

## Compatibility matrix

| Application/chart | Policy object | Output | Supported |
| --- | --- | --- | --- |
| 0.7.5 / 0.7.5 | `github-oidc-exchange.apelogic.io/v5` object | `steward-task-v2` | Yes; chart default |
| 0.7.5 / 0.7.5 | `github-oidc-exchange.apelogic.io/v6` object | `steward-task-v3` | Yes; explicit opt-in |
| 0.7.4 / 0.7.4 | matching v5 or v6 object | matching v2 or v3 | Rollback pair |

Keep application, chart, and policy selection together. Upgrading does not
change an existing exact repository rule into an owner-wide rule.

## Preflight and upgrade

Download and verify the v0.7.5 release manifest and OCI attestations as
described in the [installation guide](installation.md). Set explicit cluster
coordinates, populate the verified image digest in the reviewed values file,
then render and upgrade:

```sh
export IDENTITY_VERSION=0.7.5
export IDENTITY_RELEASE=identity
export IDENTITY_NAMESPACE=identity
export IDENTITY_KUBECONFIG=/absolute/path/to/cluster-kubeconfig
export IDENTITY_CONTEXT=platform-context

bash scripts/validate-chart-values.sh /path/to/identity-values.yaml
helm lint charts/github-oidc-exchange \
  -f /path/to/identity-values.yaml --strict
helm template "$IDENTITY_RELEASE" charts/github-oidc-exchange \
  --namespace "$IDENTITY_NAMESPACE" \
  -f /path/to/identity-values.yaml >/tmp/identity-0.7.5.yaml

helm upgrade --install "$IDENTITY_RELEASE" charts/github-oidc-exchange \
  --version "$IDENTITY_VERSION" \
  --namespace "$IDENTITY_NAMESPACE" \
  --kubeconfig "$IDENTITY_KUBECONFIG" \
  --kube-context "$IDENTITY_CONTEXT" \
  -f /path/to/identity-values.yaml \
  --atomic --wait --timeout 10m
```

To opt into owner-wide admission, create a separately reviewed v6 policy rule
with the exact numeric `owner_id` and `repository_id: "*"`. Retain any desired
`subjects`, `events`, `refs`, `job_workflow_refs`, or `job_workflow_shas`.
Do not add an exact repository rule for the same owner. Advance
`rolloutRevisions.githubPolicy` and verify a new repository is accepted only
under the intended selectors; confirm its concrete ID in source provenance.

If workload exchange was newly enabled or its RSA JWKS changed, follow the
[pairing guide](steward-openshell-workload-pairing.md) and restart OpenShell
before testing.

## Verification

```sh
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" \
  --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" rollout status \
  deployment/github-oidc-exchange --timeout=10m
```

Verify `/healthz`, `/readyz`, discovery, JWKS, one accepted exchange, wrong
audience, policy denial, and replay. A readiness failure returns 503 JSON with
stable names such as `github_jwks` or `replay_ledger`. Confirm `/metrics`
contains HELP/TYPE lines, `github_oidc_exchange_duration_seconds`,
`github_oidc_exchange_jwks_age_seconds`, and
`github_oidc_exchange_jwks_refresh_failures_total`. The optional
`config.githubJwksMaxStalenessSeconds` defaults to 21600; retain that default
unless a reviewed outage and rotation policy requires a value from 600 through
604800 seconds. Confirm established audit reason values remain unchanged and
logs follow the
[operator observability contract](operator-observability-contract-v1.md)
without bearer or private-key material.

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

Restore the prior application/chart and policy reference as one unit. Preserve
key overlap, policy objects, and replay Leases until token and rollback windows
have expired.
