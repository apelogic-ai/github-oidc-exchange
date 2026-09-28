# Upgrade to 0.7.1 — key lifecycle and network policy

> Historical guide for the 0.7.1 boundary. For current 0.7.2 installation,
> integration guidance, and rollback, use the
> [installation guide](installation.md) and
> [0.7.2 upgrade guide](upgrade-v0.7.2.md).

Application/chart 0.7.1 adds runtime signing-key expiry enforcement,
pre-expiry readiness, public expiry metrics, `keyring-tool export-jwks`, and a
static-verifier rotation handoff. The chart raises its Kubernetes floor to
1.32 and requires scoped metrics selectors when ServiceMonitor is enabled.
Policy v5/v6 authorization and `steward-task-v2`/`steward-task-v3` token
behavior are unchanged.

The complete policy contract identifiers remain
`github-oidc-exchange.apelogic.io/v5` and
`github-oidc-exchange.apelogic.io/v6`.

## Compatibility matrix

| Application/chart | Policy reference | Output | Supported |
| --- | --- | --- | --- |
| 0.7.1 / 0.7.1 | `github-oidc-exchange-policy` (v5) | `steward-task-v2` | Yes; chart default |
| 0.7.1 / 0.7.1 | `github-oidc-exchange-policy-v6` (v6) | `steward-task-v3` | Yes; explicit opt-in |
| 0.7.0 / 0.7.0 | v5 or v6 ConfigMap | v2 or v3 | Historical rollback pair |

Keep each application/chart version paired with a policy contract it can
read. Never rewrite the v5 ConfigMap into v6. Retain both reviewed policy
objects through the rollback window.

## Preflight

1. Confirm every target cluster is Kubernetes 1.32 or newer.
2. Record the current Helm revision, image/chart digests, policy object name,
   policy object `resourceVersion`, keyring Secret `resourceVersion`, active
   public JWKS `kid` set, and issuer URL.
3. Inspect the active ES256 key and, when workload exchange is enabled, the
   RSA key validity windows. Complete rotation before upgrade if either key
   has seven days or less remaining, or explicitly choose a smaller tested
   `config.keyExpiryReadinessThresholdSeconds` value from 120 through
   31536000 seconds.
4. If `serviceMonitor.enabled=true`, set both
   `networkPolicy.metricsNamespaceSelector` and
   `networkPolicy.metricsPodSelector` to nonempty maps selecting only trusted
   monitoring Pods. Metrics and exchange traffic share port 8080.
5. Preserve the selected `config.policyContract`, policy ConfigMap name, and
   matching rollout revision. The chart defaults to v5; v6 requires explicit
   values and a separately named policy object.
6. Verify the 0.7.1 image and chart coordinates from the signed
   `release-manifest.json`; do not deploy by mutable tag alone.

## Upgrade

Validate the exact private values, then update the application and chart
together while retaining the current policy selection:

```sh
export IDENTITY_VERSION=0.7.1
bash scripts/validate-chart-values.sh ./private/values.yaml
helm lint charts/github-oidc-exchange -f ./private/values.yaml --strict
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  upgrade identity \
  "oci://registry.example.org/team/charts/github-oidc-exchange" \
  --version "$IDENTITY_VERSION" --namespace "$IDENTITY_NAMESPACE" \
  --values ./private/values.yaml --wait --timeout 10m
```

Do not change `config.policyContract`, `config.policyConfigMapName`, or the
corresponding rollout revision in the same upgrade unless the independently
reviewed goal is to activate v6. For v6 activation, retain
`github-oidc-exchange-policy` (v5), create
`github-oidc-exchange-policy-v6`, and change the contract, object reference,
and `rolloutRevisions.githubPolicy` atomically.

## Verify

1. Confirm all Pods are available and both `/healthz` and `/readyz` return
   200. A 503 from `/readyz` with healthy liveness indicates an enabled active
   signing key is within the configured pre-expiry window.
2. Scrape `github_oidc_exchange_signing_key_seconds_until_expiry` and, when
   workload exchange is enabled,
   `github_oidc_exchange_workload_signing_key_seconds_until_expiry`. Treat an
   absent expected gauge as a monitoring failure.
3. Fetch both discovery documents and the public JWKS. Confirm the metadata
   documents agree, the configured issuer and endpoints are unchanged, and
   the expected active `kid` is present.
4. Run a fresh admitted exchange plus denial/replay cases. For v5, verify the
   unchanged `steward-task-v2` claim set. For v6, verify `steward-task-v3`,
   required `actor_login`, required provenance actor, and either no
   compatibility identity claims or the complete configured set.
5. When ServiceMonitor is enabled, inspect the rendered NetworkPolicy and
   prove only the selected monitoring Pods can reach port 8080.

Identity does not decide absent optional source selectors; Steward performs
any user binding and Task authority remains downstream.

## Rotate and hand off static JWKS

Generated and added keys accept `--valid-for-days DAYS` from 1 through 3650
and default to 90 days. Add an overlap key, validate the private keyring, and
export the public set:

```sh
cargo run --locked --bin keyring-tool -- add-es256 \
  ./private/issuer-keyring.json issuer-next --valid-for-days 90
cargo run --locked --bin keyring-tool -- validate-es256 \
  ./private/issuer-keyring.json
cargo run --locked --bin keyring-tool -- export-jwks \
  ./private/issuer-keyring.json > ./private/issuer-jwks.json
jq -e '.keys | length >= 2' ./private/issuer-jwks.json >/dev/null
```

Publish the overlapping private keyring to Identity and wait for all Identity
replicas to expose both public keys. Before activating the new signer, publish
`issuer-jwks.json` to every mounted/static verifier using that deployment's
own version-checked update and reload/rollout procedure. Confirm every replica
accepts both `kid`s. Identity does not call, restart, or depend on Steward;
the signed JWKS handoff is the boundary.

After activation, verify a new token through every relying party. Retire the
old key only after the 120-second token lifetime, clock skew, refresh, and
rollback windows. Export and publish the retired public set again. The exact
Secret and ConfigMap replacement commands are in the
[installation runbook](installation.md#6-rotation-recovery-uninstall).

## Rollback

Rollback restores the complete previously accepted application/chart and
policy-reference revision:

```sh
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  rollback identity PREVIOUS_REVISION --namespace "$IDENTITY_NAMESPACE" \
  --wait --timeout 10m
```

Repeat readiness, discovery, JWKS, positive exchange, negative cases,
token-contract, replay, and NetworkPolicy checks. A 0.7.0 rollback removes
runtime expiry enforcement, readiness thresholds, expiry gauges, and the
`export-jwks` command. It does not revert keyring or static-verifier objects
changed separately; select an overlapping known-good key and republish its
public JWKS before rollback when a rotation was already in progress. Never
roll back only the image while leaving an incompatible chart or policy
reference.
