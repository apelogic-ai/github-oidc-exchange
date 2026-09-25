# Upgrade and v6 activation — 0.6.0

Application/chart 0.6.0 adds an opt-in source-authentication policy v6 and
`steward-task-v3` while preserving policy v5 and `steward-task-v2` unchanged.
This guide separates the behavior-preserving application upgrade from the
optional policy activation.

## Compatibility matrix

| Application/chart | Policy reference | Output | Supported |
| --- | --- | --- | --- |
| 0.6.0 / 0.6.0 | v5 ConfigMap | `steward-task-v2` | Yes; default |
| 0.6.0 / 0.6.0 | separate v6 ConfigMap | `steward-task-v3` | Yes; explicit opt-in |
| 0.5.1 / 0.5.1 | v5 ConfigMap | `steward-task-v2` | Yes; rollback target |
| 0.5.1 / 0.5.1 | v6 ConfigMap | — | No; startup cannot read v6 |

Never rewrite the v5 ConfigMap into v6. Retain both policy objects and their
reviewed private source files through the rollback window.

## Phase 1: upgrade the application with v5 unchanged

1. Record the current Helm revision, image/chart digests, policy object name,
   policy object `resourceVersion`, and public JWKS `kid` set.
2. Verify the current values select v5 explicitly:

   ```yaml
   config:
     policyContract: github-oidc-exchange.apelogic.io/v5
     policyConfigMapName: github-oidc-exchange-policy
   ```

3. Render 0.6.0 and verify it contains
   `EXPECTED_POLICY_VERSION=github-oidc-exchange.apelogic.io/v5` and mounts the
   existing v5 object.
4. Upgrade the 0.6.0 application/chart without changing the policy reference
   or `rolloutRevisions.githubPolicy`.
5. Prove the existing v5 positive case and the exact subject/event/ref/actor
   negative cases. Decode a private test token and verify
   `identity_contract=steward-task-v2`, required email/groups, fixed audience,
   and signed provenance.

Rollback of phase 1 is a normal Helm rollback because both revisions use v5.

## Phase 2: prepare v6 without mutating v5

1. Confirm Steward accepts `steward-task-v3`, requires the service-principal
   group, treats email and human-identity groups as optional, validates source
   provenance, and performs its own Task authorization.
2. Copy and privately edit `docs/policy-contract-v6.example.json`.
3. Keep only numeric owner/repository IDs for minimal source authentication.
   Add optional exact actors/subjects/events/refs only when Identity must
   retain that compatibility restriction.
4. Validate the JSON and create a new object:

   ```sh
   jq -e '.version == "github-oidc-exchange.apelogic.io/v6"' \
     ./private/policy-v6.json >/dev/null
   kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
     -n "$IDENTITY_NAMESPACE" create configmap github-oidc-exchange-policy-v6 \
     --from-file=policy.json=./private/policy-v6.json
   ```

5. Verify both `github-oidc-exchange-policy` (v5) and
   `github-oidc-exchange-policy-v6` exist with `policy.json`. Do not log their
   contents as rollout evidence:

   ```sh
   bash scripts/check-install-inputs.sh "$IDENTITY_KUBECONFIG" \
     "$IDENTITY_CONTEXT" "$IDENTITY_NAMESPACE"
   bash scripts/check-install-inputs.sh "$IDENTITY_KUBECONFIG" \
     "$IDENTITY_CONTEXT" "$IDENTITY_NAMESPACE" \
     --github-policy github-oidc-exchange-policy-v6
   ```

## Phase 3: activate v6 atomically

In one reviewed values revision, change all three fields:

```yaml
config:
  policyContract: github-oidc-exchange.apelogic.io/v6
  policyConfigMapName: github-oidc-exchange-policy-v6
rolloutRevisions:
  githubPolicy: v6-rev-1
```

Render first. Verify the Deployment mounts only the v6 reference and passes v6
as `EXPECTED_POLICY_VERSION`; verify neither policy ConfigMap is rendered or
modified by Helm. Apply one Helm upgrade and wait for all replicas.

After activation:

- discovery advertises both policy versions and both output contracts;
- a valid main-branch, feature-branch, tag, and pull-request assertion from the
  same admitted repository succeeds when those selectors are absent;
- two distinct well-formed numeric actors succeed when `actors` is absent;
- wrong numeric owner/repository, issuer, audience, signature, time,
  provenance, and replay cases fail;
- every configured optional selector retains exact denial behavior; and
- the output is `steward-task-v3`, with only the service-principal group and no
  human entitlement claims when no actor mapping is configured.

## Atomic rollback after v6 activation

Do not roll back only the image. An older binary cannot read v6. Roll back the
Helm revision that contains the application/chart and the two policy-selection
fields together:

```sh
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  history identity --namespace "$IDENTITY_NAMESPACE"
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  rollback identity PREVIOUS_V5_REVISION --namespace "$IDENTITY_NAMESPACE" \
  --wait --timeout 10m
```

Verify the restored Deployment uses the previous application image, v5 policy
reference, and `EXPECTED_POLICY_VERSION` v5. Then repeat discovery, v5 positive
and negative exchanges, token-contract verification, and replay denial. Leave
the v6 ConfigMap untouched until a separate retention decision; its presence
does not affect pods that mount v5.
