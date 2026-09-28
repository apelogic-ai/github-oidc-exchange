# Upgrade to 0.7.2 — release evidence and integration guidance

Application/chart 0.7.2 is a patch release. It does not change Identity's
runtime routes, token claims, audiences, policy schemas, or supported
Kubernetes floor. It removes private-registry details and raw internal scan
inputs from public release assets, derives the published chart Kubernetes
range from `Chart.yaml`, and documents the current steward-run discovery flow
and the exact Steward/OpenShell workload pairing.

## Compatibility

| Application/chart | Policy object | Output contract | Supported |
| --- | --- | --- | --- |
| 0.7.2 / 0.7.2 | `github-oidc-exchange-policy` (`github-oidc-exchange.apelogic.io/v5`) | `steward-task-v2` | Yes; chart default |
| 0.7.2 / 0.7.2 | `github-oidc-exchange-policy-v6` (`github-oidc-exchange.apelogic.io/v6`) | `steward-task-v3` | Yes; explicit opt-in |
| 0.7.1 / 0.7.1 | matching v5 or v6 object | matching v2 or v3 token | Rollback pair |

The chart defaults to v5. Keep v5 and v6 policies as separately named
ConfigMaps. Upgrading while retaining the v5 reference preserves the existing
authorization behavior and v2 token shape. Selecting v6 remains a separate,
explicit activation.

The default object is `github-oidc-exchange-policy` (v5); the opt-in object is
`github-oidc-exchange-policy-v6`.

Identity authenticates the signed source. When optional v6 selectors are
absent, Identity does not decide which workflow subjects, events, refs, or
actors may submit a run. Steward performs any user binding and decides Task
authority. Identity does not call Steward or depend on its runtime state.

## Preflight

1. Confirm Kubernetes 1.32 or newer.
2. Download `release-manifest.json` and
   `release-manifest.sigstore.json` from the v0.7.2 release.
3. Verify the signed handoff, then obtain the immutable public image and chart
   coordinates from it. Do not derive deployment coordinates from a mutable
   tag.
4. Preserve the current namespace, release name, policy ConfigMap, keyring
   Secret, issuer origin, inbound audience, and replay Lease state.
5. Render the chart with the private values file and run the checked-in
   validation scripts before rollout.

```sh
export IDENTITY_VERSION=0.7.2
export IDENTITY_KUBECONFIG=/absolute/path/to/cluster-kubeconfig
export IDENTITY_CONTEXT=platform-context
export IDENTITY_NAMESPACE=identity
export IDENTITY_RELEASE=identity

gh release download "v$IDENTITY_VERSION" \
  --repo apelogic-ai/github-oidc-exchange \
  --pattern release-manifest.json \
  --pattern release-manifest.sigstore.json \
  --dir ./dist

cosign verify-blob \
  --bundle ./dist/release-manifest.sigstore.json \
  --certificate-identity-regexp \
  '^https://github.com/apelogic-ai/github-oidc-exchange/.github/workflows/(release|portable-release)\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ./dist/release-manifest.json
```

The public handoff intentionally contains public GHCR coordinates and
verification material only. Private registry descriptors and raw internal
scan/SBOM inputs are not release assets. SPDX SBOM and SLSA provenance remain
attached to the public OCI image and chart as signed attestations.

## Upgrade

Use the chart version and immutable image digest from the verified handoff:

```sh
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  upgrade "$IDENTITY_RELEASE" \
  oci://ghcr.io/apelogic-ai/charts/github-oidc-exchange \
  --version "$IDENTITY_VERSION" \
  --namespace "$IDENTITY_NAMESPACE" \
  --values ./private/values.yaml \
  --set-string image.tag="$IDENTITY_VERSION" \
  --set-string image.digest="$(jq -er '.image | capture("@(?<digest>sha256:[0-9a-f]{64})$").digest' ./dist/release-manifest.json)" \
  --wait
```

Do not change the selected policy contract during the binary/chart upgrade.
If v6 activation is desired, perform it later as a distinct reviewed change.

## Optional v6 activation

Complete the behavior-preserving application/chart upgrade and its v5
verification before starting this phase. Retain the reviewed v5 ConfigMap and
the Helm revision that uses it throughout the rollback window.

### Prepare the separate v6 policy

1. Confirm every deployed Steward verifier accepts `steward-task-v3`, reads
   `actor_login`, accepts either no compatibility identity claims or the
   complete validated set, validates the required provenance actor, and
   performs its own Task authorization. Validate against
   [`steward-task-v3.example.json`](steward-task-v3.example.json).
2. Copy and privately edit
   [`policy-contract-v6.example.json`](policy-contract-v6.example.json).
3. Keep only positive canonical numeric owner/repository IDs for minimal
   source authentication. Add optional exact subjects, events, and refs
   independently. Add `actors` only together with `allowed_email_domains` and
   `acting_group_prefix` when the complete v2-compatible transition identity
   is required.
4. Validate the private policy and create a new ConfigMap without modifying
   the v5 object:

   ```sh
   jq -e '.version == "github-oidc-exchange.apelogic.io/v6"' \
     ./private/policy-v6.json >/dev/null
   kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
     -n "$IDENTITY_NAMESPACE" create configmap github-oidc-exchange-policy-v6 \
     --from-file=policy.json=./private/policy-v6.json
   ```

5. Verify both policy ConfigMaps exist with `policy.json`. Do not log policy
   contents as rollout evidence:

   ```sh
   bash scripts/check-install-inputs.sh "$IDENTITY_KUBECONFIG" \
     "$IDENTITY_CONTEXT" "$IDENTITY_NAMESPACE"
   bash scripts/check-install-inputs.sh "$IDENTITY_KUBECONFIG" \
     "$IDENTITY_CONTEXT" "$IDENTITY_NAMESPACE" \
     --github-policy github-oidc-exchange-policy-v6
   ```

### Activate all three values atomically

In one reviewed values revision, change all three fields:

```yaml
config:
  policyContract: github-oidc-exchange.apelogic.io/v6
  policyConfigMapName: github-oidc-exchange-policy-v6
rolloutRevisions:
  githubPolicy: v6-rev-1
```

Render before applying. Verify the Deployment mounts only the v6 ConfigMap,
passes `EXPECTED_POLICY_VERSION=github-oidc-exchange.apelogic.io/v6`, and does
not render or mutate either policy ConfigMap. Apply one Helm upgrade and wait
for every replica.

After activation, prove that:

- discovery advertises both policy versions and both output contracts;
- accepted signed assertions from the admitted numeric repository succeed
  when their corresponding optional selectors are absent;
- wrong numeric owner/repository, issuer, audience, signature, time,
  provenance, and replay cases fail;
- every configured optional selector retains exact denial behavior; and
- the output is `steward-task-v3`, includes `actor_login`, and omits `email`,
  `email_verified`, and `groups` together when the actor compatibility bundle
  is absent.

### Roll back v6 activation atomically

Do not roll back only the image. An older binary cannot read v6. Roll back the
Helm revision containing the application/chart and all three policy-selection
values together:

```sh
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  history "$IDENTITY_RELEASE" --namespace "$IDENTITY_NAMESPACE"
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  rollback "$IDENTITY_RELEASE" PREVIOUS_V5_REVISION \
  --namespace "$IDENTITY_NAMESPACE" --wait --timeout 10m
```

Verify the restored Deployment uses the previous application image, v5 policy
reference, v5 `EXPECTED_POLICY_VERSION`, and previous GitHub-policy rollout
revision. Repeat discovery, v5 positive and negative exchanges, token-contract
verification, and replay denial. Leave the v6 ConfigMap untouched until a
separate retention decision; its presence does not affect Pods that mount v5.

## Verification

- Fetch both discovery documents and require identical issuer, JWKS, exchange
  URL, `github_oidc_audience`, supported policy versions, and supported output
  contracts.
- Fetch `/jwks.json` and verify the expected ES256 key remains published.
- Run one accepted exchange and the denial cases for a wrong audience,
  replayed assertion, and unadmitted repository.
- For steward-run, omit the deprecated explicit Identity exchange inputs in
  the normal path and verify discovery begins at the configured Steward API.
- If workload exchange is enabled, verify the exact values in
  [the Steward/OpenShell pairing guide](steward-openshell-workload-pairing.md).

## Rollback

Atomic rollback restores the complete 0.7.1 application/chart pair and the
matching policy reference. Keep the namespace and replay Leases. If the
upgrade did not change policy selection, the same policy object remains
valid.

```sh
helm rollback "$IDENTITY_RELEASE" PREVIOUS_REVISION \
  --namespace "$IDENTITY_NAMESPACE" \
  --wait
```

After rollback, repeat discovery, JWKS, exchange, readiness, and denial tests.
Release-evidence changes do not require a runtime configuration rollback.
