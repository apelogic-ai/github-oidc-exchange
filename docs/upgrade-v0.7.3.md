# Upgrade to 0.7.3 — network, rollout, and release assets

Application/chart 0.7.3 is a patch release. It preserves Identity's routes,
token claims, audiences, policy schemas, supported Kubernetes floor, and
default v5 behavior. The release adds portable API-server egress, optional
automated projected-input rollouts, image-bundled key administration,
release-attached policy assets, maintained Artifact Hub metadata, and corrected
integration guidance.

## Compatibility

| Application/chart | Policy object | Output contract | Supported |
| --- | --- | --- | --- |
| 0.7.3 / 0.7.3 | `github-oidc-exchange-policy` (`github-oidc-exchange.apelogic.io/v5`) | `steward-task-v2` | Yes; chart default |
| 0.7.3 / 0.7.3 | `github-oidc-exchange-policy-v6` (`github-oidc-exchange.apelogic.io/v6`) | `steward-task-v3` | Yes; explicit opt-in |
| 0.7.2 / 0.7.2 | matching v5 or v6 object | matching v2 or v3 token | Rollback pair |

The chart defaults to v5. Keep v5 and v6 policies as separately named
ConfigMaps. Upgrading while retaining the v5 reference preserves the existing
authorization behavior and v2 token shape. Selecting v6 remains a separate,
explicit activation with an atomic rollback plan.

Identity authenticates the signed source. When optional v6 selectors are
absent, Identity does not decide which workflow subjects, events, refs, or
actors may submit a run. Steward performs any user binding and decides Task
authority. Identity does not call Steward or depend on its runtime state.

## Preflight

1. Confirm Kubernetes 1.32 or newer and identify the actual API-server
   destination and port after Service DNAT.
2. Download `release-manifest.json` and
   `release-manifest.sigstore.json` from the v0.7.3 release and verify the
   signed handoff.
3. Obtain the immutable public image and chart coordinates from that handoff.
   Do not derive deployment coordinates from a mutable tag.
4. Preserve the current namespace, Helm release name, policy ConfigMap,
   keyring Secret, issuer origin, inbound audience, and replay Lease state.
5. Choose one projected-input rollout mechanism: explicit
   `rolloutRevisions`, or an already governed Stakater Reloader installation
   with `rolloutAutomation.reloader.enabled=true`.
6. Render and validate the chart with the private values file before rollout.

```sh
export IDENTITY_VERSION=0.7.3
export IDENTITY_KUBECONFIG=/absolute/path/to/cluster-kubeconfig
export IDENTITY_NAMESPACE=identity
export IDENTITY_RELEASE=identity
export IDENTITY_CONTEXT=platform-context

gh release download "v$IDENTITY_VERSION" \
  --repo apelogic-ai/github-oidc-exchange \
  --pattern release-manifest.json \
  --pattern release-manifest.sigstore.json \
  --pattern policy-contract.example.json \
  --pattern policy-contract.schema.json \
  --pattern policy-contract-v6.example.json \
  --pattern policy-contract-v6.schema.json \
  --dir ./dist

cosign verify-blob \
  --bundle ./dist/release-manifest.sigstore.json \
  --certificate-identity-regexp \
  '^https://github.com/apelogic-ai/github-oidc-exchange/.github/workflows/(release|portable-release)\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ./dist/release-manifest.json
```

## Values changes

The default egress policy now includes IPv4 and IPv6 HTTPS destinations and
API-server ports 443 and 6443. Keep both ports unless the cluster's pre- and
post-DNAT endpoint contract proves a narrower set. Configure literal NodeLocal
DNSCache CIDRs under `networkPolicy.dnsIpBlocks` and narrowly scoped proxy or
platform destinations under `networkPolicy.extraEgress`.

The controller-free path remains the default. Change only the matching
`rolloutRevisions` value in the same reviewed change as an externally owned
ConfigMap or Secret. If a platform-owned Reloader controller is already
installed and governed, enable:

```yaml
rolloutAutomation:
  reloader:
    enabled: true
```

The chart then emits the standard named ConfigMap and Secret watch annotations
for exactly the mounted inputs. It does not install Reloader or grant its RBAC.

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

Do not change policy selection during this binary/chart upgrade. If v6
activation is desired, perform it later as a distinct reviewed change that
switches `policyContract`, `policyConfigMapName`, and
`rolloutRevisions.githubPolicy` together.

## Optional v6 activation

Complete the application/chart upgrade and its v5 verification before this
phase. Retain the reviewed v5 ConfigMap and the Helm revision that uses it
throughout the rollback window.

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

5. Verify both policy ConfigMaps expose `policy.json` without logging their
   contents:

   ```sh
   bash scripts/check-install-inputs.sh "$IDENTITY_KUBECONFIG" \
     "$IDENTITY_CONTEXT" "$IDENTITY_NAMESPACE"
   bash scripts/check-install-inputs.sh "$IDENTITY_KUBECONFIG" \
     "$IDENTITY_CONTEXT" "$IDENTITY_NAMESPACE" \
     --github-policy github-oidc-exchange-policy-v6
   ```

### Activate all three values atomically

Set all three fields explicitly in one reviewed values revision:

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

### Roll back v6 activation atomically

Do not roll back only the image. Roll back the Helm revision containing the
application/chart and all three policy-selection values together:

```sh
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  history "$IDENTITY_RELEASE" --namespace "$IDENTITY_NAMESPACE"
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  rollback "$IDENTITY_RELEASE" PREVIOUS_V5_REVISION \
  --namespace "$IDENTITY_NAMESPACE" --wait --timeout 10m
```

Verify the restored Deployment uses the previous application image, v5 policy
reference, v5 `EXPECTED_POLICY_VERSION`, and previous GitHub-policy rollout
revision. Leave the v6 ConfigMap untouched until a separate retention
decision; its presence does not affect Pods that mount v5.

## Verification

- Require all replicas to complete the Deployment rollout and become ready.
- Fetch both discovery documents and require identical `issuer`, `jwks_uri`,
  `token_endpoint`, `github_oidc_exchange_endpoint`, `github_oidc_audience`,
  `identity_contracts_supported`, and `policy_versions_supported` values.
- Fetch `/jwks.json` and verify the expected ES256 key remains published.
- Run one accepted exchange and denial cases for wrong audience, replayed
  assertion, and an unadmitted repository.
- Verify replay Lease creation with API-server traffic on the cluster's actual
  post-DNAT port.
- When Reloader automation is enabled, make a harmless data change to one of
  the ConfigMaps named in the Deployment's Reloader annotation and verify
  every replica receives a new pod UID before relying on it for key or policy
  changes.
- If workload exchange is enabled, verify the exact values in the
  [Steward/OpenShell pairing guide](steward-openshell-workload-pairing.md).

## Rollback

Atomic rollback restores the complete 0.7.2 application/chart pair and its
matching policy reference. Keep the namespace and replay Leases. Retain both
versioned policy objects and overlapping signing keys until verification is
complete.

```sh
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  rollback "$IDENTITY_RELEASE" PREVIOUS_REVISION \
  --namespace "$IDENTITY_NAMESPACE" \
  --wait
```

After rollback, repeat discovery, JWKS, exchange, readiness, replay, and
denial tests. If Reloader automation itself caused a platform conflict, disable
it in the same rollback values while retaining explicit rollout revisions.
