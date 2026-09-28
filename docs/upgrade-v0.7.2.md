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
export IDENTITY_NAMESPACE=identity
export IDENTITY_RELEASE=github-oidc-exchange

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
helm upgrade "$IDENTITY_RELEASE" \
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
