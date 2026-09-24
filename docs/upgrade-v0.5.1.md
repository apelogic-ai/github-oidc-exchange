# Upgrade to 0.5.1: immutable image digest validation

Release 0.5.1 closes `ID-CUST-001` by rejecting placeholder image digests
before Kubernetes mutation. The published Helm schema and chart-owned values
preflight reject the all-zero SHA-256 value and every homogeneous hexadecimal
sentinel. Tag-only deployment remains unsupported.

The runtime and identity protocols are unchanged from 0.5.0:

- GitHub policy remains `github-oidc-exchange.apelogic.io/v5`;
- issued task tokens remain `steward-task-v2` with audience
  `steward-task-api`;
- workload exchange and browser HOP-1 contracts are unchanged;
- keyring, policy, TLS, and replay data require no migration.

## Check existing values

Run the product preflight from a 0.5.1 source checkout:

```sh
bash scripts/validate-chart-values.sh ./private/values.yaml
```

If `image.digest` is empty, malformed, all-zero, or another homogeneous
sentinel, the command fails and names the exact field. Do not replace the
digest with a mutable tag or an invented 64-character value.

## Obtain the accepted coordinates

Download and verify the 0.5.1 signed release handoff, then read the immutable
image and chart references:

```sh
export RELEASE_REPOSITORY=apelogic-ai/github-oidc-exchange
export RELEASE_VERSION=v0.5.1
export RELEASE_EVIDENCE_DIR="$(mktemp -d)"
gh release download "$RELEASE_VERSION" --repo "$RELEASE_REPOSITORY" \
  --pattern release-manifest.json \
  --pattern release-manifest.sigstore.json \
  --dir "$RELEASE_EVIDENCE_DIR"

cosign verify-blob \
  --bundle "$RELEASE_EVIDENCE_DIR/release-manifest.sigstore.json" \
  --certificate-identity \
    https://github.com/apelogic-ai/github-oidc-exchange/.github/workflows/release.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$RELEASE_EVIDENCE_DIR/release-manifest.json"

export IDENTITY_IMAGE_REFERENCE="$(jq -er .image \
  "$RELEASE_EVIDENCE_DIR/release-manifest.json")"
export IDENTITY_CHART_REFERENCE="$(jq -er .chart \
  "$RELEASE_EVIDENCE_DIR/release-manifest.json")"
```

For a private registry, copy from `IDENTITY_IMAGE_REFERENCE` by immutable
digest using a manifest-preserving OCI copy, query the destination descriptor,
and record that returned digest. Static schema validation does not contact the
registry. The operator remains responsible for destination authentication,
reachability, retention, and OCI-referrer handling for signatures,
attestations, and SBOMs.

## Roll out

1. Record the accepted 0.5.0 Helm revision and its signed immutable image/chart
   coordinates.
2. Replace `image.repository`, optional `image.tag`, and `image.digest`
   together with the accepted 0.5.1 source or verified mirror coordinates.
3. Keep the existing v5 policy ConfigMap and signing keyring references.
4. Run the values preflight and strict Helm lint before reconciliation.
5. Upgrade application and chart together to 0.5.1 and wait for rollout.
6. Verify readiness, discovery/JWKS, a fresh admitted exchange, negative
   selector cases, and replay denial.

## Roll back

Restore the complete previously accepted 0.5.0 application/chart revision with
its verified immutable image digest and the same policy v5 ConfigMap. Do not
restore a sentinel digest or use a tag as execution identity. Verify rollout,
discovery/JWKS, and a fresh exchange after rollback.

Operators upgrading directly from 0.4.0 must first account for the atomic
application/policy boundary in the
[v4-to-v5 guide](upgrade-v0.5.0.md): 0.4.0 pairs with policy v4, while 0.5.0
and 0.5.1 pair with policy v5.
