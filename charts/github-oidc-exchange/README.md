# github-oidc-exchange Helm chart 0.5.0

Read the repository's [canonical installation guide](../../docs/installation.md)
before deploying. It contains the exact prerequisites, Secret/ConfigMap bill
of materials, TLS modes, fork-owned artifact publication, upgrade/rollback,
rotation, post-install procedures, and live delivery checklist. The
[consumer contract v1](../../docs/consumer-contract-v1.md) lists routes,
audiences, token claims, and supported application/chart versions.
For the shortest baseline Gateway API path, use the
[customer quickstart](../../docs/quickstart.md); use the
[integration guide](../../docs/integration.md) for GitHub Actions and
steward-run examples.

Chart/application 0.5.0 requires the task-only GitHub policy v5. Operators
upgrading from 0.4.0 must switch the image/chart and policy ConfigMap reference
in one Helm revision; see the
[v4-to-v5 upgrade guide](../../docs/upgrade-v0.5.0.md). Rollback restores the
0.4.0/v4 pair, never only the image.

This chart deliberately fails Helm validation until a customer supplies a
fork-owned immutable image digest, HTTPS issuer, dedicated GitHub OIDC input
audience, policy ConfigMap, ES256 keyring Secret, rollout revisions, and
trusted ingress/proxy CIDRs. Copy [`values.example.yaml`](values.example.yaml)
to private deployment storage, fill its empty mandatory fields, and select
one route: Service-only behind a customer HTTPS proxy, Ingress with an explicit
class and TLS Secret, or HTTPRoute attached to an existing HTTPS Gateway.
No ALB, ECR, Secrets Manager, or ingress controller is assumed. Public TLS
may be an existing customer-PKI Secret or a chart-created cert-manager
Certificate; the Gateway owns TLS in HTTPRoute mode.

`image.digest` must come from the selected release's signed handoff or from a
verified manifest-preserving mirror. All-zero and other homogeneous
hexadecimal sentinel digests are rejected by the published values schema.
The chart does not test registry reachability during static validation; verify
the destination descriptor after copying, then record that exact digest.
For the clearest field-specific error before Helm or GitOps mutation, run:

```sh
bash scripts/validate-chart-values.sh /path/to/deployment-values.yaml
```

`workloadExchange.enabled=false` is baseline. Enabling it additionally
requires a dedicated RSA-3072 keyring Secret, workload policy ConfigMap,
server-authenticated TLS Secret, TokenReview ClusterRole/Binding, an exact
TokenReview audience, and nonempty caller namespace/pod selectors. Its
internal HTTPS path is never added to the public route. Internal TLS may be
an existing customer-PKI Secret or a chart-created cert-manager Certificate;
the caller must receive the public CA bundle and verify the Service DNS SAN.
The optional `browserHop1` feature requires workload exchange and a public
Steward JWKS ConfigMap.

```sh
# Default values fail intentionally; the CI fixtures are not install profiles.
helm lint charts/github-oidc-exchange -f charts/github-oidc-exchange/ci/test-values.yaml --strict
helm lint charts/github-oidc-exchange -f charts/github-oidc-exchange/ci/workload-values.yaml --strict
bash scripts/test-customer-chart.sh
```

Chart values contain object references only, never private key/policy/TLS
contents. The Deployment hashes each reference plus an opaque
`rolloutRevisions` value into its Pod template. After projecting a changed
input, bump **only** its matching revision and wait for rollout; the process
does not hot-reload signing keys or internal TLS. Maintain overlapping
signing keys/trust through the token TTL plus skew and rollback window.
