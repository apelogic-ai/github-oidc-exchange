# github-oidc-exchange

`github-oidc-exchange` validates a tightly scoped GitHub Actions OIDC token
and issues a short-lived task identity. It can also, when explicitly enabled,
exchange an exact Kubernetes service-account identity over a separate internal
TLS listener. It is an identity boundary, not a general OAuth provider.

The chart is an OCI Helm chart. Every deployment must select a signed,
immutable image digest and must own its policy, signing keys, and ingress
configuration outside this chart.

## Quick start and validation

The chart defaults are intentionally renderable but non-operational: they use
`example.invalid`, a reserved TEST-NET CIDR, object references which do not
exist, and a placeholder image digest. They exist so package consumers can
inspect a deterministic manifest; they are never a deployment profile.

Copy [`examples/production-values.yaml`](examples/production-values.yaml) into
your deployment repository, replace all example values, and keep key material
in an external Secret controller or an existing Kubernetes Secret. Never put
private keys, GitHub policy data, registry credentials, or cloud credentials in
values files.

```console
helm lint charts/github-oidc-exchange
helm template identity charts/github-oidc-exchange > /tmp/identity-default.yaml
helm lint charts/github-oidc-exchange \
  -f charts/github-oidc-exchange/examples/production-values.yaml
helm template identity charts/github-oidc-exchange \
  --namespace github-oidc-exchange \
  -f charts/github-oidc-exchange/examples/production-values.yaml \
  > /tmp/identity-production-example.yaml
```

Before applying a real release, verify the selected image digest and chart
digest/signature according to the repository release evidence. Helm values
contain references only; create and verify the referenced ConfigMap and Secret
objects before Helm reconciles the Deployment.

## Bring-your-own Kubernetes deployment

The chart does not assume a particular GitOps controller, cloud, registry, IAM
mechanism, secret controller, ingress implementation, or monitoring stack.
Supply an immutable image reference, pre-projected object references,
service-account annotations when your platform needs them, ingress controller
annotations or Gateway API parent references, source CIDRs, and optional
Prometheus discovery labels through a deployment-owned values file. The chart
neither creates cloud identities nor contains their credentials.

There is one deliberate product compatibility boundary: this is not a general
purpose OIDC issuer. The GitHub exchange contract has the fixed output audience
`steward-task-api` and emits `identity_contract=steward-task-v1`; the optional
workload profile has the fixed output audience `openshell-api`. Deploying it for
an arbitrary relying-party audience or identity contract requires a separately
reviewed product protocol change, not a Helm override. The optional
`browserHop1` feature is similarly product-specific and remains disabled by
default; it is not required for the ordinary GitHub or workload profiles.

## Required production inputs

| Value | Requirement |
| --- | --- |
| `image.repository`, `image.digest` | Registry path and exact `sha256` digest for a signed release image. |
| `config.issuerUrl` | Public HTTPS issuer URL; it must match the URL advertised to GitHub and token consumers. |
| `config.githubExchangeAudience` | Dedicated inbound GitHub OIDC audience, not a generic cloud audience. |
| `config.policyConfigMapName` | Deployment-owned ConfigMap containing the reviewed GitHub authorization/mapping policy. |
| `config.keyringSecretName` | Pre-projected Secret containing the signing keyring. The chart never creates it. |
| `rolloutRevisions.githubPolicy`, `rolloutRevisions.githubKeyring` | Non-secret opaque revision values used to roll the pods after a verified projection. |
| `networkPolicy.ingressCidrs` | Trusted CIDRs of the ingress/load-balancer path. Do not use `0.0.0.0/0`. |

`image.pullSecrets` is optional and contains only names of pre-existing
Kubernetes Secrets. On cloud platforms that grant registry access to nodes or
workload identity, leave it empty.

## Security and identity boundaries

- The Deployment always runs as non-root, drops all Linux capabilities, uses
  RuntimeDefault seccomp, and has a read-only root filesystem.
- The service account receives only namespaced Lease access required by the
  replay ledger. Set `serviceAccount.create: false` to use an externally
  managed account with the specified `serviceAccount.name`; the namespaced Role
  binding still targets that exact account.
- The GitHub listener is HTTP inside the cluster on `8080`. Gateway API
  `HTTPRoute` is the preferred public-routing integration: it accepts explicit
  platform-owned Gateway parent references and exposes only discovery, JWKS,
  and `/v1/exchange`. It never exposes health, metrics, or workload exchange.
  The Gateway owns public TLS and listener policy. Enable `httpRoute` only when
  the Gateway API CRDs are installed; otherwise leave it disabled and create an
  equivalent platform-owned route separately. The legacy `ingress` option is
  retained for compatible installations but cannot be enabled with
  `httpRoute`.
- NetworkPolicy permits configured public source CIDRs only to port `8080`.
  DNS and outbound TCP `443` are explicit because the service needs GitHub
  JWKS and external replay/cluster services; network policy alone is not an
  authorization boundary for those destinations.
- `workloadExchange.enabled: true` adds a dedicated HTTPS `8443` Service port,
  a narrow TokenReview ClusterRole (`create` only), and an ingress rule limited
  to the exact configured namespace and pod selectors. Its TLS Secret,
  workload policy ConfigMap, and RSA keyring Secret must be separately
  projected and reviewed. The workload endpoint is never added to Ingress.

## Availability and observability

The default has two replicas, rolling updates with `maxUnavailable: 0`, a
PodDisruptionBudget of one available pod, readiness and liveness probes, and
resource requests/limits. Adjust scheduling only with `nodeSelector`,
`tolerations`, and `affinity`; the container security posture is deliberately
not configurable through values.

Set `serviceMonitor.enabled: true` only when the Prometheus Operator CRD is
installed. `serviceMonitor.labels` supports the release-selector labels that a
Prometheus installation may require. Metrics remain cluster-local on the HTTP
Service port and the NetworkPolicy adds the explicitly configured metrics
selector only when that monitor is enabled.

## Rotation

The chart hashes object references plus each non-secret rollout revision into
the pod template. It never reads Secret content. For signing keys and TLS:

1. Project and verify overlapping material in the existing object.
2. Bump only the matching `rolloutRevisions` value in a reviewed deployment
   change.
3. Verify the rolling restart and overlap period before removing old material.

See the repository-level [keyring contract](../../docs/keyring-contract.example.json)
and [workload RSA contract](../../docs/rsa-keyring-contract.example.json) for
the exact two-phase sequence.
