# GitHub OIDC exchange issuer

`github-oidc-exchange` is a platform-owned identity boundary. Its primary profile validates a
short-lived GitHub OIDC assertion, applies a private default-deny authorization and corporate
identity mapping, records the source `jti` in a Kubernetes Lease replay ledger, and issues a two-minute
ES256 token that an EKS external OIDC identity provider can authenticate. An opt-in workload
profile validates a projected Kubernetes service-account token through `TokenReview` and issues a
separate, two-minute RS256 token with server-selected roles for OpenShell 0.0.98 compatibility.

It is not a general OAuth provider, a Kubernetes authentication webhook, or part of any calling
application. Environment policy belongs in a private deployment repository; this repository
contains only the generic engine and chart.

## Protocol

- `GET /.well-known/openid-configuration` — public OIDC discovery.
- `GET /jwks.json` — active and overlapping public P-256 keys and, when workload exchange is
  enabled, the separate RSA keys.
- `POST /v1/exchange` — requires `Authorization: Bearer <GitHub OIDC JWT>`.
- `POST /v1/workload/exchange` — HTTPS-only, requires an empty body and
  `Authorization: Bearer <projected service-account JWT>`. The chart does not publish this path
  through its Ingress.
- `POST /v1/browser-hop1/exchange` — opt-in, HTTPS-only on that same internal workload listener.
  It accepts an exact Steward API service-account caller plus a short-lived ES256 Steward browser
  attestation and returns a 60-second MCP resource bearer. It is never public or browser-facing;
  see [the browser HOP-1 contract](docs/browser-hop1-contract-v1.md).
- `GET /healthz`, `GET /readyz`, `GET /metrics` — cluster-local operations endpoints.

The GitHub assertion must have:

- exact issuer `https://token.actions.githubusercontent.com` and a deployment-selected audience;
- `RS256` and a currently published GitHub signing key;
- a maximum ten-minute lifetime and valid `exp`, `iat`, and `nbf`;
- non-empty immutable `repository_owner_id`, `repository_id`, `actor_id`, `sub`, `jti`,
  `workflow_ref`, `job_workflow_ref`, `event_name`, and `ref` claims;
- an exact match in the private policy for subject, workflow, event, ref, and verified actor.

The output contains exactly one audience, the policy-verified `email`, `email_verified=true`,
deployment-ratified `groups`, and
`identity_contract=steward-task-v2`. Policy rules select one server-controlled identity profile:

- `task` emits exactly the service-principal, verified acting-user, and opaque canonical-user
  groups;
- `bootstrap` emits exactly the route-scoped service-envelope-bootstrap group.

Profiles are selected only by exact GitHub claim matches. The caller cannot request a profile,
canonical user ID, or output groups, and ambiguous matching rules fail closed. Each reviewed actor
mapping owns one unique `usr_<32 lowercase hex>` Steward user ID. GitHub claims and workflow inputs
cannot override that mapping. The mapped ID must already resolve to the same reviewed person in
Steward; policy rollout does not register or discover users. The source assertion and issued token
are never logged.

The workload profile has a separate default-deny policy. It asks the Kubernetes API to review the
source token against one exact configured audience and requires an exact service-account username
mapping. The request cannot select an audience, subject, role, signing algorithm, or lifetime. The
initial OpenShell contract emits exactly one audience, a stable workload subject, the policy-owned
`roles` array, and `identity_contract=openshell-workload-v1`. It deliberately does not emit GitHub
claims, corporate email, or Steward groups. Unlike GitHub's one-time assertion, a rotating bound
service-account token may be exchanged more than once during its validity window.

OpenShell 0.0.98 accepts only RS256, so workload tokens use a dedicated RSA-3072-or-larger keyring.
GitHub exchange tokens remain ES256 under all configurations; callers cannot choose either
algorithm. This compatibility keyring can be retired after a reviewed OpenShell release containing
[NVIDIA/OpenShell PR #2593](https://github.com/NVIDIA/OpenShell/pull/2593) is deployed and the
workload profile is migrated through a separately reviewed contract change.

## Runtime configuration

| Environment variable | Contract |
|---|---|
| `ISSUER_URL` | Public HTTPS issuer URL used in discovery and `iss`. |
| `GITHUB_EXCHANGE_AUDIENCE` | Dedicated inbound GitHub OIDC audience. |
| `OUTPUT_AUDIENCE` | Must be `steward-task-api`. |
| `POLICY_FILE` | Mounted private JSON authorization/mapping policy. |
| `KEYRING_FILE` | Mounted Secrets Manager-backed signing keyring. |
| `REPLAY_LEASE_NAMESPACE` | Exact Kubernetes namespace where Identity creates namespaced replay `Lease` records. The chart sets this to its release namespace. |
| `LISTEN_ADDRESS` | Optional; defaults to `0.0.0.0:8080`. |
| `WORKLOAD_EXCHANGE_ENABLED` | Optional; `true` enables the separate internal workload listener and requires every workload setting below. |
| `WORKLOAD_LISTEN_ADDRESS` | Internal HTTPS listener; defaults to `0.0.0.0:8443` and must differ from `LISTEN_ADDRESS`. |
| `WORKLOAD_INPUT_AUDIENCE` | Exact audience supplied to Kubernetes `TokenReview`. |
| `WORKLOAD_OUTPUT_AUDIENCE` | Must be `openshell-api`. |
| `WORKLOAD_POLICY_FILE` | Mounted private exact-username-to-subject-and-roles policy. |
| `WORKLOAD_RSA_KEYRING_FILE` | Mounted Secrets Manager-backed RSA-3072+ compatibility keyring. |
| `TLS_CERTIFICATE_FILE` | Server certificate chain PEM. Required when workload exchange is enabled. |
| `TLS_PRIVATE_KEY_FILE` | Server private-key PEM. Required when workload exchange is enabled. |
| `KUBERNETES_CA_CERTIFICATE_FILE` | Optional Kubernetes API CA path; defaults to the in-cluster service-account CA. |
| `KUBERNETES_SERVICE_ACCOUNT_TOKEN_FILE` | Optional rotating API credential path; defaults to the in-cluster service-account token. |
| `BROWSER_HOP1_ENABLED` | Optional; `true` enables the internal-only Steward browser-attestation exchange and requires the four settings below plus workload exchange. |
| `BROWSER_HOP1_STEWARD_ISSUER` | Exact HTTPS issuer of Steward's ES256 request attestations. |
| `BROWSER_HOP1_ASSERTION_AUDIENCE` | Exact Identity-only audience required on every Steward request attestation. |
| `BROWSER_HOP1_STEWARD_JWKS_FILE` | Read-only deployment-projected Steward public ES256 JWKS. |
| `BROWSER_HOP1_OUTPUT_AUDIENCE` | Exact HTTPS MCP resource audience on the issued HOP-1 bearer. |

Every accepted source assertion creates one deterministic, SHA-256-derived Kubernetes
`coordination.k8s.io/v1 Lease` in the configured namespace. The first atomic `create` accepts;
an existing unexpired record rejects replay. An expired record is reclaimed only with its current
`resourceVersion`, with one bounded re-read/retry on conflict. Every record is labelled
`github-oidc-exchange.apelogic.io/replay-ledger=v1`, retained through the source token expiry plus
five minutes, and never logged. Cleanup is best-effort: each accepted exchange scans at most two
50-item labelled pages from a persisted Kubernetes continuation cursor and deletes at most one
expired record. It re-reads that Lease and uses a resource-version precondition before deleting.
Correct replay protection never depends on cleanup succeeding.

The chart grants the Identity service account only namespaced `create`, `get`, `update`, `list`,
and `delete` on `coordination.k8s.io` `leases`; it has no cloud replay-store, AWS SDK, IRSA, database, or
Steward/Postgres dependency. When workload exchange is disabled, this Lease permission is still
required for GitHub assertion replay protection. Enabling workload exchange separately adds exactly
`create` on `tokenreviews.authentication.k8s.io`.

Workload exchange requires product-native server-authenticated TLS. The chart contract is:

- endpoint `https://github-oidc-exchange.github-oidc-exchange.svc.cluster.local:8443/v1/workload/exchange`;
- certificate SAN `github-oidc-exchange.github-oidc-exchange.svc.cluster.local`;
- TLS Secret keys `tls.crt` and `tls.key`;
- a caller-mounted public CA bundle supplied out of band by GitOps;
- bearer TokenReview plus exact policy mapping for caller authentication; mTLS is not required.

The public HTTP listener remains on port 8080 and serves discovery, JWKS, the GitHub exchange,
health, readiness, and metrics. The separate HTTPS listener on port 8443 serves only workload
exchange plus health/readiness. The public ALB backend and ServiceMonitor use port 8080; the
workload path is never registered on that listener or added to Ingress. NetworkPolicy allows the
configured public ingress CIDRs only to port 8080 and the exact Steward namespace/pod selectors
only to port 8443.

The pod needs outbound HTTPS for GitHub JWKS and the Kubernetes API. The chart's
`0.0.0.0/0:443` egress rule therefore does not claim destination-level Kubernetes API isolation;
TLS verification, exact TokenReview audience, workload policy, and IAM remain the authorization
boundaries.

Signing and TLS material are loaded only at process startup; there is no hot reload. Signing-key
rotation is two phase: first project an overlapping keyring, trigger a checksum-based rolling
restart, and verify both old and new public keys in JWKS; then select the new current key, roll
again, wait for every old two-minute token plus clock-skew allowance to expire, and only then remove
the old key in a final rollout. TLS/root rotation likewise publishes an overlapping caller trust
bundle before issuing the new serving certificate and rolling the pods. Remove the old root only
after every caller and server replica is verified on the new chain. ESO projection alone is not a
rollout mechanism.

The chart requires deployment-owned, non-secret `rolloutRevisions` for `githubPolicy`,
`githubKeyring`, `workloadPolicy`, `workloadRsaKeyring`, and `workloadTls`. Each revision is a short
opaque value such as `rev-2`, stored safely in Git and never derived from Secret bytes. The chart
combines the revision with its Kubernetes object/key references and hashes that tuple into the
pod-template annotation. A rotation must wait for ESO or cert-manager to project and securely
verify the new overlapping content, bump only the matching revision in a reviewed GitOps change,
and observe the resulting rolling restart before advancing to the removal phase. This requires no
Secret-reading principal, controller, or image. Unchanged references and revisions render stable
annotations.

See [the policy example](docs/policy-contract.example.json) and its
[JSON schema](docs/policy-contract.schema.json),
[P-256 key rotation contract](docs/keyring-contract.example.json),
[workload policy example](docs/workload-policy-contract.example.json),
[RSA key rotation contract](docs/rsa-keyring-contract.example.json), and the Helm chart under
`charts/github-oidc-exchange`.

## Development

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
helm lint charts/github-oidc-exchange -f charts/github-oidc-exchange/ci/test-values.yaml
helm template test charts/github-oidc-exchange -f charts/github-oidc-exchange/ci/test-values.yaml
docker build --platform linux/amd64 -t github-oidc-exchange:test .
docker build --platform linux/arm64 -t github-oidc-exchange:test-arm64 .
```

The normal release binary has no integration fixture or in-memory replay implementation. Its
replay behavior is verified against a disposable real Kind API by
`scripts/test-kubernetes-lease-replay-kind.sh`; that test creates only a temporary namespaced
service account and Lease records, uses a generated mode-0600 token file, and destroys the cluster
and all test material on exit.
