# github-oidc-exchange

`github-oidc-exchange` 0.6.0 is an MIT-licensed, fork-installable Kubernetes
identity service. It verifies short-lived GitHub Actions OIDC assertions and
issues two-minute ES256 tokens for Steward. An optional internal workload
profile uses Kubernetes TokenReview and issues separate RS256 tokens for
OpenShell-compatible consumers. The optional Steward browser HOP-1 bridge is
disabled by default. This service is not a general OAuth provider or GitHub
OAuth App.

Start with the [baseline quickstart](docs/quickstart.md). The
[installation guide](docs/installation.md) covers artifact publication,
Kubernetes inputs, exposure, TLS, activation, rollback, rotation, and
uninstall. The [integration guide](docs/integration.md) provides GitHub Actions
and steward-run examples. The [consumer contract](docs/consumer-contract-v1.md)
defines the normative routes, audiences, token contracts, and verification
requirements.

Release 0.6.0 supports two GitHub policy/token paths:

| Policy | Activation | Identity decision | Issued contract |
| --- | --- | --- | --- |
| `github-oidc-exchange.apelogic.io/v5` | Default and upgrade-safe | Exact subject, event, ref, and mapped numeric actor, plus numeric owner/repository IDs | `steward-task-v2`, unchanged |
| `github-oidc-exchange.apelogic.io/v6` | Explicit opt-in | Numeric owner/repository IDs plus only the optional selectors that are present | `steward-task-v3` |

The chart defaults to v5. Upgrading the 0.6.0 application while retaining the
existing v5 ConfigMap therefore preserves the v5 authorization decisions and
v2 token shape. Activating v6 requires both `config.policyContract` and
`config.policyConfigMapName` to select a separately created v6 policy object.
Never rewrite or delete the v5 object during activation. Rollback after v6
activation switches the application/chart revision and policy reference back
together. See the [0.6.0 upgrade guide](docs/upgrade-v0.6.0.md).

In v6, `actors`, `allowed_email_domains`, `acting_group_prefix`, repository
`subjects`, `events`, and `refs` are compatibility selectors. A selector is
validated and enforced when present. When actors are absent, any well-formed
numeric actor from the admitted numeric repository is authenticated. When
subjects, events, or refs are absent, Identity does not decide which branches,
tags, pull requests, workflow subjects, events, or actors may submit a run.
Those signed values remain validated source provenance. Steward remains
responsible for user binding and Task authority. Identity has no runtime
dependency on Steward and does not query Steward users, policies, or Tasks;
Steward is a downstream verifier of the issued contract.

The v3 token keeps the stable subject
`github-actions:actor:<numeric actor ID>`. A bounded signed GitHub login may be
included as display/audit metadata, never as a durable identifier or
authorization input. The policy-selected service-principal group is always
emitted. Email and human-identity groups are emitted only when the v6 policy
contains a validated actor mapping. The caller cannot select subject,
audience, service identity, groups, TTL, contract version, or source
provenance.

## Runtime contract

| Surface | Current status |
| --- | --- |
| Application and OCI Helm chart | `0.6.0` together; Kubernetes >=1.30; `linux/amd64` and `linux/arm64`. |
| GitHub input | GitHub RS256 assertion; exact configured input audience; immutable numeric owner/repository boundary; short freshness; replay protection; internally consistent signed provenance. |
| GitHub output | ES256; `aud=["steward-task-api"]`; 120-second TTL; `steward-task-v2` for v5 or `steward-task-v3` for v6. |
| Workload exchange | Off by default; internal HTTPS port 8443; exact TokenReview audience and service-account policy; RS256 `openshell-workload-v1`. |
| Browser HOP-1 | Off by default; requires workload exchange and a public Steward JWKS; see its [v1 contract](docs/browser-hop1-contract-v1.md). |
| Public routes | `/.well-known/openid-configuration`, `/jwks.json`, and `/v1/exchange` only. The workload route is never public. |

Discovery exposes the exact issuer, JWKS URI, GitHub exchange endpoint, exact
GitHub OIDC input audience, supported policy versions, and supported output
identity contracts. It exposes no policy contents, signing material, or
identity mappings.

The chart has no operational defaults for image digest, issuer URL, inbound
audience, policy/keyring references, or ingress source CIDRs. Copy
[`values.example.yaml`](charts/github-oidc-exchange/values.example.yaml) into
private deployment storage and fill it deliberately. The chart references
operator-owned Secrets and ConfigMaps; it never stores private keys, policy
mappings, TLS material, or registry credentials in Helm values.

`image.digest` must be the immutable digest from a release handoff or a
manifest-preserving mirror whose destination descriptor was verified. The
chart rejects placeholder and homogeneous digests; tag-only deployment is not
a fallback. Run `bash scripts/validate-chart-values.sh VALUES_FILE` before
install or reconciliation.

Every accepted GitHub source `jti` is single-use in a namespaced Kubernetes
Lease ledger. Neither source nor issued token is logged. Output audiences and
claims are fixed for the documented consumers. Public discovery and JWKS use
the configured HTTPS issuer. ES256 issuer keys are always present; workload
RSA keys appear only when that profile is enabled.

The AWS-independent
[portable release workflow](.github/workflows/portable-release.yml) publishes
signed native amd64/arm64 image and chart artifacts from a fork to its GHCR.
Operators may instead use another OCI registry with equivalent release gates.
Release identity is the exact source commit plus image/chart digests, never a
mutable tag.

The project license is [MIT](LICENSE). Review the
[third-party notice inventory](THIRD_PARTY_NOTICES.md), release SBOM, and
[changelog](CHANGELOG.md).

## Development and release checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
bash scripts/validate-release.sh
bash scripts/test-chart.sh
bash scripts/validate-chart-values.sh charts/github-oidc-exchange/examples/production-values.yaml
bash scripts/test-install-inputs.sh
bash scripts/test-kubectl-files.sh
helm lint charts/github-oidc-exchange -f charts/github-oidc-exchange/ci/test-values.yaml --strict
helm lint charts/github-oidc-exchange -f charts/github-oidc-exchange/ci/workload-values.yaml --strict
```

The Kubernetes Lease replay regression uses a disposable Kind cluster and must
use a task-owned kubeconfig. See [SECURITY.md](SECURITY.md) for private
vulnerability reporting and release blockers.
