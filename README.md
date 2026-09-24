# github-oidc-exchange

`github-oidc-exchange` 0.5.1 is an MIT-licensed, fork-installable Kubernetes
identity service. Its baseline exchanges a short-lived GitHub Actions OIDC
assertion for a two-minute ES256 token after exact, default-deny policy checks.
An optional internal workload profile uses Kubernetes TokenReview and issues
a separate two-minute RS256 token for OpenShell-compatible consumers. The
optional Steward browser HOP-1 attestation bridge remains disabled by default.
It is not a general OAuth provider or a GitHub OAuth App.

For the shortest baseline path, start with the
**[customer quickstart](docs/quickstart.md)**. The
[canonical installation guide](docs/installation.md) covers every exposure
and TLS mode, fork-owned publication, workload exchange, upgrade/rollback,
key rotation, and uninstall. The [customer integration guide](docs/integration.md)
adds copy-ready GitHub Actions and steward-run examples. The
[v1 consumer contract](docs/consumer-contract-v1.md) defines the normative
routes, audiences, TTL, trust, and compatible versions used by
[Steward #103](https://github.com/apelogic-ai/steward/issues/103) and
[steward-run #41](https://github.com/apelogic-ai/steward-run/issues/41).
Release 0.5.1 retains the task-only GitHub policy contract v5 introduced in
0.5.0. The 0.5.0 release removed the
obsolete Service Envelope bootstrap profile and its privileged group without
changing normal governed-task tokens. Existing operators must follow the
atomic [v4-to-v5 upgrade guide](docs/upgrade-v0.5.0.md) when coming from
0.4.0. Operators already on 0.5.0 should follow the
[0.5.1 digest-validation upgrade guide](docs/upgrade-v0.5.1.md).

| Release surface | Current status |
| --- | --- |
| Rust application and OCI Helm chart | `0.5.1` together; Kubernetes >=1.30, `linux/amd64`/`linux/arm64`. |
| GitHub Actions exchange | Baseline enabled with task-only policy `github-oidc-exchange.apelogic.io/v5`. Input: GitHub RS256 assertion for configured audience; output: ES256, `aud=steward-task-api`, `identity_contract=steward-task-v2`. Workflow claims remain signed provenance, not authorization selectors. |
| Workload exchange | Off by default. Internal HTTPS Service port 8443 with customer PKI or cert-manager TLS, exact TokenReview audience and service-account policy; output: RS256, `aud=openshell-api`, `identity_contract=openshell-workload-v1`. |
| Browser HOP-1 | Off by default; requires workload listener and public Steward JWKS, per [its v1 contract](docs/browser-hop1-contract-v1.md). |
| Public routes | `/.well-known/openid-configuration`, `/jwks.json`, `/v1/exchange` only, via operator-owned HTTPS proxy, selected Ingress controller, or Gateway API HTTPRoute. Workload route is never public. |

The chart has **no operational defaults** for image digest, issuer URL,
inbound audience, policy/keyring references, or ingress source CIDRs. Copy
[`values.example.yaml`](charts/github-oidc-exchange/values.example.yaml) into
private deployment storage and fill it deliberately. The chart references
operator-owned Secrets/ConfigMaps; it never stores private keys, policy
identity mappings, or TLS material in Helm values. The workload-only RSA,
policy, TLS, and TokenReview permissions are absent from baseline mode.

`image.digest` must be the exact immutable digest from a published release
handoff or from a manifest-preserving mirror whose destination descriptor was
verified. The chart rejects all-zero and homogeneous hexadecimal sentinel
digests before rendering any Kubernetes object; tag-only deployment is not a
fallback. Static validation does not contact the registry: the operator owns
mirror authentication, registry reachability, and recording the verified
destination digest. Run `bash scripts/validate-chart-values.sh VALUES_FILE`
before install or reconciliation for an actionable values preflight.

GitHub's ordinary `sub` can be admitted by exact observed value while signed
numeric `repository_owner_id` and `repository_id` are checked independently.
The verified numeric actor mapping, event, ref, audience, and assertion
freshness are also mandatory; unreviewed identities fail closed. Every
accepted GitHub source `jti` is single-use in a namespaced Kubernetes Lease
ledger. A workload source token is reviewed by the Kubernetes API on every
exchange and may be reused while valid. Neither source nor issued token is
logged. The output audience/claims are intentionally fixed for current
Steward/OpenShell consumers, not configurable arbitrary relying parties.

Public discovery and JWKS reflect the exact configured HTTPS issuer. ES256
issuer keys are always present; RSA keys appear only in workload mode. Private
keyrings are generated/validated offline with `cargo run --locked --bin
keyring-tool -- ...`, mode 0600, and rotated with overlapping `kid`s and
revision-triggered Pod restarts. The chart also accepts customer-PKI TLS
Secrets or can request cert-manager Certificates for public Ingress and
internal workload TLS. Callers must verify certificate trust/SAN; a
self-signed development certificate is not production-ready.

The AWS-free [portable release workflow](.github/workflows/portable-release.yml)
publishes signed image and chart artifacts from a fork to its own GHCR using
native amd64/arm64 runners. Operators may instead publish through their own
OCI registry using the guide's commands and equivalent release gates. The
older ECR workflow is optional and is not an installation prerequisite.
Release identity is the exact source commit plus image/chart digests, not a
mutable tag. A fresh installation is accepted only after the guide's live
delivery tests; Helm rendering alone is insufficient.

The project license is [MIT](LICENSE); redistributed dependency and base-image
materials retain their own terms. Review the [third-party notice inventory](THIRD_PARTY_NOTICES.md)
and the release image SBOM for the exact digest. Release highlights and
upgrade-relevant history are maintained in the [changelog](CHANGELOG.md).

## Development and release checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
bash scripts/validate-release.sh
bash scripts/test-customer-chart.sh
bash scripts/validate-chart-values.sh charts/github-oidc-exchange/examples/production-values.yaml
bash scripts/test-install-inputs.sh
bash scripts/test-kubectl-files.sh
helm lint charts/github-oidc-exchange -f charts/github-oidc-exchange/ci/test-values.yaml --strict
helm lint charts/github-oidc-exchange -f charts/github-oidc-exchange/ci/workload-values.yaml --strict
```

The normal release image contains no test replay implementation. The
Kubernetes Lease replay semantics have a disposable Kind test in
`scripts/test-kubernetes-lease-replay-kind.sh`; it must use a task-owned
cluster and clean up its kubeconfig, containers, and generated credentials.
See [the security policy](SECURITY.md) for private vulnerability reporting
and release blockers.
