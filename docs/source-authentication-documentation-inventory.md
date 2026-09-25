# Source-authentication documentation inventory — 0.6.0

This inventory records the documentation currency review for policy v6 and
`steward-task-v3`.

| Surface | Disposition | Reason/evidence |
| --- | --- | --- |
| `README.md` | Updated | Current version, v5/v6 matrix, optional-selector semantics, discovery, Steward authority, and rollback. |
| `docs/installation.md` | Updated | Versioned object bill of materials, both policy preparation paths, chart selection, activation/rollback, and policy-specific delivery tests. |
| `docs/quickstart.md` | Updated | Current 0.6.0 commands and unchanged v5 default; links to explicit v6 activation. |
| `docs/integration.md` | Updated | Discovery-driven endpoint/audience, v5/v6 enrollment, conditional negatives, v3 consumer readiness, and Task-authority boundary. |
| `docs/consumer-contract-v1.md` | Updated | Normative v2/v3 claims, discovery fields, optional compatibility claims, and compatibility matrix. Filename retained for link stability. |
| `docs/policy-contract.schema.json` and `docs/policy-contract.example.json` | Reviewed, unchanged | Historical/current v5 schema and example remain strict and are still loaded by compatibility tests. |
| `docs/policy-contract-v6.schema.json` and `docs/policy-contract-v6.example.json` | Added | Exact new contract with optional compatibility selectors and minimal repository-only example. |
| `docs/steward-task-v3.example.json` | Added | Consumer conformance fixture with `actor_login`, canonical numeric actor subject, required provenance actor, and no partial compatibility identity. |
| `charts/github-oidc-exchange/README.md` | Updated | Chart default, explicit v6 selection, startup version guard, separate objects, and rollback. |
| `charts/github-oidc-exchange/values.yaml` | Updated | New `config.policyContract`; v5 is the default. |
| `charts/github-oidc-exchange/values.example.yaml` | Updated | Copy-ready v5 default with explicit v6 activation comment. |
| `charts/github-oidc-exchange/values.schema.json` | Updated | Requires and enumerates the two supported policy contracts. |
| `charts/github-oidc-exchange/examples/production-values.yaml` | Updated | Current version and explicit v5 contract/reference. |
| `CHANGELOG.md` | Updated | Unchanged default, v6 activation, discovery, compatibility, and rollback. |
| `docs/releases/v0.6.0.md` | Added | Release behavior, compatibility, discovery, rollback, and artifact evidence. |
| `docs/upgrade-v0.6.0.md` | Added | Two-phase upgrade/activation and atomic rollback procedure. |
| Versioned 0.5.0/0.5.1 release and upgrade documents | Marked historical | Historical claims remain intact; notices link to current contract and upgrade documents. |
| `.github/workflows/release.yml` and `portable-release.yml` | Updated | Release handoff preserves default contracts and advertises both supported lists. |
| `scripts/test-docs-drift.sh` | Updated | Validates versions, schemas/examples, current links, required semantics, release notes, and policy/object pairings. |
| `SECURITY.md` | Unaffected | Vulnerability reporting and disclosure policy do not describe GitHub policy/token semantics. |
| `docs/browser-hop1-contract-v1.md` | Unaffected | Separate browser attestation contract; v5/v6 selection does not change it. |
| Workload policy schema/example | Unaffected | Separate Kubernetes TokenReview contract; no GitHub source-policy fields. |
| GitHub claim-probe and exchange-smoke workflow examples | Updated | Neutralized operator comments; inputs remain the discovered endpoint/audience and no workflow file encodes a policy version or output entitlement requirement. |

The CI drift gate and Rust contract tests mechanically validate the copy-ready
policy JSON/schema examples, Helm examples, discovery fields, v5 compatibility,
v6 selector omission/presence, and v2/v3 output claims.
