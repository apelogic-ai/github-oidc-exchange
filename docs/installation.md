# Installation guide — github-oidc-exchange 0.6.0

This is the canonical operator guide for application **0.6.0**, Helm chart
**0.6.0**, and the [Identity consumer contracts](consumer-contract-v1.md).
It installs Identity in an operator-owned Kubernetes cluster from fork-owned
artifacts. No ApeLogic account, cloud credential, external secret controller,
GitHub OAuth App, or database is required. The baseline exchanges GitHub
Actions OIDC assertions; workload exchange and browser HOP-1 are opt-in.

The image/chart build, template, keyring, and object-name commands are tested
in this repository. Registry access, issuer DNS/TLS, real GitHub assertions,
and optional Kubernetes TokenReview must be tested in the target environment;
successful Helm rendering alone is not acceptance.

For an opinionated v5 installation using an existing HTTPS Gateway, start with
the [baseline quickstart](quickstart.md), then return here for operations and
optional features. Use the [integration guide](integration.md) for claim
observation, exchange smoke, and Steward integration.

Application 0.6.0 supports `github-oidc-exchange.apelogic.io/v5` and
`github-oidc-exchange.apelogic.io/v6`. The chart defaults to v5 and an existing
v5 ConfigMap, preserving `steward-task-v2` behavior. Policy v6 is an explicit
opt-in that issues `steward-task-v3`; activate it with a separately named
ConfigMap using the [0.6.0 upgrade procedure](upgrade-v0.6.0.md).
Existing older installations must first follow their version-specific guides.

## Prerequisites and decisions

| Input | Baseline GitHub issuer | Additional workload profile |
| --- | --- | --- |
| Cluster/architecture | Kubernetes >=1.30, `linux/amd64` or `linux/arm64`, working DNS, outbound HTTPS to GitHub JWKS and Kubernetes API; ability to create namespaced Lease Role/Binding and NetworkPolicy. Two schedulable replicas by default. | Cluster-admin or delegated right to create the chart's narrow TokenReview ClusterRole/Binding; caller namespace and pod labels for an exact NetworkPolicy selector. |
| Tools | Rust 1.95, Helm 3.17+, Docker/buildx, `kubectl`, `jq`, and `oras` for digest lookup; `crane` when mirroring; explicit kubeconfig/context. | Same, plus a projected, bound service-account token for each caller. |
| Registry | Fork-owned OCI image/chart repositories accessible from cluster nodes; immutable digest for image and chart. Private registry requires a pre-created `kubernetes.io/dockerconfigjson` pull Secret named only in `image.pullSecrets`. | Same image/chart. |
| Issuer/public network | Unique HTTPS issuer URL and DNS A/CNAME; publicly trusted certificate whose SAN covers its DNS name; select external HTTPS proxy + internal Service, chart Ingress with chosen controller, or chart HTTPRoute attached to an existing HTTPS Gateway. Allow its actual source CIDRs to port 8080. Hosted GitHub runners need a reachable public issuer/exchange; self-hosted runners may use a private route if DNS and trust agree. | Workload listener is internal Service port 8443 only. Server certificate SAN must include `github-oidc-exchange.<namespace>.svc.cluster.local`; distribute its public issuer CA bundle to callers and plan renewal/overlap. |
| GitHub policy | Dedicated inbound audience and immutable numeric `repository_owner_id`/`repository_id`. v5 additionally requires exact subject/event/ref and mapped actor. v6 enforces those selectors only when configured. All signed provenance remains shape- and consistency-validated. GitHub jobs need `permissions: id-token: write`. | Independent exact service-account username-to-subject/roles policy and TokenReview input audience. |
| Private material | Offline mode-0600 ES256 keyring; private policy file and object RBAC; TLS key controlled by the chosen certificate owner. | Offline mode-0600 RSA-3072 keyring; workload TLS private key and caller public CA trust. |
| Optional CRDs | Gateway API `gateway.networking.k8s.io/v1` for HTTPRoute, cert-manager `cert-manager.io/v1` for chart-created Certificate, Prometheus Operator for ServiceMonitor — only if selected. | cert-manager optional for internal serving Certificate too. |

Use an explicit kubeconfig and context for **every** command; do not use an
ambient context. In the examples below choose a real, isolated target:

```sh
export IDENTITY_KUBECONFIG=/absolute/path/to/cluster-kubeconfig
export IDENTITY_CONTEXT=platform-context
export IDENTITY_NAMESPACE=identity
export IDENTITY_ISSUER=https://identity.example.org
export IDENTITY_AUDIENCE=github-identity-exchange
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  get namespace "$IDENTITY_NAMESPACE" >/dev/null 2>&1 || \
  kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
    create namespace "$IDENTITY_NAMESPACE"
```

Do not run this against an existing namespace without reviewing its owner.
There is no Identity database or schema migration; the namespaced Lease replay
ledger is the only persistent runtime state.

## Exact object and integration bill of materials

All listed Identity objects live in the selected release namespace, `identity`
in these commands. The chart references but does **not** create policy/key/TLS
inputs unless cert-manager Certificate issuance is explicitly selected.
The chart regression checks object/key references against rendered
Deployment mounts and runtime file environment variables. The live checker
`scripts/check-install-inputs.sh` checks namespace, type, and key *names* only;
it never prints Secret data.

| Object / type | Exact data key(s) | Required, source, owner, rotation |
| --- | --- | --- |
| `Secret/github-oidc-exchange-keyring`, `Opaque` | `keyring.json` | Always. Offline `keyring-tool` ES256 output; operator creates and rotates. Never in Helm values/Git. |
| `ConfigMap/github-oidc-exchange-policy` (existing v5) or `ConfigMap/github-oidc-exchange-policy-v6` | `policy.json` | Always select exactly one. Retain the distinct v5 and v6 objects through activation/rollback. A v5 policy contains actor mappings; a minimal v6 policy need not. Restrict ConfigMap get/list RBAC and audit access. |
| `Secret/github-oidc-exchange-workload-rsa-keyring`, `Opaque` | `rsa-keyring.json` | Only if `workloadExchange.enabled`; required for Steward/OpenShell profile. Offline RSA-3072 output; operator rotates. |
| `ConfigMap/github-oidc-exchange-workload-policy` | `workload-policy.json` | Only if workload enabled. Exact admitted service-account usernames/roles; restrict ConfigMap RBAC. |
| `Secret/github-oidc-exchange-server-tls`, `kubernetes.io/tls` | `tls.crt`, `tls.key` | Only if workload enabled. Operator PKI creates it, or chart Certificate requests it from cert-manager. SAN `github-oidc-exchange.<namespace>.svc.cluster.local`; issuer CA is separately distributed to callers. cert-manager owns renewal if selected; operator bumps rollout revision after projection. |
| Operator-selected public Ingress TLS Secret, `kubernetes.io/tls` | `tls.crt`, `tls.key` | Only with chart Ingress. Existing PKI or chart Certificate/cert-manager. SAN exactly covers `ingress.host`/issuer host. The Ingress controller reloads its certificate; verify after renewal. Gateway mode uses a Gateway-owned certificate outside this chart. |
| Operator-selected image-pull Secret, `kubernetes.io/dockerconfigjson` | `.dockerconfigjson` | Only for private registry without node-level access. Operator owns creation/rotation; chart stores its name, not credentials. |
| `ConfigMap/<steward-public-jwks>` | `jwks.json` | Only with `browserHop1.enabled`; public Steward verifier keys, not an Identity signing secret. Operator chooses the object name and rotates trust with `rolloutRevisions.browserHop1Jwks`. |
| Caller-side CA bundle | Operator-selected public ConfigMap/file | Workload callers only, **not** an Identity Secret or chart object. CA owner distributes overlapping roots and verifies DNS SAN/renewal. |

Baseline chart RBAC creates a namespaced Role/Binding for `coordination.k8s.io`
Leases (`create/get/update/list/delete`) and a ServiceAccount. Workload mode adds
only `create` on `tokenreviews.authentication.k8s.io` via ClusterRole/Binding.
Verify any pre-existing admission, NetworkPolicy, or Pod Security rules allow
those resources. Identity needs no GitHub OAuth client. A GitHub App for ARC or
source access, a browser Google OAuth client, and downstream MCP-GW OAuth
clients are separate integrations owned by their respective products.

## 1. Build/publish fork-owned image and chart

From an exact tagged fork commit, run the repo's CI checks first. The optional
`.github/workflows/portable-release.yml` builds native amd64/arm64 candidates,
smokes/scans them, packages and publishes the chart to the **fork owner's**
GHCR, signs/attests the artifacts, and attaches immutable coordinates to a
GitHub release. It needs the fork's `GITHUB_TOKEN` package/write/OIDC rights,
not any cloud credential. The older `release.yml` ECR workflow is optional and
not part of this installation path. Make fork GHCR packages public if anonymous
pulls are intended; verify visibility separately. For another operator-owned
OCI registry, authenticate with that registry's own account and run:

```sh
export IDENTITY_VERSION=0.6.0
export IDENTITY_IMAGE_REPO=registry.example.org/team/github-oidc-exchange
export IDENTITY_CHART_REPO=registry.example.org/team/charts/github-oidc-exchange
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
bash scripts/validate-release.sh
bash scripts/test-chart.sh
docker buildx build --platform linux/amd64,linux/arm64 --push \
  -t "$IDENTITY_IMAGE_REPO:$IDENTITY_VERSION" .
install -d ./dist
helm package charts/github-oidc-exchange --destination ./dist
helm push "./dist/github-oidc-exchange-$IDENTITY_VERSION.tgz" \
  "oci://registry.example.org/team/charts"
export IDENTITY_IMAGE_DIGEST="$(oras manifest fetch --descriptor "$IDENTITY_IMAGE_REPO:$IDENTITY_VERSION" | jq -r .digest)"
export IDENTITY_CHART_DIGEST="$(oras manifest fetch --descriptor "$IDENTITY_CHART_REPO:$IDENTITY_VERSION" | jq -r .digest)"
printf 'image=%s@%s\nchart=%s@%s\n' "$IDENTITY_IMAGE_REPO" "$IDENTITY_IMAGE_DIGEST" "$IDENTITY_CHART_REPO" "$IDENTITY_CHART_DIGEST"
```

Use native platform builders and the vulnerability/SBOM/signature gates in the
portable release workflow for production; the manual commands above show the
registry-neutral mechanics, not a substitute for those gates. Both digests
must be `sha256:` plus 64 lowercase hex characters. Record source commit,
chart/image digests, platform manifests, and signature verification in a
non-secret release handoff. A Helm chart OCI digest identifies the package;
Helm installs it by version from the registry, so verify the tag still resolves
to the recorded digest before install/upgrade. Never overwrite version tags.

When a private mirror is required, copy by immutable source digest with a tool
that preserves the OCI manifest, then query the destination registry and use
the returned destination digest. For example:

```sh
export SOURCE_IMAGE="$(jq -er .image ./dist/release-manifest.json)"
export DESTINATION_IMAGE=registry.example.test/team/github-oidc-exchange
crane copy "$SOURCE_IMAGE" "$DESTINATION_IMAGE:$IDENTITY_VERSION"
export IDENTITY_IMAGE_DIGEST="$(crane digest "$DESTINATION_IMAGE:$IDENTITY_VERSION")"
```

Do not use `docker pull`, `docker tag`, and `docker push` as a digest-preserving
mirror workflow, and do not substitute a tag when the destination digest
differs. The product boundary is static reference validation plus signed
source handoff: the operator owns destination credentials, connectivity,
retention, and descriptor verification. Copy and verify signatures,
attestations, and SBOMs according to the destination registry's OCI-referrer
support.

To run the portable path from a fork whose package and release permissions are
enabled, use the exact source version and watch the resulting run:

```sh
export IDENTITY_FORK=ORG/github-oidc-exchange
gh workflow run portable-release.yml --repo "$IDENTITY_FORK" --ref main \
  -f version="$IDENTITY_VERSION"
gh run list --repo "$IDENTITY_FORK" --workflow portable-release.yml \
  --event workflow_dispatch --limit 1
gh run watch RUN_ID --repo "$IDENTITY_FORK" --exit-status
gh release download "v$IDENTITY_VERSION" --repo "$IDENTITY_FORK" \
  --pattern release-manifest.json --dir ./dist
jq -e '.image|contains("@sha256:")' ./dist/release-manifest.json >/dev/null
jq -e '.chart|contains("@sha256:")' ./dist/release-manifest.json >/dev/null
```

`release-manifest.json` is the fork-owned immutable handoff. Make the fork's
GHCR image and chart packages public for anonymous cluster pulls, or create a
registry pull Secret and reference only its name in values.

## 2. Prepare policy and signing files privately

Create a private directory (`umask` also protects temporary editor files).
Both policy examples are **schemas/examples only** and contain no approved
identity data. A new baseline copies v5. If preparing v6 activation, preserve
that v5 file and additionally copy v6; edit real values only in private
storage. The chart's fixed output audiences are `steward-task-api` and, when
enabled, `openshell-api`.

The default v5 path requires exact subjects, events, refs, and verified actor
mappings. The v6 path always binds signed numeric owner/repository IDs.
`subjects`, `events`, and `refs` are independent optional exact selectors.
`actors`, `allowed_email_domains`, and `acting_group_prefix` are optional only
as one complete compatibility bundle. Without that bundle, Identity emits no
legacy email or group claims. It still validates the shape and consistency of
signed provenance, including the required bounded actor login, and preserves
it in the token.

```sh
umask 077
install -d -m 0700 ./private
# Default v5:
install -m 0600 docs/policy-contract.example.json ./private/policy-v5.json
# Explicit v6 alternative:
install -m 0600 docs/policy-contract-v6.example.json ./private/policy-v6.json
jq empty ./private/policy-v5.json
jq empty ./private/policy-v6.json
cargo run --locked --bin keyring-tool -- generate-es256 \
  ./private/issuer-keyring.json issuer-2026-09-a
cargo run --locked --bin keyring-tool -- validate-es256 ./private/issuer-keyring.json
```

GitHub's ordinary `sub` is `repo:ORG/REPO:ref:refs/heads/BRANCH` for a branch
workflow; environments and other triggers differ. **Do not invent or infer the
subject from a repository name.** Run a short-lived, access-restricted probe in
the actual GitHub repository and reusable-workflow context with
`permissions: id-token: write`. Request the selected audience using
`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`; decode
only the local JWT payload and inspect `sub`, `repository_owner_id`,
`repository_id`, `ref`, `event_name`, `actor_id`, `actor`, `job_workflow_ref`, and
`job_workflow_sha`. Never print or retain the JWT; avoid public workflow logs.
For v5, admit the **observed exact** subject, event, ref, and actor mapping. For
v6, configure the complete actor compatibility bundle only when Identity must
emit a v2-compatible identity; configure repository selectors only when their
exact restriction is required. A minimal v6 policy intentionally accepts valid branch, tag, pull
request, event, workflow-subject, and numeric actor variations from the same
admitted numeric repository without policy edits. In both versions, the
numeric IDs and signed provenance remain mandatory trust inputs.
GitHub OAuth Apps do not participate in this flow.

If enabling workload exchange, prepare its separate policy and keyring:

```sh
install -m 0600 docs/workload-policy-contract.example.json ./private/workload-policy.json
# Privately edit exact system:serviceaccount:NAMESPACE:NAME and corresponding
# kubernetes:serviceaccount:NAMESPACE:NAME subject/roles. Never use wildcards.
jq empty ./private/workload-policy.json
cargo run --locked --bin keyring-tool -- generate-rsa \
  ./private/workload-keyring.json workload-2026-09-a
cargo run --locked --bin keyring-tool -- validate-rsa ./private/workload-keyring.json
```

The tool rejects overwrite, symlinks, non-0600 files, wrong algorithms,
duplicate IDs, invalid key windows, and RSA keys under 3072 bits. It writes
private JSON atomically and prints no key material. Generated keys are not TLS
certificates. Back up private signing files through an encrypted, access-
controlled recovery channel; a lost current key cannot re-sign or validate
already issued tokens after its public key disappears from JWKS.

## 3. Install file-based Kubernetes inputs

Select a certificate path **before** enabling workload exchange or Ingress:

- Existing operator PKI: issue public Ingress leaf/chain for the exact issuer
  DNS name and internal workload leaf/chain for
  `github-oidc-exchange.<namespace>.svc.cluster.local`. Ensure clients trust
  the chain and private key matches; install TLS Secrets with `kubectl create
  secret tls` below. Operator PKI owns renewal. A self-signed development
  certificate is not a production trust anchor.
- cert-manager: install its CRDs/controller, configure an Issuer/ClusterIssuer
  whose CA is trusted by the relevant clients, set the chart's
  `*.tls.certManager.enabled` and `issuerRef`, and let the rendered Certificate
  create/renew the named TLS Secret. Do **not** pre-create that Secret. Public
  ACME/corporate CA and internal CA may be different Issuers. Distribute the
  internal public CA bundle out of band; cert-manager Secret renewal alone
  does not reload Identity's workload listener.
- HTTPRoute: the operator-owned Gateway (outside this chart) terminates public
  TLS and must admit the route's namespace/host. The chart never creates a
  Gateway certificate. Service-only mode requires a separately managed HTTPS
  proxy/route; port 8080 itself is plaintext and must not be exposed publicly.

Use explicit namespace/context. The filenames are local only; `kubectl create`
prints object names, not file contents. Use `--type=Opaque` to make the Secret
type exact. Run only the conditional commands you selected:

```sh
# Default v5 object. Keep it for rollback if v6 is later activated.
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" \
  create configmap github-oidc-exchange-policy --from-file=policy.json=./private/policy-v5.json
# v6 opt-in only; create separately and do not replace the v5 object.
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" \
  create configmap github-oidc-exchange-policy-v6 --from-file=policy.json=./private/policy-v6.json
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" \
  create secret generic github-oidc-exchange-keyring --type=Opaque \
  --from-file=keyring.json=./private/issuer-keyring.json
# Workload mode only:
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" \
  create configmap github-oidc-exchange-workload-policy \
  --from-file=workload-policy.json=./private/workload-policy.json
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" \
  create secret generic github-oidc-exchange-workload-rsa-keyring --type=Opaque \
  --from-file=rsa-keyring.json=./private/workload-keyring.json
# Workload mode with existing operator-PKI cert only (not cert-manager):
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" \
  create secret tls github-oidc-exchange-server-tls \
  --cert=./private/server.crt --key=./private/server.key
# Chart Ingress with existing operator-PKI cert only (not cert-manager):
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" \
  create secret tls identity-public-tls \
  --cert=./private/public.crt --key=./private/public.key
```

For a private image registry, create a pull Secret from a private file in the
same namespace (or use node credentials), then list **only its name** under
`image.pullSecrets`. Do not put registry credentials in values. With local
files, validate X.509 names/expiry without dumping the private key:

```sh
openssl x509 -in ./private/server.crt -noout -subject -ext subjectAltName -enddate
openssl x509 -in ./private/public.crt -noout -subject -ext subjectAltName -enddate
bash scripts/check-install-inputs.sh "$IDENTITY_KUBECONFIG" "$IDENTITY_CONTEXT" \
  "$IDENTITY_NAMESPACE"
```

Add `--workload` and/or `--public-tls identity-public-tls` to the checker only
when those objects are expected. For cert-manager-provisioned workload TLS,
use `--workload --skip-workload-tls` before Helm install, then rerun
`--workload` after Certificate readiness. A missing key/type/name/namespace
fails without showing values.

When v6 is selected, add
`--github-policy github-oidc-exchange-policy-v6`; the default checker target is
the existing `github-oidc-exchange-policy` v5 object.

## 4. Configure and install baseline

Copy [`values.example.yaml`](../charts/github-oidc-exchange/values.example.yaml)
to a private deployment file, fill every mandatory empty field, and set
`image.repository`, `image.digest`, exact origin-only `config.issuerUrl`, dedicated
`config.githubExchangeAudience`, `config.policyContract`, the matching
`config.policyConfigMapName`, the keyring reference, and
`networkPolicy.ingressCidrs` to the actual proxy/Gateway source CIDRs. The
chart's default values intentionally **fail**. It never substitutes dummy
credentials. The renderable
[`examples/production-values.yaml`](../charts/github-oidc-exchange/examples/production-values.yaml)
demonstrates a complete values shape but is not an install profile: every
domain, digest, CIDR, object, and Gateway reference in it is fake. Use only
one exposure option:

1. Service-only: leave `ingress.enabled=false`, `httpRoute.enabled=false`; an
   operator-owned HTTPS proxy must expose exactly both metadata endpoints,
   JWKS, and exchange.
2. Ingress: set `ingress.enabled=true`, controller `className`, `host` matching
   issuer, and `tls.secretName`; optionally enable its cert-manager Certificate
   with `issuerRef.name/kind`. The chart routes only four public paths.
3. HTTPRoute: set `httpRoute.enabled=true`, `parentRefs` to an existing HTTPS
   Gateway listener, and `hostnames` containing the issuer DNS name. The
   Gateway owner controls TLS/certificate renewal and route acceptance.

`config.issuerUrl` must be an HTTPS origin without a path, query, or fragment;
both the chart schema and application startup reject path-bearing values. The
RFC 8414 path is `/.well-known/oauth-authorization-server`, and the retained
OpenID path is `/.well-known/openid-configuration`.

For the behavior-preserving baseline, retain:

```yaml
config:
  policyContract: github-oidc-exchange.apelogic.io/v5
  policyConfigMapName: github-oidc-exchange-policy
```

The chart passes the selected contract through `EXPECTED_POLICY_VERSION` and
the process refuses to start if the mounted document has another version.

```sh
umask 077
cp charts/github-oidc-exchange/values.example.yaml ./private/values.yaml
# Edit private/values.yaml: use the exact published image digest and selected route.
bash scripts/validate-chart-values.sh ./private/values.yaml
helm lint charts/github-oidc-exchange -f ./private/values.yaml --strict
helm template identity charts/github-oidc-exchange --namespace "$IDENTITY_NAMESPACE" \
  -f ./private/values.yaml >/dev/null
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  upgrade --install identity "oci://registry.example.org/team/charts/github-oidc-exchange" \
  --version "$IDENTITY_VERSION" --namespace "$IDENTITY_NAMESPACE" \
  --values ./private/values.yaml --wait --timeout 10m
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" \
  rollout status deployment/github-oidc-exchange --timeout=5m
```

`values.yaml` contains references, not private key/policy contents. To change
the installed chart, change the forked chart and image together, publish new
immutable tags/digests, review protocol compatibility, update those references,
then `helm upgrade --version NEW_VERSION --values ./private/values.yaml --wait`.
Keep the prior image/chart digest and keyring overlap for rollback. To roll
back, inspect history and select the previously accepted revision:

```sh
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  history identity --namespace "$IDENTITY_NAMESPACE"
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  rollback identity PREVIOUS_REVISION --namespace "$IDENTITY_NAMESPACE" --wait --timeout 10m
```

Validate discovery/JWKS and a fresh exchange again. There is no database
migration; keep the same namespace to preserve replay Leases. A 0.6.0
application upgrade that retains v5 is safe to roll back normally. After v6
activation, an older binary cannot read v6: roll back the chart/application
and `policyContract`/`policyConfigMapName` together to the retained v5 object.
Never perform an image-only rollback while v6 remains mounted. The exact
preflight, activation, and rollback sequence is in the
[0.6.0 upgrade guide](upgrade-v0.6.0.md).

## 5. Enable optional workload exchange

Only after baseline passes, add the RSA/policy/TLS inputs and set
`workloadExchange.enabled=true`, exact `inputAudience`, object references,
nonempty caller namespace **and** pod selectors, and opaque
`rolloutRevisions.workloadPolicy`, `workloadRsaKeyring`, `workloadTls`.
For the standard object names in `values.example.yaml`, the caller URL is
`https://github-oidc-exchange.<namespace>.svc.cluster.local:8443/v1/workload/exchange`.
If using cert-manager, set `workloadExchange.tls.certManager.enabled=true` and
its trusted `issuerRef`, apply the upgrade, wait for both Certificate `Ready`
and Secret key presence, then bump `rolloutRevisions.workloadTls` after
projection to restart the TLS server. For existing PKI, verify the installed
Secret first, then upgrade. In both cases, mount the public CA bundle in each
caller and verify SAN/chain; **never** use `curl -k` or disable TLS verification.
The workload endpoint remains absent from public routes.

Use the same Helm upgrade command as step 4 after editing values, then:

```sh
bash scripts/check-install-inputs.sh "$IDENTITY_KUBECONFIG" "$IDENTITY_CONTEXT" \
  "$IDENTITY_NAMESPACE" --workload
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" \
  auth can-i create tokenreviews.authentication.k8s.io \
  --as="system:serviceaccount:$IDENTITY_NAMESPACE:github-oidc-exchange"
```

Expected `yes` only with workload enabled. The consumer's projected token
must request exactly the configured TokenReview audience. A token for the
default Kubernetes API audience, an unmapped service account, wrong CA, or
wrong SAN must fail. An optional `browserHop1` profile additionally requires
the public Steward JWKS ConfigMap and exact Steward issuer/assertion/MCP
audiences; see [its separate contract](browser-hop1-contract-v1.md).

## 6. Rotation, recovery, uninstall

Signing files are loaded on process startup, not hot-reloaded. For ES256 or
RSA, run the matching command suffix (`es256` or `rsa`) below on the **private
file**. Before expiry (tool-created keys last 90 days), add a new key, publish
the overlapping file to the **same** Kubernetes Secret, bump only that
`rolloutRevisions` field to an opaque new value, and wait for every Pod to
restart and JWKS to publish both `kid`s. Then activate the new key, project
again, bump the revision again, and verify new tokens use the new `kid` while
old tokens still validate. If activation fails, `activate-es256 ... OLD_KID`
and reproject/bump the revision; the overlap keeps both old and new tokens
verifiable. Wait at least five minutes after the last old signing event and
confirm all consumers have refreshed JWKS before retiring the old key.

```sh
set +x
set -o pipefail
cargo run --locked --bin keyring-tool -- add-es256 ./private/issuer-keyring.json issuer-next
cargo run --locked --bin keyring-tool -- validate-es256 ./private/issuer-keyring.json
identity_keyring_rv="$(kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" get secret github-oidc-exchange-keyring \
  -o jsonpath='{.metadata.resourceVersion}')"
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" \
  create secret generic github-oidc-exchange-keyring --type=Opaque \
  --from-file=keyring.json=./private/issuer-keyring.json --dry-run=client -o json | \
  jq --arg rv "$identity_keyring_rv" '.metadata.resourceVersion=$rv' | \
  kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" replace -f -
# Edit rolloutRevisions.githubKeyring to rev-2; helm upgrade, wait, check both JWKS kids.
cargo run --locked --bin keyring-tool -- activate-es256 ./private/issuer-keyring.json issuer-next
# Reproject, bump revision to rev-3, upgrade/wait; rollback activation by selecting OLD_KID if needed.
# After the overlap/grace window only:
cargo run --locked --bin keyring-tool -- retire-es256 ./private/issuer-keyring.json issuer-2026-09-a
```

Repeat the **version-checked** file replacement after activate/retire (and for
the RSA keyring or a policy ConfigMap), fetching a fresh metadata-only
`resourceVersion` each time. `kubectl replace` can otherwise perform an
unconditional update, so the inserted version is essential: a concurrent
change yields `409 Conflict`; stop, re-read ownership/current revision, and
retry only after review. Do not use `--force`, client-side `kubectl apply`
(which can persist Secret bytes in a last-applied annotation), or terminal
output of the generated JSON. The pipeline carries bytes only between local
processes; `set +x` and `pipefail` keep it non-logged and fail closed. The
disposable [rotation regression](../scripts/test-install-rotation.sh) tests
create, version-checked replace, stale-write denial, and annotation absence.

For RSA repeat with `add-rsa`, `activate-rsa`, `retire-rsa` and the workload
RSA Secret/revision. For policy updates, project reviewed file-based ConfigMaps,
bump the matching policy revision, and roll Pods. For workload TLS, renew the
serving Secret, publish overlapping caller CA trust **first**, bump
`rolloutRevisions.workloadTls`, verify all callers and replicas on the new
chain, then remove the old CA. cert-manager issuance does not by itself reload
this process. For public Ingress/Gateway TLS, confirm its controller has
reloaded/renewed and external clients trust the new chain. Keep encrypted
recovery copies through rollback and token-verification windows; never publish
old private keys to diagnose a problem.

`helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT"
uninstall identity --namespace "$IDENTITY_NAMESPACE"` removes chart-owned workloads/routes/RBAC and
Certificate objects. It does **not** delete operator-created policy/key/TLS
objects or the namespaced replay Leases; cert-manager TLS Secret retention
depends on its policy, so inspect it explicitly. Do not delete the namespace
or private files as part of uninstall without a separate retention decision.

## 7. Post-install and delivery test checklist

Record only command, timestamp, source revision/artifact digests, pass/fail,
HTTP status, Pod/Certificate state, and **public** JWKS `kid`s. Never store
JWTs, private keys, policy identity mappings, provider bodies, Secret data,
or raw authorization headers in evidence. Set `set +x` in token-handling jobs.

| Test/action | Command or action | Expected non-secret result |
| --- | --- | --- |
| Pod/Service/RBAC | `kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" get pods,svc,deploy,role,rolebinding` | Two Ready replicas by default, ClusterIP ports 8080 (+8443 only with workload), namespaced Lease RBAC. No missing mounts/restarts. |
| TLS/route | Probe `$IDENTITY_ISSUER/.well-known/oauth-authorization-server` and `$IDENTITY_ISSUER/.well-known/openid-configuration` with `curl -fsS -o /dev/null -w '%{http_code}\n'`; run `openssl s_client -connect HOST:443 -servername HOST </dev/null` (inspect summary only). | Both metadata routes return HTTP 200 with a valid trusted external chain/SAN; neither workload path nor health/metrics is publicly routed. Ingress or Gateway reports accepted/ready; cert-manager Certificate `Ready=True` if used. |
| Discovery/JWKS | Fetch both metadata documents, require them to be equal, and require exact issuer/JWKS/exchange URLs, exact `github_oidc_audience`, both entries in `identity_contracts_supported`, and both entries in `policy_versions_supported`; fetch JWKS and require an ES256 EC key. | Predicates pass; metadata contains no policy contents, identity mappings, or key material. Record only public `kid` values. |
| Real admitted GitHub OIDC | From an admitted repository job with `id-token: write`, request a fresh assertion using the discovered audience; POST it as Bearer to `/v1/exchange`, save the response mode 0600, and verify status 200, `token_type=Bearer`, `expires_in=120`, signature, issuer, audience, selected contract, and source provenance. | v5 yields unchanged `steward-task-v2`; minimal v6 yields `steward-task-v3` with `actor_login` and no `email`, `email_verified`, or `groups`. The optional complete compatibility bundle yields all three legacy identity claims together. Replay returns 401. |
| Negative GitHub admission | With fresh signed assertions, test wrong issuer/audience/signature/algorithm/key ID, expired/not-yet-valid times, malformed actor ID, wrong numeric owner/repository IDs, inconsistent provenance, and replay. Under v5 also test subject/event/ref/actor. Under v6 test only optional selectors that are present. | Each applicable denial returns 401. A 503 is dependency failure, not denial evidence. Omitted v6 selectors deliberately do not reject that dimension. |
| Key rotation | Perform add/activate/rollback/retire sequence above; compare only public JWKS `kid`s and new token header `kid` in private test tooling. | Overlap publishes both keys, activation changes signer, rollback can select old signer while both verify, retirement occurs only after token TTL plus skew and consumer refresh. |
| Workload enabled | From an admitted caller Pod with a projected token for exact `inputAudience` and mounted public CA, POST empty body to internal `:8443/v1/workload/exchange`; verify output signature/issuer/audience/roles with JWKS. Repeat with wrong projected audience and unmapped service account; verify TLS with wrong CA fails. | Admitted request 200/RS256/120 s; wrong audience or caller 401; wrong CA/SAN fails TLS handshake. TokenReview permission `yes`; port 8443 unreachable from nonselected Pods. |
| Workload disabled | `bash scripts/test-chart.sh` plus live Service/RBAC inspection. | No workload port, TokenReview RBAC, RSA/TLS mount, or RSA JWKS key. |

For a GitHub Actions delivery job, keep both tokens in shell memory/private
runner files and emit only status; the exact HTTP probe is:

```sh
set +x
umask 077
source_jwt="$(curl -fsS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$IDENTITY_AUDIENCE" | jq -r .value)"
status="$(curl -sS -o "$RUNNER_TEMP/identity-exchange.json" -w '%{http_code}' \
  -X POST -H "Authorization: Bearer $source_jwt" --data-binary '' \
  "$IDENTITY_ISSUER/v1/exchange")"
unset source_jwt
test "$status" = 200
jq -e '.token_type=="Bearer" and .expires_in==120 and (.access_token|type)=="string"' \
  "$RUNNER_TEMP/identity-exchange.json" >/dev/null
rm -f "$RUNNER_TEMP/identity-exchange.json"
printf 'admitted GitHub OIDC exchange: HTTP %s, response contract valid\n' "$status"
```

The job's permissions must include `id-token: write`; `RUNNER_TEMP` must be
runner-owned, not an uploaded artifact path. For a denied case replace `200`
with `401` and discard the response without logging its body. A separate
downstream integration owner tests Steward and steward-run against the
[consumer contract](consumer-contract-v1.md); this installation guide does not
claim that three-product acceptance.

The [integration guide](integration.md) supplies copy-ready reusable workflows
for observing bounded claims without printing a token, exercising both policy
paths, and calling steward-run with the required exchange endpoint and audience.
Pin both values in the consumer workflow. Before enabling v6, prove that the
deployed Steward accepts `steward-task-v3`, reads `actor_login`, permits all
compatibility identity claims to be absent, consumes the required provenance
actor, and performs Task authorization independently from Identity source
authentication. The checked-in
[`steward-task-v3` fixture](steward-task-v3.example.json) is the copy-ready
consumer conformance shape.

The steward-run reusable workflow requires both exchange inputs,
`identity-exchange-url` and `identity-exchange-audience`, and passes both to
the action. Only the direct-action fallback uses
`apelogic-github-identity-exchange` when the audience is omitted; that fallback
is not the supported handoff for a deployed issuer. The established endpoint
and audience boundary is recorded in
[steward-run #43](https://github.com/apelogic-ai/steward-run/issues/43).

## Release-document drift gate

Before tagging any release, run `bash scripts/validate-release.sh`,
`bash scripts/test-chart.sh`, `bash scripts/test-install-inputs.sh`,
`bash scripts/test-kubectl-files.sh`,
the disposable-cluster `bash scripts/test-install-rotation.sh KUBECONFIG CONTEXT NAMESPACE`,
`cargo test --locked --all-targets --all-features`, and the target-cluster
delivery checklist. Review current `README.md` and this guide against
`Chart.yaml`, `values.yaml`, `values.schema.json`, the rendered Secret/ConfigMap
mounts, public routes, audiences, source policy/keyring versions, TLS modes,
and actual published image/chart digests. An outdated README or an untested
installation guide blocks release.
