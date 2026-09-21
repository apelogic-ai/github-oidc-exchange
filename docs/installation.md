# Installation guide — github-oidc-exchange 0.4.0

This is the canonical operator guide for application **0.4.0**, Helm chart
**0.4.0**, and [consumer contract v1](consumer-contract-v1.md). It installs
Identity alone in a customer-owned Kubernetes cluster from fork-owned artifacts.
No ApeLogic account, AWS credential, Secrets Manager, ECR, ALB, External Secrets
Operator, GitHub OAuth App, or database is required. The baseline exchanges
GitHub Actions OIDC assertions; workload exchange and browser HOP-1 are opt-in.
The image/chart build, template, keyring, and object-name commands are tested
in this repository. A real customer registry, issuer DNS, GitHub Actions token,
and Kubernetes TokenReview must be tested in the target environment using the
delivery checklist below; a successful `helm template` alone is not acceptance.

## Prerequisites and decisions

| Input | Baseline GitHub issuer | Additional workload profile |
| --- | --- | --- |
| Cluster/architecture | Kubernetes >=1.30, `linux/amd64` or `linux/arm64`, working DNS, outbound HTTPS to GitHub JWKS and Kubernetes API; ability to create namespaced Lease Role/Binding and NetworkPolicy. Two schedulable replicas by default. | Cluster-admin or delegated right to create the chart's narrow TokenReview ClusterRole/Binding; caller namespace and pod labels for an exact NetworkPolicy selector. |
| Tools | Rust 1.95, Helm 3.17+, Docker/buildx, `kubectl`, `jq`, and `oras` for digest lookup; explicit kubeconfig/context. | Same, plus a projected, bound service-account token for each caller. |
| Registry | Fork-owned OCI image/chart repositories accessible from cluster nodes; immutable digest for image and chart. Private registry requires a pre-created `kubernetes.io/dockerconfigjson` pull Secret named only in `image.pullSecrets`. | Same image/chart. |
| Issuer/public network | Unique HTTPS issuer URL and DNS A/CNAME; publicly trusted certificate whose SAN covers its DNS name; select external HTTPS proxy + internal Service, chart Ingress with chosen controller, or chart HTTPRoute attached to an existing HTTPS Gateway. Allow its actual source CIDRs to port 8080. Hosted GitHub runners need a reachable public issuer/exchange; self-hosted runners may use a private route if DNS and trust agree. | Workload listener is internal Service port 8443 only. Server certificate SAN must include `github-oidc-exchange.<namespace>.svc.cluster.local`; distribute its public issuer CA bundle to callers and plan renewal/overlap. |
| GitHub policy | Dedicated inbound audience, observed exact GitHub `sub`, immutable numeric `repository_owner_id` and `repository_id`, allowed event/ref and reviewed numeric `actor_id` to corporate identity mapping. GitHub jobs need `permissions: id-token: write` and must expose `job_workflow_ref`/`job_workflow_sha` via a reusable workflow. | Independent exact service-account username-to-subject/roles policy and TokenReview input audience. |
| Private material | Offline mode-0600 ES256 keyring; private policy file and object RBAC; TLS key controlled by the chosen certificate owner. | Offline mode-0600 RSA-3072 keyring; workload TLS private key and caller public CA trust. |
| Optional CRDs | Gateway API `gateway.networking.k8s.io/v1` for HTTPRoute, cert-manager `cert-manager.io/v1` for chart-created Certificate, Prometheus Operator for ServiceMonitor — only if selected. | cert-manager optional for internal serving Certificate too. |

Use an explicit kubeconfig and context for **every** command; do not use an
ambient context. In the examples below choose a real, isolated target:

```sh
export IDENTITY_KUBECONFIG=/absolute/path/to/customer-kubeconfig
export IDENTITY_CONTEXT=customer-context
export IDENTITY_NAMESPACE=identity
export IDENTITY_ISSUER=https://identity.customer.tld
export IDENTITY_AUDIENCE=customer-identity-exchange
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
`scripts/test-customer-chart.sh` checks object/key references against rendered
Deployment mounts and runtime file environment variables. The live checker
`scripts/check-install-inputs.sh` checks namespace, type, and key *names* only;
it never prints Secret data.

| Object / type | Exact data key(s) | Required, source, owner, rotation |
| --- | --- | --- |
| `Secret/github-oidc-exchange-keyring`, `Opaque` | `keyring.json` | Always. Offline `keyring-tool` ES256 output; customer operator creates and rotates. Never in Helm values/Git. |
| `ConfigMap/github-oidc-exchange-policy` | `policy.json` | Always. Reviewed private policy file; customer operator creates/rotates. Contains actor/email/canonical-user mappings: keep in a restricted repository or local mode-0600 file, restrict ConfigMap get/list RBAC and audit access. Use a separate namespace if existing RBAC is broad. |
| `Secret/github-oidc-exchange-workload-rsa-keyring`, `Opaque` | `rsa-keyring.json` | Only if `workloadExchange.enabled`; required for Steward/OpenShell profile. Offline RSA-3072 output; operator rotates. |
| `ConfigMap/github-oidc-exchange-workload-policy` | `workload-policy.json` | Only if workload enabled. Exact admitted service-account usernames/roles; restrict ConfigMap RBAC. |
| `Secret/github-oidc-exchange-server-tls`, `kubernetes.io/tls` | `tls.crt`, `tls.key` | Only if workload enabled. Customer PKI creates it, or chart Certificate requests it from cert-manager. SAN `github-oidc-exchange.<namespace>.svc.cluster.local`; issuer CA is separately distributed to callers. cert-manager owns renewal if selected; operator bumps rollout revision after projection. |
| Customer-selected public Ingress TLS Secret, `kubernetes.io/tls` | `tls.crt`, `tls.key` | Only with chart Ingress. Existing customer PKI or chart Certificate/cert-manager. SAN exactly covers `ingress.host`/issuer host. Customer's Ingress controller reloads its certificate; verify after renewal. Gateway mode instead uses a Gateway-owned certificate outside this chart. |
| Customer-selected image-pull Secret, `kubernetes.io/dockerconfigjson` | `.dockerconfigjson` | Only for private registry without node-level access. Customer owns creation/rotation; chart stores its name, not credentials. |
| `ConfigMap/<steward-public-jwks>` | `jwks.json` | Only with `browserHop1.enabled`; public Steward verifier keys, not an Identity signing secret. Operator chooses the object name and rotates trust with `rolloutRevisions.browserHop1Jwks`. |
| Caller-side CA bundle | Customer-selected public ConfigMap/file | Workload callers only, **not** an Identity Secret or chart object. CA owner distributes overlapping roots and verifies DNS SAN/renewal. |

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
pulls are intended; verify visibility separately. For another customer-owned
OCI registry, authenticate with that registry's own account and run:

```sh
export IDENTITY_VERSION=0.4.0
export IDENTITY_IMAGE_REPO=registry.customer.tld/team/github-oidc-exchange
export IDENTITY_CHART_REPO=registry.customer.tld/team/charts/github-oidc-exchange
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
bash scripts/validate-release.sh
bash scripts/test-customer-chart.sh
docker buildx build --platform linux/amd64,linux/arm64 --push \
  -t "$IDENTITY_IMAGE_REPO:$IDENTITY_VERSION" .
install -d ./dist
helm package charts/github-oidc-exchange --destination ./dist
helm push "./dist/github-oidc-exchange-$IDENTITY_VERSION.tgz" \
  "oci://registry.customer.tld/team/charts"
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

## 2. Prepare policy and signing files privately

Create a private directory (`umask` also protects temporary editor files).
The example JSON files are **schemas/examples only** and contain no usable
credentials or approved identities. Copy the policy example locally and edit
real mappings only in private storage; do not commit it or include it in CI
artifacts. The chart's fixed output audiences are `steward-task-api` and,
when enabled, `openshell-api`.

```sh
umask 077
install -d -m 0700 ./private
install -m 0600 docs/policy-contract.example.json ./private/policy.json
# Privately edit policy.json: observed exact sub, numeric owner/repository IDs,
# allowed events/refs, reviewed actor_id -> email/canonical_user_id mapping.
jq empty ./private/policy.json
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
`repository_id`, `ref`, `event_name`, `actor_id`, `job_workflow_ref`, and
`job_workflow_sha`. Never print or retain the JWT; avoid public workflow logs.
Admit the **observed exact** `sub` in `policy.json`, bind it to the separately
signed numeric IDs and reviewed actor mapping, then remove the probe. The
policy validator accepts a normal GitHub `repo:` subject; its numeric ID
checks are on separate signed claims. Task rules do not gate workflow path;
bootstrap rules additionally select exact caller/reusable workflow refs.
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

- Existing customer PKI: issue public Ingress leaf/chain for the exact issuer
  DNS name and internal workload leaf/chain for
  `github-oidc-exchange.<namespace>.svc.cluster.local`. Ensure clients trust
  the chain and private key matches; install TLS Secrets with `kubectl create
  secret tls` below. Customer PKI owns renewal. A self-signed development
  certificate is not a production trust anchor.
- cert-manager: install its CRDs/controller, configure an Issuer/ClusterIssuer
  whose CA is trusted by the relevant clients, set the chart's
  `*.tls.certManager.enabled` and `issuerRef`, and let the rendered Certificate
  create/renew the named TLS Secret. Do **not** pre-create that Secret. Public
  ACME/corporate CA and internal CA may be different Issuers. Distribute the
  internal public CA bundle out of band; cert-manager Secret renewal alone
  does not reload Identity's workload listener.
- HTTPRoute: the customer-owned Gateway (outside this chart) terminates public
  TLS and must admit the route's namespace/host. The chart never creates a
  Gateway certificate. Service-only mode requires a separately managed HTTPS
  proxy/route; port 8080 itself is plaintext and must not be exposed publicly.

Use explicit namespace/context. The filenames are local only; `kubectl create`
prints object names, not file contents. Use `--type=Opaque` to make the Secret
type exact. Run only the conditional commands you selected:

```sh
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" \
  create configmap github-oidc-exchange-policy --from-file=policy.json=./private/policy.json
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
# Workload mode with existing customer-PKI cert only (not cert-manager):
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" -n "$IDENTITY_NAMESPACE" \
  create secret tls github-oidc-exchange-server-tls \
  --cert=./private/server.crt --key=./private/server.key
# Chart Ingress with existing customer-PKI cert only (not cert-manager):
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

## 4. Configure and install baseline

Copy [`values.example.yaml`](../charts/github-oidc-exchange/values.example.yaml)
to a private deployment file, fill every mandatory empty field, and set
`image.repository`, `image.digest`, exact `config.issuerUrl`, dedicated
`config.githubExchangeAudience`, the two baseline object references, and
`networkPolicy.ingressCidrs` to the actual proxy/Gateway source CIDRs. The
chart's default values intentionally **fail**. It never substitutes dummy
credentials. Use only one exposure option:

1. Service-only: leave `ingress.enabled=false`, `httpRoute.enabled=false`; an
   operator-owned HTTPS proxy must expose exactly discovery, JWKS, and exchange.
2. Ingress: set `ingress.enabled=true`, controller `className`, `host` matching
   issuer, and `tls.secretName`; optionally enable its cert-manager Certificate
   with `issuerRef.name/kind`. The chart routes only three public paths.
3. HTTPRoute: set `httpRoute.enabled=true`, `parentRefs` to an existing HTTPS
   Gateway listener, and `hostnames` containing the issuer DNS name. The
   Gateway owner controls TLS/certificate renewal and route acceptance.

```sh
umask 077
cp charts/github-oidc-exchange/values.example.yaml ./private/values.yaml
# Edit private/values.yaml: use the exact published image digest and selected route.
helm lint charts/github-oidc-exchange -f ./private/values.yaml --strict
helm template identity charts/github-oidc-exchange --namespace "$IDENTITY_NAMESPACE" \
  -f ./private/values.yaml >/dev/null
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  upgrade --install identity "oci://registry.customer.tld/team/charts/github-oidc-exchange" \
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

Validate discovery/JWKS and a fresh exchange again. Do not roll back
to a binary that cannot read the current policy/keyring schema. There is no
database migration; keep the same namespace to preserve replay Leases.

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
| TLS/route | `curl -fsS -o /dev/null -w '%{http_code}\n' "$IDENTITY_ISSUER/.well-known/openid-configuration"`; `openssl s_client -connect HOST:443 -servername HOST </dev/null` (inspect summary only) | HTTP 200, valid trusted external chain/SAN; neither workload path nor health/metrics publicly routed. Ingress or Gateway reports accepted/ready; cert-manager Certificate `Ready=True` if used. |
| Discovery/JWKS | `curl -fsS "$IDENTITY_ISSUER/.well-known/openid-configuration" | jq -e --arg iss "$IDENTITY_ISSUER" '.issuer==$iss and .jwks_uri==($iss+"/jwks.json") and .token_endpoint==($iss+"/v1/exchange")' >/dev/null`; `curl -fsS "$IDENTITY_ISSUER/jwks.json" | jq -e '[.keys[] | select(.alg=="ES256" and .kty=="EC")] | length>0' >/dev/null` | Both predicates pass; record only public `kid` set. Baseline contains no RSA key. |
| Real admitted GitHub OIDC | From an admitted repo/ref/actor **reusable-workflow** job with `id-token: write`, request a fresh assertion with `IDENTITY_AUDIENCE`; POST it as Bearer to `/v1/exchange`, save response in a mode-0600 temporary file, assert HTTP 200 and `token_type=Bearer`, `expires_in=120`. Configure a consumer to verify issuer, audience `steward-task-api`, ES256, JWKS signature, `steward-task-v2` and signed provenance. | One fresh exchange succeeds; replay of the same assertion returns HTTP 401. Do not print assertion/output token or response body. |
| Negative GitHub admission | Repeat with a fresh assertion from another repository (wrong numeric repository/owner ID), a disallowed ref, a different unmapped actor, and a separately requested wrong audience; keep all other inputs valid. | Each returns HTTP 401. A network/JWKS outage gives 503 and is **not** a valid denial proof. Use distinct real jobs/identities; do not edit JWT payloads. |
| Key rotation | Perform add/activate/rollback/retire sequence above; compare only public JWKS `kid`s and new token header `kid` in private test tooling. | Overlap publishes both keys, activation changes signer, rollback can select old signer while both verify, retirement occurs only after token TTL plus skew and consumer refresh. |
| Workload enabled | From an admitted caller Pod with a projected token for exact `inputAudience` and mounted public CA, POST empty body to internal `:8443/v1/workload/exchange`; verify output signature/issuer/audience/roles with JWKS. Repeat with wrong projected audience and unmapped service account; verify TLS with wrong CA fails. | Admitted request 200/RS256/120 s; wrong audience or caller 401; wrong CA/SAN fails TLS handshake. TokenReview permission `yes`; port 8443 unreachable from nonselected Pods. |
| Workload disabled | `bash scripts/test-customer-chart.sh` plus live Service/RBAC inspection. | No workload port, TokenReview RBAC, RSA/TLS mount, or RSA JWKS key. |

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

The current steward-run integration still binds its GitHub input audience to
`apelogic-github-identity-exchange` and accepts a caller-supplied exchange URL.
For a customer-owned issuer, do not count a standalone Identity exchange as a
governed hand-off: pin both the expected audience and trusted endpoint in the
consumer workflow, then exercise them in the target environment. That change
and its negative tests remain [steward-run #41](https://github.com/apelogic-ai/steward-run/issues/41).

## Release-document drift gate

Before tagging any release, run `bash scripts/validate-release.sh`,
`bash scripts/test-customer-chart.sh`, `bash scripts/test-install-inputs.sh`,
`bash scripts/test-kubectl-files.sh`,
the disposable-cluster `bash scripts/test-install-rotation.sh KUBECONFIG CONTEXT NAMESPACE`,
`cargo test --locked --all-targets --all-features`, and the target-cluster
delivery checklist. Review current `README.md` and this guide against
`Chart.yaml`, `values.yaml`, `values.schema.json`, the rendered Secret/ConfigMap
mounts, public routes, audiences, source policy/keyring versions, TLS modes,
and actual published image/chart digests. An outdated README or an untested
installation guide blocks release.
