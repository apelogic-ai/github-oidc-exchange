# Baseline customer quickstart — github-oidc-exchange 0.5.0

This is the shortest supported path to a baseline GitHub Actions OIDC
exchange. It deliberately excludes workload exchange and browser HOP-1. It
assumes Kubernetes 1.30 or newer, an existing HTTPS Gateway API listener, a
customer fork, and public fork-owned GHCR packages. Use the
[full installation guide](installation.md) for Ingress, a separate HTTPS
proxy, private registries, customer CA distribution, workload exchange,
rotation, upgrade, rollback, and uninstall.

This quickstart creates a task-only GitHub policy v5. If upgrading an existing
0.4.0 deployment, use the [v4-to-v5 migration guide](upgrade-v0.5.0.md)
instead of replacing the policy in place.

The result is an Identity deployment with three public routes:

- `GET /.well-known/openid-configuration`
- `GET /jwks.json`
- `POST /v1/exchange`

The workload endpoint is not enabled or exposed. A GitHub OAuth App is not
used.

## Before starting

You need:

- a clean checkout of the customer fork at the reviewed `0.5.0` source;
- GitHub CLI authentication allowed to run Actions, create a release, and
  publish packages in that fork;
- Rust 1.95, Helm 3.17+, `kubectl`, `jq`, `oras`, and an explicit
  kubeconfig/context;
- a DNS name and existing HTTPS Gateway listener whose certificate covers it;
- the Gateway name, namespace, listener section name, and source CIDRs seen by
  the Identity Pod;
- a private, access-restricted repository in which to observe the real GitHub
  OIDC claims and run the final exchange test.

Set the non-secret coordinates used below. Keep the GHCR owner lowercase.

```sh
export IDENTITY_FORK=customer-org/github-oidc-exchange
export IDENTITY_VERSION=0.5.0
export IDENTITY_KUBECONFIG=/absolute/path/to/customer-kubeconfig
export IDENTITY_CONTEXT=customer-context
export IDENTITY_NAMESPACE=identity
export IDENTITY_ISSUER=https://identity.customer.example
export IDENTITY_AUDIENCE=customer-github-identity-exchange
```

## 1. Publish fork-owned artifacts

Run the AWS-free workflow from the fork's `main` branch. It builds native
amd64/arm64 images, scans and smokes them, publishes the image and chart to the
fork owner's GHCR, signs them, and creates `v0.5.0` with an immutable handoff.
The version must match `Cargo.toml` and `Chart.yaml`, and the release/tag must
not already exist in the fork.

```sh
gh workflow run portable-release.yml --repo "$IDENTITY_FORK" --ref main \
  -f version="$IDENTITY_VERSION"
gh run list --repo "$IDENTITY_FORK" --workflow portable-release.yml \
  --event workflow_dispatch --limit 1
# Copy the run ID from the preceding command.
gh run watch RUN_ID --repo "$IDENTITY_FORK" --exit-status

install -d ./dist
gh release download "v$IDENTITY_VERSION" --repo "$IDENTITY_FORK" \
  --pattern release-manifest.json --dir ./dist
export IDENTITY_IMAGE_REFERENCE="$(jq -er .image ./dist/release-manifest.json)"
export IDENTITY_CHART_REFERENCE="$(jq -er .chart ./dist/release-manifest.json)"
printf 'image=%s\nchart=%s\n' \
  "$IDENTITY_IMAGE_REFERENCE" "$IDENTITY_CHART_REFERENCE"

export IDENTITY_IMAGE_REPOSITORY="${IDENTITY_IMAGE_REFERENCE%@*}"
export IDENTITY_IMAGE_DIGEST="${IDENTITY_IMAGE_REFERENCE#*@}"
export IDENTITY_CHART_REPOSITORY="${IDENTITY_CHART_REFERENCE%@*}"
export IDENTITY_CHART_DIGEST="${IDENTITY_CHART_REFERENCE#*@}"
test "$(oras manifest fetch --descriptor \
  "$IDENTITY_IMAGE_REPOSITORY:$IDENTITY_VERSION" | jq -er .digest)" \
  = "$IDENTITY_IMAGE_DIGEST"
test "$(oras manifest fetch --descriptor \
  "$IDENTITY_CHART_REPOSITORY:$IDENTITY_VERSION" | jq -er .digest)" \
  = "$IDENTITY_CHART_DIGEST"
```

Both references must contain `@sha256:`. Make the two fork GHCR packages
public if cluster nodes will pull anonymously. Keep the manifest with the
deployment handoff; do not replace its digests with mutable tags.
All-zero and homogeneous hexadecimal sentinel digests are invalid even though
they match the general SHA-256 shape. For a private registry, use a
manifest-preserving copy, query the destination descriptor, and put that exact
digest in values; static chart validation intentionally does not test registry
reachability.

## 2. Create the namespace, signing key, and policy

Use only the intended cluster context. The policy example is not an approved
identity policy: replace every example identity with values observed from the
actual customer workflow by following the
[integration guide](integration.md#1-observe-the-real-github-claims).

```sh
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  create namespace "$IDENTITY_NAMESPACE"

umask 077
install -d -m 0700 ./private
install -m 0600 docs/policy-contract.example.json ./private/policy.json
cargo run --locked --bin keyring-tool -- generate-es256 \
  ./private/issuer-keyring.json issuer-0.5.0-a
cargo run --locked --bin keyring-tool -- validate-es256 \
  ./private/issuer-keyring.json

# Privately edit task-only policy v5 with observed claims and reviewed actor mappings.
jq empty ./private/policy.json

kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" create configmap github-oidc-exchange-policy \
  --from-file=policy.json=./private/policy.json
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" create secret generic github-oidc-exchange-keyring \
  --type=Opaque --from-file=keyring.json=./private/issuer-keyring.json

bash scripts/check-install-inputs.sh "$IDENTITY_KUBECONFIG" \
  "$IDENTITY_CONTEXT" "$IDENTITY_NAMESPACE"
```

The checker verifies names, Kubernetes types, and key presence without
printing values. Keep `private/` outside Git and backed up through an encrypted,
access-controlled recovery channel.

## 3. Prepare the baseline values

Copy the fail-closed template. The separate
[`production-values.yaml`](../charts/github-oidc-exchange/examples/production-values.yaml)
is a renderable shape example only; its domains, digest, CIDR, object names,
and Gateway references are deliberately fake.

```sh
cp charts/github-oidc-exchange/values.example.yaml ./private/values.yaml
```

Edit `private/values.yaml` and set all of the following:

- `image.repository` to `IDENTITY_IMAGE_REPOSITORY` and `image.digest` to
  `IDENTITY_IMAGE_DIGEST`;
- `config.issuerUrl` to `IDENTITY_ISSUER` without a trailing slash;
- `config.githubExchangeAudience` to `IDENTITY_AUDIENCE`;
- `httpRoute.enabled: true`, the real HTTPS Gateway `parentRefs`, and the
  issuer hostname under `hostnames`;
- `networkPolicy.ingressCidrs` to the actual Gateway/proxy source CIDRs;
- `ingress.enabled: false` and `workloadExchange.enabled: false`.

Do not place policy data, keys, TLS material, or registry credentials in the
values file. Then render and review:

```sh
bash scripts/validate-chart-values.sh ./private/values.yaml
helm lint charts/github-oidc-exchange -f ./private/values.yaml --strict
helm template identity charts/github-oidc-exchange \
  --namespace "$IDENTITY_NAMESPACE" -f ./private/values.yaml \
  > ./dist/identity-rendered.yaml
grep -E 'kind: (Deployment|Service|HTTPRoute|NetworkPolicy|Role|RoleBinding)' \
  ./dist/identity-rendered.yaml
```

Confirm the HTTPRoute contains only the three public paths above and the
Deployment image is the recorded digest.

## 4. Install and verify baseline readiness

Helm installs an OCI chart by version. Verify that its version tag still
resolves to `IDENTITY_CHART_REFERENCE`, then install it:

```sh
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  upgrade --install identity "oci://$IDENTITY_CHART_REPOSITORY" \
  --version "$IDENTITY_VERSION" --namespace "$IDENTITY_NAMESPACE" \
  --values ./private/values.yaml --wait --timeout 10m
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" rollout status \
  deployment/github-oidc-exchange --timeout=5m

curl -fsS "$IDENTITY_ISSUER/.well-known/openid-configuration" | \
  jq -e --arg iss "$IDENTITY_ISSUER" \
    '.issuer==$iss and .jwks_uri==($iss+"/jwks.json") and .token_endpoint==($iss+"/v1/exchange")' \
  >/dev/null
curl -fsS "$IDENTITY_ISSUER/jwks.json" | \
  jq -e '[.keys[] | select(.alg=="ES256" and .kty=="EC")] | length>0' \
  >/dev/null
```

Readiness is not delivery acceptance. Finish the positive, replay, wrong
repository/ref/actor/audience, and consumer-verification tests in the
[integration guide](integration.md) and the full guide's
[delivery checklist](installation.md#7-post-install-and-delivery-test-checklist).
