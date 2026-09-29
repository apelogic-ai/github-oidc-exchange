# Upgrade to 0.7.0 — RFC 8414 discovery

> Historical guide for the 0.7.0 boundary. For current 0.7.4 installation,
> key lifecycle, monitoring, and rollback, use the
> [installation guide](installation.md) and
> [0.7.4 upgrade guide](upgrade-v0.7.4.md).

Application/chart 0.7.0 adds RFC 8414 authorization-server discovery for
steward-run while retaining the existing OpenID discovery endpoint. It also
requires `config.issuerUrl` to be an HTTPS origin without a path, query, or
fragment. Policy v5/v6 authorization and `steward-task-v2`/`steward-task-v3`
token behavior are unchanged.

## Compatibility matrix

| Application/chart | Policy reference | Output | Supported |
| --- | --- | --- | --- |
| 0.7.0 / 0.7.0 | `github-oidc-exchange-policy` (v5) | `steward-task-v2` | Yes; chart default |
| 0.7.0 / 0.7.0 | `github-oidc-exchange-policy-v6` (v6) | `steward-task-v3` | Yes; explicit opt-in |
| 0.6.0 / 0.6.0 | v5 or v6 ConfigMap | v2 or v3 | Historical rollback pair; lacks RFC 8414 discovery |

Keep each application/chart version paired with a policy contract it can
read. Never rewrite the v5 ConfigMap into v6. Retain both reviewed policy
objects through the rollback window.

## Preflight

1. Record the current Helm revision, image/chart digests, policy object name,
   policy object `resourceVersion`, public JWKS `kid` set, and issuer URL.
2. Confirm the issuer is an HTTPS origin only. Values such as
   `https://identity.example.org/tenant`, URLs with a query or fragment, HTTP,
   and URLs with user information are rejected. If the existing issuer has a
   path, choose an origin-only issuer and treat that issuer change as a
   separate trust migration before this upgrade.
3. Preserve the selected policy contract and object reference. The chart
   defaults to v5; v6 requires explicit values plus a separate policy object.
4. Render the chart and verify all four public routes are present:
   `/.well-known/oauth-authorization-server`,
   `/.well-known/openid-configuration`, `/jwks.json`, and `/v1/exchange`.
5. Verify the 0.7.0 image and chart coordinates from the signed
   `release-manifest.json`; do not deploy by mutable tag alone.

## Upgrade

Update the application and chart together while retaining the current policy
selection:

```sh
export IDENTITY_VERSION=0.7.0
bash scripts/validate-chart-values.sh ./private/values.yaml
helm lint charts/github-oidc-exchange -f ./private/values.yaml --strict
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  upgrade identity \
  "oci://registry.example.org/team/charts/github-oidc-exchange" \
  --version "$IDENTITY_VERSION" --namespace "$IDENTITY_NAMESPACE" \
  --values ./private/values.yaml --wait --timeout 10m
```

Do not change `config.policyContract`, `config.policyConfigMapName`, or the
corresponding rollout revision in the same upgrade unless the independently
reviewed goal is to activate v6. For v6 activation, retain
`github-oidc-exchange-policy` (v5), create
`github-oidc-exchange-policy-v6`, and change the contract, object reference,
and `rolloutRevisions.githubPolicy` atomically.

## Verify

Fetch both discovery documents and prove that they are equal and advertise
routable origin-relative endpoints:

```sh
issuer=https://identity.example.org
rfc8414="$(mktemp)"
openid="$(mktemp)"
curl -fsS "$issuer/.well-known/oauth-authorization-server" >"$rfc8414"
curl -fsS "$issuer/.well-known/openid-configuration" >"$openid"
cmp "$rfc8414" "$openid"
jq -e --arg issuer "$issuer" '
  .issuer == $issuer and
  .jwks_uri == ($issuer + "/jwks.json") and
  .token_endpoint == ($issuer + "/v1/exchange") and
  .github_oidc_exchange_endpoint == ($issuer + "/v1/exchange") and
  (.policy_versions_supported | index("github-oidc-exchange.apelogic.io/v5")) and
  (.policy_versions_supported | index("github-oidc-exchange.apelogic.io/v6")) and
  (.identity_contracts_supported | index("steward-task-v2")) and
  (.identity_contracts_supported | index("steward-task-v3"))
' "$rfc8414" >/dev/null
curl -fsS "$issuer/jwks.json" | jq -e '.keys | length > 0' >/dev/null
rm "$rfc8414" "$openid"
```

Then run a fresh admitted exchange and the relevant negative/replay cases.
For v5, verify the unchanged `steward-task-v2` claim set. For v6, verify
`steward-task-v3`, required `actor_login`, required provenance actor, and
either no compatibility identity claims or the complete configured set.
Identity does not decide absent optional source selectors; Steward performs
any user binding and Task authority remains downstream.

## Rollback

Rollback restores the complete previously accepted application/chart and
policy-reference revision:

```sh
helm --kubeconfig "$IDENTITY_KUBECONFIG" --kube-context "$IDENTITY_CONTEXT" \
  rollback identity PREVIOUS_REVISION --namespace "$IDENTITY_NAMESPACE" \
  --wait --timeout 10m
```

Repeat discovery, JWKS, positive exchange, negative cases, token-contract,
and replay checks. A 0.6.0 rollback remains compatible with both policy paths,
but it does not expose `/.well-known/oauth-authorization-server`; integrations
that require RFC 8414 discovery will fail until 0.7.0 is restored. Never roll
back only the image while leaving an incompatible chart or policy reference.
