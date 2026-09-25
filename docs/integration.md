# Integration guide — github-oidc-exchange 0.6.0

This guide connects GitHub Actions to Identity and then to Steward through
steward-run. It complements the [quickstart](quickstart.md),
[installation guide](installation.md), and normative
[consumer contracts](consumer-contract-v1.md).

## 1. Discover the exchange contract

Pin the issuer URL, then obtain the exchange endpoint and exact GitHub input
audience from discovery:

```sh
export IDENTITY_ISSUER=https://identity.example.org
discovery_file="$(mktemp)"
chmod 0600 "$discovery_file"
curl -fsS "$IDENTITY_ISSUER/.well-known/openid-configuration" >"$discovery_file"
jq -e --arg issuer "$IDENTITY_ISSUER" '
  .issuer == $issuer and
  .github_oidc_exchange_endpoint == ($issuer + "/v1/exchange") and
  (.github_oidc_audience | type == "string" and length > 0) and
  (.identity_contracts_supported | index("steward-task-v2")) and
  (.identity_contracts_supported | index("steward-task-v3"))
' "$discovery_file" >/dev/null
export IDENTITY_EXCHANGE_URL="$(jq -er .github_oidc_exchange_endpoint "$discovery_file")"
export IDENTITY_AUDIENCE="$(jq -er .github_oidc_audience "$discovery_file")"
rm "$discovery_file"
```

The GitHub input audience differs from the fixed output audience
`steward-task-api`. Neither flow uses a GitHub OAuth App.

## 2. Observe signed GitHub claims

Do not infer `sub`, numeric IDs, refs, or reusable-workflow claims. Copy
[`github-oidc-claim-probe.yml`](examples/github-oidc-claim-probe.yml) into
an access-restricted workflow repository, pin it to a reviewed 40-character
commit, and call it from the intended repository:

```yaml
name: Observe Identity claims
on: workflow_dispatch
permissions: {}
jobs:
  claims:
    permissions:
      contents: read
      id-token: write
    uses: ORG/IDENTITY_WORKFLOWS/.github/workflows/identity-claim-probe.yml@REVIEWED_40_HEX_COMMIT
    with:
      identity-exchange-audience: EXACT_DISCOVERED_AUDIENCE
```

The reusable workflow exposes only an allowlisted claim projection. Review:

- exact `iss`, requested `aud`, `sub`, `ref`, and `event_name`;
- numeric `repository_owner_id`, `repository_id`, and `actor_id`;
- `workflow_ref`, `workflow_sha`, `job_workflow_ref`, and the 40-character
  `job_workflow_sha`; and
- run ID, attempt, and triggered SHA.

Remove the probe after verification. Never print, upload, or retain the raw
assertion.

## 3. Select and install a policy

The chart defaults to v5. Choose exactly one path.

### Preserve v5 and `steward-task-v2`

Copy `docs/policy-contract.example.json`. Replace every example value with
reviewed values. v5 requires exact subject, event, ref, numeric owner/repository
IDs, and a verified numeric actor mapping.

```sh
umask 077
install -m 0600 docs/policy-contract.example.json ./private/policy-v5.json
jq empty ./private/policy-v5.json
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" create configmap github-oidc-exchange-policy \
  --from-file=policy.json=./private/policy-v5.json
```

Set:

```yaml
config:
  policyContract: github-oidc-exchange.apelogic.io/v5
  policyConfigMapName: github-oidc-exchange-policy
```

### Opt in to v6 and `steward-task-v3`

Copy `docs/policy-contract-v6.example.json`. The minimal v6 rule admits only
the exact signed numeric owner/repository pair. Omitted actors, subjects,
events, and refs mean Identity does not choose which actors, branches, tags,
pull requests, events, or workflow subjects may submit from that repository.
Signed provenance is still checked and preserved.

Add any compatibility selector only when Identity must retain that exact
restriction. If `actors` is present, only mapped verified numeric actors are
accepted and the validated mapping can produce email and human-identity
groups. If it is absent, the v3 token retains only the policy-selected
service-principal group and contains no human entitlement claims.

```sh
umask 077
install -m 0600 docs/policy-contract-v6.example.json ./private/policy-v6.json
jq empty ./private/policy-v6.json
kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_CONTEXT" \
  -n "$IDENTITY_NAMESPACE" create configmap github-oidc-exchange-policy-v6 \
  --from-file=policy.json=./private/policy-v6.json
```

Set both fields explicitly:

```yaml
config:
  policyContract: github-oidc-exchange.apelogic.io/v6
  policyConfigMapName: github-oidc-exchange-policy-v6
rolloutRevisions:
  githubPolicy: v6-rev-1
```

Do not modify or delete the v5 ConfigMap. Follow the
[0.6.0 upgrade guide](upgrade-v0.6.0.md) for preflight and atomic rollback.

## 4. Prove exchange behavior

Copy [`github-oidc-exchange-smoke.yml`](examples/github-oidc-exchange-smoke.yml)
into the controlled reusable-workflow repository and pin its commit:

```yaml
name: Verify Identity exchange
on: workflow_dispatch
permissions: {}
jobs:
  admitted:
    permissions:
      contents: read
      id-token: write
    uses: ORG/IDENTITY_WORKFLOWS/.github/workflows/identity-exchange-smoke.yml@REVIEWED_40_HEX_COMMIT
    with:
      identity-exchange-url: https://identity.example.org/v1/exchange
      identity-exchange-audience: EXACT_DISCOVERED_AUDIENCE
      expected-http-status: "200"
```

Use a fresh assertion for each negative case. Both policies must reject a
wrong issuer, wrong audience, wrong numeric owner/repository pair, malformed
provenance, invalid signature/key/algorithm, expired assertion, and replayed
`jti`. For v5, also prove disallowed subject/event/ref and unmapped actor are
rejected. For v6, test only the optional selectors actually configured; an
omitted selector intentionally does not restrict that dimension.

Treat 503 as dependency failure, not admission denial. Do not edit JWTs as a
substitute for real signed test cases and never upload response bodies.

## 5. Connect Steward

Before selecting v6, verify the deployed Steward consumer accepts
`steward-task-v3`, requires the service-principal group, and does not require
optional email or human-identity groups. Steward must validate:

- exact Identity issuer and `aud=["steward-task-api"]`;
- ES256 signature from the issuer JWKS;
- current `iat`, `nbf`, and `exp` within the two-minute lifetime;
- the selected `identity_contract`; and
- signed source provenance.

Identity authenticates the signed GitHub source. Steward owns any user binding
and the decision that the authenticated source may create or operate a Task.
Repository identity, actor login, and provenance are not sufficient Task
authority by themselves. Identity has no runtime dependency on Steward and
does not query Steward users, Tasks, or authorization policy.

A minimal pinned steward-run caller is:

```yaml
name: Governed Steward task
on: workflow_dispatch
permissions: {}
jobs:
  governed:
    permissions:
      contents: read
      id-token: write
    uses: ORG/steward-run/.github/workflows/steward-task.yml@REVIEWED_40_HEX_COMMIT
    with:
      runner-label: steward-run
      workflow: REVIEWED_STEWARD_WORKFLOW_REFERENCE
      input-artifact: request
      output-artifact: result
      steward-api-url: https://steward.example.org
      identity-exchange-url: https://identity.example.org/v1/exchange
      identity-exchange-audience: EXACT_DISCOVERED_AUDIENCE
```

Keep the endpoint and audience as reviewed values. The reusable workflow
requests GitHub OIDC, exchanges it for the fixed Steward token, and sends that
token to Steward. An ARC registration secret is unrelated to this exchange.

## Completion checklist

- Discovery returns the exact exchange endpoint/audience and both supported
  contract versions.
- One real assertion exchanges successfully and replay is denied.
- Wrong issuer, audience, owner ID, and repository ID are denied.
- Configured optional selectors are each proven exact; omitted selectors are
  verified not to impose an Identity authorization decision.
- Steward verifies the chosen v2 or v3 contract and source provenance.
- v3 operation succeeds with only the service-principal group and without
  email or human-identity groups when no actor map exists.
- Evidence contains immutable revisions and public key IDs, never tokens,
  policy mappings, or authorization headers.
