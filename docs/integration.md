# Integration guide — github-oidc-exchange 0.5.1

This guide connects a customer GitHub Actions workflow to a deployed Identity
issuer and then to Steward through steward-run. It complements the
[baseline quickstart](quickstart.md), the
[full installation guide](installation.md), and the normative
[consumer contract](consumer-contract-v1.md).

## Values shared across the integration

| Value | Example | Owner and use |
| --- | --- | --- |
| Issuer | `https://identity.customer.example` | Identity operator; exact `config.issuerUrl`, discovery issuer, and issued-token `iss`. |
| Exchange endpoint | `https://identity.customer.example/v1/exchange` | Identity operator; pinned in the customer workflow. |
| GitHub input audience | `customer-github-identity-exchange` | Identity operator; exact `config.githubExchangeAudience` and GitHub OIDC request audience. |
| Output audience | `steward-task-api` | Protocol constant; Steward must require it. The caller cannot change it. |
| Reusable workflow revision | Forty-character commit SHA | Workflow owner; GitHub signs it into `job_workflow_sha`. Never use a moving branch or tag for production. |

The GitHub input audience and the issued Steward audience are intentionally
different. Neither flow uses a GitHub OAuth App. An ARC registration GitHub
App belongs to steward-run infrastructure and is not an Identity credential.

## 1. Observe the real GitHub claims

Do not infer `sub`, numeric IDs, or reusable-workflow claims. Copy
[`github-oidc-claim-probe.yml`](examples/github-oidc-claim-probe.yml) into
`.github/workflows/identity-claim-probe.yml` in a private, access-restricted
customer workflow repository. Commit it, record the resulting 40-character
commit SHA, and call it from an approved repository:

```yaml
name: Observe Identity claims
on: workflow_dispatch
permissions: {}
jobs:
  claims:
    permissions:
      contents: read
      id-token: write
    uses: CUSTOMER_ORG/IDENTITY_WORKFLOWS/.github/workflows/identity-claim-probe.yml@REVIEWED_40_HEX_COMMIT
    with:
      identity-exchange-audience: customer-github-identity-exchange
```

The reusable workflow writes only an allowlisted claim projection to the job
summary; it never prints or uploads the JWT. Restrict access to the run, copy
the required values into private policy preparation storage, and delete the
run afterward according to customer retention policy. Review at least:

- exact `sub`, `ref`, and `event_name`;
- numeric `repository_owner_id`, `repository_id`, and `actor_id`;
- exact `workflow_ref`, `job_workflow_ref`, and 40-character
  `job_workflow_sha`;
- exact `iss` and requested `aud`.

Remove the probe after enrollment. It is not a production authentication
workflow.

## 2. Enroll the repository and actor

Copy `docs/policy-contract.example.json` to a mode-0600 private file. Replace
every example value. A normal task rule binds the exact repository owner ID,
repository ID, subject, event, ref, and a reviewed numeric actor mapping.
Policy v5 is task-only: workflow refs remain signed provenance but are not
policy selectors.
Never add wildcards or derive email/canonical identity from GitHub display
data.

Application 0.5.0 and newer reject policy v4. For an existing 0.4.0
installation, create a
separate v5 ConfigMap and follow the [atomic migration procedure](upgrade-v0.5.0.md)
so old pods retain v4 while new pods receive v5.

```sh
umask 077
install -m 0600 docs/policy-contract.example.json ./private/policy.json
# Edit privately using the observed claims and reviewed corporate identity.
jq empty ./private/policy.json
```

Project the reviewed file into
`ConfigMap/github-oidc-exchange-policy` as `policy.json`, then bump only
`rolloutRevisions.githubPolicy` and run `helm upgrade`. The process does not
hot-reload policy. Follow the version-checked replacement procedure in
[the installation guide](installation.md#6-rotation-recovery-uninstall) so a
concurrent operator change returns `409 Conflict` instead of being overwritten.

## 3. Prove the exchange before adding a consumer

Copy [`github-oidc-exchange-smoke.yml`](examples/github-oidc-exchange-smoke.yml)
to `.github/workflows/identity-exchange-smoke.yml` in the controlled reusable
workflow repository, pin its commit in a caller, and run the admitted case:

```yaml
name: Verify Identity exchange
on: workflow_dispatch
permissions: {}
jobs:
  admitted:
    permissions:
      contents: read
      id-token: write
    uses: CUSTOMER_ORG/IDENTITY_WORKFLOWS/.github/workflows/identity-exchange-smoke.yml@REVIEWED_40_HEX_COMMIT
    with:
      identity-exchange-url: https://identity.customer.example/v1/exchange
      identity-exchange-audience: customer-github-identity-exchange
      expected-http-status: "200"
```

The smoke workflow retains both tokens only in shell memory or a mode-0600
runner file, checks the response contract, and emits only the HTTP status. It
does not prove that a downstream consumer verifies the issued signature and
claims.

Run separate fresh jobs for each negative case; never edit a JWT:

- another repository or owner ID;
- a disallowed ref;
- an unmapped actor;
- a different requested audience with `expected-http-status: "401"`.

Replay the admitted source assertion once in a private derivative test and
expect `401`. Treat `503` as dependency failure, not admission denial. Delete
all temporary response files, and never upload tokens or response bodies as
artifacts.

## 4. Connect steward-run and Steward

Install Steward and steward-run using their own released installation guides.
The customer-owned steward-run reusable workflow must be pinned to a reviewed
40-character commit and supplied both Identity inputs. A minimal caller shape
is:

```yaml
name: Governed Steward task
on: workflow_dispatch
permissions: {}
jobs:
  prepare:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: request
          path: request/
          if-no-files-found: error

  governed:
    needs: prepare
    permissions:
      contents: read
      id-token: write
    uses: CUSTOMER_ORG/steward-run/.github/workflows/steward-task-customer.yml@REVIEWED_40_HEX_COMMIT
    with:
      runner-label: steward-run
      workflow: CUSTOMER_STEWARD_WORKFLOW_REFERENCE
      input-artifact: request
      output-artifact: result
      steward-api-url: https://steward.customer.example
      identity-exchange-url: https://identity.customer.example/v1/exchange
      identity-exchange-audience: customer-github-identity-exchange
```

Keep the endpoint and audience as reviewed literals in the checked-in workflow
unless the customer's change-control system provides an equally strong pin.
The reusable workflow requests GitHub OIDC, exchanges it for the fixed
`steward-task-api` token, and sends that token to Steward. The ARC App Secret
is not involved in this exchange.

The integration owner must verify that Steward accepts only tokens with all of
the following:

- exact Identity issuer;
- audience exactly `steward-task-api`;
- ES256 signature from the issuer JWKS;
- `identity_contract=steward-task-v2`;
- required subject, groups, actor identity, and signed source provenance;
- current `iat`, `nbf`, and `exp` within the two-minute lifetime.

Run the governed task with known inputs and expected output hash. Then repeat
with a wrong input audience, untrusted issuer/CA, and unauthorized
repository/ref/actor. Record only source revisions, artifact digests, GitHub
run ID, bounded Task UID/status, HTTP status, and public JWKS `kid`s—never
tokens, authorization headers, policy mappings, or provider bodies.

## Completion checklist

- Discovery and JWKS match the exact issuer and publish an ES256 key.
- One real reusable-workflow assertion exchanges successfully; replay is
  denied.
- Wrong repository, ref, actor, and audience are each denied with a fresh real
  assertion.
- Steward verifies the issued token contract rather than merely decoding it.
- One fork-pinned steward-run task succeeds and finalizes with expected output.
- Wrong issuer/audience/CA tests fail before successful Task submission.
- Evidence contains immutable source/workflow/image/chart coordinates and no
  credential material.
