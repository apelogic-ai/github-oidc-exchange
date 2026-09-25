# Identity consumer contracts

Status: released with application/chart **0.6.0**. This document defines the
normative GitHub exchange protocol and the two supported Steward token
contracts. It does not deploy a consumer. See the
[integration guide](integration.md) for end-to-end examples.

## Version compatibility

| Application/chart | Selected policy | Output contract | Status |
| --- | --- | --- | --- |
| 0.6.0 / 0.6.0 | `github-oidc-exchange.apelogic.io/v5` | `steward-task-v2` | Default; behavior and token claims preserved |
| 0.6.0 / 0.6.0 | `github-oidc-exchange.apelogic.io/v6` | `steward-task-v3` | Explicit opt-in |
| 0.5.1 / 0.5.1 | v5 | v2 | Historical supported pair; cannot read v6 |

Do not combine an older application with v6. Activation and rollback use the
application/chart revision and policy reference as one unit, with distinct v5
and v6 ConfigMaps. See the [0.6.0 upgrade guide](upgrade-v0.6.0.md).

## Common protocol

| Item | Contract |
| --- | --- |
| Issuer | Exact HTTPS `config.issuerUrl`, without a trailing slash. Consumers pin it exactly. |
| Discovery | `GET {issuer}/.well-known/openid-configuration`. `issuer`, `jwks_uri`, `token_endpoint`, `github_oidc_exchange_endpoint`, `github_oidc_audience`, `identity_contracts_supported`, and `policy_versions_supported` are authoritative. |
| Public keys | `GET {issuer}/jwks.json`. ES256 P-256 keys are always present; RS256 keys appear only with workload exchange. Consumers pin the accepted algorithm per token type. |
| GitHub exchange | `POST {issuer}/v1/exchange` with `Authorization: Bearer <GitHub OIDC JWT>` and an empty body. Success returns `access_token`, `token_type=Bearer`, and `expires_in=120` with `Cache-Control: no-store`. Rejected assertions return 401; unavailable dependencies return 503. |
| GitHub input trust | Exact GitHub issuer `https://token.actions.githubusercontent.com`, configured `github_oidc_audience`, RS256 signature/key, bounded time claims, single-use `jti`, numeric actor/owner/repository IDs, and consistent signed provenance. The job needs `permissions: id-token: write`. |
| Output invariants | ES256; `iss={issuer}`; `aud=["steward-task-api"]`; 120-second TTL; stable `sub=github-actions:actor:{actor_id}`; `jti`, `iat`, `nbf`, `exp`; and `source_provenance` contract `steward.source-provenance/v1`. The caller cannot select any output claim. |
| Replay | Each accepted GitHub assertion `jti` is single-use in namespaced Kubernetes Leases. |

`sub`, `ref`, `workflow_ref`, and `job_workflow_ref` are validated for shape
and internal consistency and retained in signed source provenance. Their
presence does not by itself grant Task authority.

## `steward-task-v2` under policy v5

Policy v5 preserves the existing exact semantics:

- exact numeric repository owner and repository IDs;
- exact `subjects`, `events`, and `refs` selectors;
- a required verified numeric actor mapping;
- required validated email and canonical-user mapping; and
- policy-owned `groups`, `email`, and `email_verified=true` claims.

The output does not add `actor_login`; its claim set remains compatible with
the existing v2 consumer.

## `steward-task-v3` under policy v6

Policy v6 always requires numeric repository owner and repository IDs.
`subjects`, `events`, and `refs` on a repository rule are optional exact
selectors. `actors`, `allowed_email_domains`, and `acting_group_prefix` form
one optional all-or-none actor-compatibility bundle.

When a selector is present, Identity validates and enforces it. When
`subjects`, `events`, or `refs` are absent, Identity does not decide which
workflow subjects, events, branches, tags, or pull requests may submit a run.
When the actor compatibility bundle is absent, any positive canonical numeric
actor from the admitted numeric repository can be authenticated without an
Identity actor authorization decision.

The v3 token:

- keeps `sub=github-actions:actor:<positive canonical numeric actor ID>`;
- includes the required bounded signed login as `actor_login` display/audit
  metadata;
- omits `email`, `email_verified`, and `groups` together when the actor
  compatibility bundle is absent;
- includes a complete v2-compatible email and service/acting/canonical group
  set only from a validated configured actor compatibility bundle; and
- always preserves signed source provenance.

The GitHub login is never a durable identity or authorization selector.
Identity authenticates the signed source; Steward performs any user binding
and determines Task authority. Identity does not call Steward or depend on its
runtime state; Steward is a downstream verifier and authorization boundary.

## Source provenance

Both token contracts sign the same `source_provenance` structure:

- contract version and provider;
- numeric repository ID, numeric owner ID, and repository name;
- triggered SHA, run ID, and run attempt;
- event, ref, positive canonical numeric actor ID, and required actor login;
- caller workflow ref/SHA; and
- reusable workflow ref/SHA.

Consumers must validate issuer, audience, ES256, expiry, the selected
`identity_contract`, and source-provenance structure. A v3 consumer must accept
either no `email`/`email_verified`/`groups` claims or a complete valid
v2-compatible set; partial compatibility identity is invalid. It must read the
login from `actor_login` and must not treat repository provenance or display
metadata as sufficient Task authorization. The checked-in
[`steward-task-v3` fixture](steward-task-v3.example.json) is the normative
copy-ready claim shape for the no-compatibility path.

## Optional workload and browser contracts

The internal workload endpoint is
`POST https://{service}.{namespace}.svc.cluster.local:8443/v1/workload/exchange`.
It uses Kubernetes TokenReview with an exact configured input audience and
issues RS256 `openshell-workload-v1` tokens. It is never routed publicly and
is unchanged in 0.6.0.

The optional browser HOP-1 profile requires workload exchange and follows its
separate [v1 contract](browser-hop1-contract-v1.md). Neither optional profile
changes the GitHub v5/v6 selection.

The steward-run reusable workflow requires both exchange inputs,
`identity-exchange-url` and `identity-exchange-audience`, and passes both to
the action. Only the direct-action fallback uses
`apelogic-github-identity-exchange` when the audience is omitted; that fallback
is not the supported handoff for a deployed issuer. Pin the discovered endpoint
and audience explicitly.

During key rotation, consumers accept all published overlapping JWKS `kid`s
until the old 120-second token lifetime plus clock skew has elapsed. Refresh
JWKS on an unknown `kid`; never disable signature, issuer, audience,
algorithm, or contract-version verification.
