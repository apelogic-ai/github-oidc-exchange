# Identity consumer contract v1

Status: released with application/chart **0.5.0**. This document describes
the exact product protocol; it does not deploy any consumer. Consumer handoffs:
[Steward #103](https://github.com/apelogic-ai/steward/issues/103) and
[steward-run #41](https://github.com/apelogic-ai/steward-run/issues/41).
Copy-ready enrollment, exchange-smoke, and steward-run caller examples are in
the [customer integration guide](integration.md).

Application 0.5.0 preserves this task-token consumer contract but requires the
task-only GitHub policy contract `github-oidc-exchange.apelogic.io/v5`.
The removed Service Envelope bootstrap profile was not part of the task-token
consumer contract. Upgrade existing installations with the
[v4-to-v5 migration procedure](upgrade-v0.5.0.md).

| Item | Contract |
| --- | --- |
| Compatible application/chart | `github-oidc-exchange` `0.5.0` / Helm chart `0.5.0` together; test newer versions before adopting them. |
| Issuer | Exact HTTPS `config.issuerUrl`, with no trailing slash. Each consumer pins it exactly. |
| Discovery | `GET {issuer}/.well-known/openid-configuration`; `issuer`, `jwks_uri`, and `token_endpoint` must match the configured issuer. |
| Public keys | `GET {issuer}/jwks.json`; ES256 P-256 keys always, RS256 RSA keys only with workload exchange enabled. Pin accepted algorithms per token type; do not infer authorization from a key alone. |
| GitHub exchange | `POST {issuer}/v1/exchange`, `Authorization: Bearer <GitHub Actions OIDC JWT>`, empty body. Success: JSON `access_token`, `token_type=Bearer`, `expires_in=120`; `Cache-Control: no-store`. Invalid assertions/policy: `401`; unavailable dependencies: `503`. |
| GitHub input | Exact GitHub issuer `https://token.actions.githubusercontent.com`, configured `config.githubExchangeAudience`, RS256, short freshness, immutable owner/repository/actor IDs and exact allowed `sub`, event, ref, and actor. The GitHub workflow needs `permissions: id-token: write`; no GitHub OAuth App is involved. |
| GitHub output | ES256 JWT, `iss={issuer}`, `aud=["steward-task-api"]`, 120-second TTL, `identity_contract=steward-task-v2`; `sub=github-actions:actor:{actor_id}`, verified `email`, `email_verified=true`, policy-owned `groups`, `jti`, `iat`, `nbf`, `exp`, and signed `source_provenance` (`steward.source-provenance/v1`). A caller cannot select audience, groups, email, or TTL. |
| Workload exchange (optional) | Internal-only `POST https://{service}.{namespace}.svc.cluster.local:8443/v1/workload/exchange`, empty body, `Authorization: Bearer <projected service-account JWT>`. It is never exposed by public Ingress/HTTPRoute. |
| Workload input/trust | Identity calls Kubernetes `TokenReview` with exactly `workloadExchange.inputAudience`; caller must be a bound, projected service-account token with that audience and a username exactly admitted by workload policy. Identity service account needs `create` on `tokenreviews.authentication.k8s.io`; the chart adds this only when enabled. Callers need a trusted public CA bundle and must verify the Service DNS SAN; do not disable TLS verification. |
| Workload output | RS256 JWT, RSA-3072-or-stronger key, `iss={issuer}`, `aud=["openshell-api"]`, 120-second TTL, `identity_contract=openshell-workload-v1`, exact policy-owned `sub=kubernetes:serviceaccount:{namespace}:{serviceAccount}` and `roles`, plus `jti/iat/nbf/exp`. No GitHub provenance/email/groups. |
| Replay | Each GitHub assertion `jti` is single-use in namespaced Kubernetes Leases. Workload projected tokens may be reused while valid; TokenReview runs on each exchange. |
| Browser HOP-1 (optional) | Requires workload listener; separate [v1 contract](browser-hop1-contract-v1.md). Uses a public Steward JWKS ConfigMap to verify a signed Steward browser attestation, not a signing Secret for Identity. |

The public listener is HTTP **inside** the cluster on Service port 8080; the
operator's Ingress/Gateway/proxy must terminate publicly trusted HTTPS for the
issuer URL. The optional internal workload listener has its own server-authenticated
TLS Secret, Service port 8443, and caller-distributed trust bundle. Discovery's
`token_endpoint` is the GitHub exchange path, not the workload path.

The output audience and claim vocabulary are deliberately fixed for current
Steward/OpenShell consumers. A customer can run this service from a fork and its
own registry/cluster, but an unrelated relying party must explicitly implement
this contract or request a reviewed protocol change. A GitHub App for ARC or
source access, a browser Google OAuth client, and a downstream MCP-GW OAuth
client are **different integrations** and are not prerequisites for GitHub
Actions OIDC exchange.

The steward-run customer reusable workflow requires both exchange inputs,
`identity-exchange-url` and `identity-exchange-audience` and passes both values
to the action. Only the direct-action fallback uses
`apelogic-github-identity-exchange` when `identity-exchange-audience` is omitted;
that fallback is not the customer handoff. A customer deployment must pin the
expected audience and trusted endpoint and pass target-context negative tests
before it counts Identity exchange as governed end-to-end acceptance. The
resolved boundary is recorded in
[steward-run #43](https://github.com/apelogic-ai/steward-run/issues/43).

When rotating keys, consumers must accept all published overlapping JWKS `kid`s
until every old 120-second token plus clock-skew allowance has expired. Pin
issuer, audience, algorithm, contract version, and required claims; refresh
JWKS on a new `kid` rather than disabling verification.
