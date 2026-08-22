# Steward browser-to-MCP HOP-1 contract v1

This is the product-owned, internal-only bridge from a verified Steward browser session to a
short-lived MCP-GW HOP-1 bearer. It is intentionally **not** a browser login API and does not turn
Identity into a general OAuth provider.

## Boundary

1. Steward verifies the browser session and resolves its opaque canonical user ID from its own
   database.
2. Steward creates one ES256 JWT attestation and calls Identity's existing internal TLS workload
   listener with its projected Kubernetes service-account token.
3. Identity TokenReviews that caller against its exact configured audience, requires the exact
   `browser-hop1-issuer` workload-policy role, validates the pinned Steward JWKS assertion, and
   records the request `jti` once in its replay ledger.
4. Identity returns a 60-second ES256 bearer signed by Identity's existing published JWKS. MCP-GW
   validates the exact Identity issuer and exact MCP resource audience as an ordinary HOP-1 issuer
   profile.

The browser cookie, session handle, OAuth provider token, and any UI-visible credential are never
sent to Identity or MCP-GW. The HOP-1 bearer is a server-side transient value; Steward never
returns it to browser JavaScript or logs it.

## Internal request

`POST /v1/browser-hop1/exchange` is available only on the workload TLS listener, never the public
listener or Ingress. It requires:

- `Authorization: Bearer <projected Steward API service-account token>`;
- `Content-Type: application/jwt`;
- an ES256 JWT body, `typ=JWT`, whose `kid` is in the deployment-projected Steward public JWKS.

The request JWT has no extension claims and all of these required claims:

```json
{
  "iss": "https://steward.example.invalid",
  "sub": "usr_<32 lowercase hex>",
  "aud": "identity-browser-hop1",
  "exp": 0,
  "iat": 0,
  "nbf": 0,
  "jti": "opaque one-time assertion id",
  "email": "verified-person@example.invalid",
  "email_verified": true,
  "operation": "github_oauth_connect",
  "operation_id": "op_<32 lowercase hex>"
}
```

Its issuer and audience are exact deployment configuration, its validity period is at most 60
seconds, and replay is rejected. `sub`, `email`, and the operation fields are selected by Steward;
they are not browser request parameters. v1 authorizes only `github_oauth_connect`; a new operation
requires a reviewed contract change rather than a free-form scope.

## Output

The response is standard no-store bearer JSON. The signed JWT contains exactly the Identity issuer,
canonical-user `sub`, one configured MCP resource audience, normal time claims and output `jti`,
the verified email, `github_oauth_connect`, the opaque operation ID, and
`identity_contract=steward-browser-mcp-hop1-v1`. It intentionally contains no browser session,
Steward RBAC groups, service principal, GitHub claims, OAuth grant, or provider credential.

The existing DynamoDB replay ledger stores a namespaced hash of the source request identifier. Logs
record only event class, reviewed Kubernetes username, reason, and a truncated hash of the source
identifier—never JWTs, emails, browser state, or provider credentials.

## Deployment inputs

Set `BROWSER_HOP1_ENABLED=true` only together with workload exchange. The required environment
inputs are:

- `BROWSER_HOP1_STEWARD_ISSUER` — exact HTTPS Steward assertion issuer;
- `BROWSER_HOP1_ASSERTION_AUDIENCE` — exact nonempty Identity-only audience;
- `BROWSER_HOP1_STEWARD_JWKS_FILE` — read-only projected public ES256 JWKS;
- `BROWSER_HOP1_OUTPUT_AUDIENCE` — exact HTTPS MCP resource URL.

The Helm `browserHop1` block requires an immutable rollout revision for the public JWKS ConfigMap.
Its network path uses the already private workload listener and its exact `workloadExchange`
caller selectors. The private workload policy must grant `browser-hop1-issuer` only to the Steward
API service account; it must not be assigned to a browser, an agent sandbox, a job runner, or a
general namespace selector.
