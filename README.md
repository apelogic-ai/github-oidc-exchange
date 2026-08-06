# GitHub OIDC exchange issuer

`github-oidc-exchange` is a platform-owned identity boundary for GitHub Actions jobs. It validates
a short-lived GitHub OIDC assertion, applies a private default-deny authorization and corporate
identity mapping, records the source `jti` in a DynamoDB replay ledger, and issues a two-minute
ES256 token that an EKS external OIDC identity provider can authenticate.

It is not a general OAuth provider, a Kubernetes authentication webhook, or part of any calling
application. Environment policy belongs in a private deployment repository; this repository
contains only the generic engine and chart.

## Protocol

- `GET /.well-known/openid-configuration` — public OIDC discovery.
- `GET /jwks.json` — active and overlapping public Ed25519 keys.
- `POST /v1/exchange` — requires `Authorization: Bearer <GitHub OIDC JWT>`.
- `GET /healthz`, `GET /readyz`, `GET /metrics` — cluster-local operations endpoints.

The GitHub assertion must have:

- exact issuer `https://token.actions.githubusercontent.com` and a deployment-selected audience;
- `RS256` and a currently published GitHub signing key;
- a maximum ten-minute lifetime and valid `exp`, `iat`, and `nbf`;
- non-empty immutable `repository_owner_id`, `repository_id`, `actor_id`, `sub`, `jti`,
  `workflow_ref`, `job_workflow_ref`, `event_name`, and `ref` claims;
- an exact match in the private policy for subject, workflow, event, ref, and verified actor.

The output contains exactly one audience, `email`, two deployment-ratified `groups`, and
`identity_contract=steward-task-v1`. The source assertion and issued token are never logged.

## Runtime configuration

| Environment variable | Contract |
|---|---|
| `ISSUER_URL` | Public HTTPS issuer URL used in discovery and `iss`. |
| `GITHUB_EXCHANGE_AUDIENCE` | Dedicated inbound GitHub OIDC audience. |
| `OUTPUT_AUDIENCE` | Must be `steward-task-api`. |
| `POLICY_FILE` | Mounted private JSON authorization/mapping policy. |
| `KEYRING_FILE` | Mounted Secrets Manager-backed signing keyring. |
| `REPLAY_TABLE` | DynamoDB table with SHA-256 `jti_hash` string partition key and `expires_at` TTL. |
| `LISTEN_ADDRESS` | Optional; defaults to `0.0.0.0:8080`. |

The production pod requires an IRSA role with only `dynamodb:DescribeTable` and
`dynamodb:PutItem` on its one replay table. It receives no Kubernetes RBAC permissions.
Key rotation requires an ordinary rolling restart after ESO projects the overlapping keyring;
the prior key must remain valid until all tokens it signed have expired.

See [the policy example](docs/policy-contract.example.json),
[key rotation contract](docs/keyring-contract.example.json), and the Helm chart under
`charts/github-oidc-exchange`.

## Development

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
helm lint charts/github-oidc-exchange -f charts/github-oidc-exchange/ci/test-values.yaml
helm template test charts/github-oidc-exchange -f charts/github-oidc-exchange/ci/test-values.yaml
docker build --platform linux/amd64 -t github-oidc-exchange:test .
```

Never use the in-memory replay ledger in production. It exists only for deterministic tests.
