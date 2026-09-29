# Identity operator observability contract v1

Status: stable for application/chart 0.7.5 and later. Additive fields, reasons,
checks, and metrics may appear within v1. Removing or renaming a documented
item requires a new contract version.

## Startup

Startup failures are JSON log records with `event="startup_failed"`, a stable
`stage`, and a safe `error` description. Stages identify configuration,
GitHub policy, ES256 keyring, Kubernetes Lease replay ledger, GitHub JWKS
verifier or warm-up, optional workload policy/RSA keyring/TokenReview/TLS,
optional browser verifier, and listener binding. Errors never include bearer
tokens or private key material. Successful GitHub JWKS warm-up records
`dependency="github_jwks"` before listeners start.

Configuration failures exit before serving. Runtime dependency failure after
startup is represented by readiness and 503 responses only when no safe cached
state remains; liveness stays independent so Kubernetes can distinguish an
unhealthy process from a temporarily unavailable dependency.

## Health and readiness

`GET /healthz` returns 204 while the process can serve. `GET /readyz` returns
204 only when every enabled dependency check passes. On failure it returns 503
and JSON with the exact shape:

```json
{"status":"not_ready","failed_checks":["github_jwks","replay_ledger"]}
```

Stable public-listener check names are `github_signing_key`, `github_jwks`,
`replay_ledger`, and, when enabled, `workload_signing_key`. Stable internal
listener names are `workload_signing_key` and `browser_signing_key`. The list
may contain multiple simultaneous failures and clients must ignore unknown
additive names. A failing signing-key check means the current key is inside its
configured expiry window. `github_jwks` fails only when no successfully loaded
key set remains inside `GITHUB_JWKS_MAX_STALENESS_SECONDS`; the probe performs
no GitHub network request. `replay_ledger` uses a fixed sentinel Lease GET,
treats 200 or 404 as healthy, times the request out within one second, and
caches the result for 30 seconds. A failed check means Identity cannot safely
accept a GitHub assertion.

## Structured audit events and reasons

GitHub exchange events are `exchange_issued`, `exchange_denied`,
`exchange_replayed`, and `exchange_failed`. Stable rejection/failure reasons
are:

| Reason | Class | Meaning |
| --- | --- | --- |
| `assertion is invalid` | denied | Signature, issuer, audience, time, ID, or provenance validation failed. |
| `identity is not authorized` | denied | The verified source did not match selected policy. |
| `replay` | replayed | The source JTI was already consumed. |
| `GitHub signing keys are unavailable while <stage>: <detail>` | failed | No usable cached GitHub key remains and refresh failed; the reason preserves the safe fetch/status/decode/validation stage and cause. |
| `ledger_unavailable` | failed | The Lease ledger could not prove single use. |
| `signing_unavailable` | failed | The selected output key could not sign. |

GitHub audit fields include numeric actor/repository IDs, caller and reusable
workflow refs, and a truncated SHA-256 hash of the source JTI. Issuance records
the selected repository and workflow refs. Raw assertions, output tokens,
emails, private keys, and full source JTIs are never audit fields.

Workload events are `workload_exchange_issued`, `workload_exchange_denied`,
and `workload_exchange_failed`, with reasons `token_review_rejected`,
`token_review_unavailable`, `workload_unmapped`, and `signing_unavailable`.
The accepted username is represented only by a truncated hash. Browser HOP-1
uses `browser_hop1_issued`, `browser_hop1_denied`, `browser_hop1_replayed`, and
`browser_hop1_failed`; its stable reasons are documented in the
[browser HOP-1 contract](browser-hop1-contract-v1.md).

## Prometheus metrics

`GET /metrics` emits a `# HELP` and `# TYPE` line for every metric. Counters
are process-lifetime totals and reset on restart.

| Metric | Type | Meaning |
| --- | --- | --- |
| `github_oidc_exchange_requests_total` | counter | GitHub exchange attempts received. |
| `github_oidc_exchange_issued_total` | counter | Tokens issued. |
| `github_oidc_exchange_denied_total` | counter | Authentication/policy denials, excluding replay. |
| `github_oidc_exchange_replayed_total` | counter | Reused source JTIs. |
| `github_oidc_exchange_errors_total` | counter | Dependency or signing failures. |
| `github_oidc_exchange_jwks_refresh_failures_total` | counter | Failed GitHub JWKS refresh attempts, including failures masked by a still-usable cache. |
| `github_oidc_exchange_jwks_age_seconds` | gauge | Seconds since the last successful GitHub JWKS refresh. |
| `github_oidc_exchange_duration_seconds` | histogram | End-to-end latency for every GitHub exchange result; fixed buckets are 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, and 5 seconds plus `+Inf`. |
| `github_oidc_exchange_signing_key_seconds_until_expiry` | gauge | Nonnegative lifetime remaining for the active ES256 key. |
| `github_oidc_exchange_workload_requests_total` | counter | Workload exchange attempts received. |
| `github_oidc_exchange_workload_issued_total` | counter | Workload tokens issued. |
| `github_oidc_exchange_workload_denied_total` | counter | Workload authentication/policy denials. |
| `github_oidc_exchange_workload_errors_total` | counter | Workload dependency or signing failures. |
| `github_oidc_exchange_workload_signing_key_seconds_until_expiry` | gauge | Nonnegative lifetime remaining for the active RSA key. |

Alert on sustained readiness failure, any increase in error counters, replay
spikes, a denial-rate change relative to requests, and signing-key lifetime
approaching the configured readiness threshold. Use audit reason counts to
separate policy denials from dependency outages; HTTP 401 and 503 have the same
boundary.

After the five-minute soft refresh age, an exchange attempts a single-flight
refresh at most once per 30 seconds. A refresh failure emits
`event="github_jwks_refresh_failed"`, increments the refresh-failure counter,
and continues with a matching cached key until the configured hard-staleness
bound. An unknown `kid` gets a separately rate-limited forced refresh so key
rotation is observed without allowing untrusted key IDs to create unbounded
outbound traffic.
