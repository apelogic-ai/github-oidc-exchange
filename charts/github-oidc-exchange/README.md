# github-oidc-exchange Helm chart 0.6.0

Read the [installation guide](../../docs/installation.md) before deploying.
The [quickstart](../../docs/quickstart.md) covers the default v5 path; the
[integration guide](../../docs/integration.md) covers GitHub Actions and
Steward; the [consumer contracts](../../docs/consumer-contract-v1.md) define
token verification.

## GitHub policy selection

Chart/application 0.6.0 supports both policies:

| `config.policyContract` | Policy object | Output |
| --- | --- | --- |
| `github-oidc-exchange.apelogic.io/v5` | Existing v5 ConfigMap; chart default | Unchanged `steward-task-v2` |
| `github-oidc-exchange.apelogic.io/v6` | Separately named v6 ConfigMap; explicit opt-in | `steward-task-v3` |

The chart passes the selected contract to the application as
`EXPECTED_POLICY_VERSION`; startup fails if the mounted document does not
match. An application upgrade with the default and existing v5 ConfigMap is
behavior-preserving. Never modify the v5 object to activate v6. Create a
separate v6 ConfigMap, change `policyContract`, `policyConfigMapName`, and
`rolloutRevisions.githubPolicy` in one Helm revision. Roll back that Helm
revision as a unit. See the [0.6.0 upgrade guide](../../docs/upgrade-v0.6.0.md).

The chart deliberately fails validation until the operator supplies an
immutable image digest, HTTPS issuer, dedicated GitHub OIDC input audience,
policy ConfigMap, ES256 keyring Secret, rollout revisions, and trusted ingress
source CIDRs. Copy [`values.example.yaml`](values.example.yaml) to private
deployment storage and select one route: Service-only behind an HTTPS proxy,
Ingress with explicit class/TLS, or HTTPRoute attached to an existing HTTPS
Gateway. No cloud provider or ingress implementation is assumed.

Each exposure mode must publish the RFC 8414 path derived from
`config.issuerUrl`, the retained `/.well-known/openid-configuration`,
`/jwks.json`, and `/v1/exchange`. For example, issuer path `/tenant` produces
`/.well-known/oauth-authorization-server/tenant`. Both metadata paths return
the same discovery contract.

`image.digest` must come from the release handoff or a verified
manifest-preserving mirror. Placeholder and homogeneous digests are rejected;
tag-only deployment is unsupported. Validate before mutation:

```sh
bash scripts/validate-chart-values.sh /path/to/deployment-values.yaml
helm lint charts/github-oidc-exchange \
  -f /path/to/deployment-values.yaml --strict
```

`workloadExchange.enabled=false` is baseline. Enabling it additionally
requires a dedicated RSA-3072 keyring Secret, workload policy ConfigMap,
server-authenticated TLS Secret, TokenReview RBAC, exact input audience, and
nonempty caller namespace/pod selectors. Its internal HTTPS route is never
public. Browser HOP-1 additionally requires workload exchange and a public
Steward JWKS ConfigMap.

Chart values contain object references only, never private key, policy, TLS,
or registry credential contents. Projected inputs do not hot-reload. After a
verified object change, bump only its corresponding `rolloutRevisions` value
and wait for rollout. Preserve key overlap and both versioned policy objects
through the rollback window.
