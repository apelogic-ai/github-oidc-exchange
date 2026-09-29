# github-oidc-exchange Helm chart 0.7.3

Read the [installation guide](../../docs/installation.md) before deploying.
The [quickstart](../../docs/quickstart.md) covers the default v5 path; the
[integration guide](../../docs/integration.md) covers GitHub Actions and
Steward; the [consumer contracts](../../docs/consumer-contract-v1.md) define
token verification.

## GitHub policy selection

Chart/application 0.7.3 supports both policies:

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
revision as a unit. See the [0.7.3 upgrade guide](../../docs/upgrade-v0.7.3.md).

The chart deliberately fails validation until the operator supplies an
immutable image digest, HTTPS issuer, dedicated GitHub OIDC input audience,
policy ConfigMap, ES256 keyring Secret, rollout revisions, and trusted ingress
source CIDRs. Copy [`values.example.yaml`](values.example.yaml) to private
deployment storage and select one route: Service-only behind an HTTPS proxy,
Ingress with explicit class/TLS, or HTTPRoute attached to an existing HTTPS
Gateway. No cloud provider or ingress implementation is assumed.

`config.issuerUrl` must be an HTTPS origin without a path, query, or fragment.
Each exposure mode publishes `/.well-known/oauth-authorization-server`, the
retained `/.well-known/openid-configuration`, `/jwks.json`, and `/v1/exchange`.
Both metadata paths return the same discovery contract.

`config.keyExpiryReadinessThresholdSeconds` defaults to seven days. The Pod
becomes unready when either enabled active signing key enters that window and
runtime signing stops at key expiry. Alert earlier using the public metrics
gauges documented in the installation guide.

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
public. The standard Steward controller and OpenShell values are paired in the
[workload-exchange guide](../../docs/steward-openshell-workload-pairing.md).
Browser HOP-1 additionally requires workload exchange and a public
Steward JWKS ConfigMap.

`serviceMonitor.enabled=true` requires both
`networkPolicy.metricsNamespaceSelector` and
`networkPolicy.metricsPodSelector` to be nonempty. Metrics share port 8080
with the public exchange handler, so select only the trusted monitoring Pods;
the chart rejects selectors that would admit every namespace or Pod.

The default egress policy is dual-stack. It permits HTTPS on TCP 443 and
Kubernetes API access on TCP 443 and 6443 through
`networkPolicy.httpsEgressCidrs`, `networkPolicy.apiServerCidrs`, and
`networkPolicy.apiServerPorts`. Keep both API-server ports unless the cluster's
pre- and post-DNAT endpoint contract proves a narrower set. Add literal
NodeLocal DNSCache CIDRs to `networkPolicy.dnsIpBlocks`. Use
`networkPolicy.extraEgress` for complete, narrowly scoped rules such as an
HTTPS proxy on a nonstandard port.

Chart values contain object references only, never private key, policy, TLS,
or registry credential contents. Projected inputs do not hot-reload. The
controller-free default requires changing the corresponding
`rolloutRevisions` value after a verified object update and waiting for the
Deployment rollout.

Clusters with an operator-managed
[Stakater Reloader](https://github.com/stakater/Reloader) may instead set
`rolloutAutomation.reloader.enabled=true`. The chart then annotates the
Deployment with `configmap.reloader.stakater.com/reload` and
`secret.reloader.stakater.com/reload`, listing the exact referenced object
names. Changes to policy, signing keys, workload TLS, or optional browser JWKS
then trigger a rolling restart. The chart does not install or grant RBAC to
Reloader. Keep the explicit revisions for reviewed object-name or
policy-contract switches, and preserve key overlap and both versioned policy
objects through rollback.
