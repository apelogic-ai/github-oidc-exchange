# Steward and OpenShell workload-exchange pairing

This guide pairs Identity's optional Kubernetes workload exchange with the
Steward controller and OpenShell. It is a cross-product configuration map, not
a runtime dependency from Identity to Steward: Steward presents a Kubernetes
credential to Identity, Identity validates it with TokenReview and issues a
bounded token, and OpenShell verifies that token. Identity 0.7.1 and later
support this contract.

The standard contract has these exact joins:

| Producer | Consumer | Exact value |
| --- | --- | --- |
| Steward projected ServiceAccount token | Identity `workloadExchange.inputAudience` | `apelogic-workload-exchange` |
| Kubernetes TokenReview username | Identity workload policy `username` | `system:serviceaccount:steward:steward-controller` |
| Identity workload policy `subject` | OpenShell token subject | `kubernetes:serviceaccount:steward:steward-controller` |
| Identity `workloadExchange.outputAudience` | OpenShell `server.oidc.audience` | `openshell-api` |
| Identity workload policy `roles` claim | OpenShell role configuration | `openshell-admin` and `openshell-user` |
| Identity `config.issuerUrl` | OpenShell `server.oidc.issuer` | The same exact HTTPS issuer origin |

The `steward` namespace in this example is an installation input. If Steward
is installed elsewhere, replace `steward` in the namespace selector,
`username`, and `subject` together. The chart-owned controller ServiceAccount
name remains `steward-controller`. Do not use wildcards.

## Identity values and policy

Use this additive Identity values overlay after the baseline installation is
healthy. Keep the existing image, public exchange, policy, keyring, and
network settings in the deployment-owned values file.

```yaml
workloadExchange:
  enabled: true
  inputAudience: apelogic-workload-exchange
  outputAudience: openshell-api
  policyConfigMapName: github-oidc-exchange-workload-policy
  policyConfigMapKey: workload-policy.json
  rsaKeyringSecretName: github-oidc-exchange-workload-rsa-keyring
  rsaKeyringSecretKey: rsa-keyring.json
  tls:
    secretName: github-oidc-exchange-server-tls
    certificateKey: tls.crt
    privateKeyKey: tls.key
  networkPolicy:
    callerNamespaceSelector:
      kubernetes.io/metadata.name: steward
    callerPodSelector:
      app.kubernetes.io/name: steward
      app.kubernetes.io/component: controller

rolloutRevisions:
  workloadPolicy: workload-policy-rev-1
  workloadRsaKeyring: workload-rsa-rev-1
  workloadTls: workload-tls-rev-1
```

The referenced `workload-policy.json` must contain the exact admitted
ServiceAccount and the exact OpenShell role strings:

```json
{
  "version": "github-oidc-exchange.apelogic.io/workload-policy-v1",
  "identities": [
    {
      "username": "system:serviceaccount:steward:steward-controller",
      "subject": "kubernetes:serviceaccount:steward:steward-controller",
      "roles": ["openshell-admin", "openshell-user"]
    }
  ]
}
```

This exact document is checked in as
[`workload-policy-contract.example.json`](workload-policy-contract.example.json).
Add other admitted identities as separate exact entries; do not replace an
existing policy when another workload still depends on it. After changing the
referenced ConfigMap, change `rolloutRevisions.workloadPolicy` and wait for the
Identity Deployment rollout because projected policy content is not
hot-reloaded.

## Steward values

Steward projects the fixed `apelogic-workload-exchange` audience into the
`steward-controller` Pod. Point that controller at Identity's internal TLS
listener and pin the certificate DNS name:

```yaml
execution:
  enabled: true

config:
  controller:
    workloadExchangeEndpoint: https://github-oidc-exchange.identity.svc.cluster.local:8443/v1/workload/exchange
    workloadExchangeServerName: github-oidc-exchange.identity.svc.cluster.local

workloadExchangeTrust:
  kind: ConfigMap
  name: steward-workload-exchange-ca
  caCertificate: ca.crt
```

Here `identity` is the Identity namespace. The serving certificate selected by
Identity's `workloadExchange.tls.secretName` must cover the exact
`workloadExchangeServerName`, and Steward's public CA ConfigMap must validate
that chain. The workload endpoint stays cluster-internal and must not be added
to Ingress or HTTPRoute.

## OpenShell values

OpenShell must verify the issuer, output audience, and role claim that Identity
selects. Pair its values with the Identity configuration above:

```yaml
server:
  auth:
    allowUnauthenticatedUsers: false
  oidc:
    issuer: https://identity.example.org
    audience: openshell-api
    rolesClaim: roles
    adminRole: openshell-admin
    userRole: openshell-user
```

Replace the issuer with the exact origin-only `config.issuerUrl` used by
Identity. If different role names are deliberately selected in OpenShell,
change the Identity workload-policy roles to those exact strings in the same
rollout. Identity fixes the claim name to `roles`, the token contract to
`openshell-workload-v1`, the algorithm to RS256, and the lifetime to at most
120 seconds; callers cannot override them.

## Verification

From the selected Steward controller Pod, verify the source credential has the
projected audience without printing the token, then exercise the empty-body
exchange through the configured TLS trust. A successful response must verify
against Identity's JWKS with:

- `iss` equal to the configured Identity issuer;
- `aud` equal to `openshell-api`;
- `sub` equal to `kubernetes:serviceaccount:steward:steward-controller`;
- `roles` equal to the reviewed policy roles; and
- `identity_contract` equal to `openshell-workload-v1`.

Also prove that a token for the Kubernetes API audience, an unlisted
ServiceAccount, a Pod outside both NetworkPolicy selectors, and the wrong CA or
server name fail. Record only status, timestamps, revisions, and public key
IDs; never record either source or exchanged bearer token.
