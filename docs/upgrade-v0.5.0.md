# Upgrade to 0.5.0 and GitHub policy v5

Release 0.5.0 removes the obsolete Steward Service Envelope bootstrap identity
path. Keeping a dormant privileged path would allow accidental reactivation,
so policy v5 contains only governed-task authorization rules. Normal Steward
task claims, groups, audience, two-minute lifetime, signing, replay protection,
workload exchange, and browser HOP-1 behavior are unchanged.

Application and policy versions form an atomic compatibility pair:

- application/chart `0.5.0` requires
  `github-oidc-exchange.apelogic.io/v5`;
- application/chart `0.4.0` requires
  `github-oidc-exchange.apelogic.io/v4`.

Application 0.5.0 fails startup with `unsupported policy version` when given a
v4 policy. An image-only rollback while v5 remains mounted is unsupported.

## Convert the policy

From a v4 policy, delete the top-level `bootstrap_group`. From every repository
rule, delete `profile`, `workflow_refs`, and `job_workflow_refs`. Delete rules
that existed only to authorize a bootstrap workflow. Change only `version` to
v5; retain every reviewed governed-task owner ID, repository ID, exact subject,
event, ref, and actor mapping.

Minimal v4 shape before conversion:

```json
{
  "version": "github-oidc-exchange.apelogic.io/v4",
  "service_group": "agents.apelogic.ai/service-principal:steward-run",
  "acting_group_prefix": "agents.apelogic.ai/acting-user:",
  "bootstrap_group": "agents.apelogic.ai/service-envelope-bootstrap:steward-run",
  "allowed_email_domains": ["hypershell.ai"],
  "repositories": [
    {
      "profile": "task",
      "owner_id": "123456",
      "repository_id": "789012",
      "subjects": ["repo:example-org/example-repo:ref:refs/heads/main"],
      "events": ["workflow_dispatch"],
      "refs": ["refs/heads/main"]
    }
  ],
  "actors": {
    "345678": {
      "email": "verified-user@hypershell.ai",
      "canonical_user_id": "usr_0123456789abcdef0123456789abcdef",
      "verified": true
    }
  }
}
```

The corresponding v5 policy is:

```json
{
  "version": "github-oidc-exchange.apelogic.io/v5",
  "service_group": "agents.apelogic.ai/service-principal:steward-run",
  "acting_group_prefix": "agents.apelogic.ai/acting-user:",
  "allowed_email_domains": ["hypershell.ai"],
  "repositories": [
    {
      "owner_id": "123456",
      "repository_id": "789012",
      "subjects": ["repo:example-org/example-repo:ref:refs/heads/main"],
      "events": ["workflow_dispatch"],
      "refs": ["refs/heads/main"]
    }
  ],
  "actors": {
    "345678": {
      "email": "verified-user@hypershell.ai",
      "canonical_user_id": "usr_0123456789abcdef0123456789abcdef",
      "verified": true
    }
  }
}
```

Validate the full policy against
[`policy-contract.schema.json`](policy-contract.schema.json), and compare it to
[`policy-contract.example.json`](policy-contract.example.json). Do not copy the
example identities into a deployment.

## Roll out the atomic pair

1. Record the accepted 0.4.0 Helm revision, immutable image/chart digests, v4
   policy ConfigMap name, and a successful fresh task exchange.
2. Create a new ConfigMap such as `github-oidc-exchange-policy-v5` from the
   reviewed v5 file. Do not mutate or delete the v4 ConfigMap.
3. In one reviewed Helm values revision, set the chart/image to immutable
   0.5.0 coordinates, set `config.policyConfigMapName` to the v5 ConfigMap, and
   bump `rolloutRevisions.githubPolicy`.
4. Run one `helm upgrade --version 0.5.0 ... --wait`. Existing 0.4.0 pods retain
   their mounted v4 policy; every new 0.5.0 pod receives v5.
5. Verify Deployment rollout and readiness, discovery issuer, JWKS, and a fresh
   admitted task exchange. Confirm the token still has
   `aud=["steward-task-api"]`, `identity_contract=steward-task-v2`, and exactly
   these policy-derived groups:

   ```text
   agents.apelogic.ai/service-principal:<service>
   agents.apelogic.ai/acting-user:<verified-email>
   agents.apelogic.ai/canonical-user:<opaque-user-id>
   ```

6. Run fresh negative exchanges for the wrong repository owner ID, repository
   ID, subject, event, ref, and actor. Confirm a replay is rejected. A workflow
   that formerly had bootstrap authority is allowed only when its GitHub claims
   independently match an explicit v5 repository rule, and it receives only
   normal task groups.

## Roll back

Use `helm rollback` to restore the previously accepted revision. That revision
must restore the complete `0.4.0` application/chart plus v4 policy ConfigMap
reference. Verify rollout, readiness, discovery/JWKS, and a fresh task exchange
again. Keep both versioned policy ConfigMaps and both immutable release
coordinates through the rollback window.

Do not run 0.4.0 with policy v5, run 0.5.0 with policy v4, or change the shared
policy ConfigMap in place during this boundary.
