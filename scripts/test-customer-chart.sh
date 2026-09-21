#!/usr/bin/env bash
set -euo pipefail

chart=charts/github-oidc-exchange
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

if helm template unconfigured "$chart" >"$scratch/default.yaml" 2>"$scratch/default.err"; then
  printf 'unconfigured chart must fail before installing placeholder identity values\n' >&2
  exit 1
fi

helm lint "$chart" -f "$chart/ci/test-values.yaml" --strict >/dev/null
helm template baseline "$chart" --namespace identity \
  -f "$chart/ci/test-values.yaml" >"$scratch/baseline.yaml"
helm template workload "$chart" --namespace identity \
  -f "$chart/ci/workload-values.yaml" >"$scratch/workload.yaml"

grep -Fq 'secretName: github-oidc-exchange-keyring' "$scratch/baseline.yaml"
grep -Fq 'name: github-oidc-exchange-policy' "$scratch/baseline.yaml"
grep -Fq 'key: policy.json' "$scratch/baseline.yaml"
grep -Fq 'key: keyring.json' "$scratch/baseline.yaml"
grep -Fq 'value: "identity"' "$scratch/baseline.yaml"
grep -Fq 'value: /etc/github-oidc-exchange/policy/policy.json' "$scratch/baseline.yaml"
grep -Fq 'value: /etc/github-oidc-exchange/keyring/keyring.json' "$scratch/baseline.yaml"
if grep -Fq 'name: WORKLOAD_EXCHANGE_ENABLED' "$scratch/baseline.yaml" ||
  grep -Fq 'resources: ["tokenreviews"]' "$scratch/baseline.yaml" ||
  grep -Fq 'secretName: github-oidc-exchange-workload-rsa-keyring' "$scratch/baseline.yaml"; then
  printf 'baseline must not require workload inputs\n' >&2
  exit 1
fi
grep -Fq 'secretName: github-oidc-exchange-workload-rsa-keyring' "$scratch/workload.yaml"
grep -Fq 'secretName: github-oidc-exchange-server-tls' "$scratch/workload.yaml"
grep -Fq 'name: github-oidc-exchange-workload-policy' "$scratch/workload.yaml"
grep -Fq 'key: workload-policy.json' "$scratch/workload.yaml"
grep -Fq 'key: rsa-keyring.json' "$scratch/workload.yaml"
grep -Fq 'key: tls.crt' "$scratch/workload.yaml"
grep -Fq 'key: tls.key' "$scratch/workload.yaml"
grep -Fq 'value: /etc/github-oidc-exchange/workload-policy/workload-policy.json' "$scratch/workload.yaml"
grep -Fq 'value: /etc/github-oidc-exchange/rsa-keyring/rsa-keyring.json' "$scratch/workload.yaml"
grep -Fq 'value: /etc/github-oidc-exchange/tls/tls.crt' "$scratch/workload.yaml"
grep -Fq 'value: /etc/github-oidc-exchange/tls/tls.key' "$scratch/workload.yaml"
grep -Fq 'resources: ["tokenreviews"]' "$scratch/workload.yaml"

helm template ingress "$chart" --namespace identity \
  -f "$chart/ci/test-values.yaml" \
  --set ingress.tls.secretName=identity-public-tls >"$scratch/ingress.yaml"
grep -Fq 'secretName: identity-public-tls' "$scratch/ingress.yaml"
if grep -Fq 'alb.ingress.kubernetes.io' "$scratch/ingress.yaml"; then
  printf 'Ingress must not assume ALB\n' >&2
  exit 1
fi

helm template certificate "$chart" --namespace identity \
  -f "$chart/ci/test-values.yaml" \
  --set ingress.tls.secretName=identity-public-tls \
  --set ingress.tls.certManager.enabled=true \
  --set ingress.tls.certManager.issuerRef.name=customer-issuer \
  >"$scratch/certificate.yaml"
grep -Fq 'kind: Certificate' "$scratch/certificate.yaml"
grep -Fq 'name: customer-issuer' "$scratch/certificate.yaml"

helm template workload-certificate "$chart" --namespace identity \
  -f "$chart/ci/workload-values.yaml" \
  --set workloadExchange.tls.certManager.enabled=true \
  --set workloadExchange.tls.certManager.issuerRef.name=internal-issuer \
  >"$scratch/workload-certificate.yaml"
grep -Fq 'name: github-oidc-exchange-workload' "$scratch/workload-certificate.yaml"
grep -Fq 'github-oidc-exchange.identity.svc.cluster.local' "$scratch/workload-certificate.yaml"

for missing in image.repository image.digest config.issuerUrl \
  config.githubExchangeAudience config.policyConfigMapName \
  config.keyringSecretName networkPolicy.ingressCidrs; do
  if helm template missing "$chart" -f "$chart/ci/test-values.yaml" \
    --set "${missing}=" >/dev/null 2>&1; then
    printf 'chart must reject empty %s\n' "$missing" >&2
    exit 1
  fi
done
