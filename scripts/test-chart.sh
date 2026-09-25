#!/usr/bin/env bash
set -euo pipefail

chart=charts/github-oidc-exchange
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

if helm template unconfigured "$chart" >"$scratch/default.yaml" 2>"$scratch/default.err"; then
  printf 'unconfigured chart must fail before installing placeholder identity values\n' >&2
  exit 1
fi

released_digest=sha256:ef41cf1cf5d7f8b182e985f609884f6409d9d49ebc8a5164f7b76faf8f806dc1
activation_digest=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
zero_digest=sha256:0000000000000000000000000000000000000000000000000000000000000000

for digit in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do
  printf -v repeated '%*s' 64 ''
  repeated=${repeated// /$digit}
  sentinel="sha256:$repeated"
  if helm lint "$chart" -f "$chart/ci/test-values.yaml" --strict \
    --set-string "image.digest=$sentinel" >"$scratch/sentinel-schema.err" 2>&1; then
    printf 'chart schema must reject homogeneous sentinel digest %s\n' "$sentinel" >&2
    exit 1
  fi
  grep -Fq 'image.digest' "$scratch/sentinel-schema.err"
  if helm template sentinel "$chart" -f "$chart/ci/test-values.yaml" \
    --skip-schema-validation --set-string "image.digest=$sentinel" \
    >"$scratch/sentinel.yaml" 2>"$scratch/sentinel-preflight.err"; then
    printf 'chart preflight must reject homogeneous sentinel digest %s\n' "$sentinel" >&2
    exit 1
  fi
  grep -Fq 'image.digest: placeholder/sentinel value' "$scratch/sentinel-preflight.err"
  grep -Fq 'published release handoff or a verified manifest-preserving mirror' \
    "$scratch/sentinel-preflight.err"
done

sed "s#digest: .*#digest: $zero_digest#" \
  "$chart/ci/test-values.yaml" >"$scratch/sentinel-values.yaml"
if bash scripts/validate-chart-values.sh "$scratch/sentinel-values.yaml" \
  >"$scratch/validator.out" 2>"$scratch/validator.err"; then
  printf 'values validator must reject the all-zero image.digest\n' >&2
  exit 1
fi
grep -Fq 'image.digest: placeholder/sentinel value' "$scratch/validator.err"

# Cover both checked-in examples. values.example.yaml intentionally needs the
# complete CI overlay because its mandatory deployment inputs are empty.
for example_args in \
  "$chart/examples/production-values.yaml" \
  "$chart/values.example.yaml $chart/ci/test-values.yaml"; do
  read -r -a example_files <<<"$example_args"
  helm_args=()
  for example_file in "${example_files[@]}"; do
    helm_args+=( -f "$example_file" )
  done
  if helm lint "$chart" "${helm_args[@]}" --strict \
    --set-string "image.digest=$zero_digest" \
    >"$scratch/example-schema.err" 2>&1; then
    printf 'chart schema must reject all-zero image.digest in %s\n' "$example_args" >&2
    exit 1
  fi
  grep -Fq 'image.digest' "$scratch/example-schema.err"
done

helm lint "$chart" -f "$chart/ci/test-values.yaml" --strict >/dev/null
helm template baseline "$chart" --namespace identity \
  -f "$chart/ci/test-values.yaml" >"$scratch/baseline.yaml"
helm template workload "$chart" --namespace identity \
  -f "$chart/ci/workload-values.yaml" >"$scratch/workload.yaml"

grep -A1 -Fq 'name: EXPECTED_POLICY_VERSION
              value: "github-oidc-exchange.apelogic.io/v5"' "$scratch/baseline.yaml"
grep -Fq 'name: github-oidc-exchange-policy' "$scratch/baseline.yaml"

helm template source-auth "$chart" --namespace identity \
  -f "$chart/ci/test-values.yaml" \
  --set-string config.policyContract=github-oidc-exchange.apelogic.io/v6 \
  --set-string config.policyConfigMapName=github-oidc-exchange-policy-v6 \
  --set-string "image.digest=$activation_digest" \
  --set-string rolloutRevisions.githubPolicy=v6-rev-1 \
  >"$scratch/source-auth.yaml"
grep -A1 -Fq 'name: EXPECTED_POLICY_VERSION
              value: "github-oidc-exchange.apelogic.io/v6"' "$scratch/source-auth.yaml"
grep -Fq 'name: github-oidc-exchange-policy-v6' "$scratch/source-auth.yaml"
grep -Fq "@$activation_digest" "$scratch/source-auth.yaml"
! grep -Fq 'kind: ConfigMap' "$scratch/source-auth.yaml"

helm template baseline "$chart" --namespace identity \
  -f "$chart/ci/test-values.yaml" >"$scratch/rollback-v5.yaml"
cmp "$scratch/baseline.yaml" "$scratch/rollback-v5.yaml"
grep -Fq "@$released_digest" "$scratch/rollback-v5.yaml"

helm template released "$chart" -f "$chart/ci/test-values.yaml" \
  --set-string image.repository=ghcr.io/apelogic-ai/github-oidc-exchange \
  --set-string image.tag=0.5.0 \
  --set-string "image.digest=$released_digest" >"$scratch/released.yaml"
grep -Fq "image: ghcr.io/apelogic-ai/github-oidc-exchange:0.5.0@$released_digest" \
  "$scratch/released.yaml"

helm template mirrored "$chart" -f "$chart/ci/test-values.yaml" \
  --set-string image.repository=registry.example.test/mirror/github-oidc-exchange \
  --set-string image.tag=0.5.0 \
  --set-string "image.digest=$released_digest" >"$scratch/mirrored.yaml"
grep -Fq "image: registry.example.test/mirror/github-oidc-exchange:0.5.0@$released_digest" \
  "$scratch/mirrored.yaml"

bash scripts/validate-chart-values.sh \
  "$chart/examples/production-values.yaml" >"$scratch/validator-valid.out"

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
  --set ingress.tls.certManager.issuerRef.name=operator-issuer \
  >"$scratch/certificate.yaml"
grep -Fq 'kind: Certificate' "$scratch/certificate.yaml"
grep -Fq 'name: operator-issuer' "$scratch/certificate.yaml"

helm template workload-certificate "$chart" --namespace identity \
  -f "$chart/ci/workload-values.yaml" \
  --set workloadExchange.tls.certManager.enabled=true \
  --set workloadExchange.tls.certManager.issuerRef.name=internal-issuer \
  >"$scratch/workload-certificate.yaml"
grep -Fq 'name: github-oidc-exchange-workload' "$scratch/workload-certificate.yaml"
grep -Fq 'github-oidc-exchange.identity.svc.cluster.local' "$scratch/workload-certificate.yaml"

for missing in image.repository image.digest config.issuerUrl \
  config.githubExchangeAudience config.policyContract config.policyConfigMapName \
  config.keyringSecretName networkPolicy.ingressCidrs; do
  if helm template missing "$chart" -f "$chart/ci/test-values.yaml" \
    --set "${missing}=" >/dev/null 2>&1; then
    printf 'chart must reject empty %s\n' "$missing" >&2
    exit 1
  fi
done
if helm template invalid-policy-contract "$chart" -f "$chart/ci/test-values.yaml" \
  --set-string config.policyContract=github-oidc-exchange.apelogic.io/v7 \
  >/dev/null 2>&1; then
  printf 'chart must reject an unsupported policy contract\n' >&2
  exit 1
fi
for invalid_audience in 'contains whitespace' "$(printf 'a%.0s' {1..256})"; do
  if helm template invalid-audience "$chart" -f "$chart/ci/test-values.yaml" \
    --set-string "config.githubExchangeAudience=$invalid_audience" \
    >/dev/null 2>&1; then
    printf 'chart must reject an invalid GitHub exchange audience\n' >&2
    exit 1
  fi
done
for pair in 'config.policyConfigMapKey=wrong.json' \
  'config.keyringSecretKey=wrong.json' \
  'workloadExchange.policyConfigMapKey=wrong.json' \
  'workloadExchange.rsaKeyringSecretKey=wrong.json' \
  'workloadExchange.tls.certificateKey=wrong.crt' \
  'workloadExchange.tls.privateKeyKey=wrong.key'; do
  if helm template wrong-key "$chart" -f "$chart/ci/workload-values.yaml" \
    --set "$pair" >/dev/null 2>&1; then
    printf 'chart must reject non-contract key %s\n' "$pair" >&2
    exit 1
  fi
done
