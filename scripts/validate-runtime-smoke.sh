#!/usr/bin/env bash
set -euo pipefail

target=scripts/smoke-release-container.sh
ci=.github/workflows/ci.yml
release=.github/workflows/release.yml

first_main_statement="$(awk '/^async fn main\(\)/ { getline; sub(/^[[:space:]]+/, ""); print; exit }' src/main.rs)"
[[ "$first_main_statement" == 'rustls::crypto::aws_lc_rs::default_provider()' ]]
grep -A2 -F 'rustls::crypto::aws_lc_rs::default_provider()' src/main.rs \
  | grep -qF '.install_default()'
grep -qF 'rustls = { version = "0.23.43", default-features = false, features = ["aws-lc-rs", "std", "tls12"] }' Cargo.toml
grep -qF 'reqwest = { version = "0.12.28", default-features = false, features = ["json", "rustls-tls-webpki-roots-no-provider"] }' Cargo.toml
! grep -qE '^aws-(config|sdk-dynamodb) = ' Cargo.toml
! grep -R -n -E 'Dynamo|dynamodb|REPLAY_TABLE|AWS_ENDPOINT_URL_DYNAMODB' src charts docs README.md scripts/smoke-release-container.sh
grep -q 'KubernetesLeaseReplayLedger' src/main.rs
grep -q 'REPLAY_LEASE_NAMESPACE' src/main.rs src/config.rs charts/github-oidc-exchange/templates/deployment.yaml

rustls_features="$(cargo tree --locked -e features -i rustls@0.23.43)"
grep -qF 'rustls feature "aws-lc-rs"' <<< "$rustls_features"
! grep -qF 'rustls feature "ring"' <<< "$rustls_features"

grep -q '  Linux)' "$target"
grep -q '  Darwin)' "$target"
grep -q -- '--network host' "$target"
grep -q -- '--publish 127.0.0.1::8080' "$target"
grep -q -- '--publish 127.0.0.1::8443' "$target"
grep -q 'ThreadingHTTPServer(("127.0.0.1", 0)' "$target"
grep -q 'os.O_EXCL, 0o600' "$target"
grep -q -- '--volume "$app_dir:/smoke:ro"' "$target"
grep -q 'sys.stdin.read()' "$target"
grep -q -- '--cacert "$tmp/ca.crt"' "$target"

! grep -Eq -- '--publish 127\.0\.0\.1:[0-9]+:' "$target"
! grep -q -- '--volume "$tmp:/smoke:ro"' "$target"
! grep -q -- '--insecure' "$target"
! grep -q 'sys.argv\[1\]\.split' "$target"

[[ "$(grep -cF 'bash scripts/validate-runtime-smoke.sh' "$ci")" == 1 ]]
[[ "$(grep -cF 'bash scripts/validate-runtime-smoke.sh' "$release")" == 1 ]]
[[ "$(grep -cF 'bash scripts/smoke-release-container.sh' "$ci")" == 2 ]]
[[ "$(grep -cF 'bash scripts/smoke-release-container.sh' "$release")" == 2 ]]
grep -qF 'bash scripts/smoke-release-container.sh github-oidc-exchange:ci' "$ci"
grep -qF 'SMOKE_PLATFORM=linux/arm64 bash scripts/smoke-release-container.sh github-oidc-exchange:ci-arm64' "$ci"
grep -qF 'SMOKE_PLATFORM=linux/amd64 bash scripts/smoke-release-container.sh "$IMAGE_REFERENCE@$IMAGE_DIGEST"' "$release"
grep -qF 'SMOKE_PLATFORM=linux/arm64 bash scripts/smoke-release-container.sh "$IMAGE_REFERENCE@$IMAGE_DIGEST"' "$release"

line_number() {
  grep -n -m1 -F "$2" "$1" | cut -d: -f1
}

ci_contract="$(line_number "$ci" 'bash scripts/validate-runtime-smoke.sh')"
ci_quality="$(line_number "$ci" 'name: Rust quality gates')"
ci_build="$(line_number "$ci" 'name: Build release image locally')"
ci_smoke="$(line_number "$ci" 'bash scripts/smoke-release-container.sh')"
ci_trivy="$(line_number "$ci" 'uses: aquasecurity/trivy-action')"
(( ci_contract < ci_quality ))
(( ci_build < ci_smoke && ci_smoke < ci_trivy ))

release_contract="$(line_number "$release" 'bash scripts/validate-runtime-smoke.sh')"
release_auth="$(line_number "$release" 'uses: aws-actions/configure-aws-credentials')"
release_amd64_candidate="$(line_number "$release" 'name: Build and publish native amd64 image candidate')"
release_amd64_smoke="$(line_number "$release" 'SMOKE_PLATFORM=linux/amd64 bash scripts/smoke-release-container.sh')"
release_arm64_candidate="$(line_number "$release" 'name: Build and publish native arm64 image candidate')"
release_arm64_smoke="$(line_number "$release" 'SMOKE_PLATFORM=linux/arm64 bash scripts/smoke-release-container.sh')"
release_compose="$(line_number "$release" 'name: Compose native multi-platform image candidate')"
release_sign="$(line_number "$release" 'name: Sign, attest, and verify immutable candidate artifacts')"
release_promote="$(line_number "$release" 'name: Promote verified image candidate')"
release_handoff="$(line_number "$release" 'name: Publish signed release handoff')"
(( release_contract < release_auth ))
(( release_amd64_candidate < release_amd64_smoke ))
(( release_arm64_candidate < release_arm64_smoke ))
(( release_amd64_smoke < release_compose && release_arm64_smoke < release_compose ))
(( release_compose < release_sign && release_compose < release_promote && release_compose < release_handoff ))
