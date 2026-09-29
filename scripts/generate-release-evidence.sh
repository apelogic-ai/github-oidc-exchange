#!/usr/bin/env bash
set -euo pipefail

output_dir=${1:?usage: generate-release-evidence.sh OUTPUT_DIR}

for required in \
  RELEASE_VERSION RELEASE_COMMIT RELEASE_REPOSITORY RELEASE_WORKFLOW_REF \
  RELEASE_RUN_ID RELEASE_RUN_ATTEMPT RELEASE_IMAGE RELEASE_CHART \
  RELEASE_IMAGE_DIGEST RELEASE_CHART_DIGEST RELEASE_PLATFORMS_FILE; do
  if [[ -z "${!required:-}" ]]; then
    printf 'required environment variable is missing: %s\n' "$required" >&2
    exit 2
  fi
done

[[ "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ "$RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$RELEASE_IMAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$RELEASE_CHART_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$RELEASE_IMAGE" == ghcr.io/*@"$RELEASE_IMAGE_DIGEST" ]]
[[ "$RELEASE_CHART" == ghcr.io/*@"$RELEASE_CHART_DIGEST" ]]
jq -e '
  (.linux.amd64 | test("^sha256:[0-9a-f]{64}$"))
  and (.linux.arm64 | test("^sha256:[0-9a-f]{64}$"))
' "$RELEASE_PLATFORMS_FILE" >/dev/null

policy_contract="$(sed -n 's/^pub const POLICY_VERSION: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
identity_contract="$(sed -n 's/^pub const IDENTITY_CONTRACT: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
source_auth_policy_contract="$(sed -n 's/^pub const SOURCE_AUTH_POLICY_VERSION: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
source_auth_identity_contract="$(sed -n 's/^pub const SOURCE_AUTH_IDENTITY_CONTRACT: &str = "\([^"]*\)";/\1/p' src/lib.rs)"
[[ -n "$policy_contract" && -n "$identity_contract" ]]
[[ -n "$source_auth_policy_contract" && -n "$source_auth_identity_contract" ]]

mkdir -p "$output_dir"

jq -n \
  --arg source "https://github.com/$RELEASE_REPOSITORY" \
  --arg commit "$RELEASE_COMMIT" \
  --arg workflow "https://github.com/$RELEASE_REPOSITORY/.github/workflows/release.yml@$RELEASE_WORKFLOW_REF" \
  --arg invocation "$RELEASE_RUN_ID/$RELEASE_RUN_ATTEMPT" \
  --arg version "$RELEASE_VERSION" \
  '{
    buildDefinition: {
      buildType: "https://apelogic.ai/build-types/github-actions-release/v1",
      externalParameters: {source:$source, commit:$commit, version:$version}
    },
    runDetails: {
      builder: {id:$workflow},
      metadata: {invocationId:$invocation}
    }
  }' > "$output_dir/release.slsa.json"

jq -n \
  --arg version "$RELEASE_VERSION" \
  --arg commit "$RELEASE_COMMIT" \
  --arg release_url "https://github.com/$RELEASE_REPOSITORY/releases/tag/v$RELEASE_VERSION" \
  --arg workflow_run_url "https://github.com/$RELEASE_REPOSITORY/actions/runs/$RELEASE_RUN_ID" \
  --arg image "$RELEASE_IMAGE" \
  --arg chart "$RELEASE_CHART" \
  --arg public_image_digest "$RELEASE_IMAGE_DIGEST" \
  --arg public_chart_digest "$RELEASE_CHART_DIGEST" \
  --arg policy_contract "$policy_contract" \
  --arg identity_contract "$identity_contract" \
  --arg source_auth_policy_contract "$source_auth_policy_contract" \
  --arg source_auth_identity_contract "$source_auth_identity_contract" \
  --slurpfile platforms "$RELEASE_PLATFORMS_FILE" \
  '{version:$version,commit:$commit,release_url:$release_url,workflow_run_url:$workflow_run_url,image:$image,chart:$chart,public_image_digest:$public_image_digest,public_chart_digest:$public_chart_digest,image_platforms:$platforms[0],public_distribution:{registry:"ghcr.io",anonymous_pull_verified:true,direct_publish:true},policy_contract:$policy_contract,identity_contract:$identity_contract,supported_policy_contracts:[$policy_contract,$source_auth_policy_contract],supported_identity_contracts:[$identity_contract,$source_auth_identity_contract]}' \
  > "$output_dir/release-manifest.json"
