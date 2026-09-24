# Changelog

All notable changes to `github-oidc-exchange` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release pages remain the source for immutable image/chart coordinates,
signatures, attestations, SBOMs, and vulnerability evidence.

## [Unreleased]

## [0.5.1] - 2026-09-24

### Fixed

- Reject all-zero and homogeneous hexadecimal `image.digest` sentinel values
  in the Helm schema and chart-owned values preflight before Kubernetes
  rendering. Validation now identifies `image.digest` and requires an
  immutable digest from a published release handoff or verified
  manifest-preserving mirror.

### Changed

- Replaced placeholder digest fixtures with a known published digest and
  documented the supported private-registry mirroring and verification
  boundary. Tag-only deployments remain unsupported.

## [0.5.0] - 2026-09-22

### Added

- Added an opinionated baseline customer quickstart, a GitHub Actions and
  steward-run integration guide, and reusable claim-probe and exchange-smoke
  workflow examples.
- Documented the exact AWS-free fork release invocation and the downstream
  steward-run handoff.
- Added a v4-to-v5 migration guide with atomic application/policy rollout and
  rollback instructions, plus checked-in release notes and stronger
  documentation/version drift checks.

### Removed

- Removed the Steward Service Envelope bootstrap identity profile.
- Removed `bootstrap_group` from the GitHub policy contract.
- Removed bootstrap-specific workflow selectors and the
  `agents.apelogic.ai/service-envelope-bootstrap:*` emitted group.

### Changed

- Changed the GitHub policy contract from v4 to task-only v5. Application and
  policy must be upgraded and rolled back atomically as the 0.5.0/v5 or
  0.4.0/v4 pair.
- Marked consumer contract v1 as released with application/chart 0.5.0 and
  clarified that the renderable production values file is not an install
  profile.

### Preserved

- Preserved the existing governed-task groups, fixed audience, token claims,
  two-minute lifetime, signing, source provenance, and replay protection.
- Preserved the workload exchange and browser HOP-1 contracts.

## [0.4.0] - 2026-09-21

### Added

- Added MIT licensing and third-party notice boundaries.
- Added a customer-neutral, fail-closed Helm installation contract with
  Service-only, Ingress, and Gateway API exposure; existing-PKI and
  cert-manager TLS; and conditional workload-exchange resources.
- Added offline ES256 and RSA-3072 keyring generation, validation, activation,
  overlap, and retirement tooling.
- Added an AWS-independent fork release workflow that publishes signed native
  amd64/arm64 image and chart artifacts to the fork owner's GHCR.
- Added a versioned installation guide, exact Secret/ConfigMap bill of
  materials, consumer contract v1, rotation procedure, and delivery checklist.

### Changed

- Bound GitHub admission to exact subjects plus immutable numeric owner,
  repository, and actor identities.
- Made the public chart and documentation independent of ApeLogic ECR, AWS
  Secrets Manager, ALB, and any specific ingress controller.
- Corrected the steward-run endpoint and audience handoff documentation.

## [0.3.8] - 2026-09-16

### Added

- Added native `linux/arm64` release images and native-runner smoke coverage.
- Added signed GitHub source provenance to issued task identities.
- Added hardened OSS Helm deployment documentation and repository-scoped task
  identity policy.

### Fixed

- Fixed workload NetworkPolicy selector validation and tagged digest image
  rendering.
- Built release candidates on native architecture runners before composing the
  multi-platform image.
- Removed secret-like values from public test fixtures.

## [0.3.6] - 2026-08-23

### Added

- Added a namespaced Kubernetes Lease ledger for single-use GitHub assertion
  replay protection.

## [0.3.5] - 2026-08-23

### Added

- Mirrored verified immutable release image and chart artifacts to public GHCR.

### Fixed

- Required anonymous exact-digest pulls before publishing the public release
  handoff.

## [0.3.3] - 2026-08-23

### Added

- Added canonical Steward task identity issuance.
- Added the optional browser HOP-1 exchange from signed Steward attestations.
- Added workload identity exchange coverage to the release smoke path.

### Fixed

- Tightened canonical policy, static trust-fixture, and verified-email
  behavior.

## [0.3.2] - 2026-08-08

### Fixed

- Explicitly installed the rustls AWS-LC crypto provider before TLS startup,
  preventing workload-listener startup panics in release images.

## [0.3.1] - 2026-08-08

### Added

- Added the internal workload identity exchange using Kubernetes TokenReview
  and RS256 workload tokens.

### Fixed

- Preserved the exact Helm chart digest during release promotion.

## [0.2.1] - 2026-08-07

### Fixed

- Corrected OCI chart metadata labels, chart label regression coverage, and
  Helm setup ordering in CI.

## [0.2.0] - 2026-08-07

### Added

- Added a fail-closed bootstrap identity profile with explicit caller and
  reusable-workflow binding.

## [0.1.0] - 2026-08-07

### Added

- Initial GitHub Actions OIDC exchange service and Helm chart.
- Added GitHub assertion verification, policy-based identity mapping, and
  short-lived EKS-compatible ES256 token issuance.
- Added signed image/chart release validation with immutable artifact digests.

[Unreleased]: https://github.com/apelogic-ai/github-oidc-exchange/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/apelogic-ai/github-oidc-exchange/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/apelogic-ai/github-oidc-exchange/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/apelogic-ai/github-oidc-exchange/compare/v0.3.8...v0.4.0
[0.3.8]: https://github.com/apelogic-ai/github-oidc-exchange/compare/v0.3.6...v0.3.8
[0.3.6]: https://github.com/apelogic-ai/github-oidc-exchange/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/apelogic-ai/github-oidc-exchange/compare/v0.3.3...v0.3.5
[0.3.3]: https://github.com/apelogic-ai/github-oidc-exchange/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/apelogic-ai/github-oidc-exchange/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/apelogic-ai/github-oidc-exchange/compare/v0.2.1...v0.3.1
[0.2.1]: https://github.com/apelogic-ai/github-oidc-exchange/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/apelogic-ai/github-oidc-exchange/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/apelogic-ai/github-oidc-exchange/releases/tag/v0.1.0
