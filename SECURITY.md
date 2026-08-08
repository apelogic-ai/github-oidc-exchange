# Security policy

Report vulnerabilities privately through GitHub Security Advisories for this repository. Do not
open a public issue containing tokens, signing material, identity mappings, or exploit details.

The following are release blockers:

- accepting an unsigned, wrong-algorithm, wrong-issuer, wrong-audience, expired, replayed, or
  non-allowlisted GitHub assertion;
- deriving identity from GitHub display names or profile email;
- emitting groups not present in the private ratified policy;
- accepting a workload token without an exact Kubernetes TokenReview audience and exact
  service-account mapping;
- accepting caller-selected workload audiences, subjects, roles, algorithms, or lifetimes;
- serving the workload exchange over plaintext, exposing it through public Ingress, using an RSA
  key smaller than 3072 bits, or reusing the GitHub P-256 signing keyring;
- registering workload exchange on the public listener, allowing broad VPC/ALB sources to reach
  its internal port, or treating projected Secret changes as hot reloads without a rolling restart;
- logging source or issued bearer tokens;
- publishing an image or chart without immutable digest, critical-vulnerability gate, SBOM,
  provenance, and signature evidence.
