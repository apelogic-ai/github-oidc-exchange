# Security policy

Report vulnerabilities privately through GitHub Security Advisories for this repository. Do not
open a public issue containing tokens, signing material, identity mappings, or exploit details.

The following are release blockers:

- accepting an unsigned, wrong-algorithm, wrong-issuer, wrong-audience, expired, replayed, or
  non-allowlisted GitHub assertion;
- deriving identity from GitHub display names or profile email;
- emitting groups not present in the private ratified policy;
- logging source or issued bearer tokens;
- publishing an image or chart without immutable digest, critical-vulnerability gate, SBOM,
  provenance, and signature evidence.

