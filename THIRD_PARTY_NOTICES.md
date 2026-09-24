# Third-party license inventory for 0.5.1

The root [MIT license](LICENSE) covers this repository's first-party source and
Helm chart. It does **not** relicense Rust dependencies or the container base
images. The release workflow attaches an SBOM for each published image; use
that SBOM and the exact image digest when preparing downstream notices.

The locked Rust graph was inspected with:

```sh
cargo deny --locked --target aarch64-unknown-linux-gnu list
cargo deny --locked --target x86_64-unknown-linux-gnu list
```

At 0.5.1, the resolved Rust crates declare these SPDX license families:
`Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `BSL-1.0`, `CC0-1.0`,
`CDLA-Permissive-2.0`, `ISC`, `MIT`, `MIT-0`, `Unicode-3.0`, and `Unlicense`.
Many crates offer **alternative** licenses (`MIT OR Apache-2.0`); this list is
not a claim that all third-party material is MIT. No third-party source, fonts,
images, or other assets are vendored in this repository. The pinned Rust and
distroless base images bring their own third-party materials and notices;
operators redistributing a built image must review those notices and the
image SBOM for the chosen digest. This inventory is a provenance aid, not a
substitute for the applicable upstream license text and attribution.

Refresh this inventory and review any new license family whenever `Cargo.lock`,
the Dockerfile base-image digests, or the release artifact composition changes.
