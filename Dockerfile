# syntax=docker/dockerfile:1.10
FROM rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --bin github-oidc-exchange && strip target/release/github-oidc-exchange

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/github-oidc-exchange /github-oidc-exchange
USER 65532:65532
EXPOSE 8080 8443
ENTRYPOINT ["/github-oidc-exchange"]
