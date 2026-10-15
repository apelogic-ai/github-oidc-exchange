# syntax=docker/dockerfile:1.10
FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release \
      --bin github-oidc-exchange \
      --bin keyring-tool \
    && strip target/release/github-oidc-exchange target/release/keyring-tool

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e
COPY --from=build /src/target/release/github-oidc-exchange /github-oidc-exchange
COPY --from=build /src/target/release/keyring-tool /usr/local/bin/keyring-tool
USER 65532:65532
EXPOSE 8080 8443
ENTRYPOINT ["/github-oidc-exchange"]
