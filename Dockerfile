# syntax=docker/dockerfile:1.10
FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --bin github-oidc-exchange && strip target/release/github-oidc-exchange

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e
COPY --from=build /src/target/release/github-oidc-exchange /github-oidc-exchange
USER 65532:65532
EXPOSE 8080 8443
ENTRYPOINT ["/github-oidc-exchange"]
