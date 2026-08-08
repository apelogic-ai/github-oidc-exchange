# syntax=docker/dockerfile:1.10
FROM rust:1.97.1-bookworm@sha256:14bc9c5966e7b3a385794b3d5389a8765668342025fbcc7b2e3d2866ac4bd8c3 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release && strip target/release/github-oidc-exchange

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e
COPY --from=build /src/target/release/github-oidc-exchange /github-oidc-exchange
USER 65532:65532
EXPOSE 8080 8443
ENTRYPOINT ["/github-oidc-exchange"]
