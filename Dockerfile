# syntax=docker/dockerfile:1.10
FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --bin github-oidc-exchange && strip target/release/github-oidc-exchange

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e
COPY --from=build /src/target/release/github-oidc-exchange /github-oidc-exchange
USER 65532:65532
EXPOSE 8080 8443
ENTRYPOINT ["/github-oidc-exchange"]
