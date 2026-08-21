use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{Json, Router, routing::get};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use github_oidc_exchange::{
    IDENTITY_CONTRACT, POLICY_VERSION,
    config::WorkloadConfig,
    github::{GitHubClaims, GitHubVerifier},
    http::{router, separated_routers_with_workload},
    keys::{KeyRing, RsaKeyRing},
    policy::Policy,
    replay::MemoryReplayLedger,
    service::{ExchangeService, Metrics},
    workload::{KubernetesTokenReviewer, WorkloadExchangeService, WorkloadMetrics, WorkloadPolicy},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::EncodeRsaPrivateKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Clone, Serialize)]
struct ExpectedIdentity {
    fixture_contract: &'static str,
    policy_contract: &'static str,
    identity_contract: &'static str,
    issuer: String,
    jwks_uri: String,
    exchange_endpoint: String,
    readiness_endpoint: String,
    expected_groups: Vec<String>,
    token_ttl_seconds: u64,
    workload_exchange: Option<ExpectedWorkloadExchange>,
}

#[derive(Clone, Serialize)]
struct ExpectedWorkloadExchange {
    listen_address: String,
    exchange_endpoint: &'static str,
    readiness_endpoint: &'static str,
    input_audience: String,
    output_audience: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| std::io::Error::other("rustls CryptoProvider was already installed"))?;
    match env::args().nth(1).as_deref() {
        Some("serve") => serve().await,
        Some("issue") => issue().await,
        _ => Err(std::io::Error::other("usage: integration fixture <serve|issue>").into()),
    }
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let issuer = required("ISSUER_URL")?.trim_end_matches('/').to_owned();
    validate_https_issuer(&issuer)?;
    let output_audience = required("OUTPUT_AUDIENCE")?;
    if output_audience != "steward-task-api" {
        return Err(std::io::Error::other("OUTPUT_AUDIENCE must be steward-task-api").into());
    }
    let listen_address: SocketAddr = env::var("LISTEN_ADDRESS")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
        .parse()?;
    let token_ttl = fixture_token_ttl()?;
    let workload_config = WorkloadConfig::from_env(listen_address)?;
    let source_kid = required("FIXTURE_SOURCE_KID")?;
    let source_public_key = fs::read(required_path("FIXTURE_SOURCE_PUBLIC_KEY_FILE")?)?;
    let claims: GitHubClaims = read_json(&required_path("FIXTURE_CLAIMS_FILE")?)?;
    let policy = Arc::new(Policy::load(&required_path("POLICY_FILE")?)?);
    let expected = policy.authorize(&claims)?;
    let verifier = GitHubVerifier::with_test_key(
        required("GITHUB_EXCHANGE_AUDIENCE")?,
        source_kid,
        decoding_key_from_public_pem(&source_public_key)?,
    )
    .await?;
    let keys = Arc::new(KeyRing::load(&required_path("KEYRING_FILE")?, Utc::now())?);
    let service = ExchangeService {
        verifier,
        policy,
        ledger: Arc::new(MemoryReplayLedger::default()),
        keys: keys.clone(),
        issuer: issuer.clone(),
        output_audience,
        token_ttl,
        metrics: Arc::new(Metrics::default()),
    };
    let expected_identity = ExpectedIdentity {
        fixture_contract: "github-oidc-exchange/integration-fixture-v1",
        policy_contract: POLICY_VERSION,
        identity_contract: IDENTITY_CONTRACT,
        issuer: issuer.clone(),
        jwks_uri: format!("{issuer}/jwks.json"),
        exchange_endpoint: "/v1/exchange".to_owned(),
        readiness_endpoint: "/readyz".to_owned(),
        expected_groups: expected.groups,
        token_ttl_seconds: token_ttl.as_secs(),
        workload_exchange: workload_config
            .as_ref()
            .map(|workload| ExpectedWorkloadExchange {
                listen_address: workload.listen_address.to_string(),
                exchange_endpoint: "/v1/workload/exchange",
                readiness_endpoint: "/readyz",
                input_audience: workload.input_audience.clone(),
                output_audience: workload.output_audience.clone(),
            }),
    };
    let fixture_router = Router::new().route(
        "/fixture/v1/expected-identity",
        get(move || {
            let expected_identity = expected_identity.clone();
            async move { Json(expected_identity) }
        }),
    );
    if let Some(workload_config) = workload_config {
        let workload_keys = Arc::new(RsaKeyRing::load(
            &workload_config.rsa_keyring_file,
            Utc::now(),
        )?);
        workload_keys.ensure_disjoint_from(&keys)?;
        let workload = WorkloadExchangeService {
            reviewer: KubernetesTokenReviewer::in_cluster()?,
            policy: Arc::new(WorkloadPolicy::load(&workload_config.policy_file)?),
            keys: workload_keys,
            issuer: issuer.clone(),
            input_audience: workload_config.input_audience,
            output_audience: workload_config.output_audience,
            token_ttl: Duration::from_secs(120),
            metrics: Arc::new(WorkloadMetrics::default()),
        };
        let workload_listen_address = workload_config.listen_address;
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            workload_config.tls_certificate_file,
            workload_config.tls_private_key_file,
        )
        .await?;
        let public_listener = tokio::net::TcpListener::bind(listen_address).await?;
        let (public_router, workload_router) = separated_routers_with_workload(service, workload);
        let public_router = public_router.merge(fixture_router);
        let (shutdown_sender, _) = tokio::sync::broadcast::channel::<()>(1);
        let mut public_shutdown = shutdown_sender.subscribe();
        let mut workload_shutdown = shutdown_sender.subscribe();
        let signal_sender = shutdown_sender.clone();
        tokio::spawn(async move {
            shutdown().await;
            let _ = signal_sender.send(());
        });
        let public_server = axum::serve(public_listener, public_router.into_make_service())
            .with_graceful_shutdown(async move {
                let _ = public_shutdown.recv().await;
            });
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            let _ = workload_shutdown.recv().await;
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(30)));
        });
        info!(
            public_address = %listen_address,
            workload_address = %workload_listen_address,
            issuer,
            public_readiness_endpoint = "/readyz",
            workload_readiness_endpoint = "/readyz",
            expected_identity_endpoint = "/fixture/v1/expected-identity",
            "test-support identity exchange fixture listeners started"
        );
        let workload_server = axum_server::bind_rustls(workload_listen_address, tls)
            .handle(handle)
            .serve(workload_router.into_make_service());
        tokio::try_join!(public_server, workload_server)?;
    } else {
        let application = router(service).merge(fixture_router);
        let listener = tokio::net::TcpListener::bind(listen_address).await?;
        info!(
            address = %listen_address,
            issuer,
            readiness_endpoint = "/readyz",
            expected_identity_endpoint = "/fixture/v1/expected-identity",
            "test-support identity exchange fixture started"
        );
        axum::serve(listener, application)
            .with_graceful_shutdown(shutdown())
            .await?;
    }
    Ok(())
}

async fn issue() -> Result<(), Box<dyn std::error::Error>> {
    let claims: GitHubClaims = read_json(&required_path("FIXTURE_CLAIMS_FILE")?)?;
    let private_key = fs::read(required_path("FIXTURE_SOURCE_PRIVATE_KEY_FILE")?)?;
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(required("FIXTURE_SOURCE_KID")?);
    header.typ = Some("JWT".to_owned());
    let source_assertion = encode(
        &header,
        &claims,
        &encoding_key_from_private_pem(&private_key)?,
    )?;
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?
        .post(required("FIXTURE_EXCHANGE_URL")?)
        .bearer_auth(source_assertion)
        .body(Vec::new())
        .send()
        .await?
        .error_for_status()?
        .json::<TokenResponse>()
        .await?;
    if response.access_token.is_empty() {
        return Err(std::io::Error::other("exchange returned an empty access token").into());
    }
    let output_path = required_path("FIXTURE_TOKEN_OUTPUT_FILE")?;
    write_secret_new(&output_path, response.access_token.as_bytes())?;
    println!(
        "{}",
        serde_json::json!({
            "fixture_contract": "github-oidc-exchange/integration-fixture-v1",
            "status": "issued",
            "token_file": output_path
        })
    );
    Ok(())
}

fn validate_https_issuer(value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = reqwest::Url::parse(value)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(std::io::Error::other(
            "ISSUER_URL must be an absolute HTTPS URL without a query or fragment",
        )
        .into());
    }
    Ok(())
}

fn fixture_token_ttl() -> Result<Duration, Box<dyn std::error::Error>> {
    let value = env::var("FIXTURE_TOKEN_TTL_SECONDS");
    parse_fixture_token_ttl(value.as_deref().ok()).ok_or_else(|| {
        std::io::Error::other("FIXTURE_TOKEN_TTL_SECONDS must be an integer from 1 through 3600")
            .into()
    })
}

fn parse_fixture_token_ttl(value: Option<&str>) -> Option<Duration> {
    let seconds = match value {
        Some(value) => value.parse::<u64>().ok(),
        None => Some(120),
    }?;
    (1..=3600)
        .contains(&seconds)
        .then(|| Duration::from_secs(seconds))
}

fn required(name: &'static str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| std::io::Error::other(format!("required {name} is missing")).into())
}

fn required_path(name: &'static str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(PathBuf::from(required(name)?))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn decoding_key_from_public_pem(content: &[u8]) -> Result<DecodingKey, Box<dyn std::error::Error>> {
    let key = RsaPublicKey::from_public_key_pem(std::str::from_utf8(content)?)?;
    Ok(DecodingKey::from_rsa_components(
        &URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        &URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
    )?)
}

fn encoding_key_from_private_pem(
    content: &[u8],
) -> Result<EncodingKey, Box<dyn std::error::Error>> {
    let key = RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(content)?)?;
    let der = key.to_pkcs1_der()?;
    Ok(EncodingKey::from_rsa_der(der.as_bytes()))
}

#[cfg(unix)]
fn write_secret_new(path: &Path, content: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_new(path: &Path, content: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

async fn shutdown() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = interrupt => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::parse_fixture_token_ttl;

    #[test]
    fn fixture_token_ttl_is_defaulted_and_bounded() {
        assert_eq!(
            parse_fixture_token_ttl(None).map(|ttl| ttl.as_secs()),
            Some(120)
        );
        assert_eq!(
            parse_fixture_token_ttl(Some("900")).map(|ttl| ttl.as_secs()),
            Some(900)
        );
        for invalid in ["", "0", "3601", "-1", "not-a-number"] {
            assert!(parse_fixture_token_ttl(Some(invalid)).is_none());
        }
    }
}
