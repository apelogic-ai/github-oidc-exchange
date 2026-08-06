use std::sync::Arc;

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::Client;
use chrono::Utc;
use github_oidc_exchange::{
    config::Config,
    github::GitHubVerifier,
    http::router,
    keys::KeyRing,
    policy::Policy,
    replay::DynamoReplayLedger,
    service::{ExchangeService, Metrics},
};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let config = Config::from_env()?;
    let policy = Arc::new(Policy::load(&config.policy_file)?);
    let keys = Arc::new(KeyRing::load(&config.keyring_file, Utc::now())?);
    let aws = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let dynamodb = Client::new(&aws);
    dynamodb
        .describe_table()
        .table_name(&config.replay_table)
        .send()
        .await?;
    let verifier = GitHubVerifier::new(config.github_exchange_audience)?;
    verifier.warm_up().await?;
    let ledger = Arc::new(DynamoReplayLedger::new(
        dynamodb,
        config.replay_table.clone(),
    ));
    let service = ExchangeService {
        verifier,
        policy,
        ledger,
        keys,
        issuer: config.issuer_url,
        output_audience: config.output_audience,
        token_ttl: config.token_ttl,
        metrics: Arc::new(Metrics::default()),
    };
    let listener = tokio::net::TcpListener::bind(config.listen_address).await?;
    info!(address = %config.listen_address, "GitHub OIDC exchange issuer started");
    axum::serve(listener, router(service))
        .with_graceful_shutdown(shutdown())
        .await?;
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
