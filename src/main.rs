use std::sync::Arc;

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::Client;
use chrono::Utc;
use github_oidc_exchange::{
    config::Config,
    github::GitHubVerifier,
    http::{router, separated_routers_with_workload},
    keys::{KeyRing, RsaKeyRing},
    policy::Policy,
    replay::DynamoReplayLedger,
    service::{ExchangeService, Metrics},
    workload::{KubernetesTokenReviewer, WorkloadExchangeService, WorkloadMetrics, WorkloadPolicy},
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
        keys: keys.clone(),
        issuer: config.issuer_url,
        output_audience: config.output_audience,
        token_ttl: config.token_ttl,
        metrics: Arc::new(Metrics::default()),
    };
    if let Some(workload_config) = config.workload {
        let workload_keys = Arc::new(RsaKeyRing::load(
            &workload_config.rsa_keyring_file,
            Utc::now(),
        )?);
        workload_keys.ensure_disjoint_from(&keys)?;
        let workload = WorkloadExchangeService {
            reviewer: KubernetesTokenReviewer::in_cluster()?,
            policy: Arc::new(WorkloadPolicy::load(&workload_config.policy_file)?),
            keys: workload_keys,
            issuer: service.issuer.clone(),
            input_audience: workload_config.input_audience,
            output_audience: workload_config.output_audience,
            token_ttl: service.token_ttl,
            metrics: Arc::new(WorkloadMetrics::default()),
        };
        let workload_listen_address = workload_config.listen_address;
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            workload_config.tls_certificate_file,
            workload_config.tls_private_key_file,
        )
        .await?;
        let public_listener = tokio::net::TcpListener::bind(config.listen_address).await?;
        let (public_router, workload_router) = separated_routers_with_workload(service, workload);
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
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
        });
        info!(
            public_address = %config.listen_address,
            workload_address = %workload_listen_address,
            workload_tls = true,
            "identity exchange issuer listeners started"
        );
        let workload_server = axum_server::bind_rustls(workload_listen_address, tls)
            .handle(handle)
            .serve(workload_router.into_make_service());
        tokio::try_join!(public_server, workload_server)?;
    } else {
        let listener = tokio::net::TcpListener::bind(config.listen_address).await?;
        info!(
            address = %config.listen_address,
            tls = false,
            workload_exchange = false,
            "GitHub OIDC exchange issuer started"
        );
        axum::serve(listener, router(service))
            .with_graceful_shutdown(shutdown())
            .await?;
    }
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
