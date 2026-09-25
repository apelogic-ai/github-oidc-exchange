use std::sync::Arc;

use chrono::Utc;
use github_oidc_exchange::{
    browser_hop1::{
        BrowserHop1ExchangeService, BrowserHop1Metrics, StewardBrowserAssertionVerifier,
    },
    config::Config,
    github::GitHubVerifier,
    http::{router, separated_routers_with_workload, separated_routers_with_workload_and_browser},
    keys::{KeyRing, RsaKeyRing},
    policy::Policy,
    replay::KubernetesLeaseReplayLedger,
    service::{ExchangeService, Metrics},
    workload::{KubernetesTokenReviewer, WorkloadExchangeService, WorkloadMetrics, WorkloadPolicy},
};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| std::io::Error::other("rustls CryptoProvider was already installed"))?;
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let config = Config::from_env()?;
    let browser_hop1_config = config.browser_hop1.clone();
    let policy = Policy::load(&config.policy_file)?;
    if policy.version != config.expected_policy_version {
        return Err(std::io::Error::other(
            "loaded policy version does not match EXPECTED_POLICY_VERSION",
        )
        .into());
    }
    let policy = Arc::new(policy);
    let keys = Arc::new(KeyRing::load(&config.keyring_file, Utc::now())?);
    let ledger = Arc::new(KubernetesLeaseReplayLedger::in_cluster(
        config.replay_lease_namespace.clone(),
    )?);
    let verifier = GitHubVerifier::new(config.github_exchange_audience)?;
    verifier.warm_up().await?;
    let service = ExchangeService {
        verifier,
        policy,
        ledger: ledger.clone(),
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
        let browser_hop1: Option<BrowserHop1ExchangeService<KubernetesLeaseReplayLedger>> =
            if let Some(browser) = browser_hop1_config {
                Some(BrowserHop1ExchangeService {
                    verifier: StewardBrowserAssertionVerifier::load(
                        &browser.steward_jwks_file,
                        browser.steward_issuer,
                        browser.assertion_audience,
                    )?,
                    policy: workload.policy.clone(),
                    ledger: ledger.clone(),
                    keys: keys.clone(),
                    issuer: service.issuer.clone(),
                    output_audience: browser.output_audience,
                    token_ttl: std::time::Duration::from_secs(60),
                    metrics: Arc::new(BrowserHop1Metrics::default()),
                })
            } else {
                None
            };
        let (public_router, workload_router) = if let Some(browser_hop1) = browser_hop1 {
            separated_routers_with_workload_and_browser(service, workload, Some(browser_hop1))
        } else {
            separated_routers_with_workload(service, workload)
        };
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
