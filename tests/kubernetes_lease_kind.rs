#![cfg(feature = "test-support")]

use std::{env, fs, path::PathBuf};

use chrono::{Duration, SecondsFormat, Utc};
use github_oidc_exchange::replay::{KubernetesLeaseReplayLedger, ReplayError, ReplayLedger};
use reqwest::{Client, Url};
use serde_json::json;
use sha2::{Digest, Sha256};

const LEDGER_LABEL: &str = "github-oidc-exchange.apelogic.io/replay-ledger";
const LEDGER_VERSION: &str = "v1";

#[tokio::test]
async fn kind_api_enforces_create_replay_and_resource_version_reclaim()
-> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "failed to install the configured rustls provider")?;
    let Ok(collection_url) = env::var("KUBE_LEASE_TEST_COLLECTION_URL") else {
        return Ok(());
    };
    let collection_url = Url::parse(&collection_url)?;
    let token_file = PathBuf::from(env::var("KUBE_LEASE_TEST_TOKEN_FILE")?);
    let token = fs::read_to_string(&token_file)?.trim().to_owned();
    if token.is_empty() {
        return Err("Kind integration token is empty".into());
    }
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let probe = client
        .get(collection_url.clone())
        .bearer_auth(&token)
        .send()
        .await?;
    if !probe.status().is_success() {
        return Err(format!(
            "Kind Lease collection probe failed: {} {}",
            probe.status(),
            probe.text().await?
        )
        .into());
    }
    let ledger = KubernetesLeaseReplayLedger::from_test_api(
        client.clone(),
        collection_url.clone(),
        token_file,
    )?;
    let now = Utc::now();
    let first_jti = "kind-lease-first-create";
    let first_name = lease_name(first_jti);
    ledger
        .use_once(first_jti, (now + Duration::seconds(120)).timestamp())
        .await?;
    assert!(matches!(
        ledger
            .use_once(first_jti, (now + Duration::seconds(120)).timestamp())
            .await,
        Err(ReplayError::Replayed)
    ));

    let expired_jti = "kind-lease-expired-reclaim";
    let expired_name = lease_name(expired_jti);
    let expired_lease = json!({
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": {
            "name": expired_name,
            "labels": {LEDGER_LABEL: LEDGER_VERSION}
        },
        "spec": {
            "holderIdentity": "github-oidc-exchange-replay-ledger",
            "leaseDurationSeconds": 1,
            "acquireTime": timestamp(now - Duration::seconds(600)),
            "renewTime": timestamp(now - Duration::seconds(600))
        }
    });
    let response = client
        .post(collection_url.clone())
        .bearer_auth(&token)
        .json(&expired_lease)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(format!("failed to seed expired Kind Lease: {}", response.status()).into());
    }
    let seeded: serde_json::Value = response.json().await?;
    let seeded_resource_version = seeded["metadata"]["resourceVersion"]
        .as_str()
        .ok_or("seeded Kind Lease has no resourceVersion")?
        .to_owned();
    ledger
        .use_once(expired_jti, (now + Duration::seconds(120)).timestamp())
        .await?;
    let reclaimed = client
        .get(Url::parse(&format!(
            "{}/{expired_name}",
            collection_url.as_str()
        ))?)
        .bearer_auth(&token)
        .send()
        .await?;
    if !reclaimed.status().is_success() {
        return Err(format!(
            "failed to read reclaimed Kind Lease: {}",
            reclaimed.status()
        )
        .into());
    }
    let reclaimed: serde_json::Value = reclaimed.json().await?;
    assert_ne!(
        reclaimed["metadata"]["resourceVersion"].as_str(),
        Some(seeded_resource_version.as_str())
    );
    assert_eq!(
        reclaimed["metadata"]["labels"][LEDGER_LABEL].as_str(),
        Some(LEDGER_VERSION)
    );

    for name in [first_name, expired_name] {
        let response = client
            .delete(Url::parse(&format!("{}/{name}", collection_url.as_str()))?)
            .bearer_auth(&token)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(format!("failed to clean Kind Lease {name}: {}", response.status()).into());
        }
    }
    Ok(())
}

fn lease_name(jti: &str) -> String {
    let hash = Sha256::digest(jti.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("replay-{}", &hash[..56])
}

fn timestamp(value: chrono::DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Micros, true)
}
