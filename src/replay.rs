use std::{
    collections::BTreeMap,
    env, fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use reqwest::{Certificate, Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const LEASE_API_PATH: &str = "/apis/coordination.k8s.io/v1/namespaces";
const LEDGER_LABEL: &str = "github-oidc-exchange.apelogic.io/replay-ledger";
const LEDGER_VERSION: &str = "v1";
const LEASE_RETENTION_SECONDS: i64 = 300;
const MAX_LEASE_DURATION_SECONDS: i64 = 960;
const MAX_CLEANUP_PER_EXCHANGE: usize = 1;
const MAX_CLEANUP_PAGES_PER_EXCHANGE: usize = 2;
const CLEANUP_PAGE_SIZE: usize = 50;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReplayError {
    #[error("assertion has already been exchanged")]
    Replayed,
    #[error("replay ledger is unavailable")]
    Unavailable,
}

pub trait ReplayLedger: Send + Sync {
    fn use_once(
        &self,
        jti: &str,
        expires_at: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;
}

/// Cluster-native replay ledger. A Lease is the authoritative one-time-use record; bounded
/// cleanup only removes records after their retention period and never affects acceptance.
#[derive(Clone)]
pub struct KubernetesLeaseReplayLedger {
    client: Client,
    collection_url: Url,
    credential_file: PathBuf,
    cleanup_continue: Arc<Mutex<Option<String>>>,
}

impl KubernetesLeaseReplayLedger {
    pub fn in_cluster(namespace: String) -> Result<Self, ReplayError> {
        if !valid_dns_label(&namespace) {
            return Err(ReplayError::Unavailable);
        }
        let host = env::var("KUBERNETES_SERVICE_HOST").map_err(|_| ReplayError::Unavailable)?;
        if host.is_empty() || host.contains(['/', '?', '#']) {
            return Err(ReplayError::Unavailable);
        }
        let port = env::var("KUBERNETES_SERVICE_PORT_HTTPS").unwrap_or_else(|_| "443".to_owned());
        if port.parse::<u16>().is_err() {
            return Err(ReplayError::Unavailable);
        }
        let authority = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        let collection_url = Url::parse(&format!(
            "https://{authority}:{port}{LEASE_API_PATH}/{namespace}/leases"
        ))
        .map_err(|_| ReplayError::Unavailable)?;
        let ca_file = env::var("KUBERNETES_CA_CERTIFICATE_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
            });
        let credential_file = env::var("KUBERNETES_SERVICE_ACCOUNT_TOKEN_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token")
            });
        let certificate = fs::read(ca_file)
            .map_err(|_| ReplayError::Unavailable)
            .and_then(|pem| Certificate::from_pem(&pem).map_err(|_| ReplayError::Unavailable))?;
        let client = Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .add_root_certificate(certificate)
            .build()
            .map_err(|_| ReplayError::Unavailable)?;
        Ok(Self {
            client,
            collection_url,
            credential_file,
            cleanup_continue: Arc::default(),
        })
    }

    #[cfg(feature = "test-support")]
    pub fn from_test_api(
        client: Client,
        collection_url: Url,
        credential_file: PathBuf,
    ) -> Result<Self, ReplayError> {
        if collection_url.scheme() != "http" || !collection_url.path().ends_with("/leases") {
            return Err(ReplayError::Unavailable);
        }
        Ok(Self {
            client,
            collection_url,
            credential_file,
            cleanup_continue: Arc::default(),
        })
    }

    async fn credential(&self) -> Result<String, ReplayError> {
        let credential =
            fs::read_to_string(&self.credential_file).map_err(|_| ReplayError::Unavailable)?;
        let credential = credential.trim();
        if credential.is_empty() {
            return Err(ReplayError::Unavailable);
        }
        Ok(credential.to_owned())
    }

    async fn create(&self, lease: &Lease) -> Result<CreateResult, ReplayError> {
        let credential = self.credential().await?;
        let response = self
            .client
            .post(self.collection_url.clone())
            .bearer_auth(credential)
            .json(lease)
            .send()
            .await
            .map_err(|_| ReplayError::Unavailable)?;
        match response.status() {
            StatusCode::CREATED => Ok(CreateResult::Created),
            StatusCode::CONFLICT => Ok(CreateResult::Conflict),
            _ => Err(ReplayError::Unavailable),
        }
    }

    async fn get(&self, name: &str) -> Result<Option<Lease>, ReplayError> {
        let credential = self.credential().await?;
        let response = self
            .client
            .get(self.item_url(name)?)
            .bearer_auth(credential)
            .send()
            .await
            .map_err(|_| ReplayError::Unavailable)?;
        match response.status() {
            StatusCode::OK => response
                .json()
                .await
                .map(Some)
                .map_err(|_| ReplayError::Unavailable),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(ReplayError::Unavailable),
        }
    }

    async fn update(&self, name: &str, lease: &Lease) -> Result<UpdateResult, ReplayError> {
        let credential = self.credential().await?;
        let response = self
            .client
            .put(self.item_url(name)?)
            .bearer_auth(credential)
            .json(lease)
            .send()
            .await
            .map_err(|_| ReplayError::Unavailable)?;
        match response.status() {
            StatusCode::OK => Ok(UpdateResult::Updated),
            StatusCode::CONFLICT => Ok(UpdateResult::Conflict),
            _ => Err(ReplayError::Unavailable),
        }
    }

    async fn reclaim_expired(
        &self,
        name: &str,
        replacement: &Lease,
        now: DateTime<Utc>,
    ) -> Result<(), ReplayError> {
        for attempt in 0..=1 {
            let Some(existing) = self.get(name).await? else {
                return match self.create(replacement).await? {
                    CreateResult::Created => Ok(()),
                    CreateResult::Conflict => Err(ReplayError::Unavailable),
                };
            };
            if !expired(&existing, now) {
                return Err(ReplayError::Replayed);
            }
            let resource_version = existing
                .metadata
                .resource_version
                .filter(|value| !value.is_empty())
                .ok_or(ReplayError::Unavailable)?;
            let mut update = replacement.clone();
            update.metadata.resource_version = Some(resource_version);
            match self.update(name, &update).await? {
                UpdateResult::Updated => return Ok(()),
                UpdateResult::Conflict if attempt == 0 => continue,
                UpdateResult::Conflict => return Err(ReplayError::Unavailable),
            }
        }
        Err(ReplayError::Unavailable)
    }

    async fn cleanup_one(&self, now: DateTime<Utc>) {
        let mut continue_token = self.cleanup_continue();
        for _ in 0..MAX_CLEANUP_PAGES_PER_EXCHANGE {
            let leases = match self.list(continue_token.as_deref()).await {
                Ok(leases) => leases,
                Err(_) => {
                    // Kubernetes can invalidate a continue token. Start a new bounded sweep next
                    // time; cleanup is strictly best-effort and cannot affect replay correctness.
                    self.set_cleanup_continue(None);
                    return;
                }
            };
            let next_continue = (!leases.metadata.continue_token.is_empty())
                .then_some(leases.metadata.continue_token);
            // Advance before deletion so each successful exchange makes bounded, eventual
            // progress even when the first page contains only unexpired records.
            self.set_cleanup_continue(next_continue.clone());

            for lease in expired_owned_leases(&leases.items, now).take(MAX_CLEANUP_PER_EXCHANGE) {
                let Ok(Some(current)) = self.get(&lease.metadata.name).await else {
                    continue;
                };
                if !owned_ledger_lease(&current) || !expired(&current, now) {
                    continue;
                }
                let Some(resource_version) = current.metadata.resource_version.as_deref() else {
                    continue;
                };
                let _ = self.delete(&lease.metadata.name, resource_version).await;
                return;
            }

            let Some(next) = next_continue else {
                return;
            };
            continue_token = Some(next);
        }
    }

    fn cleanup_continue(&self) -> Option<String> {
        self.cleanup_continue
            .lock()
            .ok()
            .and_then(|continue_token| continue_token.clone())
    }

    fn set_cleanup_continue(&self, continue_token: Option<String>) {
        if let Ok(mut current) = self.cleanup_continue.lock() {
            *current = continue_token;
        }
    }

    async fn list(&self, continue_token: Option<&str>) -> Result<LeaseList, ReplayError> {
        let credential = self.credential().await?;
        let mut url = self.collection_url.clone();
        url.query_pairs_mut()
            .append_pair("labelSelector", &format!("{LEDGER_LABEL}={LEDGER_VERSION}"))
            .append_pair("limit", &CLEANUP_PAGE_SIZE.to_string());
        if let Some(continue_token) = continue_token {
            url.query_pairs_mut()
                .append_pair("continue", continue_token);
        }
        let response = self
            .client
            .get(url)
            .bearer_auth(credential)
            .send()
            .await
            .map_err(|_| ReplayError::Unavailable)?;
        if response.status() != StatusCode::OK {
            return Err(ReplayError::Unavailable);
        }
        response.json().await.map_err(|_| ReplayError::Unavailable)
    }

    async fn delete(&self, name: &str, resource_version: &str) -> Result<(), ReplayError> {
        let credential = self.credential().await?;
        let response = self
            .client
            .delete(self.item_url(name)?)
            .bearer_auth(credential)
            .json(&DeleteOptions::with_resource_version(resource_version))
            .send()
            .await
            .map_err(|_| ReplayError::Unavailable)?;
        match response.status() {
            StatusCode::OK
            | StatusCode::ACCEPTED
            | StatusCode::NOT_FOUND
            | StatusCode::CONFLICT => Ok(()),
            _ => Err(ReplayError::Unavailable),
        }
    }

    fn item_url(&self, name: &str) -> Result<Url, ReplayError> {
        Url::parse(&format!("{}/{name}", self.collection_url.as_str()))
            .map_err(|_| ReplayError::Unavailable)
    }
}

impl ReplayLedger for KubernetesLeaseReplayLedger {
    async fn use_once(&self, jti: &str, expires_at: i64) -> Result<(), ReplayError> {
        let now = Utc::now();
        let expires_at = retained_until(expires_at, now.timestamp())?;
        let lease = Lease::new(lease_name(jti), expires_at, now)?;
        match self.create(&lease).await? {
            CreateResult::Created => {
                self.cleanup_one(now).await;
                Ok(())
            }
            CreateResult::Conflict => {
                self.reclaim_expired(&lease.metadata.name, &lease, now)
                    .await?;
                self.cleanup_one(now).await;
                Ok(())
            }
        }
    }
}

#[derive(Clone, Copy)]
enum CreateResult {
    Created,
    Conflict,
}

#[derive(Clone, Copy)]
enum UpdateResult {
    Updated,
    Conflict,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Lease {
    api_version: String,
    kind: String,
    metadata: LeaseMetadata,
    spec: LeaseSpec,
}

impl Lease {
    fn new(
        name: String,
        retained_until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Self, ReplayError> {
        let lease_duration_seconds = retained_until
            .signed_duration_since(now)
            .num_seconds()
            .try_into()
            .map_err(|_| ReplayError::Unavailable)?;
        Ok(Self {
            api_version: "coordination.k8s.io/v1".to_owned(),
            kind: "Lease".to_owned(),
            metadata: LeaseMetadata {
                name,
                resource_version: None,
                labels: BTreeMap::from([(LEDGER_LABEL.to_owned(), LEDGER_VERSION.to_owned())]),
            },
            spec: LeaseSpec {
                holder_identity: "github-oidc-exchange-replay-ledger".to_owned(),
                lease_duration_seconds,
                acquire_time: timestamp(now),
                renew_time: timestamp(now),
            },
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LeaseMetadata {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource_version: Option<String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct LeaseSpec {
    holder_identity: String,
    lease_duration_seconds: i32,
    acquire_time: String,
    renew_time: String,
}

#[derive(Deserialize)]
struct LeaseList {
    #[serde(default)]
    items: Vec<Lease>,
    #[serde(default)]
    metadata: LeaseListMetadata,
}

#[derive(Default, Deserialize)]
struct LeaseListMetadata {
    #[serde(default, rename = "continue")]
    continue_token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteOptions<'a> {
    api_version: &'static str,
    kind: &'static str,
    preconditions: DeletePreconditions<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeletePreconditions<'a> {
    resource_version: &'a str,
}

impl<'a> DeleteOptions<'a> {
    fn with_resource_version(resource_version: &'a str) -> Self {
        Self {
            api_version: "v1",
            kind: "DeleteOptions",
            preconditions: DeletePreconditions { resource_version },
        }
    }
}

fn lease_name(jti: &str) -> String {
    let digest = Sha256::digest(jti.as_bytes());
    let hash = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("replay-{}", &hash[..56])
}

fn retained_until(expires_at: i64, now: i64) -> Result<DateTime<Utc>, ReplayError> {
    let retained_until = expires_at
        .checked_add(LEASE_RETENTION_SECONDS)
        .ok_or(ReplayError::Unavailable)?;
    let lease_duration = retained_until
        .checked_sub(now)
        .ok_or(ReplayError::Unavailable)?;
    if lease_duration <= 0 || lease_duration > MAX_LEASE_DURATION_SECONDS {
        return Err(ReplayError::Unavailable);
    }
    DateTime::from_timestamp(retained_until, 0).ok_or(ReplayError::Unavailable)
}

fn expired(lease: &Lease, now: DateTime<Utc>) -> bool {
    if !owned_ledger_lease(lease) || lease.spec.lease_duration_seconds <= 0 {
        return false;
    }
    let Ok(renewed_at) = DateTime::parse_from_rfc3339(&lease.spec.renew_time) else {
        return false;
    };
    renewed_at.with_timezone(&Utc)
        + ChronoDuration::seconds(i64::from(lease.spec.lease_duration_seconds))
        <= now
}

fn owned_ledger_lease(lease: &Lease) -> bool {
    lease
        .metadata
        .labels
        .get(LEDGER_LABEL)
        .is_some_and(|value| value == LEDGER_VERSION)
        && lease.spec.holder_identity == "github-oidc-exchange-replay-ledger"
}

fn expired_owned_leases(leases: &[Lease], now: DateTime<Utc>) -> impl Iterator<Item = &Lease> {
    leases
        .iter()
        .filter(move |lease| owned_ledger_lease(lease) && expired(lease, now))
}

fn timestamp(value: DateTime<Utc>) -> String {
    // Kubernetes LeaseTime is decoded by Go's microsecond-layout parser.
    value.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn valid_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(test)]
mod lease_tests {
    use chrono::{Duration, Utc};

    use super::{
        LEASE_RETENTION_SECONDS, LEDGER_LABEL, LEDGER_VERSION, Lease, LeaseMetadata, LeaseSpec,
        expired_owned_leases, lease_name, retained_until, timestamp,
    };

    #[test]
    fn replay_lease_name_is_deterministic_dns_safe_and_expiry_is_never_early() {
        let name = lease_name("source-jti");
        assert_eq!(name, lease_name("source-jti"));
        assert_ne!(name, lease_name("other-source-jti"));
        assert!(name.starts_with("replay-"));
        assert!(name.len() <= 63);
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        );

        let now = Utc::now();
        let input_expiry = now.timestamp() + 120;
        let retained = retained_until(input_expiry, now.timestamp());
        assert!(retained.is_ok());
        if let Ok(retained) = retained {
            assert!(retained.timestamp() >= input_expiry);
            assert_eq!(retained.timestamp(), input_expiry + LEASE_RETENTION_SECONDS);
        }
    }

    #[test]
    fn cleanup_scan_reaches_an_expired_owned_lease_after_an_unexpired_lease() {
        let now = Utc::now();
        let active = test_lease("active", now, 120);
        let expired = test_lease("expired", now - Duration::seconds(600), 1);
        let leases = [active, expired];
        let candidates = expired_owned_leases(&leases, now)
            .map(|lease| lease.metadata.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(candidates, ["expired"]);
    }

    fn test_lease(name: &str, renewed_at: chrono::DateTime<Utc>, duration: i32) -> Lease {
        Lease {
            api_version: "coordination.k8s.io/v1".to_owned(),
            kind: "Lease".to_owned(),
            metadata: LeaseMetadata {
                name: name.to_owned(),
                resource_version: Some("1".to_owned()),
                labels: [(LEDGER_LABEL.to_owned(), LEDGER_VERSION.to_owned())].into(),
            },
            spec: LeaseSpec {
                holder_identity: "github-oidc-exchange-replay-ledger".to_owned(),
                lease_duration_seconds: duration,
                acquire_time: timestamp(renewed_at),
                renew_time: timestamp(renewed_at),
            },
        }
    }
}
