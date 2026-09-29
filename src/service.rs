use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use jsonwebtoken::get_current_timestamp;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    SOURCE_PROVENANCE_CONTRACT,
    github::{GitHubClaims, GitHubVerifier, VerifyError},
    keys::KeyRing,
    policy::Policy,
    replay::{ReplayError, ReplayLedger},
};

#[derive(Clone)]
pub struct ExchangeService<L> {
    pub verifier: GitHubVerifier,
    pub policy: Arc<Policy>,
    pub ledger: Arc<L>,
    pub keys: Arc<KeyRing>,
    pub issuer: String,
    pub output_audience: String,
    pub token_ttl: Duration,
    pub metrics: Arc<Metrics>,
}

#[derive(Default)]
pub struct Metrics {
    pub requests: std::sync::atomic::AtomicU64,
    pub issued: std::sync::atomic::AtomicU64,
    pub denied: std::sync::atomic::AtomicU64,
    pub replayed: std::sync::atomic::AtomicU64,
    pub errors: std::sync::atomic::AtomicU64,
    duration_buckets: [std::sync::atomic::AtomicU64; 8],
    duration_count: std::sync::atomic::AtomicU64,
    duration_sum_micros: std::sync::atomic::AtomicU64,
}

pub const EXCHANGE_DURATION_BUCKET_SECONDS: [f64; 8] =
    [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

impl Metrics {
    fn observe_duration(&self, elapsed: Duration) {
        let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        self.duration_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.duration_sum_micros
            .fetch_add(micros, std::sync::atomic::Ordering::Relaxed);
        for (bucket, upper_bound) in self
            .duration_buckets
            .iter()
            .zip(EXCHANGE_DURATION_BUCKET_SECONDS)
        {
            if elapsed.as_secs_f64() <= upper_bound {
                bucket.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    pub fn duration_snapshot(&self) -> ([u64; 8], u64, u64) {
        (
            std::array::from_fn(|index| {
                self.duration_buckets[index].load(std::sync::atomic::Ordering::Relaxed)
            }),
            self.duration_count
                .load(std::sync::atomic::Ordering::Relaxed),
            self.duration_sum_micros
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

struct ExchangeTimer<'a> {
    metrics: &'a Metrics,
    started: Instant,
}

impl Drop for ExchangeTimer<'_> {
    fn drop(&mut self) {
        self.metrics.observe_duration(self.started.elapsed());
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExchangeError {
    #[error("identity assertion was rejected")]
    Unauthorized,
    #[error("identity service is unavailable")]
    Unavailable,
}

#[derive(Serialize)]
struct OutputClaims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: u64,
    iat: u64,
    nbf: u64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor_login: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<Vec<String>>,
    identity_contract: &'static str,
    source_provenance: SourceProvenance,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceProvenance {
    contract_version: &'static str,
    provider: &'static str,
    repository: SourceRepository,
    triggered_sha: String,
    run: SourceRun,
    event: String,
    #[serde(rename = "ref")]
    git_ref: String,
    actor_id: String,
    actor: String,
    caller_workflow: SourceWorkflow,
    reusable_workflow: SourceWorkflow,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceRepository {
    id: String,
    owner_id: String,
    name: String,
}

#[derive(Serialize)]
struct SourceRun {
    id: String,
    attempt: u32,
}

#[derive(Serialize)]
struct SourceWorkflow {
    #[serde(rename = "ref")]
    workflow_ref: String,
    sha: String,
}

impl From<&GitHubClaims> for SourceProvenance {
    fn from(claims: &GitHubClaims) -> Self {
        Self {
            contract_version: SOURCE_PROVENANCE_CONTRACT,
            provider: "github",
            repository: SourceRepository {
                id: claims.repository_id.clone(),
                owner_id: claims.repository_owner_id.clone(),
                name: claims.repository.clone(),
            },
            triggered_sha: typed_git_sha1(&claims.sha),
            run: SourceRun {
                id: claims.run_id.clone(),
                attempt: claims.run_attempt,
            },
            event: claims.event_name.clone(),
            git_ref: claims.git_ref.clone(),
            actor_id: claims.actor_id.clone(),
            actor: claims.actor.clone(),
            caller_workflow: SourceWorkflow {
                workflow_ref: claims.workflow_ref.clone(),
                sha: typed_git_sha1(&claims.workflow_sha),
            },
            reusable_workflow: SourceWorkflow {
                workflow_ref: claims.job_workflow_ref.clone(),
                sha: typed_git_sha1(&claims.job_workflow_sha),
            },
        }
    }
}

impl<L: ReplayLedger + 'static> ExchangeService<L> {
    pub async fn exchange(&self, assertion: &str) -> Result<String, ExchangeError> {
        self.metrics
            .requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _timer = ExchangeTimer {
            metrics: &self.metrics,
            started: Instant::now(),
        };
        let claims = match self.verifier.verify(assertion).await {
            Ok(claims) => claims,
            Err(VerifyError::Invalid) => {
                self.deny(&GitHubClaims::default(), "assertion is invalid");
                return Err(ExchangeError::Unauthorized);
            }
            Err(error @ VerifyError::KeysUnavailable { .. }) => {
                self.metrics
                    .errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.audit(
                    "exchange_failed",
                    &GitHubClaims::default(),
                    &error.to_string(),
                    None,
                );
                return Err(ExchangeError::Unavailable);
            }
        };
        let identity = self.policy.authorize(&claims).map_err(|_| {
            self.deny(&claims, "identity is not authorized");
            ExchangeError::Unauthorized
        })?;
        match self.ledger.use_once(&claims.jti, claims.exp).await {
            Ok(()) => {}
            Err(ReplayError::Replayed) => {
                self.metrics
                    .replayed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.audit("exchange_replayed", &claims, "replay", None);
                return Err(ExchangeError::Unauthorized);
            }
            Err(ReplayError::Unavailable | ReplayError::Configuration(_)) => {
                self.metrics
                    .errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.audit("exchange_failed", &claims, "ledger_unavailable", None);
                return Err(ExchangeError::Unavailable);
            }
        }
        let now = get_current_timestamp();
        let token = self
            .keys
            .sign(&OutputClaims {
                iss: self.issuer.clone(),
                sub: identity.subject,
                aud: vec![self.output_audience.clone()],
                exp: now + self.token_ttl.as_secs(),
                iat: now,
                nbf: now.saturating_sub(5),
                jti: Uuid::new_v4().to_string(),
                actor_login: identity.actor_login,
                email: identity.email,
                email_verified: identity.email_verified,
                groups: identity.groups,
                identity_contract: identity.identity_contract,
                source_provenance: SourceProvenance::from(&claims),
            })
            .map_err(|error| {
                self.metrics
                    .errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.audit(
                    "exchange_failed",
                    &claims,
                    "signing_unavailable",
                    Some(&error.to_string()),
                );
                ExchangeError::Unavailable
            })?;
        self.metrics
            .issued
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        info!(
            event = "exchange_issued",
            actor_id = identity.actor_id,
            repository = identity.repository,
            workflow_ref = identity.workflow_ref,
            job_workflow_ref = identity.job_workflow_ref,
            source_jti_hash = hash_identifier(&claims.jti),
            "identity exchange issued"
        );
        Ok(token)
    }

    fn deny(&self, claims: &GitHubClaims, reason: &str) {
        self.metrics
            .denied
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.audit("exchange_denied", claims, reason, None);
    }

    fn audit(&self, event: &str, claims: &GitHubClaims, reason: &str, detail: Option<&str>) {
        warn!(
            event,
            actor_id = claims.actor_id,
            repository_owner_id = claims.repository_owner_id,
            repository_id = claims.repository_id,
            workflow_ref = claims.workflow_ref,
            job_workflow_ref = claims.job_workflow_ref,
            source_jti_hash = hash_identifier(&claims.jti),
            reason,
            detail = detail.unwrap_or_default(),
            "identity exchange rejected"
        );
    }
}

fn typed_git_sha1(value: &str) -> String {
    format!("git:sha1:{value}")
}

fn hash_identifier(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let digest = Sha256::digest(value.as_bytes());
    hex_prefix(&digest[..8])
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
