use std::{sync::Arc, time::Duration};

use jsonwebtoken::get_current_timestamp;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    IDENTITY_CONTRACT,
    github::{GitHubClaims, GitHubVerifier},
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
    email: String,
    groups: Vec<String>,
    identity_contract: &'static str,
}

impl<L: ReplayLedger + 'static> ExchangeService<L> {
    pub async fn exchange(&self, assertion: &str) -> Result<String, ExchangeError> {
        self.metrics
            .requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let claims = self.verifier.verify(assertion).await.map_err(|error| {
            self.deny(&GitHubClaims::default(), &error.to_string());
            ExchangeError::Unauthorized
        })?;
        let identity = self.policy.authorize(&claims).map_err(|error| {
            self.deny(&claims, &error.to_string());
            ExchangeError::Unauthorized
        })?;
        match self.ledger.use_once(&claims.jti, claims.exp).await {
            Ok(()) => {}
            Err(ReplayError::Replayed) => {
                self.metrics
                    .replayed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.audit("exchange_replayed", &claims, "replay");
                return Err(ExchangeError::Unauthorized);
            }
            Err(ReplayError::Unavailable) => {
                self.metrics
                    .errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.audit("exchange_failed", &claims, "ledger_unavailable");
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
                email: identity.email,
                groups: identity.groups,
                identity_contract: IDENTITY_CONTRACT,
            })
            .map_err(|_| ExchangeError::Unavailable)?;
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
        self.audit("exchange_denied", claims, reason);
    }

    fn audit(&self, event: &str, claims: &GitHubClaims, reason: &str) {
        warn!(
            event,
            actor_id = claims.actor_id,
            repository_owner_id = claims.repository_owner_id,
            repository_id = claims.repository_id,
            workflow_ref = claims.workflow_ref,
            job_workflow_ref = claims.job_workflow_ref,
            source_jti_hash = hash_identifier(&claims.jti),
            reason,
            "identity exchange rejected"
        );
    }
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
