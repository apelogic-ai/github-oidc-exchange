//! Browser-session-to-MCP HOP-1 exchange.
//!
//! This module deliberately does **not** authenticate a browser.  Steward is the browser-session
//! authority.  It sends a short-lived signed attestation over the already authenticated internal
//! workload channel; Identity verifies both pieces independently and emits a resource-bound bearer
//! token.  Browser cookies, browser session identifiers, and provider credentials never cross this
//! boundary.

use std::{
    collections::HashMap,
    fs::File,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::Utc;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm, PublicKeyUse},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    IDENTITY_BROWSER_HOP1_CONTRACT,
    keys::KeyRing,
    replay::{ReplayError, ReplayLedger},
    workload::WorkloadPolicy,
};

/// Exact workload-policy role required to invoke this exchange.
pub const BROWSER_HOP1_ISSUER_ROLE: &str = "browser-hop1-issuer";
const MAX_ASSERTION_BYTES: usize = 8 * 1024;
const MAX_ASSERTION_LIFETIME_SECONDS: i64 = 60;
const CLOCK_SKEW_SECONDS: i64 = 5;

/// The only operation Identity currently permits from a browser-authenticated user.
///
/// A new operation must be an explicit contract change; callers cannot supply a free-form scope.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserHop1Operation {
    GithubOauthConnect,
    Other,
}

/// Steward's signed assertion.  It is a service-to-service attestation, not a browser credential.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserHop1RequestClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub jti: String,
    pub email: String,
    pub email_verified: bool,
    pub operation: BrowserHop1Operation,
    pub operation_id: String,
}

#[derive(Debug, Error)]
pub enum BrowserHop1VerifierError {
    #[error("Steward browser assertion verifier is invalid")]
    Invalid,
}

/// Verifies Steward's ES256 browser-session attestations against a deployment-projected public
/// JWKS.  The key set is local-only: Identity never follows an attacker-controlled issuer URL.
#[derive(Clone)]
pub struct StewardBrowserAssertionVerifier {
    issuer: String,
    audience: String,
    keys: HashMap<String, DecodingKey>,
}

impl StewardBrowserAssertionVerifier {
    pub fn load(
        jwks_file: &Path,
        issuer: String,
        audience: String,
    ) -> Result<Self, BrowserHop1VerifierError> {
        if !valid_https_issuer(&issuer) || audience.is_empty() {
            return Err(BrowserHop1VerifierError::Invalid);
        }
        let file = File::open(jwks_file).map_err(|_| BrowserHop1VerifierError::Invalid)?;
        let document: JwkSet =
            serde_json::from_reader(file).map_err(|_| BrowserHop1VerifierError::Invalid)?;
        let mut keys = HashMap::new();
        for jwk in document.keys {
            let Some(kid) = jwk.common.key_id.clone() else {
                continue;
            };
            if kid.is_empty()
                || jwk.common.key_algorithm != Some(KeyAlgorithm::ES256)
                || jwk.common.public_key_use != Some(PublicKeyUse::Signature)
            {
                continue;
            }
            let key = DecodingKey::from_jwk(&jwk).map_err(|_| BrowserHop1VerifierError::Invalid)?;
            if keys.insert(kid, key).is_some() {
                return Err(BrowserHop1VerifierError::Invalid);
            }
        }
        if keys.is_empty() {
            return Err(BrowserHop1VerifierError::Invalid);
        }
        Ok(Self {
            issuer,
            audience,
            keys,
        })
    }

    pub fn verify(
        &self,
        assertion: &str,
    ) -> Result<BrowserHop1RequestClaims, BrowserHop1VerifierError> {
        if assertion.is_empty() || assertion.len() > MAX_ASSERTION_BYTES {
            return Err(BrowserHop1VerifierError::Invalid);
        }
        let header = decode_header(assertion).map_err(|_| BrowserHop1VerifierError::Invalid)?;
        if header.alg != Algorithm::ES256 || header.typ.as_deref() != Some("JWT") {
            return Err(BrowserHop1VerifierError::Invalid);
        }
        let kid = header.kid.ok_or(BrowserHop1VerifierError::Invalid)?;
        let key = self
            .keys
            .get(&kid)
            .ok_or(BrowserHop1VerifierError::Invalid)?;
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "iat", "nbf", "jti"]);
        validation.validate_nbf = true;
        validation.leeway = CLOCK_SKEW_SECONDS as u64;
        let claims = decode::<BrowserHop1RequestClaims>(assertion, key, &validation)
            .map_err(|_| BrowserHop1VerifierError::Invalid)?
            .claims;
        let now = Utc::now().timestamp();
        let lifetime = claims
            .exp
            .checked_sub(claims.iat)
            .ok_or(BrowserHop1VerifierError::Invalid)?;
        if claims.iss != self.issuer
            || claims.aud != self.audience
            || lifetime <= 0
            || lifetime > MAX_ASSERTION_LIFETIME_SECONDS
            || claims.iat > now + CLOCK_SKEW_SECONDS
            || claims.nbf > claims.iat
            || !canonical_user_id(&claims.sub)
            || !canonical_email(&claims.email)
            || !claims.email_verified
            || claims.jti.is_empty()
            || !operation_id(&claims.operation_id)
            || claims.operation != BrowserHop1Operation::GithubOauthConnect
        {
            return Err(BrowserHop1VerifierError::Invalid);
        }
        Ok(claims)
    }
}

#[derive(Default)]
pub struct BrowserHop1Metrics {
    pub requests: AtomicU64,
    pub issued: AtomicU64,
    pub denied: AtomicU64,
    pub replayed: AtomicU64,
    pub errors: AtomicU64,
}

#[derive(Clone)]
pub struct BrowserHop1ExchangeService<L> {
    pub verifier: StewardBrowserAssertionVerifier,
    pub policy: Arc<WorkloadPolicy>,
    pub ledger: Arc<L>,
    pub keys: Arc<KeyRing>,
    pub issuer: String,
    pub output_audience: String,
    pub token_ttl: Duration,
    pub metrics: Arc<BrowserHop1Metrics>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BrowserHop1ExchangeError {
    #[error("browser HOP-1 request was rejected")]
    Unauthorized,
    #[error("browser HOP-1 exchange is unavailable")]
    Unavailable,
}

#[derive(Serialize)]
struct BrowserHop1OutputClaims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: u64,
    iat: u64,
    nbf: u64,
    jti: String,
    email: String,
    email_verified: bool,
    operation: BrowserHop1Operation,
    operation_id: String,
    identity_contract: &'static str,
}

impl<L: ReplayLedger + 'static> BrowserHop1ExchangeService<L> {
    /// Exchange an exact internal Steward workload caller and a signed browser-session attestation.
    /// The first argument is the TokenReview-selected Kubernetes username; it is never a browser
    /// session, cookie, or HTTP identity header.
    pub async fn exchange(
        &self,
        workload_username: &str,
        assertion: &str,
    ) -> Result<String, BrowserHop1ExchangeError> {
        self.metrics.requests.fetch_add(1, Ordering::Relaxed);
        let caller = self.policy.authorize(workload_username).map_err(|_| {
            self.deny("workload_unmapped");
            BrowserHop1ExchangeError::Unauthorized
        })?;
        if !caller
            .roles
            .iter()
            .any(|role| role == BROWSER_HOP1_ISSUER_ROLE)
        {
            self.deny("workload_role_missing");
            return Err(BrowserHop1ExchangeError::Unauthorized);
        }
        let request = self.verifier.verify(assertion).map_err(|_| {
            self.deny("attestation_rejected");
            BrowserHop1ExchangeError::Unauthorized
        })?;
        let replay_key = format!("browser-hop1:{}", request.jti);
        match self.ledger.use_once(&replay_key, request.exp).await {
            Ok(()) => {}
            Err(ReplayError::Replayed) => {
                self.metrics.replayed.fetch_add(1, Ordering::Relaxed);
                self.audit(
                    "browser_hop1_replayed",
                    workload_username,
                    &request.jti,
                    "replay",
                );
                return Err(BrowserHop1ExchangeError::Unauthorized);
            }
            Err(ReplayError::Unavailable) => {
                self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                self.audit(
                    "browser_hop1_failed",
                    workload_username,
                    &request.jti,
                    "ledger_unavailable",
                );
                return Err(BrowserHop1ExchangeError::Unavailable);
            }
        }
        let now = jsonwebtoken::get_current_timestamp();
        let token = self
            .keys
            .sign(&BrowserHop1OutputClaims {
                iss: self.issuer.clone(),
                sub: request.sub,
                aud: vec![self.output_audience.clone()],
                exp: now + self.token_ttl.as_secs(),
                iat: now,
                nbf: now.saturating_sub(CLOCK_SKEW_SECONDS as u64),
                jti: Uuid::new_v4().to_string(),
                email: request.email,
                email_verified: true,
                operation: request.operation,
                operation_id: request.operation_id,
                identity_contract: IDENTITY_BROWSER_HOP1_CONTRACT,
            })
            .map_err(|_| {
                self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                BrowserHop1ExchangeError::Unavailable
            })?;
        self.metrics.issued.fetch_add(1, Ordering::Relaxed);
        self.audit("browser_hop1_issued", workload_username, "", "issued");
        Ok(token)
    }

    fn deny(&self, reason: &str) {
        self.metrics.denied.fetch_add(1, Ordering::Relaxed);
        warn!(
            event = "browser_hop1_denied",
            reason, "browser HOP-1 exchange rejected"
        );
    }

    fn audit(&self, event: &str, workload_username: &str, source_jti: &str, reason: &str) {
        info!(
            event,
            workload_username,
            source_jti_hash = hash_identifier(source_jti),
            reason,
            "browser HOP-1 exchange event"
        );
    }
}

fn valid_https_issuer(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}

fn canonical_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !value.contains(char::is_whitespace)
        && value == value.to_ascii_lowercase()
}

fn canonical_user_id(value: &str) -> bool {
    value.strip_prefix("usr_").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn operation_id(value: &str) -> bool {
    value.strip_prefix("op_").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn hash_identifier(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let digest = Sha256::digest(value.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
