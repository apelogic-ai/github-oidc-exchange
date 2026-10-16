use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::Utc;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation,
    dangerous::insecure_decode,
    decode, decode_header, get_current_timestamp,
    jwk::{JwkSet, KeyAlgorithm, PublicKeyUse},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    IDENTITY_CONTRACT,
    keys::KeyRing,
    replay::{ReplayError, ReplayLedger},
    workload::WorkloadTaskBinding,
};

pub const OIDC_POLICY_VERSION: &str = "github-oidc-exchange.apelogic.io/oidc-policy-v1";
const MAX_ASSERTION_BYTES: usize = 32 * 1024;
const MAX_SOURCE_LIFETIME_SECONDS: i64 = 600;
const JWKS_REFRESH_RETRY_SECONDS: i64 = 30;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcPolicy {
    pub version: String,
    pub providers: Vec<OidcProviderPolicy>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcProviderPolicy {
    pub issuer: String,
    pub audience: String,
    pub bindings: Vec<OidcBinding>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcBinding {
    pub claims: BTreeMap<String, String>,
    pub task: WorkloadTaskBinding,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OidcPolicyError {
    #[error("OIDC policy is invalid: {0}")]
    Invalid(String),
    #[error("OIDC identity is not authorized")]
    Unauthorized,
}

impl OidcPolicy {
    pub fn validate(&self) -> Result<(), OidcPolicyError> {
        if self.version != OIDC_POLICY_VERSION {
            return Err(invalid_policy("unsupported version"));
        }
        if self.providers.is_empty() || self.providers.len() > 32 {
            return Err(invalid_policy(
                "providers must contain between 1 and 32 entries",
            ));
        }
        let mut issuers = HashSet::new();
        for provider in &self.providers {
            if !valid_issuer(&provider.issuer)
                || !bounded_graphic(&provider.audience, 255)
                || !issuers.insert(provider.issuer.as_str())
                || provider.bindings.is_empty()
                || provider.bindings.len() > 256
            {
                return Err(invalid_policy(
                    "providers require unique HTTPS issuers, exact audiences, and bindings",
                ));
            }
            let mut bindings = HashSet::new();
            for binding in &provider.bindings {
                let encoded = serde_json::to_string(&binding.claims)
                    .map_err(|_| invalid_policy("binding claims are not serializable"))?;
                if binding.claims.is_empty()
                    || binding.claims.len() > 16
                    || !bindings.insert(encoded)
                    || !binding
                        .claims
                        .get("sub")
                        .is_some_and(|value| bounded_graphic(value, 2_048))
                    || binding.claims.iter().any(|(name, value)| {
                        !valid_claim_name(name)
                            || !bounded_graphic(value, 2_048)
                            || matches!(
                                name.as_str(),
                                "iss" | "aud" | "exp" | "iat" | "nbf" | "jti"
                            )
                    })
                    || !valid_task_binding(&binding.task)
                {
                    return Err(invalid_policy(
                        "bindings require unique exact claims including sub and a valid task owner",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn authorize(&self, claims: &OidcClaims) -> Result<WorkloadTaskBinding, OidcPolicyError> {
        let provider = self
            .providers
            .iter()
            .find(|provider| provider.issuer == claims.issuer)
            .ok_or(OidcPolicyError::Unauthorized)?;
        let mut matches = provider.bindings.iter().filter(|binding| {
            binding.claims.iter().all(|(name, expected)| {
                claims
                    .values
                    .get(name)
                    .and_then(Value::as_str)
                    .is_some_and(|actual| actual == expected)
            })
        });
        let binding = matches.next().ok_or(OidcPolicyError::Unauthorized)?;
        if matches.next().is_some() {
            return Err(OidcPolicyError::Unauthorized);
        }
        Ok(binding.task.clone())
    }
}

fn invalid_policy(message: &str) -> OidcPolicyError {
    OidcPolicyError::Invalid(message.to_owned())
}

fn valid_issuer(value: &str) -> bool {
    value.len() <= 2_048
        && !value.ends_with('/')
        && reqwest::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
}

fn valid_claim_name(value: &str) -> bool {
    bounded_graphic(value, 128) && !value.contains(['.', '[', ']'])
}

fn valid_task_binding(task: &WorkloadTaskBinding) -> bool {
    bounded_graphic(&task.service, 128)
        && task
            .owner_canonical_user_id
            .strip_prefix("usr_")
            .is_some_and(|suffix| {
                suffix.len() == 32
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        && task.owner_email == task.owner_email.to_ascii_lowercase()
        && !task.owner_email.contains(char::is_whitespace)
        && task
            .owner_email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
}

fn bounded_graphic(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[derive(Clone, Debug)]
pub struct OidcClaims {
    pub issuer: String,
    pub subject: String,
    pub expires_at: i64,
    pub issued_at: i64,
    pub jti: Option<String>,
    pub build_number: Option<u64>,
    values: Map<String, Value>,
}

#[derive(Debug, Error)]
pub enum OidcVerifyError {
    #[error("OIDC assertion is invalid")]
    Invalid,
    #[error("OIDC signing keys are unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub struct OidcVerifierSet {
    providers: Arc<HashMap<String, ProviderVerifier>>,
}

#[derive(Clone)]
struct ProviderVerifier {
    issuer: String,
    audience: String,
    jwks_uri: Option<String>,
    client: reqwest::Client,
    keys: Arc<RwLock<HashMap<String, DecodingKey>>>,
    refresh: Arc<Mutex<RefreshState>>,
}

#[derive(Default)]
struct RefreshState {
    last_attempt: i64,
    last_failed: bool,
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct UnverifiedIssuer {
    iss: String,
}

impl OidcVerifierSet {
    pub async fn discover(policy: &OidcPolicy) -> Result<Self, OidcVerifyError> {
        policy.validate().map_err(|_| OidcVerifyError::Invalid)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| OidcVerifyError::Unavailable)?;
        let mut providers = HashMap::new();
        for configured in &policy.providers {
            let discovery_url = format!("{}/.well-known/openid-configuration", configured.issuer);
            let discovery = client
                .get(discovery_url)
                .send()
                .await
                .map_err(|_| OidcVerifyError::Unavailable)?
                .error_for_status()
                .map_err(|_| OidcVerifyError::Unavailable)?
                .json::<DiscoveryDocument>()
                .await
                .map_err(|_| OidcVerifyError::Unavailable)?;
            if discovery.issuer != configured.issuer || !valid_issuer_endpoint(&discovery.jwks_uri)
            {
                return Err(OidcVerifyError::Invalid);
            }
            let verifier = ProviderVerifier {
                issuer: configured.issuer.clone(),
                audience: configured.audience.clone(),
                jwks_uri: Some(discovery.jwks_uri),
                client: client.clone(),
                keys: Arc::new(RwLock::new(HashMap::new())),
                refresh: Arc::new(Mutex::new(RefreshState::default())),
            };
            verifier.refresh().await?;
            providers.insert(configured.issuer.clone(), verifier);
        }
        Ok(Self {
            providers: Arc::new(providers),
        })
    }

    #[cfg(feature = "test-support")]
    #[doc = "Constructs a verifier with one injected RS256 test key."]
    pub fn with_test_key(
        issuer: String,
        audience: String,
        kid: String,
        key: DecodingKey,
    ) -> Result<Self, OidcVerifyError> {
        if !valid_issuer(&issuer) || !bounded_graphic(&audience, 255) || kid.is_empty() {
            return Err(OidcVerifyError::Invalid);
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| OidcVerifyError::Unavailable)?;
        let mut keys = HashMap::new();
        keys.insert(kid, key);
        let provider = ProviderVerifier {
            issuer: issuer.clone(),
            audience,
            jwks_uri: None,
            client,
            keys: Arc::new(RwLock::new(keys)),
            refresh: Arc::new(Mutex::new(RefreshState::default())),
        };
        Ok(Self {
            providers: Arc::new(HashMap::from([(issuer, provider)])),
        })
    }

    pub async fn verify(&self, assertion: &str) -> Result<OidcClaims, OidcVerifyError> {
        if assertion.is_empty() || assertion.len() > MAX_ASSERTION_BYTES {
            return Err(OidcVerifyError::Invalid);
        }
        let header = decode_header(assertion).map_err(|_| OidcVerifyError::Invalid)?;
        if header.alg != Algorithm::RS256 || header.typ.as_deref() != Some("JWT") {
            return Err(OidcVerifyError::Invalid);
        }
        let kid = header.kid.ok_or(OidcVerifyError::Invalid)?;
        let unverified =
            insecure_decode::<UnverifiedIssuer>(assertion).map_err(|_| OidcVerifyError::Invalid)?;
        let provider = self
            .providers
            .get(&unverified.claims.iss)
            .ok_or(OidcVerifyError::Invalid)?;
        let key = provider.key(&kid).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&provider.issuer]);
        validation.set_audience(&[&provider.audience]);
        validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "iat"]);
        validation.validate_nbf = true;
        validation.leeway = 30;
        let values = decode::<Value>(assertion, &key, &validation)
            .map_err(|_| OidcVerifyError::Invalid)?
            .claims
            .as_object()
            .cloned()
            .ok_or(OidcVerifyError::Invalid)?;
        validated_claims(values, &provider.issuer, &provider.audience)
    }
}

impl ProviderVerifier {
    async fn key(&self, kid: &str) -> Result<DecodingKey, OidcVerifyError> {
        if let Some(key) = self.keys.read().await.get(kid).cloned() {
            return Ok(key);
        }
        if self.jwks_uri.is_none() {
            return Err(OidcVerifyError::Invalid);
        }
        let mut refresh = self.refresh.lock().await;
        if let Some(key) = self.keys.read().await.get(kid).cloned() {
            return Ok(key);
        }
        let now = Utc::now().timestamp();
        if refresh.last_attempt > 0
            && now.saturating_sub(refresh.last_attempt) < JWKS_REFRESH_RETRY_SECONDS
        {
            return if refresh.last_failed {
                Err(OidcVerifyError::Unavailable)
            } else {
                Err(OidcVerifyError::Invalid)
            };
        }
        refresh.last_attempt = now;
        let result = self.refresh().await;
        refresh.last_failed = result.is_err();
        result?;
        self.keys
            .read()
            .await
            .get(kid)
            .cloned()
            .ok_or(OidcVerifyError::Invalid)
    }

    async fn refresh(&self) -> Result<(), OidcVerifyError> {
        let uri = self.jwks_uri.as_ref().ok_or(OidcVerifyError::Invalid)?;
        let document = self
            .client
            .get(uri)
            .send()
            .await
            .map_err(|_| OidcVerifyError::Unavailable)?
            .error_for_status()
            .map_err(|_| OidcVerifyError::Unavailable)?
            .json::<JwkSet>()
            .await
            .map_err(|_| OidcVerifyError::Unavailable)?;
        let mut keys = HashMap::new();
        for jwk in document.keys {
            let Some(kid) = jwk.common.key_id.clone() else {
                continue;
            };
            if jwk.common.key_algorithm == Some(KeyAlgorithm::RS256)
                && jwk.common.public_key_use == Some(PublicKeyUse::Signature)
                && let Ok(key) = DecodingKey::from_jwk(&jwk)
            {
                keys.insert(kid, key);
            }
        }
        if keys.is_empty() {
            return Err(OidcVerifyError::Unavailable);
        }
        *self.keys.write().await = keys;
        Ok(())
    }
}

fn valid_issuer_endpoint(value: &str) -> bool {
    value.len() <= 2_048
        && reqwest::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
}

fn validated_claims(
    values: Map<String, Value>,
    issuer: &str,
    audience: &str,
) -> Result<OidcClaims, OidcVerifyError> {
    let claim_string = |name: &str| {
        values
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(OidcVerifyError::Invalid)
    };
    let claim_i64 = |name: &str| {
        values
            .get(name)
            .and_then(Value::as_i64)
            .ok_or(OidcVerifyError::Invalid)
    };
    let actual_issuer = claim_string("iss")?;
    let subject = claim_string("sub")?;
    let expires_at = claim_i64("exp")?;
    let issued_at = claim_i64("iat")?;
    let now = Utc::now().timestamp();
    let lifetime = expires_at
        .checked_sub(issued_at)
        .ok_or(OidcVerifyError::Invalid)?;
    if actual_issuer != issuer
        || !exact_audience(values.get("aud"), audience)
        || !bounded_graphic(&subject, 2_048)
        || lifetime <= 0
        || lifetime > MAX_SOURCE_LIFETIME_SECONDS
        || expires_at <= now
        || issued_at > now + 30
    {
        return Err(OidcVerifyError::Invalid);
    }
    let jti = values
        .get("jti")
        .map(|value| value.as_str().ok_or(OidcVerifyError::Invalid))
        .transpose()?
        .map(str::to_owned);
    if jti
        .as_deref()
        .is_some_and(|value| !bounded_graphic(value, 128))
    {
        return Err(OidcVerifyError::Invalid);
    }
    let build_number = values.get("build_number").and_then(Value::as_u64);
    if jti.is_none() && build_number.is_none() {
        return Err(OidcVerifyError::Invalid);
    }
    Ok(OidcClaims {
        issuer: actual_issuer,
        subject,
        expires_at,
        issued_at,
        jti,
        build_number,
        values,
    })
}

fn exact_audience(value: Option<&Value>, expected: &str) -> bool {
    match value {
        Some(Value::String(actual)) => actual == expected,
        Some(Value::Array(actual)) => {
            actual.len() == 1 && actual[0].as_str().is_some_and(|actual| actual == expected)
        }
        _ => false,
    }
}

#[derive(Clone)]
pub struct OidcExchangeService<L> {
    pub verifier: OidcVerifierSet,
    pub policy: Arc<OidcPolicy>,
    pub ledger: Arc<L>,
    pub keys: Arc<KeyRing>,
    pub issuer: String,
    pub output_audience: String,
    pub token_ttl: Duration,
    pub metrics: Arc<OidcMetrics>,
}

#[derive(Default)]
pub struct OidcMetrics {
    pub requests: AtomicU64,
    pub issued: AtomicU64,
    pub denied: AtomicU64,
    pub replayed: AtomicU64,
    pub errors: AtomicU64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OidcExchangeError {
    #[error("OIDC assertion was rejected")]
    Unauthorized,
    #[error("OIDC exchange is unavailable")]
    Unavailable,
}

#[derive(Serialize)]
struct OidcTaskOutputClaims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: u64,
    iat: u64,
    nbf: u64,
    jti: String,
    email: String,
    email_verified: bool,
    groups: Vec<String>,
    identity_contract: &'static str,
}

impl<L: ReplayLedger> OidcExchangeService<L> {
    pub async fn exchange(&self, assertion: &str) -> Result<String, OidcExchangeError> {
        self.metrics.requests.fetch_add(1, Ordering::Relaxed);
        let claims = match self.verifier.verify(assertion).await {
            Ok(claims) => claims,
            Err(OidcVerifyError::Invalid) => {
                self.deny("assertion_invalid", "", "");
                return Err(OidcExchangeError::Unauthorized);
            }
            Err(OidcVerifyError::Unavailable) => {
                self.fail("jwks_unavailable");
                return Err(OidcExchangeError::Unavailable);
            }
        };
        let task = self.policy.authorize(&claims).map_err(|_| {
            self.deny("identity_unbound", &claims.issuer, &claims.subject);
            OidcExchangeError::Unauthorized
        })?;
        let replay = replay_identifier(&claims).ok_or_else(|| {
            self.deny("replay_identity_invalid", &claims.issuer, &claims.subject);
            OidcExchangeError::Unauthorized
        })?;
        match self.ledger.use_once(&replay, claims.expires_at).await {
            Ok(()) => {}
            Err(ReplayError::Replayed) => {
                self.metrics.replayed.fetch_add(1, Ordering::Relaxed);
                self.deny("source_replay", &claims.issuer, &claims.subject);
                return Err(OidcExchangeError::Unauthorized);
            }
            Err(ReplayError::Unavailable | ReplayError::Configuration(_)) => {
                self.fail("ledger_unavailable");
                return Err(OidcExchangeError::Unavailable);
            }
        }
        let now = get_current_timestamp();
        let token = self
            .keys
            .sign(&OidcTaskOutputClaims {
                iss: self.issuer.clone(),
                sub: claims.subject.clone(),
                aud: vec![self.output_audience.clone()],
                exp: now + self.token_ttl.as_secs(),
                iat: now,
                nbf: now.saturating_sub(5),
                jti: Uuid::new_v4().to_string(),
                email: task.owner_email.clone(),
                email_verified: true,
                groups: vec![
                    format!("agents.apelogic.ai/service-principal:{}", task.service),
                    format!(
                        "agents.apelogic.ai/canonical-user:{}",
                        task.owner_canonical_user_id
                    ),
                    format!("agents.apelogic.ai/task-owner:{}", task.owner_email),
                ],
                identity_contract: IDENTITY_CONTRACT,
            })
            .map_err(|_| {
                self.fail("signing_unavailable");
                OidcExchangeError::Unavailable
            })?;
        self.metrics.issued.fetch_add(1, Ordering::Relaxed);
        info!(
            event = "oidc_exchange_issued",
            issuer_hash = hash_value(&claims.issuer),
            subject_hash = hash_value(&claims.subject),
            source_replay_hash = hash_value(&replay),
            "generic OIDC exchange issued"
        );
        Ok(token)
    }

    fn deny(&self, reason: &str, issuer: &str, subject: &str) {
        self.metrics.denied.fetch_add(1, Ordering::Relaxed);
        warn!(
            event = "oidc_exchange_denied",
            reason,
            issuer_hash = hash_value(issuer),
            subject_hash = hash_value(subject),
            "generic OIDC exchange rejected"
        );
    }

    fn fail(&self, reason: &str) {
        self.metrics.errors.fetch_add(1, Ordering::Relaxed);
        warn!(
            event = "oidc_exchange_failed",
            reason, "generic OIDC exchange failed"
        );
    }
}

fn replay_identifier(claims: &OidcClaims) -> Option<String> {
    let mut hasher = Sha256::new();
    write_replay_component(&mut hasher, &claims.issuer);
    if let Some(jti) = claims.jti.as_deref() {
        write_replay_component(&mut hasher, "jti");
        write_replay_component(&mut hasher, jti);
    } else {
        write_replay_component(&mut hasher, "jenkins-build");
        write_replay_component(&mut hasher, &claims.subject);
        write_replay_component(&mut hasher, &claims.issued_at.to_string());
        write_replay_component(&mut hasher, &claims.build_number?.to_string());
    }
    Some(format!("oidc-{:x}", hasher.finalize()))
}

fn write_replay_component(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hash_value(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let digest = Sha256::digest(value.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
