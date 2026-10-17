use std::{
    collections::{BTreeMap, HashMap, HashSet},
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
    Algorithm, DecodingKey, Validation,
    dangerous::insecure_decode,
    decode, decode_header, get_current_timestamp,
    jwk::{JwkSet, KeyAlgorithm, PublicKeyUse},
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
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
const MAX_DISCOVERY_BYTES: usize = 64 * 1024;
const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MAX_SOURCE_LIFETIME_SECONDS: i64 = 600;
const JWKS_REFRESH_RETRY_SECONDS: i64 = 30;
const JWKS_SOFT_REFRESH_SECONDS: u64 = 300;
const DEFAULT_JWKS_MAX_STALENESS_SECONDS: u64 = 21_600;

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
    pub fn load(path: &Path) -> Result<Self, OidcPolicyError> {
        let file = File::open(path).map_err(|error| invalid_policy(&error.to_string()))?;
        let policy: Self =
            serde_json::from_reader(file).map_err(|error| invalid_policy(&error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

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
            let mut bindings: Vec<&BTreeMap<String, String>> = Vec::new();
            for binding in &provider.bindings {
                if binding.claims.is_empty()
                    || binding.claims.len() > 16
                    || bindings
                        .iter()
                        .any(|existing| claim_bindings_overlap(existing, &binding.claims))
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
                bindings.push(&binding.claims);
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

fn claim_bindings_overlap(
    left: &BTreeMap<String, String>,
    right: &BTreeMap<String, String>,
) -> bool {
    !left.iter().any(|(name, left_value)| {
        right
            .get(name)
            .is_some_and(|right_value| right_value != left_value)
    })
}

fn valid_issuer(value: &str) -> bool {
    value.len() <= 2_048
        && !value.ends_with('/')
        && reqwest::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some_and(|host| {
                    !host.is_empty()
                        && host
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
                })
                && url.port_or_known_default() == Some(443)
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
    client: reqwest::Client,
    cache: Arc<RwLock<KeyCache>>,
    refresh: Arc<Mutex<RefreshState>>,
    max_staleness: Duration,
    #[cfg(feature = "test-support")]
    key_source: KeySource,
}

#[derive(Default)]
struct RefreshState {
    last_soft_attempt: i64,
    last_forced_attempt: i64,
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: i64,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeySource {
    Remote,
    Injected,
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
    pub fn discover(policy: &OidcPolicy) -> Result<Self, OidcVerifyError> {
        Self::discover_with_max_staleness(
            policy,
            Duration::from_secs(DEFAULT_JWKS_MAX_STALENESS_SECONDS),
        )
    }

    pub fn discover_with_max_staleness(
        policy: &OidcPolicy,
        max_staleness: Duration,
    ) -> Result<Self, OidcVerifyError> {
        Self::discover_with_additional_ca(policy, max_staleness, &[])
    }

    /// Like `discover_with_max_staleness`, but the discovery and JWKS client also trusts
    /// `additional_ca` on top of the built-in WebPKI roots. No other client receives it.
    pub fn discover_with_additional_ca(
        policy: &OidcPolicy,
        max_staleness: Duration,
        additional_ca: &[reqwest::Certificate],
    ) -> Result<Self, OidcVerifyError> {
        policy.validate().map_err(|_| OidcVerifyError::Invalid)?;
        let client = discovery_client(additional_ca)?;
        let mut providers = HashMap::new();
        for configured in &policy.providers {
            let verifier = ProviderVerifier {
                issuer: configured.issuer.clone(),
                audience: configured.audience.clone(),
                client: client.clone(),
                cache: Arc::new(RwLock::new(KeyCache::default())),
                refresh: Arc::new(Mutex::new(RefreshState::default())),
                max_staleness,
                #[cfg(feature = "test-support")]
                key_source: KeySource::Remote,
            };
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
            client,
            cache: Arc::new(RwLock::new(KeyCache {
                keys,
                fetched_at: Utc::now().timestamp(),
            })),
            refresh: Arc::new(Mutex::new(RefreshState::default())),
            max_staleness: Duration::from_secs(DEFAULT_JWKS_MAX_STALENESS_SECONDS),
            key_source: KeySource::Injected,
        };
        Ok(Self {
            providers: Arc::new(HashMap::from([(issuer, provider)])),
        })
    }

    #[cfg(feature = "test-support")]
    #[doc = "Constructs a verifier whose only provider is currently unavailable."]
    pub fn with_unready_test_provider(
        issuer: String,
        audience: String,
    ) -> Result<Self, OidcVerifyError> {
        if !valid_issuer(&issuer) || !bounded_graphic(&audience, 255) {
            return Err(OidcVerifyError::Invalid);
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| OidcVerifyError::Unavailable)?;
        let provider = ProviderVerifier {
            issuer: issuer.clone(),
            audience,
            client,
            cache: Arc::new(RwLock::new(KeyCache::default())),
            refresh: Arc::new(Mutex::new(RefreshState {
                last_soft_attempt: Utc::now().timestamp(),
                last_forced_attempt: Utc::now().timestamp(),
            })),
            max_staleness: Duration::from_secs(DEFAULT_JWKS_MAX_STALENESS_SECONDS),
            key_source: KeySource::Remote,
        };
        Ok(Self {
            providers: Arc::new(HashMap::from([(issuer, provider)])),
        })
    }

    #[cfg(feature = "test-support")]
    #[doc = "Constructs one ready provider and one independently unavailable provider."]
    pub fn with_test_key_and_unready_provider(
        ready_issuer: String,
        ready_audience: String,
        ready_kid: String,
        ready_key: DecodingKey,
        unready_issuer: String,
        unready_audience: String,
    ) -> Result<Self, OidcVerifyError> {
        if ready_issuer == unready_issuer
            || !valid_issuer(&unready_issuer)
            || !bounded_graphic(&unready_audience, 255)
        {
            return Err(OidcVerifyError::Invalid);
        }
        let mut verifiers =
            Self::with_test_key(ready_issuer, ready_audience, ready_kid, ready_key)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| OidcVerifyError::Unavailable)?;
        Arc::make_mut(&mut verifiers.providers).insert(
            unready_issuer.clone(),
            ProviderVerifier {
                issuer: unready_issuer,
                audience: unready_audience,
                client,
                cache: Arc::new(RwLock::new(KeyCache::default())),
                refresh: Arc::new(Mutex::new(RefreshState {
                    last_soft_attempt: Utc::now().timestamp(),
                    last_forced_attempt: Utc::now().timestamp(),
                })),
                max_staleness: Duration::from_secs(DEFAULT_JWKS_MAX_STALENESS_SECONDS),
                key_source: KeySource::Remote,
            },
        );
        Ok(verifiers)
    }

    #[cfg(feature = "test-support")]
    #[doc = "Constructs a provider whose injected key cache is past its hard-staleness bound."]
    pub fn with_stale_test_key(
        issuer: String,
        audience: String,
        kid: String,
        key: DecodingKey,
        max_staleness: Duration,
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
        let fetched_at = Utc::now()
            .timestamp()
            .saturating_sub(i64::try_from(max_staleness.as_secs()).unwrap_or(i64::MAX))
            .saturating_sub(1);
        let provider = ProviderVerifier {
            issuer: issuer.clone(),
            audience,
            client,
            cache: Arc::new(RwLock::new(KeyCache { keys, fetched_at })),
            refresh: Arc::new(Mutex::new(RefreshState::default())),
            max_staleness,
            key_source: KeySource::Injected,
        };
        Ok(Self {
            providers: Arc::new(HashMap::from([(issuer, provider)])),
        })
    }

    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    pub async fn ready_provider_count(&self) -> usize {
        self.provider_readiness()
            .await
            .into_iter()
            .filter(|(_, ready)| *ready)
            .count()
    }

    pub async fn provider_readiness(&self) -> Vec<(String, bool)> {
        let now = Utc::now().timestamp();
        let mut states = Vec::with_capacity(self.providers.len());
        for provider in self.providers.values() {
            let cache = provider.cache.read().await;
            states.push((
                hash_value(&provider.issuer),
                cache_is_usable(&cache, now, provider.max_staleness),
            ));
        }
        states.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        states
    }

    pub async fn run_refresh_loop(self) {
        self.run_refresh_loop_with_interval(Duration::from_secs(JWKS_REFRESH_RETRY_SECONDS as u64))
            .await;
    }

    async fn run_refresh_loop_with_interval(&self, interval: Duration) {
        loop {
            let mut refreshes = tokio::task::JoinSet::new();
            for provider in self.providers.values() {
                let provider = provider.clone();
                refreshes.spawn(async move {
                    (
                        hash_value(&provider.issuer),
                        provider.refresh_soft_if_due().await,
                    )
                });
            }
            while let Some(result) = refreshes.join_next().await {
                if let Ok((issuer_hash, Err(error))) = result {
                    warn!(
                        event = "oidc_provider_refresh_failed",
                        issuer_hash,
                        detail = %error,
                        "generic OIDC provider refresh failed"
                    );
                }
            }
            tokio::time::sleep(interval).await;
        }
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
        let now = Utc::now().timestamp();
        let cache = self.cache.read().await;
        if cache_is_usable(&cache, now, self.max_staleness) {
            if let Some(key) = cache.keys.get(kid) {
                return Ok(key.clone());
            }
        } else if !cache.keys.is_empty() {
            return Err(OidcVerifyError::Unavailable);
        }
        drop(cache);
        self.refresh_for_unknown_kid_if_due().await?;
        let cache = self.cache.read().await;
        if !cache_is_usable(&cache, Utc::now().timestamp(), self.max_staleness) {
            return Err(OidcVerifyError::Unavailable);
        }
        cache.keys.get(kid).cloned().ok_or(OidcVerifyError::Invalid)
    }

    async fn refresh_for_unknown_kid_if_due(&self) -> Result<(), OidcVerifyError> {
        let mut refresh = self.refresh.lock().await;
        let now = Utc::now().timestamp();
        if attempted_recently(refresh.last_forced_attempt, now) {
            return Err(OidcVerifyError::Unavailable);
        }
        refresh.last_forced_attempt = now;
        self.refresh_now().await
    }

    async fn refresh_soft_if_due(&self) -> Result<(), OidcVerifyError> {
        let mut refresh = self.refresh.lock().await;
        let now = Utc::now().timestamp();
        if cache_age_seconds(self.cache.read().await.fetched_at, now) < JWKS_SOFT_REFRESH_SECONDS
            || attempted_recently(refresh.last_soft_attempt, now)
        {
            return Ok(());
        }
        refresh.last_soft_attempt = now;
        let result = self.refresh_now().await;
        if result.is_ok() {
            info!(
                event = "oidc_provider_ready",
                issuer_hash = hash_value(&self.issuer),
                "generic OIDC provider is ready"
            );
        }
        result
    }

    async fn refresh_now(&self) -> Result<(), OidcVerifyError> {
        #[cfg(feature = "test-support")]
        if self.key_source == KeySource::Injected {
            let mut cache = self.cache.write().await;
            if cache.keys.is_empty() {
                return Err(OidcVerifyError::Unavailable);
            }
            cache.fetched_at = Utc::now().timestamp();
            return Ok(());
        }
        let discovery_url = format!("{}/.well-known/openid-configuration", self.issuer);
        let discovery: DiscoveryDocument =
            fetch_json(&self.client, &discovery_url, MAX_DISCOVERY_BYTES).await?;
        if !valid_discovery(&self.issuer, &discovery) {
            return Err(OidcVerifyError::Invalid);
        }
        let document: JwkSet =
            fetch_json(&self.client, &discovery.jwks_uri, MAX_JWKS_BYTES).await?;
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
        *self.cache.write().await = KeyCache {
            keys,
            fetched_at: Utc::now().timestamp(),
        };
        Ok(())
    }
}

fn discovery_client(
    additional_ca: &[reqwest::Certificate],
) -> Result<reqwest::Client, OidcVerifyError> {
    additional_ca
        .iter()
        .cloned()
        .fold(
            reqwest::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5)),
            reqwest::ClientBuilder::add_root_certificate,
        )
        .build()
        .map_err(|_| OidcVerifyError::Unavailable)
}

#[derive(Debug, Error)]
#[error("GENERIC_OIDC_ADDITIONAL_CA_FILE {path} {reason}")]
pub struct AdditionalCaError {
    path: String,
    reason: String,
}

/// Loads the PEM CA certificates that the generic-OIDC discovery and JWKS client trusts in
/// addition to the built-in WebPKI roots. Refuses unreadable files, files without
/// certificates, invalid certificates, and any file that contains a private key.
pub fn load_additional_ca(path: &Path) -> Result<Vec<reqwest::Certificate>, AdditionalCaError> {
    let refuse = |reason: String| AdditionalCaError {
        path: path.display().to_string(),
        reason,
    };
    let pem = std::fs::read(path).map_err(|error| refuse(format!("cannot be read: {error}")))?;
    if pem.windows(16).any(|window| window == b"PRIVATE KEY-----") {
        return Err(refuse(
            "contains a private key; supply public CA certificates only".to_owned(),
        ));
    }
    let certificates = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| refuse(format!("is not valid PEM: {error}")))?;
    if certificates.is_empty() {
        return Err(refuse("contains no PEM certificates".to_owned()));
    }
    let mut roots = rustls::RootCertStore::empty();
    certificates
        .into_iter()
        .map(|certificate| {
            roots
                .add(certificate.clone())
                .map_err(|error| refuse(format!("contains an invalid certificate: {error}")))?;
            reqwest::Certificate::from_der(&certificate)
                .map_err(|error| refuse(format!("contains an invalid certificate: {error}")))
        })
        .collect()
}

fn attempted_recently(last_attempt: i64, now: i64) -> bool {
    last_attempt > 0 && now.saturating_sub(last_attempt) < JWKS_REFRESH_RETRY_SECONDS
}

fn cache_age_seconds(fetched_at: i64, now: i64) -> u64 {
    if fetched_at <= 0 {
        return u64::MAX;
    }
    u64::try_from(now.saturating_sub(fetched_at)).unwrap_or(0)
}

fn cache_is_usable(cache: &KeyCache, now: i64, max_staleness: Duration) -> bool {
    !cache.keys.is_empty() && cache_age_seconds(cache.fetched_at, now) <= max_staleness.as_secs()
}

async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    uri: &str,
    maximum: usize,
) -> Result<T, OidcVerifyError> {
    let mut response = client
        .get(uri)
        .send()
        .await
        .map_err(|_| OidcVerifyError::Unavailable)?
        .error_for_status()
        .map_err(|_| OidcVerifyError::Unavailable)?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(OidcVerifyError::Unavailable);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| OidcVerifyError::Unavailable)?
    {
        if body.len().saturating_add(chunk.len()) > maximum {
            return Err(OidcVerifyError::Unavailable);
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| OidcVerifyError::Unavailable)
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

fn valid_discovery(configured_issuer: &str, discovery: &DiscoveryDocument) -> bool {
    discovery.issuer == configured_issuer
        && valid_issuer_endpoint(&discovery.jwks_uri)
        && same_origin(configured_issuer, &discovery.jwks_uri)
}

fn same_origin(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (reqwest::Url::parse(left), reqwest::Url::parse(right)) else {
        return false;
    };
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
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
                sub: provider_scoped_subject(&claims),
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

fn provider_scoped_subject(claims: &OidcClaims) -> String {
    let mut hasher = Sha256::new();
    write_replay_component(&mut hasher, &claims.issuer);
    write_replay_component(&mut hasher, &claims.subject);
    format!("oidc:{:x}", hasher.finalize())
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use jsonwebtoken::DecodingKey;

    use super::{DiscoveryDocument, OidcVerifierSet, valid_discovery};

    #[test]
    fn discovery_requires_the_exact_issuer_and_same_https_origin() {
        let issuer = "https://ci.example.invalid/oidc";
        assert!(valid_discovery(
            issuer,
            &DiscoveryDocument {
                issuer: issuer.to_owned(),
                jwks_uri: "https://ci.example.invalid/oidc/jwks".to_owned(),
            }
        ));
        for rejected in [
            DiscoveryDocument {
                issuer: "https://foreign.example.invalid/oidc".to_owned(),
                jwks_uri: "https://ci.example.invalid/oidc/jwks".to_owned(),
            },
            DiscoveryDocument {
                issuer: issuer.to_owned(),
                jwks_uri: "http://ci.example.invalid/oidc/jwks".to_owned(),
            },
            DiscoveryDocument {
                issuer: issuer.to_owned(),
                jwks_uri: "https://keys.example.invalid/jwks".to_owned(),
            },
            DiscoveryDocument {
                issuer: issuer.to_owned(),
                jwks_uri: "https://ci.example.invalid:8443/oidc/jwks".to_owned(),
            },
        ] {
            assert!(!valid_discovery(issuer, &rejected));
        }
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn background_loop_refreshes_a_hard_stale_provider_without_an_exchange()
    -> Result<(), Box<dyn std::error::Error>> {
        let verifier = OidcVerifierSet::with_stale_test_key(
            "https://ci.example.invalid/oidc".to_owned(),
            "identity-oidc-exchange".to_owned(),
            "source".to_owned(),
            DecodingKey::from_secret(b"test-only-placeholder"),
            Duration::from_secs(600),
        )?;
        assert_eq!(verifier.ready_provider_count().await, 0);
        let refresh = {
            let verifier = verifier.clone();
            tokio::spawn(async move {
                verifier
                    .run_refresh_loop_with_interval(Duration::from_millis(10))
                    .await;
            })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while verifier.ready_provider_count().await == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        refresh.abort();
        Ok(())
    }
}

#[cfg(test)]
mod additional_ca_tests {
    use std::io::Write;

    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

    use super::load_additional_ca;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn test_ca() -> Result<CertifiedIssuer<'static, KeyPair>, rcgen::Error> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        CertifiedIssuer::self_signed(params, KeyPair::generate()?)
    }

    fn pem_file(contents: &str) -> std::io::Result<tempfile::NamedTempFile> {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(contents.as_bytes())?;
        Ok(file)
    }

    #[test]
    fn additional_ca_bundle_refuses_unreadable_empty_or_private_key_material() -> TestResult {
        let ca = test_ca()?;
        let key = KeyPair::generate()?.serialize_pem();
        let directory = tempfile::tempdir()?;
        let refusal = load_additional_ca(&directory.path().join("missing.pem")).err();
        assert!(refusal.is_some_and(|error| error.to_string().contains("cannot be read")));
        for (contents, reason) in [
            (String::new(), "contains no PEM certificates"),
            (
                "not a certificate\n".to_owned(),
                "contains no PEM certificates",
            ),
            (format!("{}{key}", ca.pem()), "contains a private key"),
            (key.clone(), "contains a private key"),
            (
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_owned(),
                "contains an invalid certificate",
            ),
        ] {
            let refusal = load_additional_ca(pem_file(&contents)?.path()).err();
            assert!(
                refusal
                    .as_ref()
                    .is_some_and(|error| error.to_string().contains(reason)),
                "expected {reason:?}, got {refusal:?}"
            );
        }
        let bundle = format!("{}{}", ca.pem(), test_ca()?.pem());
        assert_eq!(load_additional_ca(pem_file(&bundle)?.path())?.len(), 2);
        Ok(())
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn additional_ca_is_trusted_only_by_generic_oidc_discovery_and_jwks() -> TestResult {
        use std::{sync::Arc, time::Duration};

        use axum::{Json, Router, routing::get};
        use serde_json::json;

        use super::{KeySource, ProviderVerifier, discovery_client};
        use crate::github::{GitHubVerifier, VerifyError};

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = test_ca()?;
        let leaf_key = KeyPair::generate()?;
        let leaf =
            CertificateParams::new(vec!["localhost".to_owned()])?.signed_by(&leaf_key, &ca)?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let origin = format!("https://localhost:{}", listener.local_addr()?.port());
        let discovery = json!({"issuer": origin, "jwks_uri": format!("{origin}/jwks")});
        let jwks = json!({"keys": [
            {"kty": "RSA", "kid": "source", "alg": "RS256", "use": "sig", "n": "AQAB", "e": "AQAB"}
        ]});
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || std::future::ready(Json(discovery.clone()))),
            )
            .route("/jwks", get(move || std::future::ready(Json(jwks.clone()))));
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            leaf.pem().into_bytes(),
            leaf_key.serialize_pem().into_bytes(),
        )
        .await?;
        let server = axum_server::from_tcp_rustls(listener, tls)?;
        let server = tokio::spawn(server.serve(app.into_make_service()));
        let provider = |client| ProviderVerifier {
            issuer: origin.clone(),
            audience: "generic-oidc-exchange".to_owned(),
            client,
            cache: Arc::default(),
            refresh: Arc::default(),
            max_staleness: Duration::from_secs(600),
            key_source: KeySource::Remote,
        };

        // Default trust (built-in WebPKI roots only) refuses the private CA.
        assert!(
            provider(discovery_client(&[])?)
                .refresh_now()
                .await
                .is_err()
        );
        // With the additional CA loaded, discovery and JWKS succeed against the same server.
        let additional_ca = load_additional_ca(pem_file(&ca.pem())?.path())?;
        let trusted = provider(discovery_client(&additional_ca)?);
        trusted.refresh_now().await?;
        assert!(trusted.cache.read().await.keys.contains_key("source"));
        // The GitHub verifier never receives the additional CA and still refuses the server.
        let github = GitHubVerifier::with_test_jwks_url(
            "github-identity-exchange".to_owned(),
            format!("{origin}/jwks"),
        )?;
        assert!(matches!(
            github.warm_up().await,
            Err(VerifyError::KeysUnavailable { detail, .. }) if detail.contains("UnknownIssuer")
        ));
        server.abort();
        Ok(())
    }
}
