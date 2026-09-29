use std::{
    collections::HashMap,
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
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use tracing::warn;

use crate::GITHUB_ISSUER;

const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const MAX_ASSERTION_BYTES: usize = 32 * 1024;
const JWKS_SOFT_REFRESH_SECONDS: u64 = 300;
const JWKS_REFRESH_RETRY_SECONDS: u64 = 30;
pub const DEFAULT_JWKS_MAX_STALENESS_SECONDS: u64 = 21_600;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GitHubClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Audience,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub jti: String,
    pub actor_id: String,
    pub actor: String,
    pub repository: String,
    pub repository_id: String,
    pub repository_owner_id: String,
    pub sha: String,
    pub run_id: String,
    #[serde(with = "numeric_string")]
    pub run_attempt: u32,
    pub workflow_ref: String,
    pub workflow_sha: String,
    pub job_workflow_ref: String,
    pub job_workflow_sha: String,
    pub event_name: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
    #[default]
    Missing,
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("assertion is invalid")]
    Invalid,
    #[error("GitHub signing keys are unavailable while {stage}: {detail}")]
    KeysUnavailable { stage: &'static str, detail: String },
}

impl VerifyError {
    fn keys_unavailable(stage: &'static str, detail: impl std::fmt::Display) -> Self {
        Self::KeysUnavailable {
            stage,
            detail: detail.to_string(),
        }
    }
}

#[derive(Clone)]
pub struct GitHubVerifier {
    audience: String,
    client: reqwest::Client,
    cache: Arc<RwLock<KeyCache>>,
    refresh: Arc<Mutex<RefreshState>>,
    refresh_failures: Arc<AtomicU64>,
    jwks_url: String,
    max_staleness: Duration,
    #[cfg(feature = "test-support")]
    key_source: KeySource,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeySource {
    Remote,
    #[cfg(feature = "test-support")]
    Injected,
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: i64,
}

#[derive(Default)]
struct RefreshState {
    last_soft_attempt: i64,
    last_forced_attempt: i64,
    last_forced_failed: bool,
}

#[derive(Clone, Copy)]
enum RefreshAttempt {
    Refreshed,
    Skipped,
}

impl GitHubVerifier {
    pub fn new(audience: String) -> Result<Self, VerifyError> {
        Self::new_with_max_staleness(
            audience,
            Duration::from_secs(DEFAULT_JWKS_MAX_STALENESS_SECONDS),
        )
    }

    pub fn new_with_max_staleness(
        audience: String,
        max_staleness: Duration,
    ) -> Result<Self, VerifyError> {
        let client = jwks_client(true)?;
        Ok(Self {
            audience,
            client,
            cache: Arc::new(RwLock::new(KeyCache::default())),
            refresh: Arc::new(Mutex::new(RefreshState::default())),
            refresh_failures: Arc::new(AtomicU64::new(0)),
            jwks_url: JWKS_URL.to_owned(),
            max_staleness,
            #[cfg(feature = "test-support")]
            key_source: KeySource::Remote,
        })
    }

    #[cfg(feature = "test-support")]
    #[doc = "Constructs a verifier with an injected key for contract tests."]
    pub async fn with_test_key(
        audience: String,
        kid: String,
        key: DecodingKey,
    ) -> Result<Self, VerifyError> {
        let mut verifier = Self::new(audience)?;
        verifier.key_source = KeySource::Injected;
        verifier.cache.write().await.keys.insert(kid, key);
        verifier.cache.write().await.fetched_at = Utc::now().timestamp();
        Ok(verifier)
    }

    #[cfg(feature = "test-support")]
    #[doc = "Constructs a verifier with an explicit JWKS URL for failure-path tests."]
    pub fn with_test_jwks_url(audience: String, jwks_url: String) -> Result<Self, VerifyError> {
        let mut verifier = Self::new(audience)?;
        verifier.client = jwks_client(false)?;
        verifier.jwks_url = jwks_url;
        Ok(verifier)
    }

    pub async fn verify(&self, assertion: &str) -> Result<GitHubClaims, VerifyError> {
        if assertion.is_empty() || assertion.len() > MAX_ASSERTION_BYTES {
            return Err(VerifyError::Invalid);
        }
        let header = decode_header(assertion).map_err(|_| VerifyError::Invalid)?;
        if header.alg != Algorithm::RS256 || header.typ.as_deref() != Some("JWT") {
            return Err(VerifyError::Invalid);
        }
        let kid = header.kid.ok_or(VerifyError::Invalid)?;
        let key = self.key(&kid).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[GITHUB_ISSUER]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "iat", "nbf", "jti"]);
        validation.validate_nbf = true;
        validation.leeway = 30;
        let token = decode::<GitHubClaims>(assertion, &key, &validation)
            .map_err(|_| VerifyError::Invalid)?;
        let claims = token.claims;
        let now = Utc::now().timestamp();
        let lifetime = claims
            .exp
            .checked_sub(claims.iat)
            .ok_or(VerifyError::Invalid)?;
        if claims.iss != GITHUB_ISSUER
            || !claims.aud.is_exactly(&self.audience)
            || lifetime <= 0
            || lifetime > 600
            || claims.iat > now + 30
            || claims.nbf > claims.iat
            || claims.sub.is_empty()
            || claims.jti.is_empty()
            || !numeric_identifier(&claims.actor_id)
            || !bounded_ascii(&claims.actor, 128)
            || !github_repository(&claims.repository)
            || !numeric_identifier(&claims.repository_id)
            || !numeric_identifier(&claims.repository_owner_id)
            || !git_sha1(&claims.sha)
            || !numeric_identifier(&claims.run_id)
            || claims.run_attempt == 0
            || !bounded_ascii(&claims.workflow_ref, 2_048)
            || !git_sha1(&claims.workflow_sha)
            || !bounded_ascii(&claims.job_workflow_ref, 2_048)
            || !git_sha1(&claims.job_workflow_sha)
            || !bounded_ascii(&claims.event_name, 255)
            || !valid_git_ref(&claims.git_ref)
            || !provenance_consistent(&claims)
        {
            return Err(VerifyError::Invalid);
        }
        Ok(claims)
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub async fn warm_up(&self) -> Result<(), VerifyError> {
        let _refresh = self.refresh.lock().await;
        let result = self.refresh_now().await;
        if let Err(error) = &result {
            self.record_refresh_failure(error).await;
        }
        result
    }

    pub async fn check_ready(&self) -> Result<(), VerifyError> {
        let now = Utc::now().timestamp();
        let cache = self.cache.read().await;
        if cache_is_usable(&cache, now, self.max_staleness) {
            return Ok(());
        }
        Err(VerifyError::keys_unavailable(
            "checking the cached GitHub JWKS",
            "the last successful refresh is past the configured hard-staleness bound",
        ))
    }

    pub async fn run_refresh_loop(self) {
        self.run_refresh_loop_with_interval(Duration::from_secs(JWKS_REFRESH_RETRY_SECONDS))
            .await;
    }

    pub fn refresh_failures(&self) -> u64 {
        self.refresh_failures.load(Ordering::Relaxed)
    }

    pub async fn cache_age_seconds(&self) -> u64 {
        cache_age_seconds(self.cache.read().await.fetched_at, Utc::now().timestamp())
    }

    async fn key(&self, kid: &str) -> Result<DecodingKey, VerifyError> {
        #[cfg(feature = "test-support")]
        if self.key_source == KeySource::Injected {
            return self
                .cache
                .read()
                .await
                .keys
                .get(kid)
                .cloned()
                .ok_or(VerifyError::Invalid);
        }
        let cached_key_is_hard_stale = {
            let cache = self.cache.read().await;
            if cache_is_usable(&cache, Utc::now().timestamp(), self.max_staleness)
                && let Some(key) = cache.keys.get(kid)
            {
                return Ok(key.clone());
            }
            cache.keys.contains_key(kid)
        };
        if cached_key_is_hard_stale {
            return Err(VerifyError::keys_unavailable(
                "using the cached GitHub JWKS",
                "the cache is past the configured hard-staleness bound",
            ));
        }

        let refresh_result = self.refresh_for_unknown_kid_if_due(kid).await;
        let cache = self.cache.read().await;
        if cache_is_usable(&cache, Utc::now().timestamp(), self.max_staleness) {
            if let Some(key) = cache.keys.get(kid) {
                return Ok(key.clone());
            }
            return match refresh_result {
                Ok(_) => Err(VerifyError::Invalid),
                Err(error) => Err(error),
            };
        }
        Err(refresh_result.err().unwrap_or_else(|| {
            VerifyError::keys_unavailable(
                "using the cached GitHub JWKS",
                "the cache is empty or past the configured hard-staleness bound",
            )
        }))
    }

    async fn refresh_soft_if_due(&self) -> Result<RefreshAttempt, VerifyError> {
        let mut refresh = self.refresh.lock().await;
        let now = Utc::now().timestamp();
        if self.cache_age_seconds().await < JWKS_SOFT_REFRESH_SECONDS
            || attempted_recently(refresh.last_soft_attempt, now)
        {
            return Ok(RefreshAttempt::Skipped);
        }
        refresh.last_soft_attempt = now;
        self.run_refresh().await
    }

    async fn run_refresh_loop_with_interval(&self, interval: Duration) {
        loop {
            tokio::time::sleep(interval).await;
            let _ = self.refresh_soft_if_due().await;
        }
    }

    async fn refresh_for_unknown_kid_if_due(
        &self,
        kid: &str,
    ) -> Result<RefreshAttempt, VerifyError> {
        let mut refresh = self.refresh.lock().await;
        let now = Utc::now().timestamp();
        if self.cache.read().await.keys.contains_key(kid) {
            return Ok(RefreshAttempt::Skipped);
        }
        if attempted_recently(refresh.last_forced_attempt, now) {
            return if refresh.last_forced_failed {
                Err(VerifyError::keys_unavailable(
                    "refreshing the GitHub JWKS for an unknown key ID",
                    "a recent forced refresh failed and retry is rate-limited",
                ))
            } else {
                Ok(RefreshAttempt::Skipped)
            };
        }
        refresh.last_forced_attempt = now;
        let result = self.run_refresh().await;
        refresh.last_forced_failed = result.is_err();
        result
    }

    async fn run_refresh(&self) -> Result<RefreshAttempt, VerifyError> {
        match self.refresh_now().await {
            Ok(()) => Ok(RefreshAttempt::Refreshed),
            Err(error) => {
                self.record_refresh_failure(&error).await;
                Err(error)
            }
        }
    }

    async fn record_refresh_failure(&self, error: &VerifyError) {
        self.refresh_failures.fetch_add(1, Ordering::Relaxed);
        let cache_age_seconds = self.cache_age_seconds().await;
        warn!(
            event = "github_jwks_refresh_failed",
            cache_age_seconds,
            detail = %error,
            "GitHub JWKS refresh failed"
        );
    }

    async fn refresh_now(&self) -> Result<(), VerifyError> {
        #[cfg(feature = "test-support")]
        if self.key_source == KeySource::Injected {
            return if self.cache.read().await.keys.is_empty() {
                Err(VerifyError::keys_unavailable(
                    "reading the injected test key cache",
                    "the cache contains no signing keys",
                ))
            } else {
                Ok(())
            };
        }
        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|error| {
                VerifyError::keys_unavailable(
                    "fetching the GitHub JWKS",
                    error_chain_detail(&error),
                )
            })?
            .error_for_status()
            .map_err(|error| {
                VerifyError::keys_unavailable(
                    "checking the GitHub JWKS HTTP status",
                    error_chain_detail(&error),
                )
            })?;
        let document: JwkSet = response.json().await.map_err(|error| {
            VerifyError::keys_unavailable("decoding the GitHub JWKS", error_chain_detail(&error))
        })?;
        let mut keys = HashMap::new();
        for jwk in document.keys {
            let Some(kid) = jwk.common.key_id.clone() else {
                continue;
            };
            if jwk.common.key_algorithm != Some(KeyAlgorithm::RS256) {
                continue;
            }
            if jwk.common.public_key_use != Some(PublicKeyUse::Signature) {
                continue;
            }
            if let Ok(key) = DecodingKey::from_jwk(&jwk) {
                keys.insert(kid, key);
            }
        }
        if keys.is_empty() {
            return Err(VerifyError::keys_unavailable(
                "validating the GitHub JWKS",
                "the document contains no usable RS256 signing keys",
            ));
        }
        *self.cache.write().await = KeyCache {
            keys,
            fetched_at: Utc::now().timestamp(),
        };
        Ok(())
    }
}

fn jwks_client(https_only: bool) -> Result<reqwest::Client, VerifyError> {
    reqwest::Client::builder()
        .https_only(https_only)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| {
            VerifyError::keys_unavailable(
                "initializing the JWKS HTTP client",
                error_chain_detail(&error),
            )
        })
}

fn attempted_recently(last_attempt: i64, now: i64) -> bool {
    last_attempt > 0 && now.saturating_sub(last_attempt) < JWKS_REFRESH_RETRY_SECONDS as i64
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

fn error_chain_detail(error: &(dyn std::error::Error + 'static)) -> String {
    const MAX_CAUSES: usize = 8;

    let mut detail = error.to_string();
    let mut cause = error.source();
    for _ in 0..MAX_CAUSES {
        let Some(current) = cause else {
            break;
        };
        let current_detail = current.to_string();
        if !current_detail.is_empty() && !detail.ends_with(&current_detail) {
            detail.push_str(": ");
            detail.push_str(&current_detail);
        }
        cause = current.source();
    }
    detail
}

fn numeric_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|character| character.is_ascii_digit())
        && value != "0"
        && !value.starts_with('0')
}

mod numeric_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || value.len() > 10
            || !value.bytes().all(|character| character.is_ascii_digit())
            || value.len() > 1 && value.starts_with('0')
        {
            return Err(serde::de::Error::custom(
                "numeric claim must use canonical u32 decimal notation",
            ));
        }
        value.parse().map_err(serde::de::Error::custom)
    }
}

fn bounded_ascii(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn github_repository(value: &str) -> bool {
    let mut components = value.split('/');
    let owner = components.next().unwrap_or_default();
    let repository = components.next().unwrap_or_default();
    components.next().is_none()
        && github_slug(owner)
        && github_slug(repository)
        && repository != "."
        && repository != ".."
}

fn github_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value != "."
        && value != ".."
        && value.bytes().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_' | b'.')
        })
}

fn git_sha1(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|character| character.is_ascii_digit() || (b'a'..=b'f').contains(&character))
}

fn provenance_consistent(claims: &GitHubClaims) -> bool {
    let Some((owner, repository)) = claims.repository.split_once('/') else {
        return false;
    };
    let standard_prefix = format!("repo:{}:", claims.repository);
    let numeric_prefix = format!(
        "repo:{owner}@{}/{repository}@{}:",
        claims.repository_owner_id, claims.repository_id
    );
    let suffix = claims
        .sub
        .strip_prefix(&standard_prefix)
        .or_else(|| claims.sub.strip_prefix(&numeric_prefix));
    let Some(suffix) = suffix.filter(|suffix| bounded_ascii(suffix, 1_024)) else {
        return false;
    };
    let subject_matches_ref = suffix
        .strip_prefix("ref:")
        .is_none_or(|subject_ref| subject_ref == claims.git_ref);
    let pull_request_matches_ref = suffix != "pull_request"
        || claims.git_ref.starts_with("refs/pull/") && claims.git_ref.ends_with("/merge");
    subject_matches_ref
        && pull_request_matches_ref
        && workflow_reference(
            &claims.workflow_ref,
            Some(&claims.repository),
            &claims.workflow_sha,
        )
        && workflow_reference(&claims.job_workflow_ref, None, &claims.job_workflow_sha)
}

fn workflow_reference(value: &str, expected_repository: Option<&str>, resolved_sha: &str) -> bool {
    if !bounded_ascii(value, 2_048) {
        return false;
    }
    let Some((repository, workflow_and_ref)) = value.split_once("/.github/workflows/") else {
        return false;
    };
    if !github_repository(repository)
        || expected_repository.is_some_and(|expected| expected != repository)
    {
        return false;
    }
    let Some((workflow, git_ref)) = workflow_and_ref.rsplit_once('@') else {
        return false;
    };
    !workflow.is_empty()
        && workflow.len() <= 255
        && (workflow.ends_with(".yml") || workflow.ends_with(".yaml"))
        && workflow
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && (valid_git_ref(git_ref) || git_sha1(git_ref) && git_ref == resolved_sha)
}

fn valid_git_ref(value: &str) -> bool {
    bounded_ascii(value, 2_048)
        && ["refs/heads/", "refs/tags/", "refs/pull/"]
            .iter()
            .any(|prefix| {
                value
                    .strip_prefix(prefix)
                    .is_some_and(|rest| !rest.is_empty())
            })
        && !value.ends_with('/')
        && !value.ends_with('.')
        && !value.contains("..")
        && !value.contains("@{")
        && !value.contains("//")
        && !value.contains('\\')
        && !value
            .bytes()
            .any(|byte| matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'['))
        && value
            .split('/')
            .all(|component| !component.starts_with('.') && !component.ends_with(".lock"))
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use axum::{Json, Router, routing::get};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rand::thread_rng;
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};

    use super::*;

    #[tokio::test]
    async fn injected_test_key_does_not_expire_into_production_jwks_refresh()
    -> Result<(), Box<dyn std::error::Error>> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let private = RsaPrivateKey::new(&mut thread_rng(), 2048)?;
        let document = private.to_pkcs1_der()?;
        let encoding = EncodingKey::from_rsa_der(document.as_bytes());
        let decoding = DecodingKey::from_rsa_components(
            &URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
            &URL_SAFE_NO_PAD.encode(private.e().to_bytes_be()),
        )?;
        let verifier = GitHubVerifier::with_test_key(
            "local-steward-run".to_owned(),
            "local-source-a".to_owned(),
            decoding,
        )
        .await?;
        verifier.cache.write().await.fetched_at = Utc::now().timestamp() - 301;

        let now = Utc::now().timestamp();
        let claims = GitHubClaims {
            iss: GITHUB_ISSUER.to_owned(),
            sub: "repo:local-fixture/steward-run:ref:refs/heads/main".to_owned(),
            aud: Audience::One("local-steward-run".to_owned()),
            exp: now + 300,
            iat: now,
            nbf: now - 5,
            jti: "fresh-after-cold-build".to_owned(),
            actor_id: "300001".to_owned(),
            actor: "alice".to_owned(),
            repository: "local-fixture/steward-run".to_owned(),
            repository_id: "200001".to_owned(),
            repository_owner_id: "100001".to_owned(),
            sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            run_id: "400001".to_owned(),
            run_attempt: 1,
            workflow_ref:
                "local-fixture/steward-run/.github/workflows/workflow.yml@refs/heads/main"
                    .to_owned(),
            workflow_sha: "123456789abcdef0123456789abcdef012345678".to_owned(),
            job_workflow_ref: "local-fixture/steward-run/.github/workflows/job.yml@refs/heads/main"
                .to_owned(),
            job_workflow_sha: "23456789abcdef0123456789abcdef0123456789".to_owned(),
            event_name: "workflow_dispatch".to_owned(),
            git_ref: "refs/heads/main".to_owned(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("local-source-a".to_owned());
        header.typ = Some("JWT".to_owned());
        let assertion = encode(&header, &claims, &encoding)?;

        verifier.warm_up().await?;
        assert!(verifier.verify(&assertion).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn cached_key_does_not_wait_for_a_failed_background_refresh_until_hard_staleness()
    -> Result<(), Box<dyn std::error::Error>> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (assertion, decoding) = signed_test_assertion("cached-source")?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let unavailable_address = listener.local_addr()?;
        drop(listener);
        let mut verifier = GitHubVerifier::new_with_max_staleness(
            "local-steward-run".to_owned(),
            Duration::from_secs(600),
        )?;
        verifier.jwks_url = format!("https://{unavailable_address}/.well-known/jwks");
        {
            let mut cache = verifier.cache.write().await;
            cache.keys.insert("cached-source".to_owned(), decoding);
            cache.fetched_at = Utc::now().timestamp() - 301;
        }

        assert!(verifier.check_ready().await.is_ok());
        assert_eq!(verifier.refresh_failures(), 0);
        assert!(verifier.verify(&assertion).await.is_ok());
        assert_eq!(verifier.refresh_failures(), 0);

        let refresh_verifier = verifier.clone();
        let refresh_task = tokio::spawn(async move {
            refresh_verifier
                .run_refresh_loop_with_interval(Duration::from_millis(10))
                .await;
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while verifier.refresh_failures() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        refresh_task.abort();

        assert!(verifier.check_ready().await.is_ok());
        assert!(verifier.verify(&assertion).await.is_ok());
        assert_eq!(verifier.refresh_failures(), 1);

        verifier.cache.write().await.fetched_at = Utc::now().timestamp() - 601;
        assert!(verifier.check_ready().await.is_err());
        assert!(matches!(
            verifier.verify(&assertion).await,
            Err(VerifyError::KeysUnavailable { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn unknown_kid_forces_only_one_refresh_inside_retry_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (assertion, decoding) = signed_test_assertion("unknown-source")?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let unavailable_address = listener.local_addr()?;
        drop(listener);
        let mut verifier = GitHubVerifier::new_with_max_staleness(
            "local-steward-run".to_owned(),
            Duration::from_secs(600),
        )?;
        verifier.jwks_url = format!("https://{unavailable_address}/.well-known/jwks");
        {
            let mut cache = verifier.cache.write().await;
            cache.keys.insert("cached-source".to_owned(), decoding);
            cache.fetched_at = Utc::now().timestamp();
        }

        assert!(matches!(
            verifier.verify(&assertion).await,
            Err(VerifyError::KeysUnavailable { .. })
        ));
        assert_eq!(verifier.refresh_failures(), 1);
        assert!(matches!(
            verifier.verify(&assertion).await,
            Err(VerifyError::KeysUnavailable { .. })
        ));
        assert_eq!(verifier.refresh_failures(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn background_refresh_recovers_a_hard_stale_cache_without_an_exchange()
    -> Result<(), Box<dyn std::error::Error>> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let private = RsaPrivateKey::new(&mut thread_rng(), 2048)?;
        let modulus = URL_SAFE_NO_PAD.encode(private.n().to_bytes_be());
        let exponent = URL_SAFE_NO_PAD.encode(private.e().to_bytes_be());
        let decoding = DecodingKey::from_rsa_components(&modulus, &exponent)?;
        let document = Arc::new(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "background-source",
                "n": modulus,
                "e": exponent
            }]
        }));
        let requests = Arc::new(AtomicU64::new(0));
        let app = Router::new().route(
            "/.well-known/jwks",
            get({
                let document = document.clone();
                let requests = requests.clone();
                move || {
                    let document = document.clone();
                    let requests = requests.clone();
                    async move {
                        requests.fetch_add(1, Ordering::Relaxed);
                        Json((*document).clone())
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let verifier = GitHubVerifier::with_test_jwks_url(
            "local-steward-run".to_owned(),
            format!("http://{address}/.well-known/jwks"),
        )?;
        {
            let mut cache = verifier.cache.write().await;
            cache.keys.insert("background-source".to_owned(), decoding);
            cache.fetched_at =
                Utc::now().timestamp() - i64::try_from(DEFAULT_JWKS_MAX_STALENESS_SECONDS)? - 1;
        }
        assert!(verifier.check_ready().await.is_err());

        let refresh_verifier = verifier.clone();
        let refresh_task = tokio::spawn(async move {
            refresh_verifier
                .run_refresh_loop_with_interval(Duration::from_millis(10))
                .await;
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while verifier.check_ready().await.is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;

        assert!(requests.load(Ordering::Relaxed) >= 1);
        assert_eq!(verifier.refresh_failures(), 0);
        refresh_task.abort();
        server.abort();
        Ok(())
    }

    fn signed_test_assertion(
        kid: &str,
    ) -> Result<(String, DecodingKey), Box<dyn std::error::Error>> {
        let private = RsaPrivateKey::new(&mut thread_rng(), 2048)?;
        let document = private.to_pkcs1_der()?;
        let encoding = EncodingKey::from_rsa_der(document.as_bytes());
        let decoding = DecodingKey::from_rsa_components(
            &URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
            &URL_SAFE_NO_PAD.encode(private.e().to_bytes_be()),
        )?;
        let now = Utc::now().timestamp();
        let claims = GitHubClaims {
            iss: GITHUB_ISSUER.to_owned(),
            sub: "repo:local-fixture/steward-run:ref:refs/heads/main".to_owned(),
            aud: Audience::One("local-steward-run".to_owned()),
            exp: now + 300,
            iat: now,
            nbf: now - 5,
            jti: "cached-key-fallback".to_owned(),
            actor_id: "300001".to_owned(),
            actor: "alice".to_owned(),
            repository: "local-fixture/steward-run".to_owned(),
            repository_id: "200001".to_owned(),
            repository_owner_id: "100001".to_owned(),
            sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            run_id: "400001".to_owned(),
            run_attempt: 1,
            workflow_ref:
                "local-fixture/steward-run/.github/workflows/workflow.yml@refs/heads/main"
                    .to_owned(),
            workflow_sha: "123456789abcdef0123456789abcdef012345678".to_owned(),
            job_workflow_ref: "local-fixture/steward-run/.github/workflows/job.yml@refs/heads/main"
                .to_owned(),
            job_workflow_sha: "23456789abcdef0123456789abcdef0123456789".to_owned(),
            event_name: "workflow_dispatch".to_owned(),
            git_ref: "refs/heads/main".to_owned(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_owned());
        header.typ = Some("JWT".to_owned());
        Ok((encode(&header, &claims, &encoding)?, decoding))
    }
}

impl Audience {
    fn is_exactly(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.len() == 1 && values[0] == expected,
            Self::Missing => false,
        }
    }
}
