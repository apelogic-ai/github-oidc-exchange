use std::{collections::HashMap, sync::Arc, time::Duration};

use chrono::Utc;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm, PublicKeyUse},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::GITHUB_ISSUER;

const JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const MAX_ASSERTION_BYTES: usize = 32 * 1024;

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
    pub repository_id: String,
    pub repository_owner_id: String,
    pub workflow_ref: String,
    pub job_workflow_ref: String,
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
    #[error("GitHub signing keys are unavailable")]
    KeysUnavailable,
}

#[derive(Clone)]
pub struct GitHubVerifier {
    audience: String,
    client: reqwest::Client,
    cache: Arc<RwLock<KeyCache>>,
    jwks_url: String,
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

impl GitHubVerifier {
    pub fn new(audience: String) -> Result<Self, VerifyError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| VerifyError::KeysUnavailable)?;
        Ok(Self {
            audience,
            client,
            cache: Arc::new(RwLock::new(KeyCache::default())),
            jwks_url: JWKS_URL.to_owned(),
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
            || claims.actor_id.is_empty()
            || claims.repository_id.is_empty()
            || claims.repository_owner_id.is_empty()
            || claims.workflow_ref.is_empty()
            || claims.job_workflow_ref.is_empty()
            || claims.event_name.is_empty()
            || claims.git_ref.is_empty()
        {
            return Err(VerifyError::Invalid);
        }
        Ok(claims)
    }

    pub async fn warm_up(&self) -> Result<(), VerifyError> {
        self.refresh().await
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
        let now = Utc::now().timestamp();
        {
            let cache = self.cache.read().await;
            if now - cache.fetched_at < 300
                && let Some(key) = cache.keys.get(kid)
            {
                return Ok(key.clone());
            }
        }
        self.refresh().await?;
        self.cache
            .read()
            .await
            .keys
            .get(kid)
            .cloned()
            .ok_or(VerifyError::Invalid)
    }

    async fn refresh(&self) -> Result<(), VerifyError> {
        #[cfg(feature = "test-support")]
        if self.key_source == KeySource::Injected {
            return if self.cache.read().await.keys.is_empty() {
                Err(VerifyError::KeysUnavailable)
            } else {
                Ok(())
            };
        }
        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|_| VerifyError::KeysUnavailable)?
            .error_for_status()
            .map_err(|_| VerifyError::KeysUnavailable)?;
        let document: JwkSet = response
            .json()
            .await
            .map_err(|_| VerifyError::KeysUnavailable)?;
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
            return Err(VerifyError::KeysUnavailable);
        }
        *self.cache.write().await = KeyCache {
            keys,
            fetched_at: Utc::now().timestamp(),
        };
        Ok(())
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
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
            repository_id: "200001".to_owned(),
            repository_owner_id: "100001".to_owned(),
            workflow_ref: "local-fixture/workflow@refs/heads/main".to_owned(),
            job_workflow_ref: "local-fixture/job@refs/heads/main".to_owned(),
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
