use std::{
    collections::{BTreeMap, HashSet},
    fs,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration as ChronoDuration, Utc};
use github_oidc_exchange::{
    IDENTITY_CONTRACT, KEYRING_VERSION,
    http::oidc_router,
    keys::KeyRing,
    oidc::{
        OIDC_POLICY_VERSION, OidcBinding, OidcExchangeError, OidcExchangeService, OidcMetrics,
        OidcPolicy, OidcProviderPolicy, OidcVerifierSet,
    },
    replay::{ReplayError, ReplayLedger},
    workload::WorkloadTaskBinding,
};
use http_body_util::BodyExt;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, get_current_timestamp,
    jwk::JwkSet,
};
use rand::thread_rng;
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tower::ServiceExt;

const SOURCE_ISSUER: &str = "https://ci.example.invalid/oidc";
const SOURCE_AUDIENCE: &str = "identity-oidc-exchange";
const SOURCE_SUBJECT: &str = "https://ci.example.invalid/job/release/";

#[derive(Clone, Default)]
struct TestReplayLedger(Arc<Mutex<HashSet<String>>>);

impl ReplayLedger for TestReplayLedger {
    async fn use_once(&self, jti: &str, _expires_at: i64) -> Result<(), ReplayError> {
        let mut seen = self.0.lock().map_err(|_| ReplayError::Unavailable)?;
        if seen.insert(jti.to_owned()) {
            Ok(())
        } else {
            Err(ReplayError::Replayed)
        }
    }

    async fn check_ready(&self) -> Result<(), ReplayError> {
        Ok(())
    }
}

fn policy() -> OidcPolicy {
    OidcPolicy {
        version: OIDC_POLICY_VERSION.to_owned(),
        providers: vec![OidcProviderPolicy {
            issuer: SOURCE_ISSUER.to_owned(),
            audience: SOURCE_AUDIENCE.to_owned(),
            bindings: vec![OidcBinding {
                claims: BTreeMap::from([("sub".to_owned(), SOURCE_SUBJECT.to_owned())]),
                task: WorkloadTaskBinding {
                    service: "automation-worker".to_owned(),
                    owner_canonical_user_id: "usr_0123456789abcdef0123456789abcdef".to_owned(),
                    owner_email: "owner@example.invalid".to_owned(),
                },
            }],
        }],
    }
}

struct SourceKey {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

fn source_key() -> Result<SourceKey, Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let private = RsaPrivateKey::new(&mut thread_rng(), 2048)?;
    let document = private.to_pkcs1_der()?;
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private.e().to_bytes_be());
    Ok(SourceKey {
        encoding: EncodingKey::from_rsa_der(document.as_bytes()),
        decoding: DecodingKey::from_rsa_components(&n, &e)?,
    })
}

struct SourceAssertion<'a> {
    issuer: &'a str,
    subject: &'a str,
    audience: &'a str,
    issued_at: i64,
    expires_at: i64,
    jti: Option<&'a str>,
    build_number: Option<u64>,
}

fn assertion(
    key: &EncodingKey,
    source: SourceAssertion<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut claims = json!({
        "iss": source.issuer,
        "sub": source.subject,
        "aud": source.audience,
        "iat": source.issued_at,
        "exp": source.expires_at,
        "service": "request-selected-service",
        "owner_email": "attacker@example.invalid",
        "groups": ["agents.apelogic.ai/acting-user:attacker@example.invalid"]
    });
    if let Some(jti) = source.jti {
        claims["jti"] = Value::String(jti.to_owned());
    }
    if let Some(build_number) = source.build_number {
        claims["build_number"] = Value::from(build_number);
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("source".to_owned());
    Ok(encode(&header, &claims, key)?)
}

fn keyring() -> Result<KeyRing, Box<dyn std::error::Error>> {
    let now = Utc::now();
    let file = NamedTempFile::new()?;
    let content = json!({
        "version": KEYRING_VERSION,
        "current_kid": "current",
        "keys": [{
            "kid": "current",
            "seed": STANDARD.encode([9_u8; 32]),
            "not_before": (now - ChronoDuration::hours(1)).to_rfc3339(),
            "not_after": (now + ChronoDuration::days(2)).to_rfc3339()
        }]
    });
    fs::write(file.path(), serde_json::to_vec(&content)?)?;
    Ok(KeyRing::load(file.path(), now)?)
}

fn service(
    source_key: DecodingKey,
) -> Result<OidcExchangeService<TestReplayLedger>, Box<dyn std::error::Error>> {
    let policy = policy();
    policy.validate()?;
    Ok(OidcExchangeService {
        verifier: OidcVerifierSet::with_test_key(
            SOURCE_ISSUER.to_owned(),
            SOURCE_AUDIENCE.to_owned(),
            "source".to_owned(),
            source_key,
        )?,
        policy: Arc::new(policy),
        ledger: Arc::new(TestReplayLedger::default()),
        keys: Arc::new(keyring()?),
        issuer: "https://identity.example.invalid".to_owned(),
        output_audience: "steward-task-api".to_owned(),
        token_ttl: Duration::from_secs(120),
        metrics: Arc::new(OidcMetrics::default()),
    })
}

#[test]
fn oidc_policy_requires_exact_non_overlapping_admin_bindings()
-> Result<(), Box<dyn std::error::Error>> {
    policy().validate()?;

    let mut missing_subject = policy();
    missing_subject.providers[0].bindings[0].claims.clear();
    assert!(missing_subject.validate().is_err());

    let mut duplicate_issuer = policy();
    duplicate_issuer
        .providers
        .push(duplicate_issuer.providers[0].clone());
    assert!(duplicate_issuer.validate().is_err());

    let mut request_selected_identity = policy();
    request_selected_identity.providers[0].bindings[0]
        .claims
        .insert("aud".to_owned(), SOURCE_AUDIENCE.to_owned());
    assert!(request_selected_identity.validate().is_err());

    let unknown: Result<OidcPolicy, _> = serde_json::from_value(json!({
        "version": OIDC_POLICY_VERSION,
        "providers": [],
        "api_key": "forbidden"
    }));
    assert!(unknown.is_err());
    Ok(())
}

#[tokio::test]
async fn jenkins_profile_uses_a_single_use_composite_and_matches_the_steward_reader()
-> Result<(), Box<dyn std::error::Error>> {
    let source_key = source_key()?;
    let service = service(source_key.decoding)?;
    let now = get_current_timestamp() as i64;
    let source = assertion(
        &source_key.encoding,
        SourceAssertion {
            issuer: SOURCE_ISSUER,
            subject: SOURCE_SUBJECT,
            audience: SOURCE_AUDIENCE,
            issued_at: now,
            expires_at: now + 300,
            jti: None,
            build_number: Some(42),
        },
    )?;
    let output = service.exchange(&source).await?;
    let header = jsonwebtoken::decode_header(&output)?;
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.kid.as_deref(), Some("current"));
    let jwks: JwkSet = serde_json::from_value(serde_json::to_value(service.keys.jwks())?)?;
    let output_key = DecodingKey::from_jwk(
        jwks.keys
            .iter()
            .find(|key| key.common.key_id.as_deref() == header.kid.as_deref())
            .ok_or("missing selected task key")?,
    )?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&["https://identity.example.invalid"]);
    validation.set_audience(&["steward-task-api"]);
    let claims = decode::<Value>(&output, &output_key, &validation)?.claims;

    // Reader contract copied from Steward crates/steward-apiserver/src/tasks.rs.
    assert_eq!(claims["sub"], SOURCE_SUBJECT);
    assert_eq!(claims["identity_contract"], IDENTITY_CONTRACT);
    assert_eq!(claims["email"], "owner@example.invalid");
    assert_eq!(claims["email_verified"], true);
    assert_eq!(
        claims["groups"],
        json!([
            "agents.apelogic.ai/service-principal:automation-worker",
            "agents.apelogic.ai/canonical-user:usr_0123456789abcdef0123456789abcdef",
            "agents.apelogic.ai/task-owner:owner@example.invalid"
        ])
    );
    assert!(claims.get("source_provenance").is_none());
    assert!(claims.get("actor_login").is_none());
    assert!(
        claims["groups"]
            .as_array()
            .ok_or("groups must be an array")?
            .iter()
            .all(|group| !group.as_str().unwrap_or_default().contains("/acting-user:"))
    );
    assert_eq!(
        service.exchange(&source).await,
        Err(OidcExchangeError::Unauthorized),
        "the Jenkins-compatible composite replay identity must be single-use"
    );
    Ok(())
}

#[tokio::test]
async fn generic_oidc_refuses_unknown_unbound_expired_wrong_audience_and_replayed_jti()
-> Result<(), Box<dyn std::error::Error>> {
    let now = get_current_timestamp() as i64;
    for (issuer, subject, audience, expires_at) in [
        (
            "https://unknown.example.invalid/oidc",
            SOURCE_SUBJECT,
            SOURCE_AUDIENCE,
            now + 300,
        ),
        (
            SOURCE_ISSUER,
            "https://ci.example.invalid/job/unbound/",
            SOURCE_AUDIENCE,
            now + 300,
        ),
        (SOURCE_ISSUER, SOURCE_SUBJECT, SOURCE_AUDIENCE, now - 1),
        (SOURCE_ISSUER, SOURCE_SUBJECT, "wrong-audience", now + 300),
    ] {
        let source_key = source_key()?;
        let source = assertion(
            &source_key.encoding,
            SourceAssertion {
                issuer,
                subject,
                audience,
                issued_at: now,
                expires_at,
                jti: Some("refusal-jti"),
                build_number: None,
            },
        )?;
        assert_eq!(
            service(source_key.decoding)?.exchange(&source).await,
            Err(OidcExchangeError::Unauthorized)
        );
    }

    let source_key = source_key()?;
    let replay_service = service(source_key.decoding)?;
    let source = assertion(
        &source_key.encoding,
        SourceAssertion {
            issuer: SOURCE_ISSUER,
            subject: SOURCE_SUBJECT,
            audience: SOURCE_AUDIENCE,
            issued_at: now,
            expires_at: now + 300,
            jti: Some("single-use-jti"),
            build_number: None,
        },
    )?;
    replay_service.exchange(&source).await?;
    assert_eq!(
        replay_service.exchange(&source).await,
        Err(OidcExchangeError::Unauthorized)
    );
    Ok(())
}

#[tokio::test]
async fn jenkins_fallback_requires_build_number_and_a_short_lifetime()
-> Result<(), Box<dyn std::error::Error>> {
    let now = get_current_timestamp() as i64;
    for (build_number, expires_at) in [(None, now + 300), (Some(7), now + 601)] {
        let source_key = source_key()?;
        let source = assertion(
            &source_key.encoding,
            SourceAssertion {
                issuer: SOURCE_ISSUER,
                subject: SOURCE_SUBJECT,
                audience: SOURCE_AUDIENCE,
                issued_at: now,
                expires_at,
                jti: None,
                build_number,
            },
        )?;
        assert_eq!(
            service(source_key.decoding)?.exchange(&source).await,
            Err(OidcExchangeError::Unauthorized)
        );
    }
    Ok(())
}

#[tokio::test]
async fn oidc_route_is_explicit_and_uses_the_existing_token_response_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let source_key = source_key()?;
    let now = get_current_timestamp() as i64;
    let source = assertion(
        &source_key.encoding,
        SourceAssertion {
            issuer: SOURCE_ISSUER,
            subject: SOURCE_SUBJECT,
            audience: SOURCE_AUDIENCE,
            issued_at: now,
            expires_at: now + 300,
            jti: None,
            build_number: Some(9),
        },
    )?;
    let app = oidc_router(service(source_key.decoding)?);
    let missing = app
        .clone()
        .oneshot(Request::post("/v1/oidc/exchange").body(Body::empty())?)
        .await?;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(
            Request::post("/v1/oidc/exchange")
                .header(header::AUTHORIZATION, format!("Bearer {source}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    let body = response.into_body().collect().await?.to_bytes();
    let document: Value = serde_json::from_slice(&body)?;
    assert!(document["access_token"].as_str().is_some());
    assert_eq!(document["token_type"], "Bearer");
    assert_eq!(document["expires_in"], 120);
    Ok(())
}
