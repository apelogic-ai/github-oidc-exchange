use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration as ChronoDuration, Utc};
use github_oidc_exchange::{
    GITHUB_ISSUER, IDENTITY_CONTRACT, KEYRING_VERSION, POLICY_VERSION,
    github::GitHubVerifier,
    http::router_with_oidc,
    keys::KeyRing,
    oidc::{
        OIDC_POLICY_VERSION, OidcBinding, OidcExchangeService, OidcMetrics, OidcPolicy,
        OidcProviderPolicy, OidcVerifierSet,
    },
    policy::{Actor, Policy, RepositoryPolicy},
    replay::{ReplayError, ReplayLedger},
    service::{ExchangeService, Metrics},
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
const GITHUB_AUDIENCE: &str = "github-test-audience";
const GITHUB_SUBJECT: &str = "repo:example-org@1/example-repo@2:ref:refs/heads/main";
const GITHUB_WORKFLOW: &str =
    "example-org/example-repo/.github/workflows/release.yml@refs/heads/main";
const GITHUB_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

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

#[derive(Clone, Copy)]
struct SourceAssertion<'a> {
    issuer: &'a str,
    subject: &'a str,
    audience: &'a str,
    issued_at: i64,
    expires_at: i64,
    jti: Option<&'a str>,
    build_number: Option<u64>,
    nbf: Option<i64>,
    extra_audience: Option<&'a str>,
    branch: Option<&'a str>,
}

fn assertion(
    key: &EncodingKey,
    source: SourceAssertion<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    assertion_with_kid(key, source, "source")
}

fn assertion_with_kid(
    key: &EncodingKey,
    source: SourceAssertion<'_>,
    kid: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let claims = source_claims(source);
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    Ok(encode(&header, &claims, key)?)
}

fn source_claims(source: SourceAssertion<'_>) -> Value {
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
    if let Some(nbf) = source.nbf {
        claims["nbf"] = Value::from(nbf);
    }
    if let Some(extra) = source.extra_audience {
        claims["aud"] = json!([source.audience, extra]);
    }
    if let Some(branch) = source.branch {
        claims["branch"] = Value::String(branch.to_owned());
    }
    claims
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

fn github_policy() -> Policy {
    Policy {
        version: POLICY_VERSION.to_owned(),
        service_group: "agents.apelogic.ai/service-principal:steward-run".to_owned(),
        acting_group_prefix: Some("agents.apelogic.ai/acting-user:".to_owned()),
        allowed_email_domains: Some(vec!["example.invalid".to_owned()]),
        repositories: vec![RepositoryPolicy {
            owner_id: "1".to_owned(),
            repository_id: "2".to_owned(),
            subjects: Some(vec![GITHUB_SUBJECT.to_owned()]),
            events: Some(vec!["workflow_dispatch".to_owned()]),
            refs: Some(vec!["refs/heads/main".to_owned()]),
            job_workflow_refs: None,
            job_workflow_shas: None,
        }],
        actors: Some(HashMap::from([(
            "3".to_owned(),
            Actor {
                email: "operator@example.invalid".to_owned(),
                canonical_user_id: "usr_abcdef0123456789abcdef0123456789".to_owned(),
                verified: true,
            },
        )])),
    }
}

async fn application(
    oidc: OidcExchangeService<TestReplayLedger>,
) -> Result<Router, Box<dyn std::error::Error>> {
    let github_key = source_key()?;
    application_with_github_key(oidc, github_key.decoding).await
}

async fn application_with_github_key(
    oidc: OidcExchangeService<TestReplayLedger>,
    github_key: DecodingKey,
) -> Result<Router, Box<dyn std::error::Error>> {
    let github = ExchangeService {
        verifier: GitHubVerifier::with_test_key(
            GITHUB_AUDIENCE.to_owned(),
            "github".to_owned(),
            github_key,
        )
        .await?,
        policy: Arc::new(github_policy()),
        ledger: oidc.ledger.clone(),
        keys: oidc.keys.clone(),
        issuer: oidc.issuer.clone(),
        output_audience: oidc.output_audience.clone(),
        token_ttl: oidc.token_ttl,
        metrics: Arc::new(Metrics::default()),
    };
    Ok(router_with_oidc(github, oidc))
}

fn github_assertion(key: &EncodingKey, jti: &str) -> Result<String, Box<dyn std::error::Error>> {
    let now = get_current_timestamp() as i64;
    let claims = json!({
        "iss": GITHUB_ISSUER,
        "sub": GITHUB_SUBJECT,
        "aud": GITHUB_AUDIENCE,
        "exp": now + 300,
        "iat": now,
        "nbf": now - 5,
        "jti": jti,
        "actor_id": "3",
        "actor": "operator",
        "repository": "example-org/example-repo",
        "repository_id": "2",
        "repository_owner_id": "1",
        "sha": GITHUB_SHA,
        "run_id": "4",
        "run_attempt": "1",
        "workflow_ref": GITHUB_WORKFLOW,
        "workflow_sha": GITHUB_SHA,
        "job_workflow_ref": GITHUB_WORKFLOW,
        "job_workflow_sha": GITHUB_SHA,
        "event_name": "workflow_dispatch",
        "ref": "refs/heads/main"
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("github".to_owned());
    Ok(encode(&header, &claims, key)?)
}

async fn oidc_status(
    application: &Router,
    assertion: &str,
) -> Result<StatusCode, Box<dyn std::error::Error>> {
    Ok(application
        .clone()
        .oneshot(
            Request::post("/v1/oidc/exchange")
                .header(header::AUTHORIZATION, format!("Bearer {assertion}"))
                .body(Body::empty())?,
        )
        .await?
        .status())
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

    let mut overlapping = policy();
    let mut narrower = overlapping.providers[0].bindings[0].clone();
    narrower
        .claims
        .insert("branch".to_owned(), "main".to_owned());
    overlapping.providers[0].bindings.push(narrower);
    assert!(
        overlapping.validate().is_err(),
        "a sub-only binding overlaps a binding that merely adds another exact claim"
    );

    let mut disjoint = policy();
    disjoint.providers[0].bindings[0]
        .claims
        .insert("branch".to_owned(), "main".to_owned());
    let mut release = disjoint.providers[0].bindings[0].clone();
    release
        .claims
        .insert("branch".to_owned(), "release".to_owned());
    disjoint.providers[0].bindings.push(release);
    disjoint.validate()?;

    let unknown: Result<OidcPolicy, _> = serde_json::from_value(json!({
        "version": OIDC_POLICY_VERSION,
        "providers": [],
        "api_key": "forbidden"
    }));
    assert!(unknown.is_err());
    Ok(())
}

#[test]
fn oidc_policy_file_loads_strict_versioned_bindings() -> Result<(), Box<dyn std::error::Error>> {
    let file = NamedTempFile::new()?;
    fs::write(
        file.path(),
        serde_json::to_vec(&json!({
            "version": OIDC_POLICY_VERSION,
            "providers": [{
                "issuer": SOURCE_ISSUER,
                "audience": SOURCE_AUDIENCE,
                "bindings": [{
                    "claims": {"sub": SOURCE_SUBJECT},
                    "task": {
                        "service": "automation-worker",
                        "owner_canonical_user_id": "usr_0123456789abcdef0123456789abcdef",
                        "owner_email": "owner@example.invalid"
                    }
                }]
            }]
        }))?,
    )?;
    assert_eq!(OidcPolicy::load(file.path())?, policy());

    fs::write(
        file.path(),
        serde_json::to_vec(&json!({
            "version": OIDC_POLICY_VERSION,
            "providers": [],
            "unexpected": true
        }))?,
    )?;
    assert!(OidcPolicy::load(file.path()).is_err());
    Ok(())
}

#[test]
fn documented_oidc_policy_matches_schema_and_runtime() -> Result<(), Box<dyn std::error::Error>> {
    let schema: Value =
        serde_json::from_slice(&fs::read("docs/oidc-policy-contract.schema.json")?)?;
    let example: Value =
        serde_json::from_slice(&fs::read("docs/oidc-policy-contract.example.json")?)?;
    let validator = jsonschema::validator_for(&schema)?;
    assert!(validator.is_valid(&example));
    let policy: OidcPolicy = serde_json::from_value(example.clone())?;
    policy.validate()?;
    for invalid_issuer in [
        "https://ci.example.invalid/oidc/",
        "https://user@ci.example.invalid/oidc",
        "https://ci.example.invalid:8443/oidc",
    ] {
        let mut candidate: Value =
            serde_json::from_slice(&fs::read("docs/oidc-policy-contract.example.json")?)?;
        candidate["providers"][0]["issuer"] = Value::String(invalid_issuer.to_owned());
        assert!(!validator.is_valid(&candidate));
        let runtime: OidcPolicy = serde_json::from_value(candidate)?;
        assert!(runtime.validate().is_err());
    }
    let mut duplicate = example.clone();
    let repeated = duplicate["providers"][0].clone();
    duplicate["providers"]
        .as_array_mut()
        .ok_or("providers must be an array")?
        .push(repeated);
    assert!(!validator.is_valid(&duplicate));
    let duplicate: OidcPolicy = serde_json::from_value(duplicate)?;
    assert!(duplicate.validate().is_err());

    let mut invalid_claim_name = example;
    let claims = invalid_claim_name["providers"][0]["bindings"][0]["claims"]
        .as_object_mut()
        .ok_or("claims must be an object")?;
    claims.insert("bad claim".to_owned(), Value::String("value".to_owned()));
    assert!(!validator.is_valid(&invalid_claim_name));
    let invalid_claim_name: OidcPolicy = serde_json::from_value(invalid_claim_name)?;
    assert!(invalid_claim_name.validate().is_err());
    Ok(())
}

#[tokio::test]
async fn unavailable_providers_are_tracked_without_network_startup_work()
-> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut policy = policy();
    policy.providers[0].issuer = "https://unavailable-one.example.invalid/oidc".to_owned();
    let mut second = policy.providers[0].clone();
    second.issuer = "https://unavailable-two.example.invalid/oidc".to_owned();
    policy.providers.push(second);

    let verifiers = OidcVerifierSet::discover(&policy)?;
    assert_eq!(verifiers.provider_count(), 2);
    assert_eq!(verifiers.ready_provider_count().await, 0);
    Ok(())
}

#[tokio::test]
async fn unavailable_provider_isolated_from_readiness_github_and_ready_oidc_provider()
-> Result<(), Box<dyn std::error::Error>> {
    let ready_key = source_key()?;
    let unavailable_key = source_key()?;
    let unavailable_issuer = "https://unavailable.example.invalid/oidc";
    let verifier = OidcVerifierSet::with_test_key_and_unready_provider(
        SOURCE_ISSUER.to_owned(),
        SOURCE_AUDIENCE.to_owned(),
        "source".to_owned(),
        ready_key.decoding.clone(),
        unavailable_issuer.to_owned(),
        SOURCE_AUDIENCE.to_owned(),
    )?;
    let mut mixed_policy = policy();
    let mut unavailable_policy = mixed_policy.providers[0].clone();
    unavailable_policy.issuer = unavailable_issuer.to_owned();
    mixed_policy.providers.push(unavailable_policy);
    mixed_policy.validate()?;

    let mut oidc = service(ready_key.decoding)?;
    oidc.verifier = verifier;
    oidc.policy = Arc::new(mixed_policy);
    let github_key = source_key()?;
    let github_token = github_assertion(&github_key.encoding, "github-isolation-jti")?;
    let app = application_with_github_key(oidc, github_key.decoding).await?;

    let readiness = app
        .clone()
        .oneshot(Request::get("/readyz").body(Body::empty())?)
        .await?;
    assert_eq!(readiness.status(), StatusCode::NO_CONTENT);
    let github = app
        .clone()
        .oneshot(
            Request::post("/v1/exchange")
                .header(header::AUTHORIZATION, format!("Bearer {github_token}"))
                .body(Body::from("{}"))?,
        )
        .await?;
    assert_eq!(
        github.status(),
        StatusCode::OK,
        "the established GitHub route continues to accept an ignored request body"
    );

    let now = get_current_timestamp() as i64;
    let ready = assertion(
        &ready_key.encoding,
        SourceAssertion {
            issuer: SOURCE_ISSUER,
            subject: SOURCE_SUBJECT,
            audience: SOURCE_AUDIENCE,
            issued_at: now,
            expires_at: now + 300,
            jti: Some("ready-provider-jti"),
            build_number: None,
            nbf: None,
            extra_audience: None,
            branch: None,
        },
    )?;
    assert_eq!(oidc_status(&app, &ready).await?, StatusCode::OK);
    let unavailable = assertion(
        &unavailable_key.encoding,
        SourceAssertion {
            issuer: unavailable_issuer,
            subject: SOURCE_SUBJECT,
            audience: SOURCE_AUDIENCE,
            issued_at: now,
            expires_at: now + 300,
            jti: Some("unavailable-provider-jti"),
            build_number: None,
            nbf: None,
            extra_audience: None,
            branch: None,
        },
    )?;
    assert_eq!(
        oidc_status(&app, &unavailable).await?,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let metrics = app
        .oneshot(Request::get("/metrics").body(Body::empty())?)
        .await?;
    let metrics = String::from_utf8(metrics.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(metrics.contains("github_oidc_exchange_generic_oidc_providers 2"));
    assert!(metrics.contains("github_oidc_exchange_generic_oidc_ready_providers 1"));
    assert_eq!(
        metrics
            .lines()
            .filter(|line| line.starts_with("github_oidc_exchange_generic_oidc_provider_ready{"))
            .count(),
        2
    );
    Ok(())
}

#[tokio::test]
async fn stale_provider_key_fails_closed_at_the_production_route()
-> Result<(), Box<dyn std::error::Error>> {
    let source_key = source_key()?;
    let verifier = OidcVerifierSet::with_stale_test_key(
        SOURCE_ISSUER.to_owned(),
        SOURCE_AUDIENCE.to_owned(),
        "source".to_owned(),
        source_key.decoding.clone(),
        Duration::from_secs(600),
    )?;
    let mut oidc = service(source_key.decoding)?;
    oidc.verifier = verifier;
    let now = get_current_timestamp() as i64;
    let token = assertion(
        &source_key.encoding,
        SourceAssertion {
            issuer: SOURCE_ISSUER,
            subject: SOURCE_SUBJECT,
            audience: SOURCE_AUDIENCE,
            issued_at: now,
            expires_at: now + 300,
            jti: Some("stale-key-jti"),
            build_number: None,
            nbf: None,
            extra_audience: None,
            branch: None,
        },
    )?;
    let app = application(oidc).await?;
    assert_eq!(
        oidc_status(&app, &token).await?,
        StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}

#[tokio::test]
async fn throttled_unknown_kid_is_temporarily_unavailable_not_an_identity_denial()
-> Result<(), Box<dyn std::error::Error>> {
    let source_key = source_key()?;
    let app = application(service(source_key.decoding)?).await?;
    let now = get_current_timestamp() as i64;
    let fixture = |jti| SourceAssertion {
        issuer: SOURCE_ISSUER,
        subject: SOURCE_SUBJECT,
        audience: SOURCE_AUDIENCE,
        issued_at: now,
        expires_at: now + 300,
        jti: Some(jti),
        build_number: None,
        nbf: None,
        extra_audience: None,
        branch: None,
    };
    let first = assertion_with_kid(&source_key.encoding, fixture("unknown-one"), "random-one")?;
    assert_eq!(oidc_status(&app, &first).await?, StatusCode::UNAUTHORIZED);
    let throttled = assertion_with_kid(&source_key.encoding, fixture("unknown-two"), "random-two")?;
    assert_eq!(
        oidc_status(&app, &throttled).await?,
        StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}

#[tokio::test]
async fn jenkins_profile_uses_a_single_use_composite_and_matches_the_steward_reader()
-> Result<(), Box<dyn std::error::Error>> {
    let source_key = source_key()?;
    let oidc_service = service(source_key.decoding.clone())?;
    let output_keys = oidc_service.keys.clone();
    let app = application(oidc_service).await?;
    let now = get_current_timestamp() as i64;
    let fixture = SourceAssertion {
        issuer: SOURCE_ISSUER,
        subject: SOURCE_SUBJECT,
        audience: SOURCE_AUDIENCE,
        issued_at: now,
        expires_at: now + 300,
        jti: None,
        build_number: Some(42),
        nbf: None,
        extra_audience: None,
        branch: None,
    };
    let source = assertion(&source_key.encoding, fixture)?;
    let response = app
        .clone()
        .oneshot(
            Request::post("/v1/oidc/exchange")
                .header(header::AUTHORIZATION, format!("Bearer {source}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let response: Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    let output = response["access_token"]
        .as_str()
        .ok_or("missing access token")?;
    let header = jsonwebtoken::decode_header(output)?;
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.kid.as_deref(), Some("current"));
    let jwks: JwkSet = serde_json::from_value(serde_json::to_value(output_keys.jwks())?)?;
    let output_key = DecodingKey::from_jwk(
        jwks.keys
            .iter()
            .find(|key| key.common.key_id.as_deref() == header.kid.as_deref())
            .ok_or("missing selected task key")?,
    )?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&["https://identity.example.invalid"]);
    validation.set_audience(&["steward-task-api"]);
    let claims = decode::<Value>(output, &output_key, &validation)?.claims;

    // Reader contract copied from Steward crates/steward-apiserver/src/tasks.rs.
    assert!(
        claims["sub"]
            .as_str()
            .is_some_and(|subject| subject.starts_with("oidc:") && subject.len() == 69),
        "the output subject must be an opaque issuer-plus-subject identity"
    );
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
    let second_token_for_same_build_and_second = assertion(&source_key.encoding, fixture)?;
    assert_eq!(
        oidc_status(&app, &second_token_for_same_build_and_second).await?,
        StatusCode::UNAUTHORIZED,
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
                nbf: None,
                extra_audience: None,
                branch: None,
            },
        )?;
        let app = application(service(source_key.decoding)?).await?;
        assert_eq!(oidc_status(&app, &source).await?, StatusCode::UNAUTHORIZED);
    }

    let source_key = source_key()?;
    let replay_app = application(service(source_key.decoding)?).await?;
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
            nbf: None,
            extra_audience: None,
            branch: None,
        },
    )?;
    assert_eq!(oidc_status(&replay_app, &source).await?, StatusCode::OK);
    assert_eq!(
        oidc_status(&replay_app, &source).await?,
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[tokio::test]
async fn generic_oidc_refuses_wrong_algorithms_and_bad_signatures()
-> Result<(), Box<dyn std::error::Error>> {
    let trusted = source_key()?;
    let app = application(service(trusted.decoding)?).await?;
    let now = get_current_timestamp() as i64;
    let fixture = SourceAssertion {
        issuer: SOURCE_ISSUER,
        subject: SOURCE_SUBJECT,
        audience: SOURCE_AUDIENCE,
        issued_at: now,
        expires_at: now + 300,
        jti: Some("algorithm-jti"),
        build_number: None,
        nbf: None,
        extra_audience: None,
        branch: None,
    };
    let claims = source_claims(fixture);

    let mut hs_header = Header::new(Algorithm::HS256);
    hs_header.kid = Some("source".to_owned());
    let hs256 = encode(
        &hs_header,
        &claims,
        &EncodingKey::from_secret(b"attacker-selected-secret"),
    )?;
    let none_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
        "alg": "none",
        "typ": "JWT",
        "kid": "source"
    }))?);
    let none_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let unsigned = format!("{none_header}.{none_payload}.");
    let attacker = source_key()?;
    let bad_signature = assertion(&attacker.encoding, fixture)?;

    for rejected in [hs256, unsigned, bad_signature] {
        assert_eq!(
            oidc_status(&app, &rejected).await?,
            StatusCode::UNAUTHORIZED
        );
    }
    Ok(())
}

#[tokio::test]
async fn generic_oidc_refuses_invalid_jti_time_audience_and_ambiguous_bindings()
-> Result<(), Box<dyn std::error::Error>> {
    let source_key = source_key()?;
    let app = application(service(source_key.decoding.clone())?).await?;
    let now = get_current_timestamp() as i64;
    for fixture in [
        SourceAssertion {
            issuer: SOURCE_ISSUER,
            subject: SOURCE_SUBJECT,
            audience: SOURCE_AUDIENCE,
            issued_at: now,
            expires_at: now + 300,
            jti: Some(""),
            build_number: None,
            nbf: None,
            extra_audience: None,
            branch: None,
        },
        SourceAssertion {
            issuer: SOURCE_ISSUER,
            subject: SOURCE_SUBJECT,
            audience: SOURCE_AUDIENCE,
            issued_at: now,
            expires_at: now + 300,
            jti: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            build_number: None,
            nbf: None,
            extra_audience: None,
            branch: None,
        },
        SourceAssertion {
            issuer: SOURCE_ISSUER,
            subject: SOURCE_SUBJECT,
            audience: SOURCE_AUDIENCE,
            issued_at: now + 120,
            expires_at: now + 300,
            jti: Some("future-iat"),
            build_number: None,
            nbf: None,
            extra_audience: None,
            branch: None,
        },
        SourceAssertion {
            issuer: SOURCE_ISSUER,
            subject: SOURCE_SUBJECT,
            audience: SOURCE_AUDIENCE,
            issued_at: now,
            expires_at: now + 300,
            jti: Some("future-nbf"),
            build_number: None,
            nbf: Some(now + 120),
            extra_audience: None,
            branch: None,
        },
        SourceAssertion {
            issuer: SOURCE_ISSUER,
            subject: SOURCE_SUBJECT,
            audience: SOURCE_AUDIENCE,
            issued_at: now,
            expires_at: now + 300,
            jti: Some("extra-audience"),
            build_number: None,
            nbf: None,
            extra_audience: Some("foreign-audience"),
            branch: None,
        },
    ] {
        let rejected = assertion(&source_key.encoding, fixture)?;
        assert_eq!(
            oidc_status(&app, &rejected).await?,
            StatusCode::UNAUTHORIZED
        );
    }

    let mut overlapping = policy();
    let mut narrower = overlapping.providers[0].bindings[0].clone();
    narrower
        .claims
        .insert("branch".to_owned(), "main".to_owned());
    overlapping.providers[0].bindings.push(narrower);
    let mut ambiguous_service = service(source_key.decoding)?;
    ambiguous_service.policy = Arc::new(overlapping);
    let ambiguous = assertion(
        &source_key.encoding,
        SourceAssertion {
            issuer: SOURCE_ISSUER,
            subject: SOURCE_SUBJECT,
            audience: SOURCE_AUDIENCE,
            issued_at: now,
            expires_at: now + 300,
            jti: Some("ambiguous-binding"),
            build_number: None,
            nbf: None,
            extra_audience: None,
            branch: Some("main"),
        },
    )?;
    let ambiguous_app = application(ambiguous_service).await?;
    assert_eq!(
        oidc_status(&ambiguous_app, &ambiguous).await?,
        StatusCode::UNAUTHORIZED
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
                nbf: None,
                extra_audience: None,
                branch: None,
            },
        )?;
        let app = application(service(source_key.decoding)?).await?;
        assert_eq!(oidc_status(&app, &source).await?, StatusCode::UNAUTHORIZED);
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
            nbf: None,
            extra_audience: None,
            branch: None,
        },
    )?;
    let app = application(service(source_key.decoding)?).await?;
    let missing = app
        .clone()
        .oneshot(Request::post("/v1/oidc/exchange").body(Body::empty())?)
        .await?;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let selected_identity_body = app
        .clone()
        .oneshot(
            Request::post("/v1/oidc/exchange")
                .header(header::AUTHORIZATION, format!("Bearer {source}"))
                .body(Body::from(r#"{"service":"attacker"}"#))?,
        )
        .await?;
    assert_eq!(selected_identity_body.status(), StatusCode::BAD_REQUEST);

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
