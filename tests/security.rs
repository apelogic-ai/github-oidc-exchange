use std::{collections::HashMap, fs, sync::Arc, sync::atomic::Ordering, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration as ChronoDuration, Utc};
use github_oidc_exchange::{
    GITHUB_ISSUER, IDENTITY_CONTRACT, KEYRING_VERSION, POLICY_VERSION,
    github::{Audience, GitHubClaims, GitHubVerifier},
    keys::KeyRing,
    policy::{Actor, Policy, PolicyError, RepositoryPolicy},
    replay::{MemoryReplayLedger, ReplayError, ReplayLedger},
    service::{ExchangeError, ExchangeService, Metrics},
};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, jwk::JwkSet,
};
use rand::thread_rng;
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use serde::Deserialize;
use tempfile::NamedTempFile;

const AUDIENCE: &str = "apelogic-github-identity-exchange";
const SUBJECT: &str = "repo:apelogic-ai@227278099/steward-run@1320906141:ref:refs/heads/main";
const CALLER_WORKFLOW: &str =
    "apelogic-ai/steward-run/.github/workflows/roundtrip.yml@refs/heads/main";
const WORKFLOW: &str = "apelogic-ai/steward-run/.github/workflows/steward-task.yml@refs/heads/main";

fn policy() -> Policy {
    Policy {
        version: POLICY_VERSION.to_owned(),
        service_group: "agents.apelogic.ai/service-principal:steward-run".to_owned(),
        acting_group_prefix: "agents.apelogic.ai/acting-user:".to_owned(),
        allowed_email_domains: vec!["apelogic.io".to_owned()],
        repositories: vec![RepositoryPolicy {
            owner_id: "227278099".to_owned(),
            repository_id: "1320906141".to_owned(),
            subjects: vec![SUBJECT.to_owned()],
            workflow_refs: vec![CALLER_WORKFLOW.to_owned()],
            job_workflow_refs: vec![WORKFLOW.to_owned()],
            events: vec!["workflow_dispatch".to_owned()],
            refs: vec!["refs/heads/main".to_owned()],
        }],
        actors: HashMap::from([(
            "12345".to_owned(),
            Actor {
                email: "engineer@apelogic.io".to_owned(),
                verified: true,
            },
        )]),
    }
}

fn claims() -> GitHubClaims {
    let now = Utc::now().timestamp();
    GitHubClaims {
        iss: GITHUB_ISSUER.to_owned(),
        sub: SUBJECT.to_owned(),
        aud: Audience::One(AUDIENCE.to_owned()),
        exp: now + 300,
        iat: now,
        nbf: now - 5,
        jti: "one-time-source-token".to_owned(),
        actor_id: "12345".to_owned(),
        repository_id: "1320906141".to_owned(),
        repository_owner_id: "227278099".to_owned(),
        workflow_ref: CALLER_WORKFLOW.to_owned(),
        job_workflow_ref: WORKFLOW.to_owned(),
        event_name: "workflow_dispatch".to_owned(),
        git_ref: "refs/heads/main".to_owned(),
    }
}

fn rsa_key() -> Result<(EncodingKey, DecodingKey), Box<dyn std::error::Error>> {
    let private = RsaPrivateKey::new(&mut thread_rng(), 2048)?;
    let document = private.to_pkcs1_der()?;
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private.e().to_bytes_be());
    Ok((
        EncodingKey::from_rsa_der(document.as_bytes()),
        DecodingKey::from_rsa_components(&n, &e)?,
    ))
}

fn signed_github_assertion(
    claims: &GitHubClaims,
    key: &EncodingKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("github-test-key".to_owned());
    header.typ = Some("JWT".to_owned());
    Ok(encode(&header, claims, key)?)
}

fn keyring() -> Result<KeyRing, Box<dyn std::error::Error>> {
    let now = Utc::now();
    let file = NamedTempFile::new()?;
    let content = serde_json::json!({
        "version": KEYRING_VERSION,
        "current_kid": "current",
        "keys": [
            {
                "kid": "previous",
                "seed": STANDARD.encode([7_u8; 32]),
                "not_before": (now - ChronoDuration::days(2)).to_rfc3339(),
                "not_after": (now + ChronoDuration::hours(1)).to_rfc3339()
            },
            {
                "kid": "current",
                "seed": STANDARD.encode([9_u8; 32]),
                "not_before": (now - ChronoDuration::hours(1)).to_rfc3339(),
                "not_after": (now + ChronoDuration::days(2)).to_rfc3339()
            }
        ]
    });
    fs::write(file.path(), serde_json::to_vec(&content)?)?;
    Ok(KeyRing::load(file.path(), now)?)
}

#[test]
fn policy_is_default_deny_and_emits_only_ratified_groups() -> Result<(), Box<dyn std::error::Error>>
{
    let policy = policy();
    policy.validate()?;
    let identity = policy.authorize(&claims())?;
    assert_eq!(identity.email, "engineer@apelogic.io");
    assert_eq!(
        identity.groups,
        vec![
            "agents.apelogic.ai/acting-user:engineer@apelogic.io",
            "agents.apelogic.ai/service-principal:steward-run",
        ]
    );

    let mut wrong_repository = claims();
    wrong_repository.repository_id = "999".to_owned();
    assert_eq!(
        policy.authorize(&wrong_repository),
        Err(PolicyError::Unauthorized)
    );
    let mut wrong_workflow = claims();
    wrong_workflow.job_workflow_ref = "untrusted/workflow@refs/heads/main".to_owned();
    assert_eq!(
        policy.authorize(&wrong_workflow),
        Err(PolicyError::Unauthorized)
    );
    let mut wrong_caller = claims();
    wrong_caller.workflow_ref = "untrusted/caller@refs/heads/main".to_owned();
    assert_eq!(
        policy.authorize(&wrong_caller),
        Err(PolicyError::Unauthorized)
    );
    let mut unmapped_actor = claims();
    unmapped_actor.actor_id = "999".to_owned();
    assert_eq!(
        policy.authorize(&unmapped_actor),
        Err(PolicyError::Unauthorized)
    );
    Ok(())
}

#[test]
fn unverified_or_noncanonical_actor_mapping_fails_closed() {
    let mut unverified = policy();
    if let Some(actor) = unverified.actors.get_mut("12345") {
        actor.verified = false;
    }
    assert!(unverified.validate().is_err());

    let mut profile_email = policy();
    if let Some(actor) = profile_email.actors.get_mut("12345") {
        actor.email = "Display Name <Engineer@apelogic.io>".to_owned();
    }
    assert!(profile_email.validate().is_err());

    let mut personal_email = policy();
    if let Some(actor) = personal_email.actors.get_mut("12345") {
        actor.email = "engineer@example.com".to_owned();
    }
    assert!(personal_email.validate().is_err());
}

#[tokio::test]
async fn github_assertions_require_exact_issuer_audience_and_freshness()
-> Result<(), Box<dyn std::error::Error>> {
    let (encoding, decoding) = rsa_key()?;
    let verifier =
        GitHubVerifier::with_test_key(AUDIENCE.to_owned(), "github-test-key".to_owned(), decoding)
            .await?;
    assert!(
        verifier
            .verify(&signed_github_assertion(&claims(), &encoding)?)
            .await
            .is_ok()
    );

    let mut wrong_audience = claims();
    wrong_audience.aud = Audience::One("wrong".to_owned());
    assert!(
        verifier
            .verify(&signed_github_assertion(&wrong_audience, &encoding)?)
            .await
            .is_err()
    );
    let mut multiple_audiences = claims();
    multiple_audiences.aud = Audience::Many(vec![AUDIENCE.to_owned(), "other".to_owned()]);
    assert!(
        verifier
            .verify(&signed_github_assertion(&multiple_audiences, &encoding)?)
            .await
            .is_err()
    );
    let mut wrong_issuer = claims();
    wrong_issuer.iss = "https://attacker.invalid".to_owned();
    assert!(
        verifier
            .verify(&signed_github_assertion(&wrong_issuer, &encoding)?)
            .await
            .is_err()
    );
    let mut expired = claims();
    expired.iat = Utc::now().timestamp() - 600;
    expired.nbf = expired.iat;
    expired.exp = Utc::now().timestamp() - 60;
    assert!(
        verifier
            .verify(&signed_github_assertion(&expired, &encoding)?)
            .await
            .is_err()
    );
    let mut future = claims();
    future.iat = Utc::now().timestamp() + 300;
    future.nbf = Utc::now().timestamp() - 5;
    future.exp = future.iat + 300;
    assert!(
        verifier
            .verify(&signed_github_assertion(&future, &encoding)?)
            .await
            .is_err()
    );
    let mut overflowing_lifetime = claims();
    overflowing_lifetime.iat = i64::MIN;
    overflowing_lifetime.nbf = i64::MIN;
    overflowing_lifetime.exp = i64::MAX;
    assert!(
        verifier
            .verify(&signed_github_assertion(&overflowing_lifetime, &encoding)?)
            .await
            .is_err()
    );
    let mut excessive_lifetime = claims();
    excessive_lifetime.exp = excessive_lifetime.iat + 601;
    assert!(
        verifier
            .verify(&signed_github_assertion(&excessive_lifetime, &encoding)?)
            .await
            .is_err()
    );
    Ok(())
}

#[test]
fn keyring_requires_exact_seed_length_and_rejects_unknown_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    for length in [31_usize, 33] {
        let file = NamedTempFile::new()?;
        let content = serde_json::json!({
            "version": KEYRING_VERSION,
            "current_kid": "current",
            "keys": [{
                "kid": "current",
                "seed": STANDARD.encode(vec![1_u8; length]),
                "not_before": (now - ChronoDuration::minutes(1)).to_rfc3339(),
                "not_after": (now + ChronoDuration::minutes(10)).to_rfc3339()
            }]
        });
        fs::write(file.path(), serde_json::to_vec(&content)?)?;
        assert!(KeyRing::load(file.path(), now).is_err());
    }

    let file = NamedTempFile::new()?;
    let content = serde_json::json!({
        "version": KEYRING_VERSION,
        "current_kid": "current",
        "unknown": true,
        "keys": [{
            "kid": "current",
            "seed": STANDARD.encode([1_u8; 32]),
            "not_before": (now - ChronoDuration::minutes(1)).to_rfc3339(),
            "not_after": (now + ChronoDuration::minutes(10)).to_rfc3339()
        }]
    });
    fs::write(file.path(), serde_json::to_vec(&content)?)?;
    assert!(KeyRing::load(file.path(), now).is_err());
    Ok(())
}

#[test]
fn policy_file_rejects_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
    let file = NamedTempFile::new()?;
    let content = serde_json::json!({
        "version": POLICY_VERSION,
        "service_group": "agents.apelogic.ai/service-principal:steward-run",
        "acting_group_prefix": "agents.apelogic.ai/acting-user:",
        "allowed_email_domains": ["apelogic.io"],
        "repositories": [],
        "actors": {},
        "unexpected": true
    });
    fs::write(file.path(), serde_json::to_vec(&content)?)?;
    assert!(Policy::load(file.path()).is_err());
    Ok(())
}

#[tokio::test]
async fn source_jti_is_single_use_and_output_is_eks_shaped()
-> Result<(), Box<dyn std::error::Error>> {
    let (encoding, decoding) = rsa_key()?;
    let verifier =
        GitHubVerifier::with_test_key(AUDIENCE.to_owned(), "github-test-key".to_owned(), decoding)
            .await?;
    let keyring = keyring()?;
    let jwks: JwkSet = serde_json::from_value(serde_json::to_value(keyring.jwks())?)?;
    let output_key = DecodingKey::from_jwk(&jwks.keys[0])?;
    let metrics = Arc::new(Metrics::default());
    let service = ExchangeService {
        verifier,
        policy: Arc::new(policy()),
        ledger: Arc::new(MemoryReplayLedger::default()),
        keys: Arc::new(keyring),
        issuer: "https://identity.dev.apelogic.io".to_owned(),
        output_audience: "steward-task-api".to_owned(),
        token_ttl: Duration::from_secs(120),
        metrics: metrics.clone(),
    };
    let assertion = signed_github_assertion(&claims(), &encoding)?;
    let output = service.exchange(&assertion).await?;

    #[derive(Debug, Deserialize)]
    struct OutputClaims {
        iss: String,
        aud: Vec<String>,
        email: String,
        groups: Vec<String>,
        identity_contract: String,
    }
    let output_header = jsonwebtoken::decode_header(&output)?;
    assert_eq!(output_header.alg, Algorithm::ES256);
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&["https://identity.dev.apelogic.io"]);
    validation.set_audience(&["steward-task-api"]);
    let decoded = decode::<OutputClaims>(&output, &output_key, &validation)?.claims;
    assert_eq!(decoded.iss, "https://identity.dev.apelogic.io");
    assert_eq!(decoded.aud, vec!["steward-task-api"]);
    assert_eq!(decoded.email, "engineer@apelogic.io");
    assert_eq!(decoded.identity_contract, IDENTITY_CONTRACT);
    assert_eq!(decoded.groups.len(), 2);
    assert_eq!(
        service.exchange(&assertion).await,
        Err(ExchangeError::Unauthorized)
    );
    assert_eq!(metrics.issued.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.replayed.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn memory_ledger_rejects_replay() {
    let ledger = MemoryReplayLedger::default();
    let expiry = Utc::now().timestamp() + 60;
    assert_eq!(ledger.use_once("jti", expiry).await, Ok(()));
    assert_eq!(
        ledger.use_once("jti", expiry).await,
        Err(ReplayError::Replayed)
    );
}
