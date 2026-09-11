use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    sync::{Arc, Mutex, OnceLock, atomic::Ordering},
    time::Duration,
};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration as ChronoDuration, Utc};
use github_oidc_exchange::{
    GITHUB_ISSUER, IDENTITY_CONTRACT, KEYRING_VERSION, POLICY_VERSION, RSA_KEYRING_VERSION,
    SOURCE_PROVENANCE_CONTRACT, WORKLOAD_IDENTITY_CONTRACT, WORKLOAD_POLICY_VERSION,
    github::{Audience, GitHubClaims, GitHubVerifier},
    http::separated_routers_with_workload,
    keys::{KeyRing, RsaKeyRing},
    policy::{Actor, IdentityProfile, Policy, PolicyError, RepositoryPolicy},
    replay::{ReplayError, ReplayLedger},
    service::{ExchangeError, ExchangeService, Metrics},
    workload::{
        ReviewError, ReviewedWorkload, TokenReviewer, WorkloadExchangeError,
        WorkloadExchangeService, WorkloadIdentity, WorkloadMetrics, WorkloadPolicy,
        WorkloadPolicyError,
    },
};
use http_body_util::BodyExt;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, jwk::JwkSet,
};
use rand::thread_rng;
use rsa::{
    RsaPrivateKey,
    pkcs1::EncodeRsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::fmt::MakeWriter;

static TEST_CRYPTO_PROVIDER: OnceLock<Result<(), &'static str>> = OnceLock::new();

fn install_test_crypto_provider() -> Result<(), Box<dyn std::error::Error>> {
    match TEST_CRYPTO_PROVIDER.get_or_init(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .map_err(|_| "rustls CryptoProvider was already installed before test setup")
    }) {
        Ok(()) => Ok(()),
        Err(message) => Err(std::io::Error::other(*message).into()),
    }
}

const AUDIENCE: &str = "apelogic-github-identity-exchange";
const SUBJECT: &str = "repo:apelogic-ai@227278099/steward-run@1320906141:ref:refs/heads/main";
const CALLER_WORKFLOW: &str =
    "apelogic-ai/steward-run/.github/workflows/roundtrip.yml@refs/heads/main";
const WORKFLOW: &str = "apelogic-ai/steward-run/.github/workflows/steward-task.yml@refs/heads/main";
const TRIGGERED_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const CALLER_WORKFLOW_SHA: &str = "123456789abcdef0123456789abcdef012345678";
const REUSABLE_WORKFLOW_SHA: &str = "23456789abcdef0123456789abcdef0123456789";
const REPOSITORY: &str = "apelogic-ai/steward-run";
const ACTOR: &str = "alice";
const BOOTSTRAP_CALLER_WORKFLOW: &str =
    "apelogic-ai/steward-run/.github/workflows/bootstrap.yml@refs/heads/main";
const BOOTSTRAP_WORKFLOW: &str =
    "apelogic-ai/steward-run/.github/workflows/bootstrap-executor.yml@refs/heads/main";
const WORKLOAD_INPUT_AUDIENCE: &str = "apelogic-workload-exchange";
const WORKLOAD_OUTPUT_AUDIENCE: &str = "openshell-api";
const WORKLOAD_USERNAME: &str = "system:serviceaccount:steward:steward-controller";
const WORKLOAD_SUBJECT: &str = "kubernetes:serviceaccount:steward:steward-controller";

#[derive(Clone, Default)]
struct TestReplayLedger(Arc<Mutex<HashSet<String>>>);

impl ReplayLedger for TestReplayLedger {
    async fn use_once(&self, jti: &str, _expires_at: i64) -> Result<(), ReplayError> {
        let mut used = self.0.lock().map_err(|_| ReplayError::Unavailable)?;
        if used.insert(jti.to_owned()) {
            Ok(())
        } else {
            Err(ReplayError::Replayed)
        }
    }
}

fn policy() -> Policy {
    Policy {
        version: POLICY_VERSION.to_owned(),
        service_group: "agents.apelogic.ai/service-principal:steward-run".to_owned(),
        acting_group_prefix: "agents.apelogic.ai/acting-user:".to_owned(),
        bootstrap_group: "agents.apelogic.ai/service-envelope-bootstrap:steward-run".to_owned(),
        allowed_email_domains: vec!["apelogic.io".to_owned()],
        repositories: vec![RepositoryPolicy {
            profile: IdentityProfile::Task,
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
                canonical_user_id: "usr_0123456789abcdef0123456789abcdef".to_owned(),
                verified: true,
            },
        )]),
    }
}

#[test]
fn workflow_selected_profiles_are_mutually_exclusive() -> Result<(), Box<dyn std::error::Error>> {
    let mut policy = policy();
    let mut bootstrap_rule = policy.repositories[0].clone();
    bootstrap_rule.profile = IdentityProfile::Bootstrap;
    bootstrap_rule.workflow_refs = vec![BOOTSTRAP_CALLER_WORKFLOW.to_owned()];
    bootstrap_rule.job_workflow_refs = vec![BOOTSTRAP_WORKFLOW.to_owned()];
    policy.repositories.push(bootstrap_rule);
    policy.validate()?;

    let task_identity = policy.authorize(&claims())?;
    assert_eq!(
        task_identity.groups,
        vec![
            "agents.apelogic.ai/acting-user:engineer@apelogic.io",
            "agents.apelogic.ai/canonical-user:usr_0123456789abcdef0123456789abcdef",
            "agents.apelogic.ai/service-principal:steward-run",
        ]
    );

    let mut bootstrap_claims = claims();
    bootstrap_claims.workflow_ref = BOOTSTRAP_CALLER_WORKFLOW.to_owned();
    bootstrap_claims.job_workflow_ref = BOOTSTRAP_WORKFLOW.to_owned();
    let bootstrap_identity = policy.authorize(&bootstrap_claims)?;
    assert!(bootstrap_identity.email_verified);
    assert_eq!(
        bootstrap_identity.groups,
        vec!["agents.apelogic.ai/service-envelope-bootstrap:steward-run"]
    );

    let mut ambiguous = policy.clone();
    let mut overlapping_rule = ambiguous.repositories[0].clone();
    overlapping_rule.profile = IdentityProfile::Bootstrap;
    ambiguous.repositories.push(overlapping_rule);
    assert!(ambiguous.validate().is_err());
    assert_eq!(
        ambiguous.authorize(&claims()),
        Err(PolicyError::Unauthorized)
    );

    let mut invalid_bootstrap_group = policy;
    invalid_bootstrap_group.bootstrap_group =
        "agents.apelogic.ai/service-principal:steward-run".to_owned();
    assert!(invalid_bootstrap_group.validate().is_err());
    Ok(())
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
        actor: ACTOR.to_owned(),
        repository: REPOSITORY.to_owned(),
        repository_id: "1320906141".to_owned(),
        repository_owner_id: "227278099".to_owned(),
        sha: TRIGGERED_SHA.to_owned(),
        run_id: "3456789012".to_owned(),
        run_attempt: 2,
        workflow_ref: CALLER_WORKFLOW.to_owned(),
        workflow_sha: CALLER_WORKFLOW_SHA.to_owned(),
        job_workflow_ref: WORKFLOW.to_owned(),
        job_workflow_sha: REUSABLE_WORKFLOW_SHA.to_owned(),
        event_name: "workflow_dispatch".to_owned(),
        git_ref: "refs/heads/main".to_owned(),
    }
}

fn claims_with_source_provenance() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut value = serde_json::to_value(claims())?;
    let object = value
        .as_object_mut()
        .ok_or("claims fixture must be an object")?;
    object.insert("repository".to_owned(), serde_json::json!(REPOSITORY));
    object.insert("sha".to_owned(), serde_json::json!(TRIGGERED_SHA));
    object.insert("run_id".to_owned(), serde_json::json!("3456789012"));
    object.insert("run_attempt".to_owned(), serde_json::json!("2"));
    object.insert("actor".to_owned(), serde_json::json!(ACTOR));
    object.insert(
        "workflow_sha".to_owned(),
        serde_json::json!(CALLER_WORKFLOW_SHA),
    );
    object.insert(
        "job_workflow_sha".to_owned(),
        serde_json::json!(REUSABLE_WORKFLOW_SHA),
    );
    Ok(value)
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

fn signed_github_assertion<T: Serialize>(
    claims: &T,
    key: &EncodingKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("github-test-key".to_owned());
    header.typ = Some("JWT".to_owned());
    Ok(encode(&header, claims, key)?)
}

#[tokio::test]
async fn source_claims_cannot_select_or_override_canonical_identity()
-> Result<(), Box<dyn std::error::Error>> {
    install_test_crypto_provider()?;
    let (encoding, decoding) = rsa_key()?;
    let verifier =
        GitHubVerifier::with_test_key(AUDIENCE.to_owned(), "github-test-key".to_owned(), decoding)
            .await?;
    let mut attacker_controlled = serde_json::to_value(claims())?;
    let object = attacker_controlled
        .as_object_mut()
        .ok_or("claims fixture must be an object")?;
    object.insert(
        "canonical_user_id".to_owned(),
        serde_json::json!("usr_ffffffffffffffffffffffffffffffff"),
    );
    object.insert(
        "groups".to_owned(),
        serde_json::json!([
            "agents.apelogic.ai/canonical-user:usr_ffffffffffffffffffffffffffffffff"
        ]),
    );
    object.insert(
        "inputs".to_owned(),
        serde_json::json!({
            "canonical_user_id": "usr_ffffffffffffffffffffffffffffffff"
        }),
    );

    let reviewed = verifier
        .verify(&signed_github_assertion(&attacker_controlled, &encoding)?)
        .await?;
    let identity = policy().authorize(&reviewed)?;
    assert!(identity.groups.contains(
        &"agents.apelogic.ai/canonical-user:usr_0123456789abcdef0123456789abcdef".to_owned()
    ));
    assert!(
        !identity
            .groups
            .iter()
            .any(|group| group.contains("ffffffff"))
    );
    Ok(())
}

#[tokio::test]
async fn source_provenance_is_derived_from_verified_claims_not_an_embedded_override()
-> Result<(), Box<dyn std::error::Error>> {
    install_test_crypto_provider()?;
    let (encoding, decoding) = rsa_key()?;
    let verifier =
        GitHubVerifier::with_test_key(AUDIENCE.to_owned(), "github-test-key".to_owned(), decoding)
            .await?;
    let mut asserted = claims_with_source_provenance()?;
    asserted
        .as_object_mut()
        .ok_or("claims fixture must be an object")?
        .insert(
            "source_provenance".to_owned(),
            serde_json::json!({
                "contractVersion": SOURCE_PROVENANCE_CONTRACT,
                "provider": "github",
                "repository": {
                    "id": "999",
                    "ownerId": "999",
                    "name": "attacker/example"
                },
                "triggeredSha": "git:sha1:ffffffffffffffffffffffffffffffffffffffff",
                "run": {"id": "999", "attempt": "999"},
                "event": "pull_request_target",
                "ref": "refs/heads/attacker",
                "actorId": "999",
                "actor": "attacker",
                "callerWorkflow": {
                    "ref": "attacker/example/.github/workflows/caller.yml@refs/heads/main",
                    "sha": "git:sha1:ffffffffffffffffffffffffffffffffffffffff"
                },
                "reusableWorkflow": {
                    "ref": "attacker/example/.github/workflows/reusable.yml@refs/heads/main",
                    "sha": "git:sha1:ffffffffffffffffffffffffffffffffffffffff"
                }
            }),
        );
    let keyring = keyring()?;
    let jwks: JwkSet = serde_json::from_value(serde_json::to_value(keyring.jwks())?)?;
    let output_key = DecodingKey::from_jwk(&jwks.keys[0])?;
    let service = ExchangeService {
        verifier,
        policy: Arc::new(policy()),
        ledger: Arc::new(TestReplayLedger::default()),
        keys: Arc::new(keyring),
        issuer: "https://identity.example.com".to_owned(),
        output_audience: "steward-task-api".to_owned(),
        token_ttl: Duration::from_secs(120),
        metrics: Arc::new(Metrics::default()),
    };

    let output = service
        .exchange(&signed_github_assertion(&asserted, &encoding)?)
        .await?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&["https://identity.example.com"]);
    validation.set_audience(&["steward-task-api"]);
    let decoded = decode::<serde_json::Value>(&output, &output_key, &validation)?.claims;

    assert_eq!(
        decoded["source_provenance"],
        serde_json::json!({
            "contractVersion": SOURCE_PROVENANCE_CONTRACT,
            "provider": "github",
            "repository": {
                "id": "1320906141",
                "ownerId": "227278099",
                "name": REPOSITORY
            },
            "triggeredSha": format!("git:sha1:{TRIGGERED_SHA}"),
            "run": {"id": "3456789012", "attempt": 2},
            "event": "workflow_dispatch",
            "ref": "refs/heads/main",
            "actorId": "12345",
            "actor": ACTOR,
            "callerWorkflow": {
                "ref": CALLER_WORKFLOW,
                "sha": format!("git:sha1:{CALLER_WORKFLOW_SHA}")
            },
            "reusableWorkflow": {
                "ref": WORKFLOW,
                "sha": format!("git:sha1:{REUSABLE_WORKFLOW_SHA}")
            }
        })
    );
    Ok(())
}

#[tokio::test]
async fn github_assertions_require_every_source_provenance_claim()
-> Result<(), Box<dyn std::error::Error>> {
    install_test_crypto_provider()?;
    let (encoding, decoding) = rsa_key()?;
    let verifier =
        GitHubVerifier::with_test_key(AUDIENCE.to_owned(), "github-test-key".to_owned(), decoding)
            .await?;

    for required in [
        "actor_id",
        "repository_id",
        "repository_owner_id",
        "workflow_ref",
        "job_workflow_ref",
        "event_name",
        "ref",
        "repository",
        "sha",
        "run_id",
        "run_attempt",
        "actor",
        "workflow_sha",
        "job_workflow_sha",
    ] {
        let mut missing = claims_with_source_provenance()?;
        missing
            .as_object_mut()
            .ok_or("claims fixture must be an object")?
            .remove(required);
        assert!(
            verifier
                .verify(&signed_github_assertion(&missing, &encoding)?)
                .await
                .is_err(),
            "GitHub assertion missing {required} must fail closed"
        );
    }
    Ok(())
}

#[tokio::test]
async fn malformed_source_provenance_claims_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    install_test_crypto_provider()?;
    let (encoding, decoding) = rsa_key()?;
    let verifier =
        GitHubVerifier::with_test_key(AUDIENCE.to_owned(), "github-test-key".to_owned(), decoding)
            .await?;

    for (claim, malformed) in [
        ("actor_id", "alice"),
        ("actor", "alice example"),
        ("repository", "example-org/../example-repo"),
        ("repository_id", "example-repo"),
        ("repository_owner_id", "example-org"),
        ("sha", "0123456789ABCDEF0123456789ABCDEF01234567"),
        ("run_id", "run-3456789012"),
        ("run_attempt", "attempt-2"),
        ("workflow_sha", "123456789abcdef0123456789abcdef01234567"),
        (
            "job_workflow_sha",
            "23456789abcdef0123456789abcdef012345678z",
        ),
        ("event_name", "workflow dispatch"),
        ("ref", "refs/heads/main branch"),
    ] {
        let mut claims = claims_with_source_provenance()?;
        claims[claim] = serde_json::json!(malformed);
        assert!(
            verifier
                .verify(&signed_github_assertion(&claims, &encoding)?)
                .await
                .is_err(),
            "GitHub assertion with malformed {claim} must fail closed"
        );
    }
    Ok(())
}

#[tokio::test]
async fn repository_name_cannot_substitute_for_a_mismatched_stable_id()
-> Result<(), Box<dyn std::error::Error>> {
    install_test_crypto_provider()?;
    let (encoding, decoding) = rsa_key()?;
    let verifier =
        GitHubVerifier::with_test_key(AUDIENCE.to_owned(), "github-test-key".to_owned(), decoding)
            .await?;
    let mut mismatched = claims_with_source_provenance()?;
    mismatched["repository_id"] = serde_json::json!("999");
    mismatched["repository"] = serde_json::json!(REPOSITORY);

    let verified = verifier
        .verify(&signed_github_assertion(&mismatched, &encoding)?)
        .await?;
    assert_eq!(
        policy().authorize(&verified),
        Err(PolicyError::Unauthorized)
    );
    Ok(())
}

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

struct CapturedLogWriter(CapturedLogs);

impl Write for CapturedLogWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0
            .0
            .lock()
            .map_err(|_| std::io::Error::other("captured log mutex poisoned"))?
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for CapturedLogs {
    type Writer = CapturedLogWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        CapturedLogWriter(self.clone())
    }
}

#[tokio::test]
async fn rejected_assertions_never_enter_identity_logs() -> Result<(), Box<dyn std::error::Error>> {
    install_test_crypto_provider()?;
    let (encoding, decoding) = rsa_key()?;
    let verifier =
        GitHubVerifier::with_test_key(AUDIENCE.to_owned(), "github-test-key".to_owned(), decoding)
            .await?;
    let keyring = keyring()?;
    let service = ExchangeService {
        verifier,
        policy: Arc::new(policy()),
        ledger: Arc::new(TestReplayLedger::default()),
        keys: Arc::new(keyring),
        issuer: "https://identity.example.com".to_owned(),
        output_audience: "steward-task-api".to_owned(),
        token_ttl: Duration::from_secs(120),
        metrics: Arc::new(Metrics::default()),
    };
    let mut rejected = claims_with_source_provenance()?;
    rejected["repository_id"] = serde_json::json!("999");
    let assertion = signed_github_assertion(&rejected, &encoding)?;
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(logs.clone())
        .finish();

    assert_eq!(
        service
            .exchange(&assertion)
            .with_subscriber(subscriber)
            .await,
        Err(ExchangeError::Unauthorized)
    );
    let captured = String::from_utf8(
        logs.0
            .lock()
            .map_err(|_| "captured log mutex poisoned")?
            .clone(),
    )?;
    assert!(!captured.contains(&assertion));
    assert!(!captured.contains("source_provenance"));
    Ok(())
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

fn workload_policy() -> WorkloadPolicy {
    WorkloadPolicy {
        version: WORKLOAD_POLICY_VERSION.to_owned(),
        identities: vec![WorkloadIdentity {
            username: WORKLOAD_USERNAME.to_owned(),
            subject: WORKLOAD_SUBJECT.to_owned(),
            roles: vec!["openshell-user".to_owned(), "openshell-admin".to_owned()],
        }],
    }
}

fn rsa_keyring_with_bits(bits: usize) -> Result<RsaKeyRing, Box<dyn std::error::Error>> {
    let now = Utc::now();
    let private = RsaPrivateKey::new(&mut thread_rng(), bits)?;
    let pem = private.to_pkcs8_pem(LineEnding::LF)?.to_string();
    let file = NamedTempFile::new()?;
    let content = serde_json::json!({
        "version": RSA_KEYRING_VERSION,
        "current_kid": "current-rsa",
        "keys": [
            {
                "kid": "previous-rsa",
                "private_key_pkcs8_pem": pem.clone(),
                "not_before": (now - ChronoDuration::days(2)).to_rfc3339(),
                "not_after": (now + ChronoDuration::hours(1)).to_rfc3339()
            },
            {
                "kid": "current-rsa",
                "private_key_pkcs8_pem": pem,
                "not_before": (now - ChronoDuration::hours(1)).to_rfc3339(),
                "not_after": (now + ChronoDuration::days(2)).to_rfc3339()
            }
        ]
    });
    fs::write(file.path(), serde_json::to_vec(&content)?)?;
    Ok(RsaKeyRing::load(file.path(), now)?)
}

#[derive(Clone)]
enum MockReview {
    Accept(String),
    Invalid,
    Unavailable,
}

#[derive(Clone)]
struct MockReviewer {
    outcome: MockReview,
}

impl TokenReviewer for MockReviewer {
    async fn review(
        &self,
        token: String,
        audience: String,
    ) -> Result<ReviewedWorkload, ReviewError> {
        if token != "projected-source-token" || audience != WORKLOAD_INPUT_AUDIENCE {
            return Err(ReviewError::Invalid);
        }
        match &self.outcome {
            MockReview::Accept(username) => Ok(ReviewedWorkload {
                username: username.clone(),
            }),
            MockReview::Invalid => Err(ReviewError::Invalid),
            MockReview::Unavailable => Err(ReviewError::Unavailable),
        }
    }
}

#[test]
fn policy_is_default_deny_and_emits_only_ratified_groups() -> Result<(), Box<dyn std::error::Error>>
{
    let policy = policy();
    policy.validate()?;
    let identity = policy.authorize(&claims())?;
    assert_eq!(identity.email, "engineer@apelogic.io");
    assert!(identity.email_verified);
    assert_eq!(
        identity.groups,
        vec![
            "agents.apelogic.ai/acting-user:engineer@apelogic.io",
            "agents.apelogic.ai/canonical-user:usr_0123456789abcdef0123456789abcdef",
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
    assert_eq!(
        unverified.authorize(&claims()),
        Err(PolicyError::Unauthorized)
    );

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

    for malformed in [
        "",
        "0123456789abcdef0123456789abcdef",
        "usr_0123456789abcdef0123456789abcde",
        "usr_0123456789abcdef0123456789abcdef0",
        "usr_0123456789abcdef0123456789abcdeg",
        "usr_0123456789ABCDEF0123456789ABCDEF",
    ] {
        let mut invalid_canonical_user = policy();
        if let Some(actor) = invalid_canonical_user.actors.get_mut("12345") {
            actor.canonical_user_id = malformed.to_owned();
        }
        assert!(invalid_canonical_user.validate().is_err());
    }

    let mut duplicate_canonical_user = policy();
    duplicate_canonical_user.actors.insert(
        "67890".to_owned(),
        Actor {
            email: "other@apelogic.io".to_owned(),
            canonical_user_id: "usr_0123456789abcdef0123456789abcdef".to_owned(),
            verified: true,
        },
    );
    assert!(duplicate_canonical_user.validate().is_err());
}

#[test]
fn policy_file_requires_canonical_user_mapping() -> Result<(), Box<dyn std::error::Error>> {
    let file = NamedTempFile::new()?;
    let mut content = serde_json::to_value(policy())?;
    content["actors"]["12345"]
        .as_object_mut()
        .ok_or("actor fixture must be an object")?
        .remove("canonical_user_id");
    fs::write(file.path(), serde_json::to_vec(&content)?)?;
    assert!(Policy::load(file.path()).is_err());
    Ok(())
}

#[tokio::test]
async fn github_assertions_require_exact_issuer_audience_and_freshness()
-> Result<(), Box<dyn std::error::Error>> {
    install_test_crypto_provider()?;
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
        "bootstrap_group": "agents.apelogic.ai/service-envelope-bootstrap:steward-run",
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
    install_test_crypto_provider()?;
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
        ledger: Arc::new(TestReplayLedger::default()),
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
        email_verified: bool,
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
    assert!(decoded.email_verified);
    assert_eq!(decoded.identity_contract, IDENTITY_CONTRACT);
    assert_eq!(
        decoded.groups,
        vec![
            "agents.apelogic.ai/acting-user:engineer@apelogic.io",
            "agents.apelogic.ai/canonical-user:usr_0123456789abcdef0123456789abcdef",
            "agents.apelogic.ai/service-principal:steward-run",
        ]
    );
    assert_eq!(
        service.exchange(&assertion).await,
        Err(ExchangeError::Unauthorized)
    );
    assert_eq!(metrics.issued.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.replayed.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn test_ledger_rejects_replay() {
    let ledger = TestReplayLedger::default();
    let expiry = Utc::now().timestamp() + 60;
    assert_eq!(ledger.use_once("jti", expiry).await, Ok(()));
    assert_eq!(
        ledger.use_once("jti", expiry).await,
        Err(ReplayError::Replayed)
    );
}

#[test]
fn workload_policy_is_exact_and_default_deny() -> Result<(), Box<dyn std::error::Error>> {
    let policy = workload_policy();
    policy.validate()?;
    let identity = policy.authorize(WORKLOAD_USERNAME)?;
    assert_eq!(identity.subject, WORKLOAD_SUBJECT);
    assert_eq!(identity.roles, vec!["openshell-admin", "openshell-user"]);
    assert_eq!(
        policy.authorize("system:serviceaccount:steward:other"),
        Err(WorkloadPolicyError::Unauthorized)
    );

    let mut wildcard = workload_policy();
    wildcard.identities[0].username = "system:serviceaccount:steward:*".to_owned();
    assert!(wildcard.validate().is_err());
    let mut duplicate = workload_policy();
    duplicate.identities.push(duplicate.identities[0].clone());
    assert!(duplicate.validate().is_err());
    let mut mismatched_subject = workload_policy();
    mismatched_subject.identities[0].subject = "kubernetes:serviceaccount:other:caller".to_owned();
    assert!(mismatched_subject.validate().is_err());
    let mut duplicate_role = workload_policy();
    duplicate_role.identities[0].roles = vec!["openshell-admin".to_owned(); 2];
    assert!(duplicate_role.validate().is_err());
    Ok(())
}

#[test]
fn workload_rsa_keyring_requires_rsa_3072_and_publishes_overlap()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(rsa_keyring_with_bits(2048).is_err());
    let keyring = rsa_keyring_with_bits(3072)?;
    let jwks: JwkSet = serde_json::from_value(serde_json::to_value(keyring.jwks())?)?;
    assert_eq!(jwks.keys.len(), 2);
    assert!(
        jwks.keys.iter().all(|key| {
            key.common.key_algorithm == Some(jsonwebtoken::jwk::KeyAlgorithm::RS256)
        })
    );
    Ok(())
}

#[tokio::test]
async fn workload_exchange_emits_only_server_selected_rs256_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let keys = Arc::new(rsa_keyring_with_bits(3072)?);
    let jwks: JwkSet = serde_json::from_value(serde_json::to_value(keys.jwks())?)?;
    let output_key = DecodingKey::from_jwk(&jwks.keys[0])?;
    let metrics = Arc::new(WorkloadMetrics::default());
    let service = WorkloadExchangeService {
        reviewer: MockReviewer {
            outcome: MockReview::Accept(WORKLOAD_USERNAME.to_owned()),
        },
        policy: Arc::new(workload_policy()),
        keys,
        issuer: "https://identity.dev.apelogic.io".to_owned(),
        input_audience: WORKLOAD_INPUT_AUDIENCE.to_owned(),
        output_audience: WORKLOAD_OUTPUT_AUDIENCE.to_owned(),
        token_ttl: Duration::from_secs(120),
        metrics: metrics.clone(),
    };
    let output = service.exchange("projected-source-token").await?;
    assert_eq!(jsonwebtoken::decode_header(&output)?.alg, Algorithm::RS256);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://identity.dev.apelogic.io"]);
    validation.set_audience(&[WORKLOAD_OUTPUT_AUDIENCE]);
    let claims = decode::<serde_json::Value>(&output, &output_key, &validation)?.claims;
    assert_eq!(claims["sub"], WORKLOAD_SUBJECT);
    assert_eq!(claims["aud"], serde_json::json!([WORKLOAD_OUTPUT_AUDIENCE]));
    assert_eq!(
        claims["roles"],
        serde_json::json!(["openshell-admin", "openshell-user"])
    );
    assert_eq!(claims["identity_contract"], WORKLOAD_IDENTITY_CONTRACT);
    assert!(claims.get("email").is_none());
    assert!(claims.get("email_verified").is_none());
    assert!(claims.get("groups").is_none());
    assert_eq!(metrics.issued.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn workload_exchange_separates_denial_from_token_review_outage()
-> Result<(), Box<dyn std::error::Error>> {
    let keys = Arc::new(rsa_keyring_with_bits(3072)?);
    for (outcome, expected) in [
        (MockReview::Invalid, WorkloadExchangeError::Unauthorized),
        (MockReview::Unavailable, WorkloadExchangeError::Unavailable),
        (
            MockReview::Accept("system:serviceaccount:steward:unmapped".to_owned()),
            WorkloadExchangeError::Unauthorized,
        ),
    ] {
        let service = WorkloadExchangeService {
            reviewer: MockReviewer { outcome },
            policy: Arc::new(workload_policy()),
            keys: keys.clone(),
            issuer: "https://identity.dev.apelogic.io".to_owned(),
            input_audience: WORKLOAD_INPUT_AUDIENCE.to_owned(),
            output_audience: WORKLOAD_OUTPUT_AUDIENCE.to_owned(),
            token_ttl: Duration::from_secs(120),
            metrics: Arc::new(WorkloadMetrics::default()),
        };
        assert_eq!(
            service.exchange("projected-source-token").await,
            Err(expected)
        );
    }
    Ok(())
}

#[tokio::test]
async fn workload_http_contract_is_empty_body_only_and_preserves_github_es256()
-> Result<(), Box<dyn std::error::Error>> {
    install_test_crypto_provider()?;
    let (github_encoding, github_decoding) = rsa_key()?;
    let verifier = GitHubVerifier::with_test_key(
        AUDIENCE.to_owned(),
        "github-test-key".to_owned(),
        github_decoding,
    )
    .await?;
    let github_service = ExchangeService {
        verifier,
        policy: Arc::new(policy()),
        ledger: Arc::new(TestReplayLedger::default()),
        keys: Arc::new(keyring()?),
        issuer: "https://identity.dev.apelogic.io".to_owned(),
        output_audience: "steward-task-api".to_owned(),
        token_ttl: Duration::from_secs(120),
        metrics: Arc::new(Metrics::default()),
    };
    let workload_service = WorkloadExchangeService {
        reviewer: MockReviewer {
            outcome: MockReview::Accept(WORKLOAD_USERNAME.to_owned()),
        },
        policy: Arc::new(workload_policy()),
        keys: Arc::new(rsa_keyring_with_bits(3072)?),
        issuer: "https://identity.dev.apelogic.io".to_owned(),
        input_audience: WORKLOAD_INPUT_AUDIENCE.to_owned(),
        output_audience: WORKLOAD_OUTPUT_AUDIENCE.to_owned(),
        token_ttl: Duration::from_secs(120),
        metrics: Arc::new(WorkloadMetrics::default()),
    };
    let (public_application, workload_application) =
        separated_routers_with_workload(github_service, workload_service);

    let discovery = public_application
        .clone()
        .oneshot(Request::get("/.well-known/openid-configuration").body(Body::empty())?)
        .await?;
    assert_eq!(discovery.status(), StatusCode::OK);
    let discovery: serde_json::Value =
        serde_json::from_slice(&discovery.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        discovery["id_token_signing_alg_values_supported"],
        serde_json::json!(["ES256", "RS256"])
    );

    let public_workload_route = public_application
        .clone()
        .oneshot(
            Request::post("/v1/workload/exchange")
                .header(header::AUTHORIZATION, "Bearer projected-source-token")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(public_workload_route.status(), StatusCode::NOT_FOUND);

    let internal_discovery_route = workload_application
        .clone()
        .oneshot(Request::get("/.well-known/openid-configuration").body(Body::empty())?)
        .await?;
    assert_eq!(internal_discovery_route.status(), StatusCode::NOT_FOUND);

    let rejected_body = workload_application
        .clone()
        .oneshot(
            Request::post("/v1/workload/exchange")
                .header(header::AUTHORIZATION, "Bearer projected-source-token")
                .body(Body::from(r#"{"roles":["attacker"]}"#))?,
        )
        .await?;
    assert_eq!(rejected_body.status(), StatusCode::BAD_REQUEST);

    let missing_bearer = workload_application
        .clone()
        .oneshot(Request::post("/v1/workload/exchange").body(Body::empty())?)
        .await?;
    assert_eq!(missing_bearer.status(), StatusCode::UNAUTHORIZED);

    let workload_response = workload_application
        .clone()
        .oneshot(
            Request::post("/v1/workload/exchange")
                .header(header::AUTHORIZATION, "Bearer projected-source-token")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(workload_response.status(), StatusCode::OK);
    assert_eq!(
        workload_response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    let workload_response: serde_json::Value =
        serde_json::from_slice(&workload_response.into_body().collect().await?.to_bytes())?;
    assert_eq!(workload_response["token_type"], "Bearer");
    assert_eq!(workload_response["expires_in"], 120);
    assert_eq!(
        jsonwebtoken::decode_header(
            workload_response["access_token"]
                .as_str()
                .ok_or("missing workload access token")?
        )?
        .alg,
        Algorithm::RS256
    );

    let github_assertion = signed_github_assertion(&claims(), &github_encoding)?;
    let github_response = public_application
        .oneshot(
            Request::post("/v1/exchange")
                .header(header::AUTHORIZATION, format!("Bearer {github_assertion}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(github_response.status(), StatusCode::OK);
    let github_response: serde_json::Value =
        serde_json::from_slice(&github_response.into_body().collect().await?.to_bytes())?;
    assert_eq!(
        jsonwebtoken::decode_header(
            github_response["access_token"]
                .as_str()
                .ok_or("missing GitHub access token")?
        )?
        .alg,
        Algorithm::ES256
    );
    Ok(())
}
