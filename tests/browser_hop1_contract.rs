use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration as ChronoDuration, Utc};
use github_oidc_exchange::{
    KEYRING_VERSION,
    browser_hop1::{
        BROWSER_HOP1_ISSUER_ROLE, BrowserHop1ExchangeError, BrowserHop1ExchangeService,
        BrowserHop1Operation, BrowserHop1RequestClaims, StewardBrowserAssertionVerifier,
    },
    github::GitHubVerifier,
    http::separated_routers_with_workload_and_browser,
    keys::KeyRing,
    policy::Policy,
    replay::MemoryReplayLedger,
    service::{ExchangeService, Metrics},
    workload::{
        ReviewError, ReviewedWorkload, TokenReviewer, WorkloadExchangeService, WorkloadIdentity,
        WorkloadMetrics, WorkloadPolicy,
    },
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, decode, encode};
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint, pkcs8::EncodePrivateKey};
use tempfile::NamedTempFile;
use tower::ServiceExt;

const IDENTITY_ISSUER: &str = "https://identity.example.test";
const ASSERTION_ISSUER: &str = "https://steward.example.test";
const ASSERTION_AUDIENCE: &str = "identity-browser-hop1";
const MCP_RESOURCE: &str = "https://mcp.example.test/mcp";
const CANONICAL_USER: &str = "usr_0123456789abcdef0123456789abcdef";

#[test]
fn browser_hop1_role_is_fixed_and_not_a_caller_supplied_scope() {
    // A browser session must not be accepted directly by Identity: only a Steward-signed, bounded
    // request plus an exact workload caller can yield an MCP audience token.
    assert_eq!(BROWSER_HOP1_ISSUER_ROLE, "browser-hop1-issuer");
}

#[tokio::test]
async fn browser_hop1_uses_a_steward_attestation_once_and_emits_only_the_canonical_mcp_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let (steward_key, verifier) = steward_assertion_verifier()?;
    let service = BrowserHop1ExchangeService {
        verifier,
        policy: Arc::new(WorkloadPolicy {
            version: github_oidc_exchange::WORKLOAD_POLICY_VERSION.to_owned(),
            identities: vec![WorkloadIdentity {
                username: "system:serviceaccount:steward:steward-apiserver".to_owned(),
                subject: "kubernetes:serviceaccount:steward:steward-apiserver".to_owned(),
                roles: vec![BROWSER_HOP1_ISSUER_ROLE.to_owned()],
            }],
        }),
        ledger: Arc::new(MemoryReplayLedger::default()),
        keys: Arc::new(identity_keyring()?),
        issuer: IDENTITY_ISSUER.to_owned(),
        output_audience: MCP_RESOURCE.to_owned(),
        token_ttl: Duration::from_secs(60),
        metrics: Arc::default(),
    };
    let assertion = signed_assertion(&steward_key, request_claims())?;
    let token = service
        .exchange(
            "system:serviceaccount:steward:steward-apiserver",
            &assertion,
        )
        .await?;
    let output = decode_output(&token, &service.keys)?;
    assert_eq!(output["iss"], IDENTITY_ISSUER);
    assert_eq!(output["sub"], CANONICAL_USER);
    assert_eq!(output["aud"], serde_json::json!([MCP_RESOURCE]));
    assert_eq!(output["email"], "engineer@example.test");
    assert_eq!(output["email_verified"], true);
    assert_eq!(output["operation"], "github_oauth_connect");
    assert_eq!(
        output["operation_id"],
        "op_0123456789abcdef0123456789abcdef"
    );
    assert!(output.get("groups").is_none());
    assert!(output.get("service_principal").is_none());

    assert_eq!(
        service
            .exchange(
                "system:serviceaccount:steward:steward-apiserver",
                &assertion
            )
            .await,
        Err(BrowserHop1ExchangeError::Unauthorized)
    );
    Ok(())
}

#[tokio::test]
async fn browser_hop1_rejects_a_browser_cookie_surrogate_wrong_workload_or_unbounded_operation()
-> Result<(), Box<dyn std::error::Error>> {
    let (steward_key, verifier) = steward_assertion_verifier()?;
    let service = BrowserHop1ExchangeService {
        verifier,
        policy: Arc::new(WorkloadPolicy {
            version: github_oidc_exchange::WORKLOAD_POLICY_VERSION.to_owned(),
            identities: vec![WorkloadIdentity {
                username: "system:serviceaccount:steward:steward-apiserver".to_owned(),
                subject: "kubernetes:serviceaccount:steward:steward-apiserver".to_owned(),
                roles: vec![],
            }],
        }),
        ledger: Arc::new(MemoryReplayLedger::default()),
        keys: Arc::new(identity_keyring()?),
        issuer: IDENTITY_ISSUER.to_owned(),
        output_audience: MCP_RESOURCE.to_owned(),
        token_ttl: Duration::from_secs(60),
        metrics: Arc::default(),
    };
    let assertion = signed_assertion(&steward_key, request_claims())?;
    assert_eq!(
        service
            .exchange(
                "system:serviceaccount:steward:steward-apiserver",
                &assertion
            )
            .await,
        Err(BrowserHop1ExchangeError::Unauthorized)
    );
    assert_eq!(
        service
            .exchange("browser-session-cookie-value", &assertion)
            .await,
        Err(BrowserHop1ExchangeError::Unauthorized)
    );

    let mut invalid = request_claims();
    invalid.operation = BrowserHop1Operation::Other;
    let invalid = signed_assertion(&steward_key, invalid)?;
    assert_eq!(
        service
            .exchange("system:serviceaccount:steward:steward-apiserver", &invalid)
            .await,
        Err(BrowserHop1ExchangeError::Unauthorized)
    );
    Ok(())
}

#[tokio::test]
async fn browser_hop1_route_is_internal_tls_listener_only_and_requires_the_signed_jwt_media_type()
-> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (steward_key, verifier) = steward_assertion_verifier()?;
    let browser = BrowserHop1ExchangeService {
        verifier,
        policy: Arc::new(WorkloadPolicy {
            version: github_oidc_exchange::WORKLOAD_POLICY_VERSION.to_owned(),
            identities: vec![WorkloadIdentity {
                username: "system:serviceaccount:steward:steward-apiserver".to_owned(),
                subject: "kubernetes:serviceaccount:steward:steward-apiserver".to_owned(),
                roles: vec![BROWSER_HOP1_ISSUER_ROLE.to_owned()],
            }],
        }),
        ledger: Arc::new(MemoryReplayLedger::default()),
        keys: Arc::new(identity_keyring()?),
        issuer: IDENTITY_ISSUER.to_owned(),
        output_audience: MCP_RESOURCE.to_owned(),
        token_ttl: Duration::from_secs(60),
        metrics: Arc::default(),
    };
    let workload = WorkloadExchangeService {
        reviewer: StewardApiReviewer,
        policy: browser.policy.clone(),
        keys: Arc::new(github_oidc_exchange::keys::RsaKeyRing::load(
            rsa_keyring_file()?.path(),
            Utc::now(),
        )?),
        issuer: IDENTITY_ISSUER.to_owned(),
        input_audience: "identity-workload".to_owned(),
        output_audience: "openshell-api".to_owned(),
        token_ttl: Duration::from_secs(120),
        metrics: Arc::new(WorkloadMetrics::default()),
    };
    let public = ExchangeService {
        verifier: GitHubVerifier::new("unused-test-audience".to_owned())?,
        policy: Arc::new(empty_policy()),
        ledger: Arc::new(MemoryReplayLedger::default()),
        keys: browser.keys.clone(),
        issuer: IDENTITY_ISSUER.to_owned(),
        output_audience: "steward-task-api".to_owned(),
        token_ttl: Duration::from_secs(120),
        metrics: Arc::new(Metrics::default()),
    };
    let (public, internal) =
        separated_routers_with_workload_and_browser(public, workload, Some(browser));
    let assertion = signed_assertion(&steward_key, request_claims())?;
    let public_response = public
        .oneshot(Request::post("/v1/browser-hop1/exchange").body(Body::empty())?)
        .await?;
    assert_eq!(public_response.status(), StatusCode::NOT_FOUND);
    let bad_media_type = internal
        .clone()
        .oneshot(
            Request::post("/v1/browser-hop1/exchange")
                .header(header::AUTHORIZATION, "Bearer projected-steward-token")
                .body(Body::from(assertion.clone()))?,
        )
        .await?;
    assert_eq!(bad_media_type.status(), StatusCode::BAD_REQUEST);
    let response = internal
        .oneshot(
            Request::post("/v1/browser-hop1/exchange")
                .header(header::AUTHORIZATION, "Bearer projected-steward-token")
                .header(header::CONTENT_TYPE, "application/jwt")
                .body(Body::from(assertion))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    Ok(())
}

#[derive(Clone)]
struct StewardApiReviewer;

impl TokenReviewer for StewardApiReviewer {
    async fn review(
        &self,
        token: String,
        audience: String,
    ) -> Result<ReviewedWorkload, ReviewError> {
        if token == "projected-steward-token" && audience == "identity-workload" {
            Ok(ReviewedWorkload {
                username: "system:serviceaccount:steward:steward-apiserver".to_owned(),
            })
        } else {
            Err(ReviewError::Invalid)
        }
    }
}

fn empty_policy() -> Policy {
    Policy {
        version: github_oidc_exchange::POLICY_VERSION.to_owned(),
        service_group: "agents.apelogic.ai/service-principal:unused".to_owned(),
        acting_group_prefix: "agents.apelogic.ai/acting-user:".to_owned(),
        bootstrap_group: "agents.apelogic.ai/service-envelope-bootstrap:unused".to_owned(),
        allowed_email_domains: vec!["example.test".to_owned()],
        repositories: vec![],
        actors: Default::default(),
    }
}

fn rsa_keyring_file() -> Result<NamedTempFile, Box<dyn std::error::Error>> {
    let now = Utc::now();
    let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 3072)?;
    let pem = rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(&private, rsa::pkcs8::LineEnding::LF)?;
    let document = serde_json::json!({
        "version": github_oidc_exchange::RSA_KEYRING_VERSION,
        "current_kid": "workload-current",
        "keys": [{
            "kid": "workload-current", "private_key_pkcs8_pem": pem.to_string(),
            "not_before": (now - ChronoDuration::minutes(1)).to_rfc3339(),
            "not_after": (now + ChronoDuration::minutes(5)).to_rfc3339()
        }]
    });
    let file = NamedTempFile::new()?;
    std::fs::write(file.path(), serde_json::to_vec(&document)?)?;
    Ok(file)
}

fn request_claims() -> BrowserHop1RequestClaims {
    let now = Utc::now().timestamp();
    BrowserHop1RequestClaims {
        iss: ASSERTION_ISSUER.to_owned(),
        sub: CANONICAL_USER.to_owned(),
        aud: ASSERTION_AUDIENCE.to_owned(),
        exp: now + 45,
        iat: now,
        nbf: now - 1,
        jti: "browser-hop1-assertion-1".to_owned(),
        email: "engineer@example.test".to_owned(),
        email_verified: true,
        operation: BrowserHop1Operation::GithubOauthConnect,
        operation_id: "op_0123456789abcdef0123456789abcdef".to_owned(),
    }
}

fn signed_assertion(
    encoding: &EncodingKey,
    claims: BrowserHop1RequestClaims,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("steward-browser-hop1-current".to_owned());
    header.typ = Some("JWT".to_owned());
    Ok(encode(&header, &claims, encoding)?)
}

fn steward_assertion_verifier()
-> Result<(EncodingKey, StewardBrowserAssertionVerifier), Box<dyn std::error::Error>> {
    let secret = SecretKey::random(&mut rand_core::OsRng);
    let public = secret.public_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(public.x().ok_or("missing EC x coordinate")?);
    let y = URL_SAFE_NO_PAD.encode(public.y().ok_or("missing EC y coordinate")?);
    let jwks = serde_json::json!({
        "keys": [{
            "kty": "EC", "use": "sig", "alg": "ES256", "kid": "steward-browser-hop1-current",
            "crv": "P-256", "x": x, "y": y
        }]
    });
    let file = NamedTempFile::new()?;
    std::fs::write(file.path(), serde_json::to_vec(&jwks)?)?;
    let verifier = StewardBrowserAssertionVerifier::load(
        file.path(),
        ASSERTION_ISSUER.to_owned(),
        ASSERTION_AUDIENCE.to_owned(),
    )?;
    let private = secret.to_pkcs8_der()?;
    Ok((EncodingKey::from_ec_der(private.as_bytes()), verifier))
}

fn identity_keyring() -> Result<KeyRing, Box<dyn std::error::Error>> {
    let now = Utc::now();
    let file = NamedTempFile::new()?;
    let seed = STANDARD.encode([7_u8; 32]);
    let document = serde_json::json!({
        "version": KEYRING_VERSION,
        "current_kid": "identity-current",
        "keys": [{
            "kid": "identity-current", "seed": seed,
            "not_before": (now - ChronoDuration::minutes(1)).to_rfc3339(),
            "not_after": (now + ChronoDuration::minutes(5)).to_rfc3339()
        }]
    });
    std::fs::write(file.path(), serde_json::to_vec(&document)?)?;
    Ok(KeyRing::load(file.path(), now)?)
}

fn decode_output(
    token: &str,
    keys: &KeyRing,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let jwks = serde_json::to_value(keys.jwks())?;
    let set: jsonwebtoken::jwk::JwkSet = serde_json::from_value(jwks)?;
    let key = jsonwebtoken::DecodingKey::from_jwk(&set.keys[0])?;
    let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
    validation.validate_aud = false;
    validation.set_issuer(&[IDENTITY_ISSUER]);
    Ok(decode::<serde_json::Value>(token, &key, &validation)?.claims)
}
