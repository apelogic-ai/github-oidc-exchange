use std::{
    collections::HashSet,
    env,
    fs::{self, File},
    future::Future,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use jsonwebtoken::get_current_timestamp;
use reqwest::{Certificate, Client, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{WORKLOAD_IDENTITY_CONTRACT, WORKLOAD_POLICY_VERSION, keys::RsaKeyRing};

const MAX_ASSERTION_BYTES: usize = 32 * 1024;
const TOKEN_REVIEW_PATH: &str = "/apis/authentication.k8s.io/v1/tokenreviews";
const SERVICE_ACCOUNT_PREFIX: &str = "system:serviceaccount:";
const SUBJECT_PREFIX: &str = "kubernetes:serviceaccount:";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadPolicy {
    pub version: String,
    pub identities: Vec<WorkloadIdentity>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentity {
    pub username: String,
    pub subject: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WorkloadPolicyError {
    #[error("workload policy is invalid: {0}")]
    Invalid(String),
    #[error("workload identity is not authorized")]
    Unauthorized,
}

impl WorkloadPolicy {
    pub fn load(path: &Path) -> Result<Self, WorkloadPolicyError> {
        let file = File::open(path).map_err(|error| invalid_policy(&error.to_string()))?;
        let policy: Self =
            serde_json::from_reader(file).map_err(|error| invalid_policy(&error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), WorkloadPolicyError> {
        if self.version != WORKLOAD_POLICY_VERSION || self.identities.is_empty() {
            return Err(invalid_policy("unsupported or empty workload policy"));
        }
        let mut usernames = HashSet::new();
        let mut subjects = HashSet::new();
        for identity in &self.identities {
            let Some(suffix) = identity.username.strip_prefix(SERVICE_ACCOUNT_PREFIX) else {
                return Err(invalid_policy(
                    "usernames must be exact Kubernetes service-account usernames",
                ));
            };
            let mut segments = suffix.split(':');
            let (Some(namespace), Some(service_account), None) =
                (segments.next(), segments.next(), segments.next())
            else {
                return Err(invalid_policy(
                    "usernames must contain one namespace and service-account name",
                ));
            };
            if namespace.is_empty()
                || service_account.is_empty()
                || identity.username.contains('*')
                || identity.subject != format!("{SUBJECT_PREFIX}{namespace}:{service_account}")
                || !usernames.insert(identity.username.as_str())
                || !subjects.insert(identity.subject.as_str())
            {
                return Err(invalid_policy(
                    "workload usernames and subjects must be exact, unique, and corresponding",
                ));
            }
            let unique_roles: HashSet<&str> = identity.roles.iter().map(String::as_str).collect();
            if identity.roles.is_empty()
                || unique_roles.len() != identity.roles.len()
                || identity.roles.iter().any(|role| {
                    role.is_empty() || role.contains(char::is_whitespace) || role.contains('*')
                })
            {
                return Err(invalid_policy(
                    "roles must contain unique non-empty exact values",
                ));
            }
        }
        Ok(())
    }

    pub fn authorize(&self, username: &str) -> Result<WorkloadIdentity, WorkloadPolicyError> {
        let mut matching = self
            .identities
            .iter()
            .filter(|identity| identity.username == username);
        let mut identity = matching
            .next()
            .cloned()
            .ok_or(WorkloadPolicyError::Unauthorized)?;
        if matching.next().is_some() {
            return Err(WorkloadPolicyError::Unauthorized);
        }
        identity.roles.sort();
        Ok(identity)
    }
}

fn invalid_policy(message: &str) -> WorkloadPolicyError {
    WorkloadPolicyError::Invalid(message.to_owned())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewedWorkload {
    pub username: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReviewError {
    #[error("workload token is invalid")]
    Invalid,
    #[error("Kubernetes TokenReview is unavailable")]
    Unavailable,
}

pub trait TokenReviewer: Send + Sync + 'static {
    fn review(
        &self,
        token: String,
        audience: String,
    ) -> impl Future<Output = Result<ReviewedWorkload, ReviewError>> + Send;
}

#[derive(Clone)]
pub struct KubernetesTokenReviewer {
    client: Client,
    endpoint: Url,
    credential_file: PathBuf,
}

impl KubernetesTokenReviewer {
    pub fn in_cluster() -> Result<Self, ReviewError> {
        let host = env::var("KUBERNETES_SERVICE_HOST").map_err(|_| ReviewError::Unavailable)?;
        if host.is_empty() || host.contains(['/', '?', '#']) {
            return Err(ReviewError::Unavailable);
        }
        let port = env::var("KUBERNETES_SERVICE_PORT_HTTPS").unwrap_or_else(|_| "443".to_owned());
        if port.parse::<u16>().is_err() {
            return Err(ReviewError::Unavailable);
        }
        let authority = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        let endpoint = Url::parse(&format!("https://{authority}:{port}{TOKEN_REVIEW_PATH}"))
            .map_err(|_| ReviewError::Unavailable)?;
        let ca_file = env::var("KUBERNETES_CA_CERTIFICATE_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
            });
        let credential_file = env::var("KUBERNETES_SERVICE_ACCOUNT_TOKEN_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token")
            });
        let certificate = fs::read(ca_file)
            .map_err(|_| ReviewError::Unavailable)
            .and_then(|pem| Certificate::from_pem(&pem).map_err(|_| ReviewError::Unavailable))?;
        let client = Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .add_root_certificate(certificate)
            .build()
            .map_err(|_| ReviewError::Unavailable)?;
        Ok(Self {
            client,
            endpoint,
            credential_file,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenReviewRequest<'a> {
    api_version: &'static str,
    kind: &'static str,
    spec: TokenReviewSpec<'a>,
}

#[derive(Serialize)]
struct TokenReviewSpec<'a> {
    token: &'a str,
    audiences: [&'a str; 1],
}

#[derive(Deserialize)]
struct TokenReviewResponse {
    status: Option<TokenReviewStatus>,
}

#[derive(Deserialize)]
struct TokenReviewStatus {
    authenticated: Option<bool>,
    audiences: Option<Vec<String>>,
    user: Option<TokenReviewUser>,
}

#[derive(Deserialize)]
struct TokenReviewUser {
    username: Option<String>,
}

impl TokenReviewer for KubernetesTokenReviewer {
    async fn review(
        &self,
        token: String,
        audience: String,
    ) -> Result<ReviewedWorkload, ReviewError> {
        if token.is_empty() || token.len() > MAX_ASSERTION_BYTES || audience.is_empty() {
            return Err(ReviewError::Invalid);
        }
        let credential =
            fs::read_to_string(&self.credential_file).map_err(|_| ReviewError::Unavailable)?;
        let credential = credential.trim();
        if credential.is_empty() {
            return Err(ReviewError::Unavailable);
        }
        let response = self
            .client
            .post(self.endpoint.clone())
            .bearer_auth(credential)
            .json(&TokenReviewRequest {
                api_version: "authentication.k8s.io/v1",
                kind: "TokenReview",
                spec: TokenReviewSpec {
                    token: &token,
                    audiences: [&audience],
                },
            })
            .send()
            .await
            .map_err(|_| ReviewError::Unavailable)?
            .error_for_status()
            .map_err(|_| ReviewError::Unavailable)?
            .json::<TokenReviewResponse>()
            .await
            .map_err(|_| ReviewError::Unavailable)?;
        validate_token_review(response, &audience)
    }
}

fn validate_token_review(
    response: TokenReviewResponse,
    audience: &str,
) -> Result<ReviewedWorkload, ReviewError> {
    let status = response.status.ok_or(ReviewError::Invalid)?;
    let exact_audience = matches!(
        status.audiences.as_deref(),
        Some([reviewed_audience]) if reviewed_audience == audience
    );
    if status.authenticated != Some(true) || !exact_audience {
        return Err(ReviewError::Invalid);
    }
    let username = status
        .user
        .and_then(|user| user.username)
        .filter(|username| !username.is_empty())
        .ok_or(ReviewError::Invalid)?;
    Ok(ReviewedWorkload { username })
}

#[derive(Clone)]
pub struct WorkloadExchangeService<R> {
    pub reviewer: R,
    pub policy: Arc<WorkloadPolicy>,
    pub keys: Arc<RsaKeyRing>,
    pub issuer: String,
    pub input_audience: String,
    pub output_audience: String,
    pub token_ttl: Duration,
    pub metrics: Arc<WorkloadMetrics>,
}

#[derive(Default)]
pub struct WorkloadMetrics {
    pub requests: AtomicU64,
    pub issued: AtomicU64,
    pub denied: AtomicU64,
    pub errors: AtomicU64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WorkloadExchangeError {
    #[error("workload identity assertion was rejected")]
    Unauthorized,
    #[error("workload identity service is unavailable")]
    Unavailable,
}

#[derive(Serialize)]
struct WorkloadOutputClaims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    exp: u64,
    iat: u64,
    nbf: u64,
    jti: String,
    roles: Vec<String>,
    identity_contract: &'static str,
}

impl<R: TokenReviewer> WorkloadExchangeService<R> {
    pub async fn exchange(&self, assertion: &str) -> Result<String, WorkloadExchangeError> {
        self.metrics.requests.fetch_add(1, Ordering::Relaxed);
        let reviewed = self
            .reviewer
            .review(assertion.to_owned(), self.input_audience.clone())
            .await
            .map_err(|error| match error {
                ReviewError::Invalid => {
                    self.deny("token_review_rejected");
                    WorkloadExchangeError::Unauthorized
                }
                ReviewError::Unavailable => {
                    self.fail("token_review_unavailable");
                    WorkloadExchangeError::Unavailable
                }
            })?;
        let identity = self.policy.authorize(&reviewed.username).map_err(|_| {
            self.deny("workload_unmapped");
            WorkloadExchangeError::Unauthorized
        })?;
        let now = get_current_timestamp();
        let token = self
            .keys
            .sign(&WorkloadOutputClaims {
                iss: self.issuer.clone(),
                sub: identity.subject,
                aud: vec![self.output_audience.clone()],
                exp: now + self.token_ttl.as_secs(),
                iat: now,
                nbf: now.saturating_sub(5),
                jti: Uuid::new_v4().to_string(),
                roles: identity.roles,
                identity_contract: WORKLOAD_IDENTITY_CONTRACT,
            })
            .map_err(|_| {
                self.fail("signing_unavailable");
                WorkloadExchangeError::Unavailable
            })?;
        self.metrics.issued.fetch_add(1, Ordering::Relaxed);
        info!(
            event = "workload_exchange_issued",
            source_username_hash = hash_identifier(&reviewed.username),
            "workload identity exchange issued"
        );
        Ok(token)
    }

    fn deny(&self, reason: &str) {
        self.metrics.denied.fetch_add(1, Ordering::Relaxed);
        warn!(
            event = "workload_exchange_denied",
            reason, "workload identity exchange rejected"
        );
    }

    fn fail(&self, reason: &str) {
        self.metrics.errors.fetch_add(1, Ordering::Relaxed);
        warn!(
            event = "workload_exchange_failed",
            reason, "workload identity exchange unavailable"
        );
    }
}

fn hash_identifier(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUDIENCE: &str = "example-workload-exchange";

    fn response(authenticated: bool, audiences: Vec<&str>, username: Option<&str>) -> String {
        serde_json::json!({
            "status": {
                "authenticated": authenticated,
                "audiences": audiences,
                "user": {"username": username}
            }
        })
        .to_string()
    }

    #[test]
    fn token_review_request_uses_exact_single_audience() -> Result<(), Box<dyn std::error::Error>> {
        let request = TokenReviewRequest {
            api_version: "authentication.k8s.io/v1",
            kind: "TokenReview",
            spec: TokenReviewSpec {
                token: "source-token",
                audiences: [AUDIENCE],
            },
        };
        assert_eq!(
            serde_json::to_value(request)?,
            serde_json::json!({
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenReview",
                "spec": {
                    "token": "source-token",
                    "audiences": [AUDIENCE]
                }
            })
        );
        Ok(())
    }

    #[test]
    fn token_review_response_requires_exact_audience_and_username()
    -> Result<(), Box<dyn std::error::Error>> {
        let accepted: TokenReviewResponse = serde_json::from_str(&response(
            true,
            vec![AUDIENCE],
            Some("system:serviceaccount:example:caller"),
        ))?;
        assert_eq!(
            validate_token_review(accepted, AUDIENCE)?,
            ReviewedWorkload {
                username: "system:serviceaccount:example:caller".to_owned()
            }
        );
        for rejected in [
            response(
                false,
                vec![AUDIENCE],
                Some("system:serviceaccount:example:caller"),
            ),
            response(
                true,
                vec!["wrong"],
                Some("system:serviceaccount:example:caller"),
            ),
            response(
                true,
                vec![AUDIENCE, "other"],
                Some("system:serviceaccount:example:caller"),
            ),
            response(true, vec![AUDIENCE], None),
            serde_json::json!({}).to_string(),
        ] {
            let document: TokenReviewResponse = serde_json::from_str(&rejected)?;
            assert_eq!(
                validate_token_review(document, AUDIENCE),
                Err(ReviewError::Invalid)
            );
        }
        Ok(())
    }
}
