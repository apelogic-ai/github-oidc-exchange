use std::{sync::Arc, sync::atomic::Ordering};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::{
    IDENTITY_CONTRACT, POLICY_VERSION, SOURCE_AUTH_IDENTITY_CONTRACT, SOURCE_AUTH_POLICY_VERSION,
    browser_hop1::{BrowserHop1ExchangeError, BrowserHop1ExchangeService},
    keys::KeyRing,
    replay::ReplayLedger,
    service::{ExchangeError, ExchangeService},
    workload::{
        ReviewError, ReviewedWorkload, TokenReviewer, WorkloadExchangeError,
        WorkloadExchangeService,
    },
};

#[derive(Clone)]
struct AppState<L, R> {
    service: Arc<ExchangeService<L>>,
    workload: Option<Arc<WorkloadExchangeService<R>>>,
}

#[derive(Clone)]
struct WorkloadAppState<R, B> {
    workload: Arc<WorkloadExchangeService<R>>,
    browser_hop1: Option<Arc<BrowserHop1ExchangeService<B>>>,
}

pub fn router<L: ReplayLedger + Clone + 'static>(service: ExchangeService<L>) -> Router {
    build_router(AppState::<L, DisabledReviewer> {
        service: Arc::new(service),
        workload: None,
    })
}

pub fn separated_routers_with_workload<
    L: ReplayLedger + Clone + 'static,
    R: TokenReviewer + Clone + 'static,
>(
    service: ExchangeService<L>,
    workload: WorkloadExchangeService<R>,
) -> (Router, Router) {
    separated_routers_with_workload_and_browser::<L, R, crate::replay::KubernetesLeaseReplayLedger>(
        service, workload, None,
    )
}

pub fn separated_routers_with_workload_and_browser<
    L: ReplayLedger + Clone + 'static,
    R: TokenReviewer + Clone + 'static,
    B: ReplayLedger + Clone + 'static,
>(
    service: ExchangeService<L>,
    workload: WorkloadExchangeService<R>,
    browser_hop1: Option<BrowserHop1ExchangeService<B>>,
) -> (Router, Router) {
    let workload = Arc::new(workload);
    let state = AppState {
        service: Arc::new(service),
        workload: Some(workload.clone()),
    };
    let workload_state = WorkloadAppState {
        workload,
        browser_hop1: browser_hop1.map(Arc::new),
    };
    (build_router(state), build_workload_router(workload_state))
}

fn build_router<L: ReplayLedger + Clone + 'static, R: TokenReviewer + Clone + 'static>(
    state: AppState<L, R>,
) -> Router {
    let application = Router::new()
        .route("/.well-known/openid-configuration", get(discovery::<L, R>))
        .route(
            "/.well-known/oauth-authorization-server",
            get(discovery::<L, R>),
        )
        .route("/jwks.json", get(jwks::<L, R>))
        .route("/v1/exchange", post(exchange::<L, R>))
        .route("/healthz", get(no_content))
        .route("/readyz", get(no_content))
        .route("/metrics", get(metrics::<L, R>))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            header::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            header::HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            header::HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        ));
    application
        .layer(DefaultBodyLimit::max(1024))
        .with_state(state)
}

fn build_workload_router<R: TokenReviewer + Clone + 'static, B: ReplayLedger + Clone + 'static>(
    state: WorkloadAppState<R, B>,
) -> Router {
    let routes = Router::new()
        .route("/v1/workload/exchange", post(workload_exchange::<R, B>))
        .route("/healthz", get(no_content))
        .route("/readyz", get(no_content))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            header::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            header::HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CONTENT_SECURITY_POLICY,
            header::HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        ))
        .layer(DefaultBodyLimit::max(8 * 1024));
    let routes = if state.browser_hop1.is_some() {
        routes.route(
            "/v1/browser-hop1/exchange",
            post(browser_hop1_exchange::<R, B>),
        )
    } else {
        routes
    };
    routes.with_state(state)
}

async fn browser_hop1_exchange<
    R: TokenReviewer + Clone + 'static,
    B: ReplayLedger + Clone + 'static,
>(
    State(state): State<WorkloadAppState<R, B>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(browser_hop1) = state.browser_hop1 else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/jwt")
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Some(workload_assertion) = bearer_assertion(&headers) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let assertion = match std::str::from_utf8(&body) {
        Ok(assertion) if !assertion.is_empty() => assertion,
        _ => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let reviewed = match state
        .workload
        .reviewer
        .review(
            workload_assertion.to_owned(),
            state.workload.input_audience.clone(),
        )
        .await
    {
        Ok(reviewed) => reviewed,
        Err(ReviewError::Invalid) => return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token"),
        Err(ReviewError::Unavailable) => {
            return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
        }
    };
    match browser_hop1.exchange(&reviewed.username, assertion).await {
        Ok(token) => token_response(token, browser_hop1.token_ttl.as_secs()),
        Err(BrowserHop1ExchangeError::Unauthorized) => {
            oauth_error(StatusCode::UNAUTHORIZED, "invalid_token")
        }
        Err(BrowserHop1ExchangeError::Unavailable) => {
            oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
    }
}

async fn discovery<L: ReplayLedger + Clone + 'static, R: TokenReviewer + Clone + 'static>(
    State(state): State<AppState<L, R>>,
) -> impl IntoResponse {
    let algorithms = if state.workload.is_some() {
        vec!["ES256", "RS256"]
    } else {
        vec!["ES256"]
    };
    Json(serde_json::json!({
        "issuer": state.service.issuer,
        "jwks_uri": format!("{}/jwks.json", state.service.issuer),
        "token_endpoint": format!("{}/v1/exchange", state.service.issuer),
        "github_oidc_exchange_endpoint": format!("{}/v1/exchange", state.service.issuer),
        "github_oidc_audience": state.service.verifier.audience(),
        "identity_contracts_supported": [IDENTITY_CONTRACT, SOURCE_AUTH_IDENTITY_CONTRACT],
        "policy_versions_supported": [POLICY_VERSION, SOURCE_AUTH_POLICY_VERSION],
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": algorithms
    }))
}

async fn jwks<L: ReplayLedger + Clone + 'static, R: TokenReviewer + Clone + 'static>(
    State(state): State<AppState<L, R>>,
) -> impl IntoResponse {
    let mut keys = state.service.keys.jwks();
    if let Some(workload) = &state.workload {
        keys.extend(workload.keys.jwks());
    }
    Json(keys)
}

async fn exchange<L: ReplayLedger + Clone + 'static, R: TokenReviewer + Clone + 'static>(
    State(state): State<AppState<L, R>>,
    headers: HeaderMap,
) -> Response {
    let Some(assertion) = bearer_assertion(&headers) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    match state.service.exchange(assertion).await {
        Ok(token) => token_response(token, state.service.token_ttl.as_secs()),
        Err(ExchangeError::Unauthorized) => oauth_error(StatusCode::UNAUTHORIZED, "invalid_token"),
        Err(ExchangeError::Unavailable) => {
            oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
    }
}

async fn no_content() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn metrics<L: ReplayLedger + Clone + 'static, R: TokenReviewer + Clone + 'static>(
    State(state): State<AppState<L, R>>,
) -> String {
    let metrics = &state.service.metrics;
    let mut output = format!(
        "github_oidc_exchange_requests_total {}\n\
         github_oidc_exchange_issued_total {}\n\
         github_oidc_exchange_denied_total {}\n\
         github_oidc_exchange_replayed_total {}\n\
         github_oidc_exchange_errors_total {}\n",
        metrics.requests.load(Ordering::Relaxed),
        metrics.issued.load(Ordering::Relaxed),
        metrics.denied.load(Ordering::Relaxed),
        metrics.replayed.load(Ordering::Relaxed),
        metrics.errors.load(Ordering::Relaxed),
    );
    if let Some(workload) = state.workload {
        output.push_str(&format!(
            "github_oidc_exchange_workload_requests_total {}\n\
             github_oidc_exchange_workload_issued_total {}\n\
             github_oidc_exchange_workload_denied_total {}\n\
             github_oidc_exchange_workload_errors_total {}\n",
            workload.metrics.requests.load(Ordering::Relaxed),
            workload.metrics.issued.load(Ordering::Relaxed),
            workload.metrics.denied.load(Ordering::Relaxed),
            workload.metrics.errors.load(Ordering::Relaxed),
        ));
    }
    output
}

async fn workload_exchange<
    R: TokenReviewer + Clone + 'static,
    B: ReplayLedger + Clone + 'static,
>(
    State(state): State<WorkloadAppState<R, B>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !body.is_empty() {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Some(assertion) = bearer_assertion(&headers) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let workload = state.workload;
    match workload.exchange(assertion).await {
        Ok(token) => token_response(token, workload.token_ttl.as_secs()),
        Err(WorkloadExchangeError::Unauthorized) => {
            oauth_error(StatusCode::UNAUTHORIZED, "invalid_token")
        }
        Err(WorkloadExchangeError::Unavailable) => {
            oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
    }
}

fn bearer_assertion(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn token_response(token: String, expires_in: u64) -> Response {
    let mut response = Json(TokenResponse {
        access_token: token,
        token_type: "Bearer",
        expires_in,
    })
    .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
}

fn oauth_error(status: StatusCode, code: &'static str) -> Response {
    let mut response = (status, Json(serde_json::json!({ "error": code }))).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[derive(Clone)]
struct DisabledReviewer;

impl TokenReviewer for DisabledReviewer {
    async fn review(
        &self,
        _token: String,
        _audience: String,
    ) -> Result<ReviewedWorkload, ReviewError> {
        Err(ReviewError::Unavailable)
    }
}

#[allow(dead_code)]
fn _assert_keyring_is_send_sync(_: Arc<KeyRing>) {}
