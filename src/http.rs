use std::{sync::Arc, sync::atomic::Ordering};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::{
    keys::KeyRing,
    replay::ReplayLedger,
    service::{ExchangeError, ExchangeService},
};

#[derive(Clone)]
struct AppState<L> {
    service: Arc<ExchangeService<L>>,
}

pub fn router<L: ReplayLedger + Clone + 'static>(service: ExchangeService<L>) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery::<L>))
        .route("/jwks.json", get(jwks::<L>))
        .route("/v1/exchange", post(exchange::<L>))
        .route("/healthz", get(no_content))
        .route("/readyz", get(no_content))
        .route("/metrics", get(metrics::<L>))
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
        .with_state(AppState {
            service: Arc::new(service),
        })
}

async fn discovery<L: ReplayLedger + Clone + 'static>(
    State(state): State<AppState<L>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "issuer": state.service.issuer,
        "jwks_uri": format!("{}/jwks.json", state.service.issuer),
        "token_endpoint": format!("{}/v1/exchange", state.service.issuer),
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"]
    }))
}

async fn jwks<L: ReplayLedger + Clone + 'static>(
    State(state): State<AppState<L>>,
) -> impl IntoResponse {
    Json(state.service.keys.jwks())
}

async fn exchange<L: ReplayLedger + Clone + 'static>(
    State(state): State<AppState<L>>,
    headers: HeaderMap,
) -> Response {
    let assertion = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(assertion) = assertion else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    match state.service.exchange(assertion).await {
        Ok(token) => {
            let mut response = Json(TokenResponse {
                access_token: token,
                token_type: "Bearer",
                expires_in: state.service.token_ttl.as_secs(),
            })
            .into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            );
            response
        }
        Err(ExchangeError::Unauthorized) => oauth_error(StatusCode::UNAUTHORIZED, "invalid_token"),
        Err(ExchangeError::Unavailable) => {
            oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
    }
}

async fn no_content() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn metrics<L: ReplayLedger + Clone + 'static>(State(state): State<AppState<L>>) -> String {
    let metrics = &state.service.metrics;
    format!(
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
    )
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

#[allow(dead_code)]
fn _assert_keyring_is_send_sync(_: Arc<KeyRing>) {}
