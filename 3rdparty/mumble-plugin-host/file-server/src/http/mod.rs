//! HTTP routing - assembles the axum router with shared state.

use axum::extract::{DefaultBodyLimit, Request};
use axum::http::HeaderValue;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;

use crate::state::AppState;

pub mod admin;
pub mod auth;
pub mod capabilities;
pub mod common;
pub mod download;
pub mod emotes;
pub mod files_admin;
pub mod files_me;
pub mod me;
pub mod upload;

/// Small fixed overhead (boundary, headers, text fields) added on top of
/// `max_file_size_bytes` when sizing the axum body limit for the upload route.
const FORM_OVERHEAD_BYTES: u64 = 8 * 1024;

/// Injects `Cross-Origin-Resource-Policy: cross-origin` on every response
/// so that Chromium/WebKit allow the Tauri webview (a different origin) to
/// load file resources such as images and videos inline.  Without this header
/// the browser enforces the default same-site policy and blocks the load with
/// `ERR_BLOCKED_BY_RESPONSE.NotSameSite`.
async fn cross_origin_resource_policy(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let _ = resp.headers_mut().insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("cross-origin"),
    );
    resp
}

/// Logs every incoming HTTP request and the response status so we can
/// see in `docker logs` whether a stuck client request actually reached
/// the server.
///
/// Query strings are scrubbed (replaced with `?<scrubbed>`) before being
/// emitted because download URLs carry the HMAC signature and ticket
/// values that would otherwise be replayable from the access log.
async fn request_log(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let has_query = req.uri().query().is_some();
    let logged_uri = if has_query {
        format!("{path}?<scrubbed>")
    } else {
        path
    };
    let content_length = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    tracing::info!(%method, uri = %logged_uri, ?content_length, "http: request received");
    let started = std::time::Instant::now();
    let resp = next.run(req).await;
    tracing::info!(
        %method,
        uri = %logged_uri,
        status = resp.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "http: response sent"
    );
    resp
}

/// Build the axum router with all file-server routes wired up.
pub fn build_router(state: AppState) -> Router {
    // Axum's default body limit is 2 MB, which would reject uploads larger
    // than that before the handler even runs.  Override only the upload route
    // to allow up to the configured file-size cap (plus a small overhead for
    // the multipart envelope).
    let upload_body_limit = (state.config.max_file_size_bytes + FORM_OVERHEAD_BYTES) as usize;

    let cors = build_cors_layer(&state.config.allowed_origins);

    let admin_router = admin::router(&state);

    Router::new()
        .route(
            "/files",
            post(upload::upload).layer(DefaultBodyLimit::max(upload_body_limit)),
        )
        .route("/files/{file_id}", get(download::download))
        .route("/files/{file_id}/auth", post(auth::pre_auth))
        .route("/emotes", get(emotes::list).post(emotes::upload))
        .route("/emotes/{shortcode}", axum::routing::delete(emotes::delete))
        .route("/capabilities", get(capabilities::get))
        .merge(admin_router)
        .merge(files_admin::router())
        .merge(files_me::router())
        .merge(me::router())
        .layer(middleware::from_fn(request_log))
        .layer(middleware::from_fn(cross_origin_resource_policy))
        .layer(cors)
        .with_state(state)
}

/// Build a CORS layer.  When no origins are configured, browser-driven
/// cross-origin requests are denied (server-to-server callers and same-
/// origin requests still work).  Wildcard `*` is intentionally rejected
/// when `Authorization` is in the allow-list - the previous behavior of
/// `allow_origin(Any)` plus `allow_headers([AUTHORIZATION])` would have
/// let any website preflight admin endpoints (M-2).
fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    let mut layer = CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::DELETE,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])
        .expose_headers([axum::http::header::CONTENT_DISPOSITION]);

    let parsed: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    if !parsed.is_empty() {
        layer = layer.allow_origin(parsed);
    }
    layer
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests panic on failure"
    )]
    use super::*;

    #[test]
    fn cors_with_no_origins_omits_allow_origin() {
        // Should not panic - the layer is constructible with an empty
        // allow-origin list (which means "no cross-origin browser access").
        let _layer = build_cors_layer(&[]);
    }

    #[test]
    fn cors_parses_configured_origins() {
        let _layer = build_cors_layer(&[
            "https://chat.example.com".to_owned(),
            "https://admin.example.com".to_owned(),
        ]);
    }

    #[test]
    fn merge_same_path_disjoint_methods_does_not_panic() {
        use axum::routing::{delete, get};
        // The sibling-plugin (admin_token) GET/PUT and the dashboard
        // (session-JWT) DELETE both live at `/admin/documents/{name}` but in
        // separate routers; axum must merge the disjoint methods, not panic.
        let a =
            Router::<()>::new().route("/admin/documents/{name}", get(|| async {}).put(|| async {}));
        let b = Router::<()>::new().route("/admin/documents/{name}", delete(|| async {}));
        let _merged = a.merge(b);
    }
}
