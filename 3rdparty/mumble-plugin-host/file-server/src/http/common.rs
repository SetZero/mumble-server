//! Helpers shared by the upload / auth / download handlers.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Lightweight error wrapper that converts to a JSON error response with
/// a stable shape: `{"error": "<msg>"}`.
#[derive(Debug)]
pub struct ApiError {
    /// HTTP status code to return to the client.
    pub status: StatusCode,
    /// Human-readable message safe to surface to clients.
    pub message: String,
}

impl ApiError {
    /// Convenience constructor.
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// 400 Bad Request shorthand.
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, msg)
    }
    /// 401 Unauthorized shorthand.
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, msg)
    }
    /// 403 Forbidden shorthand.
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, msg)
    }
    /// 404 Not Found shorthand.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, msg)
    }
    /// 413 Payload Too Large shorthand.
    pub fn too_large(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, msg)
    }
    /// 429 Too Many Requests shorthand.
    pub fn too_many_requests(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, msg)
    }
    /// 500 Internal Server Error shorthand.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.message });
        (self.status, axum::Json(body)).into_response()
    }
}

/// Strip a `Bearer ` prefix from an `Authorization` header value.
pub fn parse_bearer(header: &str) -> Option<&str> {
    header.strip_prefix("Bearer ").or_else(|| header.strip_prefix("bearer "))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn parse_bearer_strips_prefix() {
        assert_eq!(parse_bearer("Bearer abc"), Some("abc"));
        assert_eq!(parse_bearer("bearer abc"), Some("abc"));
        assert_eq!(parse_bearer("Basic abc"), None);
        assert_eq!(parse_bearer(""), None);
    }
}
