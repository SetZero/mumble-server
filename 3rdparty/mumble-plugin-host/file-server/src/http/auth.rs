//! `POST /files/{id}/auth` - exchange a credential for a single-use ticket.
//!
//! This endpoint exists so passwords and session JWTs are sent in the
//! `Authorization` header instead of the GET URL. The returned ticket is
//! opaque, single-use, and short-lived (30 seconds), so leaking it is
//! harmless.

use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Serialize;
use std::net::SocketAddr;

use zeroize::Zeroizing;

use crate::auth::{verify_password, verify_session_jwt};
use crate::http::common::{parse_bearer, ApiError};
use crate::rate_limit::LimitDecision;
use crate::state::AppState;
use crate::storage::AccessMode;
use crate::tickets::DEFAULT_TICKET_TTL;

/// JSON body returned on successful authentication.
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    /// Opaque single-use ticket the client appends to the GET URL.
    pub ticket: String,
    /// Time-to-live of the ticket in seconds.
    pub ttl_seconds: u64,
}

/// Handler for `POST /files/{id}/auth`.
pub async fn pre_auth(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(file_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AuthResponse>, ApiError> {
    let peer_key = peer.ip().to_string();
    let window = state.config.auth_rate_limit_window;
    let max_failures = state.config.auth_rate_limit_max_failures;

    if matches!(
        state
            .auth_rate_limiter
            .check(&peer_key, window, max_failures),
        LimitDecision::Block
    ) {
        return Err(ApiError::too_many_requests(
            "too many failed authentication attempts; try again later",
        ));
    }

    let result = perform_auth(&state, &file_id, &headers);
    match result {
        Ok((cert_hash, enc_key)) => {
            state.auth_rate_limiter.clear(&peer_key);
            let ticket = state
                .tickets
                .issue(&file_id, DEFAULT_TICKET_TTL, cert_hash, enc_key);
            Ok(Json(AuthResponse {
                ticket,
                ttl_seconds: DEFAULT_TICKET_TTL.as_secs(),
            }))
        }
        Err(err) => {
            // Only count credential-failure-class errors (401/403); never
            // count the genuinely-user-error 400 / 404 / 5xx so a missing
            // file or malformed request can't lock somebody out.
            if matches!(
                err.status,
                axum::http::StatusCode::UNAUTHORIZED | axum::http::StatusCode::FORBIDDEN
            ) {
                state.auth_rate_limiter.record_failure(&peer_key, window);
            }
            Err(err)
        }
    }
}

/// On success returns `(cert_hash, enc_key)`: the authenticated identity (for
/// session mode) and the ephemeral file-decryption key (for encrypted
/// password files).
type AuthOutcome = (Option<String>, Option<Zeroizing<[u8; 32]>>);

fn perform_auth(
    state: &AppState,
    file_id: &str,
    headers: &HeaderMap,
) -> Result<AuthOutcome, ApiError> {
    let record = state
        .storage
        .get(file_id)
        .map_err(|e| ApiError::internal(format!("storage: {e}")))?
        .ok_or_else(|| ApiError::not_found("file not found"))?;

    match record.access_mode {
        AccessMode::Public => Err(ApiError::bad_request(
            "public files do not require pre-auth; GET directly",
        )),
        AccessMode::Password => {
            let password = verify_password_credential(headers, record.password_hash.as_deref())?;
            // Encrypted at rest: derive the decryption key so the GET can
            // decrypt.  Legacy/plaintext password files have no `enc_salt`.
            let enc_key = match record.enc_salt.as_deref() {
                Some(salt_hex) => {
                    let salt = hex::decode(salt_hex)
                        .map_err(|_| ApiError::internal("corrupt encryption salt"))?;
                    Some(
                        crate::crypto::derive_file_key(&password, &salt)
                            .map_err(|_| ApiError::internal("key derivation failed"))?,
                    )
                }
                None => None,
            };
            Ok((None, enc_key))
        }
        AccessMode::Session => {
            let claims = verify_session_credential(state, headers)?;
            ensure_channel_access(state, &claims, record.channel_id, record.server_id)?;
            Ok((Some(claims.sub), None))
        }
    }
}

/// Verify the password from the `Authorization` header against the stored
/// Argon2id hash and return the validated plaintext (zeroized on drop) so the
/// caller can derive the file key.
fn verify_password_credential(
    headers: &HeaderMap,
    stored_hash: Option<&str>,
) -> Result<Zeroizing<String>, ApiError> {
    let stored =
        stored_hash.ok_or_else(|| ApiError::internal("password file missing stored hash"))?;
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_bearer)
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;
    let plaintext_bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| ApiError::unauthorized("malformed credential"))?,
    );
    let plaintext = std::str::from_utf8(&plaintext_bytes)
        .map_err(|_| ApiError::unauthorized("malformed credential"))?;
    verify_password(plaintext, stored).map_err(|_| ApiError::forbidden("invalid password"))?;
    Ok(Zeroizing::new(plaintext.to_owned()))
}

fn verify_session_credential(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<crate::auth::SessionClaims, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_bearer)
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;
    verify_session_jwt(state.signing_secret.as_ref(), token)
        .map_err(|e| ApiError::forbidden(format!("invalid session token: {e}")))
}

fn ensure_channel_access(
    state: &AppState,
    claims: &crate::auth::SessionClaims,
    channel_id: u32,
    server_id: u32,
) -> Result<(), ApiError> {
    if !state.plugin_ctx.is_session_active(server_id, claims.sid) {
        return Err(ApiError::forbidden("session no longer active"));
    }
    if !state
        .plugin_ctx
        .user_has_channel_access(server_id, claims.sid, channel_id)
    {
        return Err(ApiError::forbidden("no access to source channel"));
    }
    Ok(())
}
