//! HTTP routes for managing custom server emotes.
//!
//! Routes:
//!
//! * `GET    /emotes`              - list all emotes (no auth required;
//!   anyone connected can see them).
//! * `POST   /emotes`              - admin-only: upload a new emote.
//! * `DELETE /emotes/{shortcode}`  - admin-only: delete an emote.
//!
//! Admin auth is performed by `require_admin`: the request must carry a
//! valid `Authorization: Bearer <session-jwt>` header AND the JWT
//! subject's session must currently hold `Write` on the root channel
//! (the canonical Mumble "is server admin" ACL check).
//!
//! After every mutation, [`broadcast_emotes_to_all`] is invoked to
//! re-send the full emote list to every active session via
//! `PluginContext::send_plugin_data`.

use axum::extract::{Multipart, Path, State};
use axum::http::HeaderMap;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use mumble_plugin_api::permissions;
use serde::{Deserialize, Serialize};

use crate::auth::verify_session_jwt;
use crate::emotes::{self, EmoteError, EmoteRecord, EmoteSummary};
use crate::http::common::{parse_bearer, ApiError};
use crate::state::AppState;

/// Plugin data id used to push the custom emote list to clients.
pub const EMOTES_DATA_ID: &str = "fancy-server-emotes";

/// Single emote as exposed over the HTTP API and the broadcast payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmoteDto {
    /// Unique shortcode.
    pub shortcode: String,
    /// Fallback unicode emoji.
    pub alias_emoji: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `data:` URL containing the image bytes (base64-encoded).
    pub image_data_url: String,
}

/// Response body for `GET /emotes`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EmoteListResponse {
    /// All emotes currently stored on the server.
    pub emotes: Vec<EmoteDto>,
}

/// Response body for `POST /emotes`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EmoteUploadResponse {
    /// Shortcode of the newly created emote.
    pub shortcode: String,
}

fn emote_summary_to_dto(s: EmoteSummary) -> EmoteDto {
    let encoded = B64.encode(&s.bytes);
    EmoteDto {
        shortcode: s.shortcode,
        alias_emoji: s.alias_emoji,
        description: s.description,
        image_data_url: format!("data:{};base64,{}", s.mime_type, encoded),
    }
}

/// Convert a [`EmoteError`] into an [`ApiError`] response.
fn map_emote_error(e: EmoteError) -> ApiError {
    match e {
        EmoteError::Invalid(msg) => ApiError::bad_request(msg),
        EmoteError::DuplicateShortcode(s) => {
            ApiError::bad_request(format!("emote '{s}' already exists"))
        }
        EmoteError::NotFound => ApiError::not_found("emote not found"),
        EmoteError::Db(e) => ApiError::internal(format!("db: {e}")),
        EmoteError::Io(e) => ApiError::internal(format!("io: {e}")),
    }
}

/// Verify the request is from an admin session.
///
/// Returns the cert hash (for audit logging) on success.
fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing Authorization header"))?;
    let token = parse_bearer(header)
        .ok_or_else(|| ApiError::unauthorized("Authorization must use Bearer scheme"))?;
    let claims = verify_session_jwt(state.signing_secret.as_ref(), token)
        .map_err(|e| ApiError::unauthorized(format!("invalid session token: {e}")))?;
    let is_admin =
        state
            .plugin_ctx
            .has_permission(claims.srv, claims.sid, 0, permissions::MANAGE_EMOTES);
    if !is_admin {
        return Err(ApiError::forbidden(
            "this account is not allowed to manage emotes",
        ));
    }
    Ok(claims.sub)
}

/// `GET /emotes` - list all emotes. No auth required.
pub async fn list(State(state): State<AppState>) -> Result<Json<EmoteListResponse>, ApiError> {
    let summaries = emotes::list_all(state.storage.emote_db()).map_err(map_emote_error)?;
    let emotes = summaries.into_iter().map(emote_summary_to_dto).collect();
    Ok(Json(EmoteListResponse { emotes }))
}

/// `POST /emotes` - admin-only multipart upload. Fields:
///
/// * `shortcode`    - required, see [`emotes::validate_shortcode`].
/// * `alias_emoji`  - required.
/// * `description`  - optional.
/// * `file`         - required image bytes (PNG/JPEG/GIF/WebP/SVG).
pub async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Result<Json<EmoteUploadResponse>, ApiError> {
    let admin_cert_hash = require_admin(&state, &headers)?;
    let parsed = parse_emote_multipart(multipart).await?;

    let record = EmoteRecord {
        shortcode: parsed.shortcode.clone(),
        alias_emoji: parsed.alias_emoji,
        description: parsed.description,
        mime_type: parsed.mime_type,
        bytes: parsed.bytes,
        created_at: now_unix_ms(),
        created_by_cert_hash: admin_cert_hash,
    };
    emotes::insert(state.storage.emote_db(), &record).map_err(map_emote_error)?;

    broadcast_emotes_to_all(&state);

    Ok(Json(EmoteUploadResponse {
        shortcode: parsed.shortcode,
    }))
}

/// `DELETE /emotes/{shortcode}` - admin-only.
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(shortcode): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _admin = require_admin(&state, &headers)?;
    emotes::delete(state.storage.emote_db(), &shortcode).map_err(map_emote_error)?;
    broadcast_emotes_to_all(&state);
    Ok(Json(serde_json::json!({ "ok": true })))
}

struct ParsedEmote {
    shortcode: String,
    alias_emoji: String,
    description: Option<String>,
    mime_type: String,
    bytes: Vec<u8>,
}

async fn parse_emote_multipart(mut multipart: Multipart) -> Result<ParsedEmote, ApiError> {
    let mut shortcode: Option<String> = None;
    let mut alias_emoji: Option<String> = None;
    let mut description: Option<String> = None;
    let mut mime_type = String::from("application/octet-stream");
    let mut bytes: Option<Vec<u8>> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("multipart error: {e}")))?
    {
        let name = field.name().unwrap_or("").to_owned();
        match name.as_str() {
            "shortcode" => {
                shortcode = Some(field.text().await.unwrap_or_default());
            }
            "alias_emoji" => {
                alias_emoji = Some(field.text().await.unwrap_or_default());
            }
            "description" => {
                let s = field.text().await.unwrap_or_default();
                if !s.is_empty() {
                    description = Some(s);
                }
            }
            "file" => {
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("file bytes: {e}")))?;
                if data.len() > emotes::MAX_EMOTE_SIZE_BYTES {
                    return Err(ApiError::too_large("emote image exceeds size limit"));
                }
                mime_type = infer::get(&data)
                    .map(|k| k.mime_type().to_owned())
                    .unwrap_or_else(|| "application/octet-stream".to_owned());
                bytes = Some(data.to_vec());
            }
            _ => {}
        }
    }

    Ok(ParsedEmote {
        shortcode: shortcode.ok_or_else(|| ApiError::bad_request("missing shortcode"))?,
        alias_emoji: alias_emoji.ok_or_else(|| ApiError::bad_request("missing alias_emoji"))?,
        description,
        mime_type,
        bytes: bytes.ok_or_else(|| ApiError::bad_request("missing file"))?,
    })
}

/// Re-fetch the emote list and push it to every active session.
pub fn broadcast_emotes_to_all(state: &AppState) {
    let summaries = match emotes::list_all(state.storage.emote_db()) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "failed to load emotes for broadcast");
            return;
        }
    };
    let payload = EmoteListResponse {
        emotes: summaries.into_iter().map(emote_summary_to_dto).collect(),
    };
    let bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize emote broadcast");
            return;
        }
    };
    for session in state.sessions.all_session_ids() {
        if let Err(e) = state
            .plugin_ctx
            .send_plugin_data(0, session, EMOTES_DATA_ID, &bytes)
        {
            tracing::warn!(session, error = %e, "send emotes broadcast failed");
        }
    }
}

/// Send the current emote list to a single session (used on connect).
pub fn send_emotes_to_session(state: &AppState, server_id: u32, session: u32) {
    let summaries = match emotes::list_all(state.storage.emote_db()) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "failed to load emotes for session push");
            return;
        }
    };
    let payload = EmoteListResponse {
        emotes: summaries.into_iter().map(emote_summary_to_dto).collect(),
    };
    let bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize emote payload");
            return;
        }
    };
    if let Err(e) = state
        .plugin_ctx
        .send_plugin_data(server_id, session, EMOTES_DATA_ID, &bytes)
    {
        tracing::warn!(session, error = %e, "send emotes to session failed");
    }
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers panic on failure"
)]
mod tests {
    use super::*;

    #[test]
    fn emote_summary_to_dto_builds_data_url() {
        let s = EmoteSummary {
            shortcode: "foo".into(),
            alias_emoji: "\u{1F600}".into(),
            description: Some("desc".into()),
            mime_type: "image/png".into(),
            bytes: b"hi".to_vec(),
        };
        let dto = emote_summary_to_dto(s);
        assert_eq!(dto.shortcode, "foo");
        assert_eq!(dto.image_data_url, "data:image/png;base64,aGk=");
    }
}
