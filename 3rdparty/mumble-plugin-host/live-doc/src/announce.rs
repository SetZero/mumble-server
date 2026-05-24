//! Handle `FancyLiveDocOpen` (wire ID 141) requests from clients.
//!
//! When a session asks to open a doc, the plugin:
//!
//! 1. Verifies the session is currently in the requested channel
//!    and has the required permissions.
//! 2. Mints a short-lived handshake JWT and delivers a native
//!    `FancyLiveDocInvite` (wire ID 142) directly to the requester.
//! 3. Announce fan-out (wire ID 143) is handled by the client and
//!    server: the opener's client sends `FancyLiveDocAnnounce` and
//!    the server relays it to channel peers.

use mumble_plugin_api::{ChannelId, LiveDocInviteParams, ServerId, SessionId};
use serde::Deserialize;

use crate::auth::issue_handshake_jwt;
use crate::state::AppState;
use crate::HANDSHAKE_JWT_TTL_SECS;

/// Request payload used when the open path comes via `on_plugin_data`
/// (legacy path, kept for completeness).
#[derive(Debug, Clone, Deserialize)]
pub struct OpenRequest {
    /// Channel the document belongs to.
    pub channel_id: ChannelId,
    /// Doc slug within the channel.  Sanitised before use.
    pub slug: String,
    /// Human-readable title for announce banners.
    #[serde(default)]
    pub title: String,
}

/// Sanitise a slug to a URL-safe form (lowercase ascii + hyphen
/// + digit, max 64 chars).  Returns `None` if nothing survived.
pub fn sanitize_slug(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len().min(64));
    for ch in raw.chars().take(128) {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
        } else if c == ' ' || c == '.' || c == '/' {
            out.push('-');
        }
        if out.len() >= 64 {
            break;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Entry point invoked from the native `on_fancy_live_doc_open` hook.
pub async fn handle_open_request_typed(
    state: &AppState,
    server_id: ServerId,
    sender: SessionId,
    channel_id: ChannelId,
    slug: &str,
    title: &str,
) {
    let Some(slug) = sanitize_slug(slug) else {
        tracing::debug!(slug, "rejecting open request with empty slug after sanitization");
        return;
    };

    if state.ctx().current_channel(server_id, sender) != Some(channel_id) {
        tracing::debug!(
            sender,
            requested = channel_id,
            "rejecting open: sender not in requested channel"
        );
        return;
    }
    if !state.session_can_access(server_id, sender, channel_id) {
        return;
    }

    let ws_url = build_ws_url(state, server_id, channel_id, &slug);

    send_invite(state, server_id, sender, channel_id, &slug, title, &ws_url);
}

/// Entry point invoked from the legacy `on_plugin_data` hook.
pub async fn handle_open_request(
    state: &AppState,
    server_id: ServerId,
    sender: SessionId,
    payload: &[u8],
) {
    let req: OpenRequest = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(err) => {
            tracing::debug!(?err, "ignoring malformed open request");
            return;
        }
    };
    handle_open_request_typed(state, server_id, sender, req.channel_id, &req.slug, &req.title)
        .await;
}

fn send_invite(
    state: &AppState,
    server_id: ServerId,
    sender: SessionId,
    channel_id: ChannelId,
    slug: &str,
    title: &str,
    ws_url: &str,
) {
    let Ok(token) = issue_handshake_jwt(
        state.jwt_secret(),
        server_id,
        sender,
        channel_id,
        slug,
        HANDSHAKE_JWT_TTL_SECS,
    ) else {
        return;
    };
    if let Err(err) = state.ctx().send_fancy_live_doc_invite(
        server_id,
        sender,
        channel_id,
        &LiveDocInviteParams { slug, title, ws_url, token: &token },
    ) {
        tracing::warn!(?err, "failed to send live-doc invite");
    }
}

fn build_ws_url(state: &AppState, server_id: ServerId, channel_id: ChannelId, slug: &str) -> String {
    let base = state
        .cfg()
        .public_url
        .clone()
        .unwrap_or_else(|| format!("ws://{}", state.cfg().bind));
    format!("{base}/ws/{server_id}/{channel_id}/{slug}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_strips_unsafe_chars() {
        assert_eq!(sanitize_slug("Design Notes!").as_deref(), Some("design-notes"));
        assert_eq!(sanitize_slug("../etc/passwd").as_deref(), Some("etc-passwd"));
        assert_eq!(sanitize_slug("___---").as_deref(), Some("___"));
        assert_eq!(sanitize_slug(""), None);
    }
}
