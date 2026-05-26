//! Handle live-doc `OpenRequest` envelopes from clients.
//!
//! When a session asks to open a doc, the plugin:
//!
//! 1. Verifies the session is currently in the requested channel
//!    and has the required permissions.
//! 2. Mints a short-lived handshake JWT and delivers an `Invite`
//!    payload back to the requester through the generic
//!    `PluginMessage` envelope (wire ID 200, `payload_type`
//!    `"Invite"`).
//! 3. Announce fan-out is handled client-side via another
//!    `PluginMessage` envelope (`payload_type = "Announce"`) that
//!    the server relays to channel peers.

use mumble_plugin_api::{ChannelId, ServerId, SessionId};
use serde::Deserialize;
use serde_json::json;

use crate::auth::issue_handshake_jwt;
use crate::host_facade::PluginMessageArgs;
use crate::state::AppState;
use crate::{HANDSHAKE_JWT_TTL_SECS, PLUGIN_NAME};

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

/// Typed entry point shared by both open-request paths.
pub async fn handle_open_request_typed(
    state: &AppState,
    server_id: ServerId,
    sender: SessionId,
    channel_id: ChannelId,
    slug: &str,
    title: &str,
) {
    let Some(slug) = sanitize_slug(slug) else {
        tracing::debug!(
            slug,
            "rejecting open request with empty slug after sanitization"
        );
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
    handle_open_request_typed(
        state,
        server_id,
        sender,
        req.channel_id,
        &req.slug,
        &req.title,
    )
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
    let payload = json!({
        "channelId": channel_id,
        "slug": slug,
        "title": title,
        "wsUrl": ws_url,
        "token": token,
    });
    let bytes = match serde_json::to_vec(&payload) {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(?err, "failed to encode live-doc invite payload");
            return;
        }
    };
    let targets = [sender];
    if let Err(err) = state.ctx().send_plugin_message(PluginMessageArgs {
        server_id,
        plugin_name: PLUGIN_NAME,
        payload_type: "Invite",
        payload: &bytes,
        target_sessions: &targets,
        channel_id: None,
    }) {
        tracing::warn!(?err, "failed to send live-doc invite");
    }
}

fn build_ws_url(
    state: &AppState,
    server_id: ServerId,
    channel_id: ChannelId,
    slug: &str,
) -> String {
    let base = state
        .cfg()
        .public_url
        .clone()
        .unwrap_or_else(|| default_ws_base(state.cfg().bind));
    format!("{base}/ws/{server_id}/{channel_id}/{slug}")
}

/// Build a WS base URL from the configured bind address.
///
/// When the operator did not set `plugin.fancy-live-doc.public_url` and
/// the bind host is an unspecified address (`0.0.0.0`, `::`), we cannot
/// advertise it verbatim - browsers reject those as a destination with
/// `ERR_ADDRESS_INVALID`. Substitute the loopback address so a local
/// dev client can at least connect, and emit a warning so the admin
/// knows to set `public_url` for remote clients.
fn default_ws_base(bind: std::net::SocketAddr) -> String {
    if bind.ip().is_unspecified() {
        let host = if bind.is_ipv6() { "[::1]" } else { "127.0.0.1" };
        tracing::warn!(
            bind = %bind,
            "plugin.fancy-live-doc.public_url is not set and bind address is unspecified; \
             advertising {host}:{port} - remote clients will not be able to connect, \
             set plugin.fancy-live-doc.public_url to a routable URL",
            host = host,
            port = bind.port(),
        );
        format!("ws://{host}:{port}", host = host, port = bind.port())
    } else {
        format!("ws://{bind}")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn slug_strips_unsafe_chars() {
        assert_eq!(
            sanitize_slug("Design Notes!").as_deref(),
            Some("design-notes")
        );
        assert_eq!(
            sanitize_slug("../etc/passwd").as_deref(),
            Some("etc-passwd")
        );
        assert_eq!(sanitize_slug("___---").as_deref(), Some("___"));
        assert_eq!(sanitize_slug(""), None);
    }

    #[test]
    fn default_ws_base_substitutes_loopback_for_unspecified_ipv4() {
        let bind: std::net::SocketAddr = "0.0.0.0:64740".parse().unwrap();
        assert_eq!(default_ws_base(bind), "ws://127.0.0.1:64740");
    }

    #[test]
    fn default_ws_base_substitutes_loopback_for_unspecified_ipv6() {
        let bind: std::net::SocketAddr = "[::]:64740".parse().unwrap();
        assert_eq!(default_ws_base(bind), "ws://[::1]:64740");
    }

    #[test]
    fn default_ws_base_passes_through_routable_address() {
        let bind: std::net::SocketAddr = "10.0.0.5:64740".parse().unwrap();
        assert_eq!(default_ws_base(bind), "ws://10.0.0.5:64740");
    }
}
