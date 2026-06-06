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

use mumble_plugin_api::{identity_owns, ChannelId, ServerId, SessionId};
use serde::Deserialize;
use serde_json::json;

use crate::auth::issue_handshake_jwt;
use crate::doc::{DocKey, Visibility};
use crate::host_facade::PluginMessageArgs;
use crate::state::AppState;
use crate::{HANDSHAKE_JWT_TTL_SECS, PLUGIN_NAME};

/// Request payload used when the open path comes via `on_plugin_data`
/// (legacy path, kept for completeness).
#[derive(Debug, Clone, Deserialize)]
pub struct OpenRequest {
    /// Channel to publish into when creating a new published document.
    pub channel_id: ChannelId,
    /// Server-scoped doc slug.  Sanitised before use.
    pub slug: String,
    /// Human-readable title.
    #[serde(default)]
    pub title: String,
    /// `"private"` (default) or `"publish"` - only meaningful when the
    /// requester is creating a brand-new document.
    #[serde(default)]
    pub mode: String,
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
///
/// Resolves ownership and membership: the first opener of a slug becomes
/// the owner; a non-owner may join only if the document is published to
/// a channel they can access (recording them as a share recipient), or
/// if they were already shared with.  On success an `Invite` (ws url +
/// token) is delivered back to the requester.
pub async fn handle_open_request_typed(
    state: &AppState,
    server_id: ServerId,
    sender: SessionId,
    channel_id: ChannelId,
    slug: &str,
    title: &str,
    mode: &str,
) {
    let Some(slug) = sanitize_slug(slug) else {
        tracing::debug!(slug, "rejecting open request with empty slug after sanitization");
        return;
    };
    let Some(identity) = state.identity(server_id, sender).await else {
        tracing::debug!(sender, "rejecting open: unknown session identity");
        return;
    };

    let key = DocKey {
        server_id,
        slug: slug.clone(),
    };
    let room = state.ensure_room(key).await;
    let mut meta = room.meta().await;

    if meta.owner_cert_hash.is_empty() {
        // Brand-new document: the requester claims ownership.
        if identity.cert_hash.is_empty() {
            tracing::debug!(sender, "rejecting open: creator has no cert identity");
            return;
        }
        meta.owner_cert_hash = identity.cert_hash.clone();
        meta.owner_user_id = (identity.user_id >= 0).then_some(identity.user_id);
        meta.title = title.to_owned();
        if mode == "publish" {
            meta.bound_channel = Some(channel_id);
            meta.visibility = Visibility::Published;
        } else {
            meta.bound_channel = None;
            meta.visibility = Visibility::Private;
        }
        room.set_meta(meta.clone()).await;
        state.persist_room_now(&room).await;
    }

    if !resolve_access(state, server_id, sender, &room, &meta, &identity).await {
        tracing::debug!(sender, slug = %slug, "rejecting open: not permitted");
        return;
    }

    // Backfill the durable owner id for a legacy document the cert-owner just
    // reopened, so their ownership survives a future certificate rotation.
    if meta.owner_user_id.is_none()
        && identity.user_id >= 0
        && !identity.cert_hash.is_empty()
        && meta.owner_cert_hash == identity.cert_hash
    {
        meta.owner_user_id = Some(identity.user_id);
        room.set_meta(meta.clone()).await;
        state.persist_room_now(&room).await;
    }

    let ws_url = build_ws_url(state, server_id, &slug);
    // The invite carries the channel the requester is acting in (for the
    // client to place/keep its panel), which is distinct from the authz
    // `bound_channel` (None for a private doc).
    send_invite(state, server_id, sender, Some(channel_id), &slug, &meta.title, &ws_url);
    send_shared_with(state, server_id, sender, &slug, &room).await;
}

/// Deliver the document's shared-with list to the requester so the
/// client can display who it has been shared with.
async fn send_shared_with(
    state: &AppState,
    server_id: ServerId,
    sender: SessionId,
    slug: &str,
    room: &crate::doc::DocRoom,
) {
    let members = state.shared_with_members(room).await;
    let payload = json!({ "slug": slug, "sharedWith": members });
    let Ok(bytes) = serde_json::to_vec(&payload) else {
        return;
    };
    let targets = [sender];
    if let Err(err) = state.ctx().send_plugin_message(PluginMessageArgs {
        server_id,
        plugin_name: PLUGIN_NAME,
        payload_type: "SharedWith",
        payload: &bytes,
        target_sessions: &targets,
        channel_id: None,
    }) {
        tracing::warn!(?err, "failed to send live-doc shared-with");
    }
}

/// Decide whether `identity` may open the document, recording a new
/// share grant when a channel member joins a published document.
async fn resolve_access(
    state: &AppState,
    server_id: ServerId,
    sender: SessionId,
    room: &crate::doc::DocRoom,
    meta: &crate::doc::DocMeta,
    identity: &crate::state::Identity,
) -> bool {
    // Owner - matched by the stable user id (surviving cert rotation between
    // sessions) or the cert hash.  Shared with the file-server via
    // `identity_owns` so ownership resolves identically across both plugins.
    if identity_owns(
        identity.user_id,
        &identity.cert_hash,
        meta.owner_user_id,
        &meta.owner_cert_hash,
    ) {
        return true;
    }
    // A recorded share recipient (cert-based).
    if room.is_member(&identity.cert_hash).await {
        return true;
    }
    // Server administrators (Write on the root channel) may open any document,
    // matching the admin file-server documents dashboard.
    if state.is_server_admin(server_id, sender) {
        return true;
    }
    let Some(channel) = meta.bound_channel else {
        return false;
    };
    if state.has_channel_permission(server_id, sender, channel) {
        state.record_shared_with(room, identity).await;
        true
    } else {
        false
    }
}

/// Publish an existing document to a channel.  Only the owner may
/// publish; the target channel must be one the owner can access.
pub async fn handle_publish(
    state: &AppState,
    server_id: ServerId,
    sender: SessionId,
    slug: &str,
    channel_id: ChannelId,
) {
    let Some(slug) = sanitize_slug(slug) else {
        return;
    };
    let Some(identity) = state.identity(server_id, sender).await else {
        return;
    };
    let key = DocKey {
        server_id,
        slug,
    };
    let room = state.ensure_room(key).await;
    if !room.is_owner(&identity.cert_hash).await {
        tracing::debug!(sender, "rejecting publish: not the document owner");
        return;
    }
    if !state.has_channel_permission(server_id, sender, channel_id) {
        return;
    }
    let mut meta = room.meta().await;
    meta.bound_channel = Some(channel_id);
    meta.visibility = Visibility::Published;
    room.set_meta(meta).await;
    state.persist_room_now(&room).await;
}

/// Rename an existing document.  Only the owner may rename; the new
/// title is stored in the document metadata and flushed to persistence
/// so the saved entry reflects the change.  Live propagation to peers
/// that currently have the document open is handled separately through
/// the shared Yjs `meta` map.
pub async fn handle_rename(
    state: &AppState,
    server_id: ServerId,
    sender: SessionId,
    slug: &str,
    title: &str,
) {
    let Some(slug) = sanitize_slug(slug) else {
        return;
    };
    let title = title.trim();
    if title.is_empty() {
        return;
    }
    let Some(identity) = state.identity(server_id, sender).await else {
        return;
    };
    let key = DocKey { server_id, slug };
    let room = state.ensure_room(key).await;
    if !room.is_owner(&identity.cert_hash).await {
        tracing::debug!(sender, "rejecting rename: not the document owner");
        return;
    }
    let mut meta = room.meta().await;
    if meta.title == title {
        return;
    }
    meta.title = title.to_owned();
    room.set_meta(meta).await;
    state.persist_room_now(&room).await;
}

/// Flush a document to persistence on demand (owner-initiated manual
/// save).  Only the owner may force a snapshot; the autosave loop still
/// covers other members.
pub async fn handle_persist(
    state: &AppState,
    server_id: ServerId,
    sender: SessionId,
    slug: &str,
) {
    let Some(slug) = sanitize_slug(slug) else {
        return;
    };
    let Some(identity) = state.identity(server_id, sender).await else {
        return;
    };
    let key = DocKey { server_id, slug };
    let room = state.ensure_room(key).await;
    if !room.is_owner(&identity.cert_hash).await {
        tracing::debug!(sender, "rejecting persist: not the document owner");
        return;
    }
    state.persist_room_now(&room).await;
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
        &req.mode,
    )
    .await;
}

fn send_invite(
    state: &AppState,
    server_id: ServerId,
    sender: SessionId,
    bound_channel: Option<ChannelId>,
    slug: &str,
    title: &str,
    ws_url: &str,
) {
    let Ok(token) =
        issue_handshake_jwt(state.jwt_secret(), server_id, sender, slug, HANDSHAKE_JWT_TTL_SECS)
    else {
        return;
    };
    let payload = json!({
        "channelId": bound_channel.unwrap_or(0),
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

fn build_ws_url(state: &AppState, server_id: ServerId, slug: &str) -> String {
    let base = state
        .cfg()
        .public_url
        .clone()
        .unwrap_or_else(|| default_ws_base(state.cfg().bind));
    format!("{base}/ws/{server_id}/{slug}")
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
        let bind: SocketAddr = "0.0.0.0:64740".parse().unwrap();
        assert_eq!(default_ws_base(bind), "ws://127.0.0.1:64740");
    }

    #[test]
    fn default_ws_base_substitutes_loopback_for_unspecified_ipv6() {
        let bind: SocketAddr = "[::]:64740".parse().unwrap();
        assert_eq!(default_ws_base(bind), "ws://[::1]:64740");
    }

    #[test]
    fn default_ws_base_passes_through_routable_address() {
        let bind: SocketAddr = "10.0.0.5:64740".parse().unwrap();
        assert_eq!(default_ws_base(bind), "ws://10.0.0.5:64740");
    }

    use crate::config::LiveDocConfig;
    use crate::doc::{DocKey, DocMeta, Visibility as DocVisibility};
    use crate::host_facade::{FacadeResult, HostFacade, PluginMessageArgs};
    use crate::state::Identity;
    use mumble_plugin_api::Permissions;
    use std::net::SocketAddr;
    use std::sync::Arc;

    #[derive(Debug)]
    struct AllowCtx;

    impl HostFacade for AllowCtx {
        fn send_plugin_data(&self, _: u32, _: u32, _: &str, _: &[u8]) -> FacadeResult<()> {
            Ok(())
        }
        fn is_session_active(&self, _: u32, _: u32) -> bool {
            true
        }
        fn user_has_channel_access(&self, _: u32, _: u32, _: u32) -> bool {
            true
        }
        fn has_permission(&self, _: u32, _: u32, _: u32, _: Permissions) -> bool {
            true
        }
        fn get_config(&self, _: &str) -> Option<String> {
            None
        }
        fn send_plugin_message(&self, _: PluginMessageArgs<'_>) -> FacadeResult<()> {
            Ok(())
        }
    }

    fn test_state() -> AppState {
        let cfg = LiveDocConfig {
            bind: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            public_url: None,
            jwt_secret: Some("test-secret-0123456789abcdef0123456789".to_owned()),
            state_path: std::env::temp_dir(),
            max_update_bytes: 4 * 1024 * 1024,
            snapshot_idle_secs: 60,
            teardown_grace_secs: 30,
            file_server_url: None,
            file_server_admin_token: None,
            port: 0,
        };
        AppState::new(Arc::new(cfg), Arc::new(AllowCtx))
    }

    async fn seed_owned_room(state: &AppState, server_id: ServerId, slug: &str) -> DocKey {
        state
            .set_identity(
                server_id,
                10,
                Identity {
                    cert_hash: "owner-cert".into(),
                    user_id: 10,
                    name: "owner".into(),
                },
            )
            .await;
        state
            .set_identity(
                server_id,
                11,
                Identity {
                    cert_hash: "intruder-cert".into(),
                    user_id: 11,
                    name: "intruder".into(),
                },
            )
            .await;
        let key = DocKey {
            server_id,
            slug: slug.to_owned(),
        };
        let room = state.ensure_room(key.clone()).await;
        room.set_meta(DocMeta {
            owner_cert_hash: "owner-cert".into(),
            owner_user_id: None,
            title: "Old Title".into(),
            bound_channel: None,
            visibility: DocVisibility::Private,
        })
        .await;
        key
    }

    #[tokio::test]
    async fn owner_can_rename_document() {
        let state = test_state();
        let key = seed_owned_room(&state, 1, "notes").await;
        handle_rename(&state, 1, 10, "notes", "  New Title  ").await;
        let room = state.ensure_room(key).await;
        assert_eq!(room.meta().await.title, "New Title");
    }

    #[tokio::test]
    async fn non_owner_cannot_rename_document() {
        let state = test_state();
        let key = seed_owned_room(&state, 1, "notes").await;
        handle_rename(&state, 1, 11, "notes", "Hijacked").await;
        let room = state.ensure_room(key).await;
        assert_eq!(room.meta().await.title, "Old Title");
    }

    #[tokio::test]
    async fn rename_ignores_blank_title() {
        let state = test_state();
        let key = seed_owned_room(&state, 1, "notes").await;
        handle_rename(&state, 1, 10, "notes", "   ").await;
        let room = state.ensure_room(key).await;
        assert_eq!(room.meta().await.title, "Old Title");
    }

    #[tokio::test]
    async fn non_owner_persist_is_rejected() {
        let state = test_state();
        let _ = seed_owned_room(&state, 1, "notes").await;
        // Should be a no-op and must not panic for a non-owner session.
        handle_persist(&state, 1, 11, "notes").await;
    }
}
