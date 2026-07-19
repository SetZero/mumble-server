//! `mumble-audit` — the server audit log & moderation-signals plugin
//! (`docs/audit-log.md`).
//!
//! This crate is the plugin side of the design: it owns storage, the git-style
//! hash chain (§7.1), the per-part toggle matrix (§9.2), retention (§7.9) and
//! the permission seam (§9.1). Core stays the trusted source of authoritative
//! events; the plugin owns the opinionated, swappable parts.
//!
//! ## Module map
//!
//! - [`model`] — the `server_audit` data model (§4).
//! - [`chain`] — the tamper-evident hash chain and `verify` (§7.1).
//! - [`event_log`] — the durable, Kafka-like host event stream (§7.10). In the
//!   shipped architecture this lifts into the `host` crate so every plugin can
//!   subscribe; the semantics and tests live here.
//! - [`toggles`] — the fine-grained collect/export switches (§9.2).
//! - [`retention`] — write-time expiry and the 30-day accountability floor (§7.9).
//! - [`authz`] — the `AuditAuthz` permission seam (§9.1).
//! - [`store`] — `SQLite` persistence, queries and chain verification (§4, §5).
//! - [`ingest`] — idempotent event → chained entry mapping (§7.10).
//! - [`runtime`] — the live subsystem that ties it together.
//!
//! ## Integration seam (not wired in this build)
//!
//! Live ingestion activates once the host gains an `on_server_event` fan-out
//! hook (§7.10, §11 phase 1): add the hook to `MumblePlugin` (bumping
//! `PLUGIN_ABI_VERSION`), a `plugin_host_on_server_event` entry in
//! `host/src/ffi.rs`, a fan-out on `Host`, and `emitServerEvent(...)` calls in
//! the core C++ moderation handlers. This plugin's [`runtime::AuditRuntime::ingest`]
//! is the consumer those events feed. Until then the plugin still serves
//! authorized query/verify requests over the generic plugin-message channel.

pub mod authz;
pub mod chain;
pub mod config;
pub mod event_log;
pub mod ingest;
pub mod model;
pub mod retention;
pub mod runtime;
pub mod store;
pub mod toggles;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use abi_stable::std_types::RResult::{RErr, ROk};
use abi_stable::std_types::{RArc, RSlice, RStr, RString};
use mumble_plugin_api::{
    MumblePlugin, PluginContext_TO, PluginInfo, PluginMessageIn, PluginResult,
};

use crate::authz::PERM_WRITE;
use crate::config::PLUGIN_NAME;
use crate::event_log::ServerEvent;
use crate::model::{AuditEntry, Identity, Source};
use crate::runtime::AuditRuntime;
use crate::store::Query;
use crate::toggles::Part;

const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Core/bridge → plugin: run an audit query on behalf of an authorized admin.
/// Payload is a JSON filter (see [`parse_query`]) carrying a `request_id`.
/// Requires `Write` on root (the `ViewAudit` gate, §9.1).
const MSG_QUERY: &str = "audit.query";
/// Plugin → bridge: audit query results as a JSON array of entries, routed
/// back through the host's request/response seam (packed into a
/// `FancyAuditResponse` by the murmur-side `AuditLogBridge`).
const MSG_RESULT: &str = "audit.result";
/// Core/bridge → plugin: verify a server's hash chain (§7.1).
const MSG_VERIFY: &str = "audit.verify";
/// Plugin → bridge: the verify outcome as JSON.
const MSG_VERIFY_RESULT: &str = "audit.verify.result";
/// Core → plugin: one authoritative moderation event to ingest (§7.10).
/// Server-originated only: the bridge stamps `sender_session == 0`, which no
/// real client session ever carries, so client-forged ingests are dropped.
const MSG_INGEST: &str = "audit.ingest";
/// Core/bridge → plugin: request the config snapshot (toggle matrix + chain
/// status). Requires `Write` on root (the `ConfigureAudit` gate).
const MSG_CONFIG_GET: &str = "audit.config.get";
/// Core/bridge → plugin: apply changed toggles. Same gate as get.
const MSG_CONFIG_SET: &str = "audit.config.set";
/// Plugin → bridge: the config snapshot (packed into `FancyAuditConfig`).
const MSG_CONFIG: &str = "audit.config";

/// Root channel id — the scope the audit permissions are checked against (§5).
const ROOT_CHANNEL: u32 = 0;

/// The audit plugin. Holds the live [`AuditRuntime`], or `None` if the store
/// could not be opened (the plugin still loads, inert, and says why).
struct AuditPlugin {
    runtime: Mutex<Option<AuditRuntime>>,
    /// Monotonic config-snapshot revision (bumped on every accepted update)
    /// so clients can drop stale `FancyAuditConfig` snapshots.
    config_revision: AtomicU64,
}

impl AuditPlugin {
    fn new() -> Self {
        Self {
            runtime: Mutex::new(None),
            config_revision: AtomicU64::new(1),
        }
    }

    fn with_runtime<R>(&self, f: impl FnOnce(&AuditRuntime) -> R) -> Option<R> {
        let guard = self
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.as_ref().map(f)
    }

    /// Handle an authorized `audit.query`, replying with matching entries.
    fn handle_query(&self, ctx: &PluginContext_TO<RArc<()>>, msg: &PluginMessageIn) {
        let server_id = msg.server_id;
        let request_id = request_id_of(msg.payload.as_slice());
        let authorized =
            ctx.has_permission(server_id, msg.sender_session, ROOT_CHANNEL, PERM_WRITE);
        // Non-authorized queries get an empty result, never a partial leak (§5).
        let entries = if authorized {
            self.run_query(server_id, msg.payload.as_slice())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let payload = entries_to_json(&entries);
        respond(
            ctx,
            server_id,
            &request_id,
            msg.sender_session,
            MSG_RESULT,
            payload.as_bytes(),
        );
    }

    /// Handle an authorized `audit.verify`, replying with the chain outcome.
    fn handle_verify(&self, ctx: &PluginContext_TO<RArc<()>>, msg: &PluginMessageIn) {
        let server_id = msg.server_id;
        let request_id = request_id_of(msg.payload.as_slice());
        if !ctx.has_permission(server_id, msg.sender_session, ROOT_CHANNEL, PERM_WRITE) {
            return;
        }
        let outcome = self.with_runtime(|rt| rt.verify(i32_server(server_id)));
        let payload = verify_to_json(outcome);
        respond(
            ctx,
            server_id,
            &request_id,
            msg.sender_session,
            MSG_VERIFY_RESULT,
            payload.as_bytes(),
        );
    }

    /// Ingest one server-authoritative event (bridge-originated only).
    fn handle_ingest(&self, msg: &PluginMessageIn) {
        // Real client sessions are never 0; the murmur bridge stamps 0 on the
        // events it emits, so anything else is a forged client message.
        if msg.sender_session != 0 {
            tracing::warn!(
                session = msg.sender_session,
                "audit: dropping client-originated ingest"
            );
            return;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(msg.payload.as_slice()) else {
            return;
        };
        let Some(offset) = value.get("offset").and_then(serde_json::Value::as_u64) else {
            return;
        };
        let Some(event_json) = value.get("event") else {
            return;
        };
        let Some(event) = parse_server_event(i32_server(msg.server_id), event_json) else {
            return;
        };
        let outcome = self.with_runtime(|rt| rt.ingest(&event, offset));
        if let Some(Err(e)) = outcome {
            tracing::error!(error = %e, kind = %event.kind, "audit: ingest failed");
        }
    }

    /// Reply with the config snapshot (toggle matrix + chain status).
    fn handle_config_get(&self, ctx: &PluginContext_TO<RArc<()>>, msg: &PluginMessageIn) {
        let server_id = msg.server_id;
        if !ctx.has_permission(server_id, msg.sender_session, ROOT_CHANNEL, PERM_WRITE) {
            return;
        }
        let request_id = request_id_of(msg.payload.as_slice());
        let payload = self.config_snapshot_json(server_id);
        respond(
            ctx,
            server_id,
            &request_id,
            msg.sender_session,
            MSG_CONFIG,
            payload.as_bytes(),
        );
    }

    /// Apply changed toggles, then reply with the fresh snapshot.
    fn handle_config_set(&self, ctx: &PluginContext_TO<RArc<()>>, msg: &PluginMessageIn) {
        let server_id = msg.server_id;
        if !ctx.has_permission(server_id, msg.sender_session, ROOT_CHANNEL, PERM_WRITE) {
            return;
        }
        let request_id = request_id_of(msg.payload.as_slice());
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(msg.payload.as_slice()) {
            let actor = Identity {
                user_id: None,
                hash: None,
                name: Some(msg.sender_name.to_string()),
            };
            let now_ms = now_ms();
            let settings = value
                .get("settings")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            for setting in &settings {
                let Some(key) = setting.get("key").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let Some(part) = key
                    .strip_prefix(TOGGLE_KEY_PREFIX)
                    .and_then(Part::from_str)
                else {
                    continue;
                };
                let enable = setting
                    .get("value")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|v| v == "true");
                let changed = self.with_runtime(|rt| {
                    rt.set_toggle(part, enable, i32_server(server_id), now_ms, actor.clone())
                });
                if let Some(Err(e)) = changed {
                    tracing::error!(error = %e, part = part.as_str(), "audit: toggle update failed");
                }
            }
            let _ = self.config_revision.fetch_add(1, Ordering::Relaxed);
        }
        let payload = self.config_snapshot_json(server_id);
        respond(
            ctx,
            server_id,
            &request_id,
            msg.sender_session,
            MSG_CONFIG,
            payload.as_bytes(),
        );
    }

    /// The config snapshot as JSON for the bridge to pack into
    /// `FancyAuditConfig`: generic `Setting` rows for every toggle, the chain
    /// height, and the snapshot revision.
    fn config_snapshot_json(&self, server_id: u32) -> String {
        let toggles = self
            .with_runtime(AuditRuntime::toggle_snapshot)
            .unwrap_or_default();
        let settings: Vec<serde_json::Value> = toggles
            .into_iter()
            .map(|(part, enabled)| {
                serde_json::json!({
                    "key": format!("{TOGGLE_KEY_PREFIX}{}", part.as_str()),
                    "type": "bool",
                    "group": group_for(part),
                    "label": part.as_str(),
                    "value": if enabled { "true" } else { "false" },
                })
            })
            .collect();
        let chain_height = self
            .with_runtime(|rt| match rt.verify(i32_server(server_id)) {
                Ok(chain::VerifyOutcome::Intact { checked, .. }) => checked,
                Ok(chain::VerifyOutcome::Broken { index, .. }) => index,
                Err(_) => 0,
            })
            .unwrap_or(0);
        serde_json::json!({
            "settings": settings,
            "revision": self.config_revision.load(Ordering::Relaxed),
            "advanced_sql_available": false,
            "chain_height": chain_height,
        })
        .to_string()
    }

    fn run_query(&self, server_id: u32, payload: &[u8]) -> Option<Vec<AuditEntry>> {
        let value = serde_json::from_slice::<serde_json::Value>(payload).ok()?;
        let query = parse_query(&value);
        self.with_runtime(|rt| rt.query(i32_server(server_id), &query).unwrap_or_default())
    }
}

/// Config key prefix for the per-part toggles, matching the generic
/// plugin-setting key convention (`plugin.<name>.<key>`).
const TOGGLE_KEY_PREFIX: &str = "plugin.fancy-audit.part.";

/// Group heading for a part's Setting row in the config UI.
fn group_for(part: Part) -> &'static str {
    let s = part.as_str();
    if s.starts_with("audit.") {
        "Audit"
    } else if s.starts_with("signal.") {
        "Signals"
    } else if s.starts_with("telemetry.") {
        "Telemetry"
    } else {
        "General"
    }
}

/// Current unix time in milliseconds.
#[allow(
    clippy::cast_possible_wrap,
    reason = "unix millis fit i64 for the next ~292 million years"
)]
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// Pull the correlation `request_id` out of a request payload.
fn request_id_of(payload: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()
        .and_then(|v| {
            v.get("request_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

/// Parse one bridge event into a [`ServerEvent`].
fn parse_server_event(server_id: i32, value: &serde_json::Value) -> Option<ServerEvent> {
    let kind = value.get("kind")?.as_str()?.to_owned();
    let ts_ms = value
        .get("ts_ms")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_else(now_ms);
    let mut event = ServerEvent::new(server_id, ts_ms, kind);
    event.actor = parse_identity(value.get("actor"));
    event.target = parse_identity(value.get("target"));
    event.channel_id = value.get("channel_id").and_then(serde_json::Value::as_i64);
    event.detail_json = value
        .get("detail_json")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Some(event)
}

fn parse_identity(value: Option<&serde_json::Value>) -> Identity {
    let Some(value) = value else {
        return Identity::default();
    };
    Identity {
        user_id: value.get("user_id").and_then(serde_json::Value::as_i64),
        hash: value
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        name: value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    }
}

/// The host's `ServerId` is a `u32`; audit rows key `server_id` as `i32` (the
/// murmur virtual-server id domain). This is a lossless reinterpretation for
/// the id range servers actually use.
#[allow(
    clippy::cast_possible_wrap,
    reason = "virtual-server ids are small positive integers; the mapping is stable and reversible"
)]
const fn i32_server(server_id: u32) -> i32 {
    server_id as i32
}

/// Build an [`AuditStore`](store::AuditStore)-backed [`Query`] from a JSON
/// request body.
fn parse_query(value: &serde_json::Value) -> Query {
    let string = |key: &str| value.get(key).and_then(serde_json::Value::as_str);
    let int = |key: &str| value.get(key).and_then(serde_json::Value::as_i64);
    let categories = value
        .get("categories")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    Query {
        categories,
        source: string("source").and_then(Source::from_wire),
        actor_user_id: int("actor_user_id"),
        target_user_id: int("target_user_id"),
        channel_id: int("channel_id"),
        text: string("text").map(str::to_owned),
        since_ms: int("since_ms"),
        until_ms: int("until_ms"),
        before_id: int("before_id"),
        limit: int("limit").and_then(|n| u32::try_from(n).ok()),
    }
}

/// Serialize entries to a compact JSON array for the wire.
fn entries_to_json(entries: &[AuditEntry]) -> String {
    let items: Vec<serde_json::Value> = entries.iter().map(entry_to_json).collect();
    serde_json::Value::Array(items).to_string()
}

fn entry_to_json(entry: &AuditEntry) -> serde_json::Value {
    let record = &entry.record;
    serde_json::json!({
        "id": entry.id,
        "ts_ms": record.ts_ms,
        "source": record.source.as_str(),
        "category": record.category,
        "severity": record.severity.as_str(),
        "actor": { "user_id": record.actor.user_id, "name": record.actor.name },
        "target": { "user_id": record.target.user_id, "name": record.target.name },
        "channel_id": record.channel_id,
        "reason": record.reason,
        "detail_json": record.detail_json,
        "relates_to": record.relates_to,
        "entry_hash": hex(&entry.entry_hash),
    })
}

fn verify_to_json(outcome: Option<Result<chain::VerifyOutcome, store::StoreError>>) -> String {
    let value = match outcome {
        Some(Ok(chain::VerifyOutcome::Intact { checked, head })) => serde_json::json!({
            "intact": true, "checked": checked, "head": hex(&head)
        }),
        Some(Ok(chain::VerifyOutcome::Broken { id, index, kind })) => serde_json::json!({
            "intact": false, "broken_id": id, "index": index,
            "kind": format!("{kind:?}"), "description": kind.description()
        }),
        Some(Err(err)) => serde_json::json!({ "error": err.to_string() }),
        None => serde_json::json!({ "error": "audit runtime unavailable" }),
    };
    value.to_string()
}

/// Lowercase hex-encode a 32-byte hash (no dependency needed).
fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Deliver a typed response through the host's server-side request/response
/// seam. The murmur `AuditLogBridge` registered a handler per response type
/// and packs the JSON into the matching `FancyAudit*` wire message for
/// `session` (mirroring the link-preview bridge).
fn respond(
    ctx: &PluginContext_TO<RArc<()>>,
    server_id: u32,
    request_id: &str,
    session: u32,
    response_type: &str,
    payload: &[u8],
) {
    if let RErr(e) = ctx.send_request_response(
        server_id,
        RStr::from_str(response_type),
        RStr::from_str(request_id),
        session,
        RSlice::from_slice(payload),
    ) {
        tracing::warn!(error = %e, response_type, "audit: send_request_response failed");
    }
}

fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_env("MUMBLE_PLUGIN_LOG")
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();
    });
}

impl MumblePlugin for AuditPlugin {
    fn name(&self) -> RStr<'_> {
        RStr::from_str(PLUGIN_NAME)
    }

    fn version(&self) -> RStr<'_> {
        RStr::from_str(PLUGIN_VERSION)
    }

    fn info_json(&self) -> RString {
        PluginInfo {
            description: "Server audit log: a tamper-evident, hash-chained, searchable record of \
                          moderation actions, with fine-grained per-part collection toggles."
                .to_owned(),
            author: Some("Fancy Mumble Developers".to_owned()),
            homepage: None,
            tags: vec![
                "audit".to_owned(),
                "moderation".to_owned(),
                "security".to_owned(),
            ],
            debug_rows: Vec::new(),
            client_manifest: None,
        }
        .to_rstring()
    }

    fn on_load(&self, ctx: PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        init_tracing();
        let configured = ctx
            .get_config(RStr::from_str("storage_path"))
            .into_option()
            .map(RString::into_string);
        let path = config::resolve_db_path(configured);
        match AuditRuntime::open(&path) {
            Ok(runtime) => {
                *self
                    .runtime
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(runtime);
                tracing::info!(db = %path.display(), "audit plugin loaded");
            }
            Err(e) => {
                tracing::error!(error = %e, db = %path.display(), "audit plugin: store unavailable, running inert");
            }
        }
        ROk(())
    }

    fn on_unload(&self, _ctx: &PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        *self
            .runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        ROk(())
    }

    fn on_plugin_message(
        &self,
        ctx: &PluginContext_TO<RArc<()>>,
        msg: PluginMessageIn,
    ) -> PluginResult<()> {
        match msg.payload_type.as_str() {
            MSG_QUERY => self.handle_query(ctx, &msg),
            MSG_VERIFY => self.handle_verify(ctx, &msg),
            MSG_INGEST => self.handle_ingest(&msg),
            MSG_CONFIG_GET => self.handle_config_get(ctx, &msg),
            MSG_CONFIG_SET => self.handle_config_set(ctx, &msg),
            _ => {}
        }
        ROk(())
    }
}

mumble_plugin_api::fancy_export_plugin!(AuditPlugin::new);

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "unwrap is the standard, readable idiom in unit tests"
)]
mod tests {
    use super::*;

    #[test]
    fn query_parsing_reads_all_fields() {
        let body = serde_json::json!({
            "categories": ["audit.ban", "audit.kick"],
            "source": "server",
            "actor_user_id": 3,
            "text": "spam",
            "since_ms": 100,
            "limit": 50
        });
        let query = parse_query(&body);
        assert_eq!(query.categories, vec!["audit.ban", "audit.kick"]);
        assert_eq!(query.source, Some(Source::Server));
        assert_eq!(query.actor_user_id, Some(3));
        assert_eq!(query.text.as_deref(), Some("spam"));
        assert_eq!(query.since_ms, Some(100));
        assert_eq!(query.limit, Some(50));
    }

    #[test]
    fn hex_encodes_lowercase_fixed_width() {
        let mut h = [0u8; 32];
        h[0] = 0x0a;
        h[31] = 0xff;
        let s = hex(&h);
        assert_eq!(s.len(), 64);
        assert!(s.starts_with("0a"));
        assert!(s.ends_with("ff"));
    }

    #[test]
    fn verify_json_shapes_both_outcomes() {
        let intact = verify_to_json(Some(Ok(chain::VerifyOutcome::Intact {
            checked: 2,
            head: [0u8; 32],
        })));
        assert!(intact.contains("\"intact\":true"));
        let broken = verify_to_json(Some(Ok(chain::VerifyOutcome::Broken {
            id: 5,
            index: 1,
            kind: chain::BreakKind::ContentMismatch,
        })));
        assert!(broken.contains("\"intact\":false"));
        assert!(broken.contains("\"broken_id\":5"));
    }
}
