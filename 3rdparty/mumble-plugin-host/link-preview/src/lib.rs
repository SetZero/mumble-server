//! `mumble-link-preview` - Mumble plugin that builds link/media previews.
//!
//! Ports the server's former in-process C++ subsystem (oEmbed / `OpenGraph` /
//! direct-media providers, SSRF gating, and server-side image downscaling) into
//! a native plugin loaded by the plugin host. The server forwards each
//! `FancyLinkPreviewRequest` as a generic plugin message (`preview.request`);
//! this plugin fetches and assembles the embeds and hands them back via the
//! host's generalized request/response bridge (`send_request_response`), which
//! the server packs into a `FancyLinkPreviewResponse`.
#![allow(
    unreachable_pub,
    reason = "internal cdylib: modules are private; cross-module items use `pub` for ergonomics, not as a library API"
)]

mod embed;
mod fetch;
mod manager;
mod media_preview;
mod providers;
mod ssrf;

use std::sync::{Arc, Mutex};

use abi_stable::std_types::RResult::{RErr, ROk};
use abi_stable::std_types::{RArc, RSlice, RStr, RString};
use mumble_plugin_api::{
    MumblePlugin, PluginContext_TO, PluginError, PluginInfo, PluginMessageIn, PluginResult,
};

use crate::embed::PreviewRequest;
use crate::manager::Manager;

/// Stable plugin identifier (the envelope `plugin_name` the server addresses).
const PLUGIN_NAME: &str = "fancy-link-preview";
const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Inbound message type the server sends with `{request_id, urls}` JSON.
const REQUEST_TYPE: &str = "preview.request";
/// Response routing key the server's bridge switches on to pack a
/// `FancyLinkPreviewResponse`.
const RESPONSE_TYPE: &str = "link-preview";

struct RunningState {
    runtime: tokio::runtime::Runtime,
    manager: Arc<Manager>,
    /// Long-lived context handle retained from `on_load`, shared into spawned
    /// tasks (via `Arc`, as the trait object itself is not `Clone`) so they can
    /// deliver responses after the hook returns.
    ctx: Arc<PluginContext_TO<RArc<()>>>,
}

/// The plugin instance. Holds its runtime + manager once loaded.
struct LinkPreviewPlugin {
    inner: Mutex<Option<RunningState>>,
}

impl LinkPreviewPlugin {
    fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

impl MumblePlugin for LinkPreviewPlugin {
    fn name(&self) -> RStr<'_> {
        RStr::from_str(PLUGIN_NAME)
    }

    fn version(&self) -> RStr<'_> {
        RStr::from_str(PLUGIN_VERSION)
    }

    fn info_json(&self) -> RString {
        PluginInfo {
            description: "Builds link & media previews (oEmbed, OpenGraph, direct media) \
                          with server-side SSRF gating and downscaled thumbnails."
                .to_owned(),
            author: Some("Fancy Mumble Developers".to_owned()),
            homepage: None,
            tags: vec![
                "link-preview".to_owned(),
                "http".to_owned(),
                "opengraph".to_owned(),
                "oembed".to_owned(),
            ],
            debug_rows: Vec::new(),
            client_manifest: None,
        }
        .to_rstring()
    }

    fn on_load(&self, ctx: PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        init_tracing();
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                return RErr(PluginError::Other(
                    format!("link-preview: failed to build runtime: {e}").into(),
                ))
            }
        };
        let mut guard = lock(&self.inner);
        *guard = Some(RunningState {
            runtime,
            manager: Arc::new(Manager::new()),
            ctx: Arc::new(ctx),
        });
        tracing::info!("link-preview plugin loaded");
        ROk(())
    }

    fn on_unload(&self, _ctx: &PluginContext_TO<RArc<()>>) -> PluginResult<()> {
        *lock(&self.inner) = None;
        ROk(())
    }

    fn on_plugin_message(
        &self,
        _ctx: &PluginContext_TO<RArc<()>>,
        msg: PluginMessageIn,
    ) -> PluginResult<()> {
        if msg.payload_type.as_str() != REQUEST_TYPE {
            return ROk(());
        }
        let req: PreviewRequest = match serde_json::from_slice(msg.payload.as_slice()) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "link-preview: bad preview.request payload");
                return ROk(());
            }
        };

        let guard = lock(&self.inner);
        let Some(state) = guard.as_ref() else {
            return ROk(());
        };
        let manager = Arc::clone(&state.manager);
        // Shared, long-lived context handle for the spawned task.
        let ctx = Arc::clone(&state.ctx);
        let server_id = msg.server_id;
        let session = msg.sender_session; // the requesting user; reply target

        drop(state.runtime.spawn(async move {
            let response = manager.handle_request(session, &req.urls).await;
            let json = serde_json::to_vec(&response).unwrap_or_default();
            let result = ctx.send_request_response(
                server_id,
                RStr::from_str(RESPONSE_TYPE),
                RStr::from_str(&req.request_id),
                session,
                RSlice::from_slice(&json),
            );
            if let RErr(e) = result {
                tracing::warn!(error = %e, "link-preview: failed to deliver response");
            }
        }));
        ROk(())
    }
}

/// Lock a mutex, recovering on poison.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
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

mod plugin_export {
    use super::LinkPreviewPlugin;
    mumble_plugin_api::fancy_export_plugin!(LinkPreviewPlugin::new);
}
