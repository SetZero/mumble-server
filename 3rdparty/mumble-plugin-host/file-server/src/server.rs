//! HTTP server bootstrap and background cleanup task.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::http::build_router;
use crate::state::AppState;
use crate::storage::Storage;

/// Handle to a running file server. Drop or call [`Self::shutdown`] to stop.
#[derive(Debug)]
pub struct ServerHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    cleanup_shutdown_tx: Option<oneshot::Sender<()>>,
    http_task: Option<JoinHandle<()>>,
    cleanup_task: Option<JoinHandle<()>>,
}

impl ServerHandle {
    /// Send the shutdown signal and wait for both background tasks to
    /// finish gracefully. The cleanup task is signalled (instead of
    /// `abort`-ed) so any in-flight delete is allowed to commit.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.cleanup_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.cleanup_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.http_task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.cleanup_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.cleanup_task.take() {
            task.abort();
        }
        if let Some(task) = self.http_task.take() {
            task.abort();
        }
    }
}

/// Start the HTTP server bound to `{config.bind_address}:{config.port}`
/// and the periodic cleanup task that deletes expired files.
pub async fn start(state: AppState) -> Result<ServerHandle, std::io::Error> {
    let addr = SocketAddr::new(state.config.bind_address, state.config.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "file server listening");

    let router = build_router(state.clone());
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let http_task = tokio::spawn(async move {
        let server = axum::serve(
            listener,
            // The rate limiter needs the peer IP - install ConnectInfo<SocketAddr>.
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        });
        if let Err(e) = server.await {
            tracing::error!(error = %e, "axum server stopped with error");
        }
    });

    let (cleanup_shutdown_tx, cleanup_shutdown_rx) = oneshot::channel::<()>();
    let cleanup_task = spawn_cleanup_task(
        state.storage.clone(),
        state.config.ttl,
        cleanup_shutdown_rx,
    );

    Ok(ServerHandle {
        shutdown_tx: Some(shutdown_tx),
        cleanup_shutdown_tx: Some(cleanup_shutdown_tx),
        http_task: Some(http_task),
        cleanup_task: Some(cleanup_task),
    })
}

fn spawn_cleanup_task(
    storage: Arc<Storage>,
    ttl: Duration,
    mut shutdown: oneshot::Receiver<()>,
) -> JoinHandle<()> {
    let interval = compute_cleanup_interval(ttl);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => break,
                _ = ticker.tick() => run_cleanup(&storage),
            }
        }
    })
}

/// How long after the last successful download a file is exempt from the
/// TTL-based cleanup.  Avoids racing with a long in-flight stream that
/// just touched `downloaded_at` (M-6).
const CLEANUP_RECENT_DOWNLOAD_GRACE: Duration = Duration::from_secs(60);

fn run_cleanup(storage: &Storage) {
    let now_s = crate::signing::now_unix_seconds();
    let grace_ms = CLEANUP_RECENT_DOWNLOAD_GRACE.as_millis() as i64;
    let now_ms = (now_s as i64).saturating_mul(1000);
    match storage.list_expired(now_s) {
        Ok(ids) => {
            for id in ids {
                if let Ok(Some(rec)) = storage.get(&id) {
                    if let Some(touched) = rec.downloaded_at {
                        if touched.saturating_add(grace_ms) > now_ms {
                            tracing::debug!(
                                file_id = %id,
                                "skip cleanup: recently downloaded"
                            );
                            continue;
                        }
                    }
                }
                if let Err(e) = storage.delete(&id) {
                    tracing::warn!(file_id = %id, error = %e, "failed to delete expired file");
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "list_expired failed"),
    }
}

fn compute_cleanup_interval(ttl: Duration) -> Duration {
    let secs = (ttl.as_secs() / 4).clamp(60, 3600);
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests panic on failure")]
    use super::*;

    #[test]
    fn cleanup_interval_is_clamped() {
        assert_eq!(compute_cleanup_interval(Duration::from_secs(60)), Duration::from_secs(60));
        assert_eq!(compute_cleanup_interval(Duration::from_secs(3600)), Duration::from_secs(900));
        assert_eq!(compute_cleanup_interval(Duration::from_secs(86_400)), Duration::from_secs(3600));
        assert_eq!(compute_cleanup_interval(Duration::from_secs(10)), Duration::from_secs(60));
    }
}
