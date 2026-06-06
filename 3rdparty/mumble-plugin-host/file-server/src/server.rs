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

/// How long graceful shutdown waits for in-flight work to drain before the
/// task is force-aborted.  Bounding this is essential: a stuck/slow connection
/// (e.g. a client that paused mid-upload) must never keep the listening socket
/// bound indefinitely, or a subsequent re-enable of the plugin would fail with
/// `EADDRINUSE` and leave the file server unreachable.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

impl ServerHandle {
    /// Send the shutdown signal and wait for both background tasks to
    /// finish gracefully. The cleanup task is signalled (instead of
    /// `abort`-ed) so any in-flight delete is allowed to commit.  Each wait is
    /// bounded by [`SHUTDOWN_GRACE`]; on timeout the task is aborted so the
    /// runtime/listener is always released promptly.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.cleanup_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(mut task) = self.cleanup_task.take() {
            if tokio::time::timeout(SHUTDOWN_GRACE, &mut task)
                .await
                .is_err()
            {
                task.abort();
            }
        }
        if let Some(mut task) = self.http_task.take() {
            if tokio::time::timeout(SHUTDOWN_GRACE, &mut task)
                .await
                .is_err()
            {
                // Graceful shutdown stalled on a hung connection - force it so
                // the bound socket is released and a re-enable can re-bind.
                task.abort();
                let _ = (&mut task).await;
            }
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
        // Loud start/exit markers: this task must run until shutdown.  If it
        // ever returns (cleanly or via error) the file server has stopped
        // serving while still appearing "listening" from the startup log, which
        // is exactly the silent-death failure mode that leaves clients with
        // "error sending request" against a bound-but-unresponsive port.
        tracing::info!(%addr, "file server accept loop running (serving HTTP)");
        match server.await {
            Ok(()) => tracing::warn!(
                %addr,
                "file server accept loop exited cleanly - no longer serving HTTP"
            ),
            Err(e) => tracing::error!(
                %addr,
                error = %e,
                "file server accept loop exited with error - no longer serving HTTP"
            ),
        }
    });

    // One-shot startup self-test: probe our own `/capabilities` over loopback.
    // This definitively separates "the HTTP accept loop is not serving" (a
    // freeze/deadlock inside this runtime - the self-test fails/times out) from
    // "the server serves fine but clients can't reach it" (a Docker port / proxy
    // / client-side issue - the self-test succeeds).  Detached: purely a
    // diagnostic, its result is logged, not awaited.
    drop(spawn_startup_self_test(addr));

    let (cleanup_shutdown_tx, cleanup_shutdown_rx) = oneshot::channel::<()>();
    let cleanup_task =
        spawn_cleanup_task(state.storage.clone(), state.config.ttl, cleanup_shutdown_rx);

    Ok(ServerHandle {
        shutdown_tx: Some(shutdown_tx),
        cleanup_shutdown_tx: Some(cleanup_shutdown_tx),
        http_task: Some(http_task),
        cleanup_task: Some(cleanup_task),
    })
}

/// How long the startup self-test waits for the server to answer its own
/// `/capabilities` request before declaring the accept loop unresponsive.
const SELF_TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Spawn a detached task that probes our own `/capabilities` endpoint over
/// loopback shortly after startup and logs the outcome.  See the call site for
/// why this is worth the handful of bytes it sends.
fn spawn_startup_self_test(bind_addr: SocketAddr) -> JoinHandle<()> {
    // If we bound to a wildcard address (0.0.0.0 / ::), connect via loopback.
    let target = if bind_addr.ip().is_unspecified() {
        SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), bind_addr.port())
    } else {
        bind_addr
    };
    tokio::spawn(async move {
        // Give the accept loop a moment to reach `serve()`.
        tokio::time::sleep(Duration::from_millis(500)).await;
        match tokio::time::timeout(SELF_TEST_TIMEOUT, self_test_capabilities(target)).await {
            Ok(Ok(status)) => tracing::info!(
                %target,
                status,
                "file server self-test OK: served own /capabilities (HTTP loop is healthy; \
                 if clients still can't connect the problem is the Docker port mapping / proxy / client)"
            ),
            Ok(Err(e)) => tracing::error!(
                %target,
                error = %e,
                "file server self-test FAILED: could not complete own /capabilities request \
                 (the HTTP accept loop is bound but not serving)"
            ),
            Err(_) => tracing::error!(
                %target,
                timeout_s = SELF_TEST_TIMEOUT.as_secs(),
                "file server self-test TIMED OUT: own /capabilities did not respond \
                 (the HTTP accept loop is bound but not serving - likely frozen/deadlocked)"
            ),
        }
    })
}

/// Minimal dependency-free HTTP/1.0 GET of `/capabilities`, returning the
/// numeric status code from the response status line.
async fn self_test_capabilities(target: SocketAddr) -> Result<u16, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(target)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    // HTTP/1.0 with no keep-alive so the server closes the socket after the
    // response, letting us read to EOF without parsing Content-Length.
    let req = format!("GET /capabilities HTTP/1.0\r\nHost: {target}\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = [0u8; 64];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| format!("read: {e}"))?;
    if n == 0 {
        return Err("server closed connection without responding".to_owned());
    }
    let line = String::from_utf8_lossy(&buf[..n]);
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            format!(
                "malformed status line: {:?}",
                line.lines().next().unwrap_or("")
            )
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
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "tests panic on failure"
    )]
    use super::*;

    #[test]
    fn cleanup_interval_is_clamped() {
        assert_eq!(
            compute_cleanup_interval(Duration::from_secs(60)),
            Duration::from_secs(60)
        );
        assert_eq!(
            compute_cleanup_interval(Duration::from_secs(3600)),
            Duration::from_secs(900)
        );
        assert_eq!(
            compute_cleanup_interval(Duration::from_secs(86_400)),
            Duration::from_secs(3600)
        );
        assert_eq!(
            compute_cleanup_interval(Duration::from_secs(10)),
            Duration::from_secs(60)
        );
    }
}
