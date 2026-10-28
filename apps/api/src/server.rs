//! The connection loop.
//!
//! `axum::serve` offers no header timeout, no limit on open connections and no say in what is
//! recorded as the peer, so the loop is written here over `hyper` and `hyper-util`, and the axum
//! router is the service each connection calls.
//!
//! * **Slow clients.** hyper's header read timeout closes a connection that has not finished its
//!   request line and headers in time (a slow-loris sender). A body that is slow is cut off by the
//!   pipeline's own deadline (`routes`).
//! * **Open connections** are bounded by a semaphore. A connection over the limit is closed at
//!   once, before anything is read from it.
//! * **The peer** is the address the operating system reports for the connection. It is put in the
//!   request as [`Peer`](crate::routes::Peer) and nothing else is ever used as a source address.
//! * **Stopping.** When the shutdown signal is raised the listener stops accepting, each open
//!   connection finishes the request it is serving and closes, and the loop waits for them up to
//!   the drain budget.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use factory_composition::system::Shutdown;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tower::ServiceExt;

use crate::config::Limits;
use crate::routes::Peer;

/// The largest buffer hyper keeps for one request head, in bytes. A head larger than this is
/// refused with `431`.
const MAX_HEAD_BYTES: usize = 32 * 1024;

/// Serves `app` on `listener` until `shutdown` is raised, then drains.
///
/// # Errors
/// Never in normal use; a failure to accept is logged and the loop goes on.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    limits: Limits,
    shutdown: Shutdown,
) -> std::io::Result<()> {
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let mut connections: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            () = shutdown.raised() => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => {
                        tracing::warn!(error = %error, "a connection could not be accepted");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    // Over the limit: closed before a byte is read.
                    drop(stream);
                    continue;
                };
                let app = app.clone();
                let shutdown = shutdown.clone();
                let header_timeout = limits.header_timeout();
                connections.spawn(async move {
                    serve_connection(stream, peer, app, header_timeout, shutdown).await;
                    drop(permit);
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    drop(listener);
    let drained = tokio::time::timeout(limits.drain(), async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!("open connections were closed at the end of the drain budget");
        connections.abort_all();
    }
    Ok(())
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    app: Router,
    header_timeout: Duration,
    shutdown: Shutdown,
) {
    let service = service_fn(move |request: hyper::Request<Incoming>| {
        let app = app.clone();
        async move {
            let mut request = request.map(Body::new);
            request.extensions_mut().insert(Peer(peer));
            Ok::<_, Infallible>(
                app.oneshot(request)
                    .await
                    .unwrap_or_else(|never| match never {}),
            )
        }
    });
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout)
        .max_buf_size(MAX_HEAD_BYTES)
        .serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    let finished = tokio::select! {
        outcome = connection.as_mut() => Some(outcome),
        () = shutdown.raised() => None,
    };
    let outcome = match finished {
        Some(outcome) => outcome,
        None => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    };
    if let Err(error) = outcome {
        // A client that hangs up or sends garbage is routine; it is not logged as a fault.
        tracing::debug!(error = %error, "a connection ended with an error");
    }
}
