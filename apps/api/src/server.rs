//! The connection loop.
//!
//! `axum::serve` offers no header timeout, no limit on open connections and no say in what is
//! recorded as the peer, so the loop is written here over `hyper` and `hyper-util`, and the axum
//! router is the service each connection calls.
//!
//! * **Slow clients.** hyper's header read timeout closes a connection that has not finished its
//!   request line and headers in time (a slow-loris sender). A body that is slow is cut off by the
//!   pipeline's own deadline (`routes`).
//! * **Open connections** are bounded by a semaphore, and each source (an address, or an IPv6
//!   /64) by a count of its own that is smaller than the table (API-6). A connection over either
//!   limit is closed at once, before anything is read from it.
//! * **The peer** is the address the operating system reports for the connection. It is put in the
//!   request as [`Peer`](crate::routes::Peer) and nothing else is ever used as a source address.
//! * **Stopping.** When the shutdown signal is raised the listener stops accepting, each open
//!   connection finishes the request it is serving and closes, and the loop waits for them up to
//!   the drain budget.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
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
use crate::limits::source_of;
use crate::routes::Peer;

/// The largest buffer hyper keeps for one request head, in bytes. A head larger than this is
/// refused with `431`.
const MAX_HEAD_BYTES: usize = 32 * 1024;

/// How many connections each source holds open, and the most one may hold (API-6).
///
/// A silent connection costs its sender nothing and is never counted as a request, so the request
/// rate limit cannot see it; without a count per source one address could hold every slot of the
/// table until the header timeout, and again after it. The count is made when the connection is
/// accepted, before a byte is read, under [`source_of`]: an IPv6 client is its /64 and an IPv4
/// client behind a dual-stack listener is its IPv4 address.
#[derive(Debug)]
pub struct Sources {
    held: Mutex<HashMap<IpAddr, usize>>,
    most: usize,
}

/// A place in the count of one source. It gives the place back when it is dropped.
#[derive(Debug)]
pub struct Slot {
    sources: Arc<Sources>,
    source: IpAddr,
}

impl Sources {
    /// A count that lets each source hold `most` connections.
    #[must_use]
    pub fn new(most: usize) -> Arc<Self> {
        Arc::new(Self {
            held: Mutex::new(HashMap::new()),
            most,
        })
    }

    /// Takes a place for a connection from `peer`, or `None` when that source holds its share.
    #[must_use]
    pub fn enter(self: &Arc<Self>, peer: IpAddr) -> Option<Slot> {
        let source = source_of(peer);
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let count = held.entry(source).or_insert(0);
        if *count >= self.most {
            return None;
        }
        *count += 1;
        Some(Slot {
            sources: Arc::clone(self),
            source,
        })
    }

    /// How many sources hold at least one connection now.
    #[must_use]
    pub fn sources_held(&self) -> usize {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut held = self
            .sources
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.remove(&self.source);
            }
        }
    }
}

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
    let sources = Sources::new(limits.connections_per_source());
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
                // A source that holds its share is closed before a byte is read, and before it
                // can take a place from the table that the other sources share.
                let Some(slot) = sources.enter(peer.ip()) else {
                    drop(stream);
                    continue;
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    // The table is full: closed before a byte is read.
                    drop(stream);
                    continue;
                };
                let app = app.clone();
                let shutdown = shutdown.clone();
                let header_timeout = limits.header_timeout();
                connections.spawn(async move {
                    serve_connection(stream, peer, app, header_timeout, shutdown).await;
                    drop(permit);
                    drop(slot);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn a_source_holds_no_more_than_its_share_and_gives_the_place_back() {
        let sources = Sources::new(2);
        let peer = IpAddr::from([192, 0, 2, 1]);
        let first = sources.enter(peer).expect("the first place");
        let _second = sources.enter(peer).expect("the second place");
        assert!(sources.enter(peer).is_none(), "the third is refused");
        // Another source is not affected.
        assert!(sources.enter(IpAddr::from([192, 0, 2, 2])).is_some());
        drop(first);
        assert!(sources.enter(peer).is_some(), "a freed place can be taken");
    }

    #[test]
    fn the_count_forgets_a_source_that_holds_nothing() {
        let sources = Sources::new(1);
        let slot = sources
            .enter(IpAddr::from([192, 0, 2, 1]))
            .expect("a place");
        assert_eq!(sources.sources_held(), 1);
        drop(slot);
        assert_eq!(
            sources.sources_held(),
            0,
            "the map does not grow with the past"
        );
    }

    #[test]
    fn the_addresses_of_one_ipv6_prefix_and_both_spellings_of_an_ipv4_client_are_one_source() {
        let sources = Sources::new(1);
        let in_prefix = |last: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, last));
        let _held = sources.enter(in_prefix(1)).expect("a place");
        assert!(
            sources.enter(in_prefix(2)).is_none(),
            "a second address of the same /64 is the same source"
        );
        assert!(
            sources
                .enter(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1)))
                .is_some(),
            "another /64 is another source"
        );
        let v4 = Ipv4Addr::new(198, 51, 100, 9);
        let _plain = sources.enter(IpAddr::V4(v4)).expect("a place");
        assert!(
            sources.enter(IpAddr::V6(v4.to_ipv6_mapped())).is_none(),
            "the mapped spelling is the same client"
        );
    }
}
