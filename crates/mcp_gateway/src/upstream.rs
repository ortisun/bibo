//! The upstream MCP servers behind the gateway, behind one trait.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use rmcp::model::{CallToolRequestParams, CallToolResult, JsonObject, Tool};
use rmcp::service::{Peer, RoleClient, RunningService};
use rmcp::{ServerHandler, ServiceExt};

pub use factory_domain::policy::troubleshooting::Upstream as UpstreamId;

use crate::secret::SecretValue;

/// A boxed future, so that [`Upstream`] can be a trait object.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One upstream MCP server, as the gateway sees it.
///
/// The gateway connects each upstream once at start (and again on
/// [`crate::Gateway::refresh`]), reads its tools, and forwards allowlisted calls to it. Errors
/// are categories without the transport's own message, which could carry a URL or a header.
pub trait Upstream: Send + Sync {
    /// Which upstream of the policy this is.
    fn id(&self) -> UpstreamId;

    /// The credential values this upstream sends, with a label each. The gateway registers every
    /// one with the redactor before it connects, so a credential echoed in a result is replaced.
    fn credentials(&self) -> Vec<(&'static str, SecretValue)> {
        Vec::new()
    }

    /// Opens (or reopens) the MCP session.
    fn connect(&self) -> BoxFuture<'_, Result<(), UpstreamError>>;

    /// The tools the upstream offers now.
    fn list_tools(&self) -> BoxFuture<'_, Result<Vec<Tool>, UpstreamError>>;

    /// Calls one upstream tool. A tool that failed answers `Ok` with `is_error`; `Err` means the
    /// call did not complete.
    fn call_tool(
        &self,
        name: String,
        arguments: Option<JsonObject>,
    ) -> BoxFuture<'_, Result<CallToolResult, UpstreamError>>;
}

/// What went wrong with an upstream, without the transport's message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpstreamError {
    /// No session: `connect` was not called or failed.
    #[error("the upstream {} is not connected", .0.as_str())]
    NotConnected(UpstreamId),
    /// The session could not be opened in time or at all.
    #[error("the upstream {} could not be reached", .0.as_str())]
    Connect(UpstreamId),
    /// A request failed in transport or protocol.
    #[error("the upstream {} failed to answer", .0.as_str())]
    Request(UpstreamId),
}

/// An MCP client session, shared by the HTTP and in-process upstreams.
pub(crate) struct ClientSession {
    id: UpstreamId,
    running: Mutex<Option<Arc<RunningService<RoleClient, ()>>>>,
}

impl ClientSession {
    pub(crate) fn new(id: UpstreamId) -> Self {
        Self {
            id,
            running: Mutex::new(None),
        }
    }

    pub(crate) fn install(&self, service: RunningService<RoleClient, ()>) {
        let previous = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(Arc::new(service));
        if let Some(previous) = previous {
            previous.cancellation_token().cancel();
        }
    }

    fn peer(&self) -> Result<Peer<RoleClient>, UpstreamError> {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|service| service.peer().clone())
            .ok_or(UpstreamError::NotConnected(self.id))
    }

    pub(crate) async fn list_tools(&self) -> Result<Vec<Tool>, UpstreamError> {
        let peer = self.peer()?;
        peer.list_all_tools()
            .await
            .map_err(|_| UpstreamError::Request(self.id))
    }

    pub(crate) async fn call_tool(
        &self,
        name: String,
        arguments: Option<JsonObject>,
    ) -> Result<CallToolResult, UpstreamError> {
        let peer = self.peer()?;
        let mut params = CallToolRequestParams::new(name);
        params.arguments = arguments;
        peer.call_tool(params)
            .await
            .map_err(|_| UpstreamError::Request(self.id))
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        if let Some(service) = self
            .running
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            service.cancellation_token().cancel();
        }
    }
}

type ServeFn = dyn Fn(tokio::io::DuplexStream) -> BoxFuture<'static, Result<(), ()>> + Send + Sync;

/// An MCP server of this process, reached through an in-memory pipe. The troubleshooter plugs
/// the read-only PostgreSQL server in this way (ADR 0021, decision 3).
pub struct InProcessUpstream {
    id: UpstreamId,
    serve: Box<ServeFn>,
    session: ClientSession,
    connect_timeout: Duration,
}

/// The bytes the in-memory pipe buffers in each direction.
const PIPE_BYTES: usize = 256 * 1024;

impl InProcessUpstream {
    /// An upstream over `server`. Each [`Upstream::connect`] serves a clone of it on a new pipe.
    pub fn new<S>(id: UpstreamId, server: S) -> Self
    where
        S: ServerHandler + Clone + Send + Sync + 'static,
    {
        let serve = move |pipe: tokio::io::DuplexStream| -> BoxFuture<'static, Result<(), ()>> {
            let server = server.clone();
            Box::pin(async move {
                let running = server.serve(pipe).await.map_err(|_| ())?;
                tokio::spawn(async move {
                    let _ = running.waiting().await;
                });
                Ok(())
            })
        };
        Self {
            id,
            serve: Box::new(serve),
            session: ClientSession::new(id),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

impl std::fmt::Debug for InProcessUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessUpstream")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Upstream for InProcessUpstream {
    fn id(&self) -> UpstreamId {
        self.id
    }

    fn connect(&self) -> BoxFuture<'_, Result<(), UpstreamError>> {
        Box::pin(async move {
            let (ours, theirs) = tokio::io::duplex(PIPE_BYTES);
            let id = self.id;
            let opened = tokio::time::timeout(self.connect_timeout, async move {
                let (served, client) = tokio::join!((self.serve)(theirs), ().serve(ours));
                served.map_err(|()| UpstreamError::Connect(id))?;
                client.map_err(|_| UpstreamError::Connect(id))
            })
            .await
            .map_err(|_| UpstreamError::Connect(id))??;
            self.session.install(opened);
            Ok(())
        })
    }

    fn list_tools(&self) -> BoxFuture<'_, Result<Vec<Tool>, UpstreamError>> {
        Box::pin(self.session.list_tools())
    }

    fn call_tool(
        &self,
        name: String,
        arguments: Option<JsonObject>,
    ) -> BoxFuture<'_, Result<CallToolResult, UpstreamError>> {
        Box::pin(self.session.call_tool(name, arguments))
    }
}
