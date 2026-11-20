//! The broker's network side: the listener the sidecar forwards to, the call to the provider, and
//! the reading of usage from what comes back.
//!
//! The listener and the upstream client are blocking and use one thread per connection, bounded
//! by `ServerLimits::max_connections`. The job runs one tool at a time in Slice 1 (single
//! concurrency), so a thread per connection is a few threads, and the code stays readable from top
//! to bottom. The domain-level rules (who may spend what) are in [`crate::broker`].

pub mod scrub;
pub mod secret;
pub mod server;
pub mod usage;
pub mod wire;

pub use secret::{KeyError, ProviderKey, SUBSCRIPTION_TOKEN_PREFIX, TokenError};
pub use server::{
    BrokerServer, BrokerServerConfig, ServerLimits, StartError, UpstreamConfig, UpstreamCredential,
};
