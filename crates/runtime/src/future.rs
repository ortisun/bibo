//! The return type that `#[async_trait]` gives an `async fn` of a port trait.
//!
//! The `async-trait` crate is not on the `runtime` entry of the dependency rules, so the port trait
//! `AgentRuntime` is implemented with the signatures the macro would write, and each body is
//! `Box::pin(async move { .. })`. The sandbox crate does the same.

use std::future::Future;
use std::pin::Pin;

/// A boxed, sendable future, as `#[async_trait]` returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
