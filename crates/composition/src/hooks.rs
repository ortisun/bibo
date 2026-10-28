//! Work that a binary's loop does at fixed points. The traits live here, in the library, so that a
//! seam implementation (such as [`RefreshRequests`](crate::seams::RefreshRequests)) can implement
//! one without depending on the binary that runs the loop.

/// Work to do before each claim. The loop is single-threaded, so the future need not be `Send`.
#[async_trait::async_trait(?Send)]
pub trait BeforeClaim {
    /// Runs once before each call to `Engine::claim_next`. It must not fail the loop: a hook that
    /// cannot do its work logs and returns.
    async fn before_claim(&self);
}
