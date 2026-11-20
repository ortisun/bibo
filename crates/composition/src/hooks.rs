//! Work that a binary's loop does at fixed points. The traits live here, in the library, so that a
//! seam implementation (such as [`RefreshRequests`](crate::seams::RefreshRequests)) can implement
//! one without depending on the binary that runs the loop.

/// Work to do before each claim. The loop is single-threaded, so the future need not be `Send`; the
/// hook itself is shared by `Arc`, so it is `Send` and `Sync`.
#[async_trait::async_trait(?Send)]
pub trait BeforeClaim: Send + Sync {
    /// Runs once before each call to `Engine::claim_next`. It must not fail the loop: a hook that
    /// cannot do its work logs and returns.
    async fn before_claim(&self);
}

/// Work to do, again and again, while one attempt runs.
///
/// The steps before a claim run between attempts only, and a worker runs one attempt at a time. A
/// person who cancels a job while its stage runs would otherwise wait for the stage to end before
/// anything reads the request. The loop calls this at its poll interval for the job of the attempt
/// it is running. Like [`BeforeClaim`], it must not fail the loop.
#[async_trait::async_trait(?Send)]
pub trait WhileRunning: Send + Sync {
    /// Applies the cancel requests recorded for `job` and nothing else. Once the engine has the
    /// cancel, the next heartbeat of the attempt reads it and raises the attempt's cancel signal.
    async fn apply_cancels(
        &self,
        tenant: factory_domain::ids::TenantId,
        job: factory_domain::ids::JobId,
    );
}
