//! Two small helpers that stand in for crates this adapter may not depend on.
//!
//! * [`race`] polls two futures and returns the output of the first to finish. It does what
//!   `tokio::select!` does for two branches, without the `macros` feature of `tokio`, which is not
//!   on the `sandbox` entry of the dependency rules. The first future is polled first, so when
//!   both are ready it wins.
//! * [`BoxFuture`] is the return type that `#[async_trait]` gives an `async fn` of a port trait.
//!   The `async-trait` crate is not on the `sandbox` entry either, so the port traits are
//!   implemented with the signatures the macro would write, and the body is `Box::pin(async move
//!   { .. })`.

use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::task::Poll;

/// A boxed, sendable future, as `#[async_trait]` returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Which future of a [`race`] finished first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Either<A, B> {
    /// The first future finished first.
    First(A),
    /// The second future finished first.
    Second(B),
}

/// Polls `first` and `second` together and returns the output of whichever finishes first. The
/// other future is dropped.
pub async fn race<A: Future, B: Future>(first: A, second: B) -> Either<A::Output, B::Output> {
    let mut first = pin!(first);
    let mut second = pin!(second);
    poll_fn(|cx| {
        if let Poll::Ready(value) = first.as_mut().poll(cx) {
            return Poll::Ready(Either::First(value));
        }
        if let Poll::Ready(value) = second.as_mut().poll(cx) {
            return Poll::Ready(Either::Second(value));
        }
        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{pending, ready};

    #[test]
    fn the_first_ready_future_wins_and_the_first_wins_a_tie() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        runtime.block_on(async {
            assert_eq!(race(ready(1), pending::<u8>()).await, Either::First(1));
            assert_eq!(race(pending::<u8>(), ready(2)).await, Either::Second(2));
            assert_eq!(race(ready(1), ready(2)).await, Either::First(1));
        });
    }
}
