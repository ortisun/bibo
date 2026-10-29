//! The test ticker keeps its promises: a move is never spent before a wait is open to use it, and
//! a wait that is dropped leaves nothing open.
//!
//! Every scenario that moves time by hand goes through it, and a ticker that loses a move makes a
//! scenario hang for ever, so its own behaviour is pinned here and not left to the scenarios. The
//! tests that expect a hang run on paused time, so the guard that ends them fires at once.

#[path = "support/ticker.rs"]
mod ticker;

use std::time::Duration;

use factory_testkit::clock::within;
use factory_workflow::scheduler::Ticker;
use ticker::ManualTicker;

const SECOND: Duration = Duration::from_secs(1);

#[tokio::test(start_paused = true)]
async fn a_move_that_comes_before_the_wait_is_held_until_the_wait_opens() {
    let ticker = ManualTicker::new();
    // The move is polled first and finds no wait open. The wait that opens right after must end.
    let moved = ticker.advance_when_a_wait_is_due(16 * SECOND);
    let waiting = ticker.sleep(15 * SECOND);
    within(5 * SECOND, "the wait and the held move", async {
        tokio::join!(moved, waiting)
    })
    .await;
    assert_eq!(ticker.waiting(), 0);
}

#[tokio::test(start_paused = true)]
#[should_panic(expected = "the later wait: not finished after 5s")]
async fn a_plain_move_with_no_wait_open_is_lost_which_is_why_the_held_move_exists() {
    let ticker = ManualTicker::new();
    ticker.advance(16 * SECOND);
    // The wait is due 15 seconds after the move, by the ticker's own time, so nothing ends it.
    within(5 * SECOND, "the later wait", ticker.sleep(15 * SECOND)).await;
}

#[tokio::test(start_paused = true)]
#[should_panic(expected = "no wait of the engine opened that a move of 16s would end")]
async fn a_move_waits_for_a_wait_it_would_end_and_not_for_a_farther_one() {
    let ticker = ManualTicker::new();
    // Only a wait of 30 seconds is open, which a move of 16 does not end. Neither the wait nor the
    // move can finish, and the move fails the test instead of spending itself.
    let far = ticker.sleep(30 * SECOND);
    let moved = ticker.advance_when_a_wait_is_due(16 * SECOND);
    tokio::join!(far, moved);
}

#[tokio::test(start_paused = true)]
#[should_panic(expected = "no wait of the engine opened")]
async fn a_move_that_no_wait_will_use_fails_the_test_instead_of_hanging_it() {
    let ticker = ManualTicker::new();
    ticker.advance_when_a_wait_is_due(16 * SECOND).await;
}

#[tokio::test]
async fn a_wait_whose_future_is_dropped_leaves_nothing_open() {
    let ticker = ManualTicker::new();
    tokio::select! {
        biased;
        () = ticker.sleep(15 * SECOND) => panic!("nothing moved the ticker"),
        () = async { assert_eq!(ticker.waiting(), 1, "the wait is open while it is polled") } => {}
    }
    assert_eq!(ticker.waiting(), 0, "dropping the future ended the wait");
}

#[tokio::test(start_paused = true)]
async fn a_wait_that_ends_is_taken_off_and_a_later_wait_is_not_affected() {
    let ticker = ManualTicker::new();
    let first = ticker.sleep(15 * SECOND);
    let mover = async {
        ticker.advance_when_a_wait_is_due(16 * SECOND).await;
    };
    tokio::join!(first, mover);
    assert_eq!(ticker.waiting(), 0);
    // The second wait is due 15 seconds after the ticker's time of 16, which is 31.
    let second = ticker.sleep(15 * SECOND);
    let mover = async {
        ticker.advance_when_a_wait_is_due(15 * SECOND).await;
    };
    within(5 * SECOND, "the second wait and its move", async {
        tokio::join!(second, mover)
    })
    .await;
}
