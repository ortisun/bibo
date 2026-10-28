//! Attack: resource exhaustion of the control plane by a candidate lockfile.
//!
//! The reader bounds the size of a document (8 MiB) and the nesting depth, but the checks that
//! follow are quadratic in the number of packages: `LockDiff::between` scans every package once
//! per distinct name (and allocates a normalized name on each comparison), and
//! `Lockfile::resolve` scans the whole lockfile once per dependency edge. The checks run on the
//! host, in the async task of the validation stage, before any sandbox limit applies, and the
//! candidate writes the lockfile.
//!
//! Measured on the reviewer's machine in the debug profile (the profile tests run in), with the
//! timing probe that was used before the clock ban of `clippy.toml` made the tests use a thread
//! and a deadline instead:
//!
//! | packages | bytes   | time   |
//! |----------|---------|--------|
//! | 500      | 97 854  | 61 ms  |
//! | 1 000    | 195 854 | 203 ms |
//! | 2 000    | 393 854 | 824 ms |
//! | 4 000    | 789 854 | 3.39 s |
//!
//! Every doubling of the packages quadruples the time. A lockfile at the 8 MiB bound holds about
//! 40 000 packages of this shape, which is roughly a hundred times the 4 000 row (minutes in the
//! debug profile, tens of seconds in release).
//!
//! The tests take no reading of the clock (the workspace bans `Instant::now`): the check runs on
//! its own thread and the test waits for it with a deadline.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use factory_workflow::gates::supply_chain::cargo::CargoFormat;
use factory_workflow::gates::supply_chain::integrity::{Context, inspect};
use factory_workflow::gates::supply_chain::model::Side;
use factory_workflow::gates::supply_chain::names::PopularNames;

const BASE_LOCK: &str = "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n";

/// A lockfile where `app` depends on `count` registry packages.
fn wide_lockfile(count: usize) -> String {
    let mut text = String::from(
        "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n",
    );
    for index in 0..count {
        text.push_str(&format!(" \"p{index}\",\n"));
    }
    text.push_str("]\n");
    let checksum = "a".repeat(64);
    for index in 0..count {
        text.push_str(&format!(
            "[[package]]\nname = \"p{index}\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{checksum}\"\n"
        ));
    }
    text
}

/// True when the integrity checks over a candidate lockfile of `count` packages finish within
/// `budget`. The thread is left to finish by itself when it does not.
fn finishes_within(count: usize, budget: Duration) -> bool {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let popular = PopularNames::bundled().expect("the bundled list");
        let cx = Context {
            internal_names: &[],
            popular: &popular,
        };
        let lock = wide_lockfile(count);
        let base = Side::of(&CargoFormat, [("Cargo.lock", BASE_LOCK)]);
        let head = Side::of(&CargoFormat, [("Cargo.lock", lock.as_str())]);
        let integrity = inspect(&CargoFormat, &base, &head, &cx).expect("the base is readable");
        // Every package is new, so the answer is the same however fast it came.
        let _ = sender.send(integrity.new_direct.len());
    });
    receiver.recv_timeout(budget) == Ok(count)
}

/// 4 000 packages are 790 KiB, a tenth of what the reader accepts. A linear check takes a few
/// tens of milliseconds in the debug profile. The budget is generous (1.5 s) and the current code
/// needs more than twice that on the reviewer's machine.
#[test]
#[ignore = "confirmed defect SC-4: the integrity checks are quadratic in the number of locked packages"]
fn sc4_the_integrity_checks_stay_fast_on_a_large_candidate_lockfile() {
    assert!(
        finishes_within(4_000, Duration::from_millis(1_500)),
        "4000 packages did not finish in 1.5 s; doubling the packages quadruples the time"
    );
}

/// Control: a small lockfile is fast, so the test above measures growth and not a slow machine.
#[test]
fn control_a_small_lockfile_is_fast() {
    assert!(finishes_within(200, Duration::from_millis(1_500)));
}
