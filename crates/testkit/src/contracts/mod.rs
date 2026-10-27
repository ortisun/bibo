//! Shared contract suites: one per port, run by the in-memory fake now and by the real adapter
//! later.
//!
//! A fake that is easier than the port's documented contract is a defect, and the suite is how
//! the fake and the real adapter are kept honest together. Each module here holds the checks for
//! one port. A check is an `async fn` that drives the port through its public methods only and
//! returns `Err(message)` when the port breaks its contract. Nothing in a check knows which
//! implementation it is running against.
//!
//! # Using a suite
//!
//! 1. Implement the module's `*Subject` trait for your implementation. A subject gives the suite
//!    the port itself plus the few levers a black-box test cannot reach through the port, such as
//!    moving the database clock forward or damaging a stored blob. For a fake the lever is a
//!    method call. For a real adapter it is a sleep, a SQL statement or a file edit.
//! 2. Call the module's `run` with a function that makes a **fresh** subject for every check, then
//!    call [`Report::assert_ok`] on the result. `checks()` lists the checks if you need to select
//!    some.
//!
//! ```ignore
//! let report = factory_testkit::contracts::store::run(|| async { MySubject::new().await }).await;
//! report.assert_ok();
//! ```
//!
//! # Proving a suite can fail
//!
//! Each fake can be built with a deliberate defect (for example a store that grants one lease to
//! two workers). The tests in `crates/testkit/tests/` run the suite against every defect and
//! require the named check to fail, so a suite that has gone soft is noticed.

use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;

pub mod artifact;
pub mod sandbox;
pub mod store;
pub mod workspace;

/// A check that returns an error starting with this text is recorded as skipped, not failed.
pub const SKIPPED_PREFIX: &str = "skipped: ";

/// A boxed future, so a check can be stored in a list.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One named check of a port's contract.
pub struct Check<D: ?Sized + 'static> {
    /// The check's name, in plain words joined by underscores. It appears in failure reports.
    pub name: &'static str,
    /// Runs the check against a subject. `Err` carries what went wrong, in plain English.
    pub run: for<'a> fn(&'a D) -> BoxFuture<'a, Result<(), String>>,
}

/// What a suite found.
#[derive(Debug, Default)]
pub struct Report {
    /// The checks that held.
    pub passed: Vec<&'static str>,
    /// The checks that failed, each with what went wrong.
    pub failed: Vec<(&'static str, String)>,
    /// The checks the subject cannot support, each with why. A skipped check is not a pass: an
    /// adapter that skips one must cover it in a test of its own.
    pub skipped: Vec<(&'static str, String)>,
}

impl Report {
    /// True when every check held.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.failed.is_empty()
    }

    /// True when the named check failed.
    #[must_use]
    pub fn failed_check(&self, name: &str) -> bool {
        self.failed.iter().any(|(failed, _)| *failed == name)
    }

    /// The names of the failed checks.
    #[must_use]
    pub fn failed_names(&self) -> Vec<&'static str> {
        self.failed.iter().map(|(name, _)| *name).collect()
    }

    /// Panics with every failure when any check failed.
    ///
    /// # Panics
    /// Panics when a check failed, listing each check and why. That is how a test fails.
    pub fn assert_ok(&self) {
        assert!(
            self.is_ok(),
            "{} of {} contract check(s) failed:\n{}",
            self.failed.len(),
            self.failed.len() + self.passed.len(),
            self.failed
                .iter()
                .map(|(name, why)| format!("  - {name}: {why}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// Runs every check against a fresh subject.
///
/// `make` is called once per check, so no check sees the leftovers of another. Each suite module
/// has a typed `run` that boxes the subject for you.
pub async fn run_checks<D, F, Fut>(checks: &[Check<D>], make: F) -> Report
where
    D: ?Sized + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = Box<D>>,
{
    let mut report = Report::default();
    for check in checks {
        let subject = make().await;
        match (check.run)(&*subject).await {
            Ok(()) => report.passed.push(check.name),
            Err(why) if why.starts_with(SKIPPED_PREFIX) => report.skipped.push((check.name, why)),
            Err(why) => report.failed.push((check.name, why)),
        }
    }
    report
}

/// Adds a context to an error, as a plain-English `String`.
pub trait Context<T> {
    /// Turns an error into `"{what}: {error:?}"`.
    ///
    /// # Errors
    /// Returns the error rendered as a string with `what` in front.
    fn ctx(self, what: &str) -> Result<T, String>;
}

impl<T, E: Debug> Context<T> for Result<T, E> {
    fn ctx(self, what: &str) -> Result<T, String> {
        self.map_err(|error| format!("{what}: {error:?}"))
    }
}

/// Returns `Err(message)` unless the condition holds.
macro_rules! ensure {
    ($condition:expr, $($message:tt)+) => {
        if !$condition {
            return Err(format!($($message)+));
        }
    };
}

/// Returns `Err(message)` unless both sides are equal, showing both.
macro_rules! ensure_eq {
    ($left:expr, $right:expr, $($message:tt)+) => {{
        let (left, right) = (&$left, &$right);
        if left != right {
            return Err(format!(
                "{}: expected {:?} but found {:?}",
                format!($($message)+),
                right,
                left
            ));
        }
    }};
}

/// Returns `Err(message)` unless the result is an error that matches the pattern.
macro_rules! ensure_err {
    ($result:expr, $pattern:pat, $($message:tt)+) => {
        match $result {
            Err($pattern) => {}
            Err(other) => {
                return Err(format!(
                    "{}: expected the error {} but found {:?}",
                    format!($($message)+),
                    stringify!($pattern),
                    other
                ));
            }
            Ok(_) => {
                return Err(format!(
                    "{}: expected the error {} but the call succeeded",
                    format!($($message)+),
                    stringify!($pattern)
                ));
            }
        }
    };
}

/// Returns early from a check, recording it as skipped with the reason.
macro_rules! skip {
    ($($message:tt)+) => {
        return Err(format!("{}{}", $crate::contracts::SKIPPED_PREFIX, format!($($message)+)))
    };
}

pub(crate) use {ensure, ensure_eq, ensure_err, skip};

/// Builds a [`Check`] list from async functions that take `&D`.
macro_rules! check_list {
    ($subject:ty; $($name:ident),+ $(,)?) => {
        vec![
            $( $crate::contracts::Check::<$subject> {
                name: stringify!($name),
                run: |subject| ::std::boxed::Box::pin($name(subject)),
            } ),+
        ]
    };
}

pub(crate) use check_list;
