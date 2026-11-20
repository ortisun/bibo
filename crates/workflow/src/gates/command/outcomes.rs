//! One model of a test run, whatever the test runner printed.
//!
//! The readers of the three report formats ([`super::libtest`], [`super::junit`] and
//! [`super::tap`]) all produce an [`Outcomes`]: each test by name with how it ended, and one
//! answer to "can this report be trusted". The verdict of the test gate, the comparison with
//! the base commit and the acceptance evidence gate use this model and never know the format.
//!
//! A reading that is not trusted says why in one sentence ([`Outcomes::problem`]). The gate
//! that reads it is `BLOCKED` with that sentence. No reading that is not trusted is ever a pass.
//!
//! # How a test is named
//!
//! | Format | The name of a test |
//! |---|---|
//! | `libtest` | `<binary>::<test>`, where the binary is what cargo names on standard error |
//! | `junit-xml` | `<classname>::<name>` of the `testcase`, or `<name>` alone when the class name is empty or equal to the name |
//! | `tap` | the description of the test line, or `test <number>` when the line has none |
//!
//! The acceptance evidence gate looks for the identifier of a requirement in this whole name
//! (see [`crate::gates::scope::acceptance`]), so for a JUnit report the identifier may be in the
//! name of the test case or in its class name.

use std::collections::BTreeMap;

/// How a test ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// The test ran and passed.
    Passed,
    /// The test ran and failed, or ended with an error.
    Failed,
    /// The test was skipped or ignored and did not run to a result.
    Ignored,
}

/// A report format that is not the default one, read from one text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    /// JUnit XML.
    JunitXml,
    /// The Test Anything Protocol, version 13 or 14.
    Tap,
}

impl ReportKind {
    /// The name the project manifest uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JunitXml => "junit-xml",
            Self::Tap => "tap",
        }
    }

    /// Reads a report of this kind.
    #[must_use]
    pub fn read(self, text: &str) -> Outcomes {
        match self {
            Self::JunitXml => super::junit::read(text),
            Self::Tap => super::tap::read(text),
        }
    }
}

/// What a report says about the tests.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcomes {
    results: BTreeMap<String, Status>,
    problem: Option<&'static str>,
}

impl Outcomes {
    /// A reading that can be trusted.
    #[must_use]
    pub fn trusted(results: BTreeMap<String, Status>) -> Self {
        Self {
            results,
            problem: None,
        }
    }

    /// A reading that cannot be trusted, with the reason as a plain sentence. The results are
    /// kept for a person who reads a debugger, and no gate uses them.
    #[must_use]
    pub fn untrusted(results: BTreeMap<String, Status>, problem: &'static str) -> Self {
        Self {
            results,
            problem: Some(problem),
        }
    }

    /// True when the report is whole, well formed and adds up. A report that is not consistent
    /// proves nothing.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.problem.is_none()
    }

    /// Why the report is not trusted, as a plain sentence.
    #[must_use]
    pub fn problem(&self) -> Option<&'static str> {
        self.problem
    }

    /// Every test, by name, with how it ended.
    #[must_use]
    pub fn results(&self) -> &BTreeMap<String, Status> {
        &self.results
    }

    /// How many tests ended with this status.
    #[must_use]
    pub fn count(&self, status: Status) -> usize {
        self.results.values().filter(|s| **s == status).count()
    }

    /// The names of the tests that ended with this status, in order.
    #[must_use]
    pub fn ids(&self, status: Status) -> Vec<&str> {
        self.results
            .iter()
            .filter(|(_, s)| **s == status)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// True when at least one test ran to a result. A run in which every test is skipped, or in
    /// which none exists, has shown nothing.
    #[must_use]
    pub fn ran_something(&self) -> bool {
        self.count(Status::Passed) + self.count(Status::Failed) > 0
    }
}
