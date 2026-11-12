//! Acceptance-scenario evidence: every requirement of the frozen specification has a covering
//! test that this change made pass.
//!
//! # The rule
//!
//! A test **names** a requirement by carrying its identifier, or the identifier of one of its
//! scenarios, in the test's own name, in the usual way of a code identifier: `FR-001` is
//! `fr_001`, so `tests/it.rs::fr_001_counts_a_line` names `FR-001`. A name matches only as a
//! whole token, so `fr_0011` does not name `FR-001`.
//!
//! The rule is the same for every test report format, because it is applied to the name of the
//! test in the one model of a test run (`crate::gates::command::outcomes`):
//!
//! 1. Both the name and the identifier are put in one form: letters in lower case, and every
//!    character that is not an ASCII letter or digit written as an underscore. So the letter
//!    case of the identifier does not matter, and `FR-001`, `fr_001`, `Fr 001` and `fr.001`
//!    are the same.
//! 2. The identifier must then appear in the name with no letter or digit directly before or
//!    after it.
//!
//! For a JUnit XML report the name is `<classname>::<name>`, so the identifier may be in the
//! name of the test case or in its class name. A class or a module named after a requirement
//! therefore names the requirement for every test case in it, as a Rust test binary named
//! after one does.
//!
//! | The test | Names `FR-001` |
//! |---|---|
//! | `tests/it.rs::fr_001_counts_a_line` (Rust) | yes |
//! | `tests.test_count::test_fr_001_counts_a_line` (pytest) | yes |
//! | `word count FR-001 counts a line` (Jest) | yes |
//! | `example.com/wc::Test_FR_001_CountsALine` (Go) | yes |
//! | `example.com/wc::TestFR_001_CountsALine` (Go) | no: the letter `t` of `Test` comes directly before `fr` |
//! | `com.example.FR_001_Test::countsALine` (JUnit, in the class name) | yes |
//! | `com.example.CountTest::fr001CountsALine` | no: `fr001` has no separator |
//! | `example.com/wc::Test_FR_001CountsALine` | no: a letter follows `001` |
//! | `tests.test_count::test_fr_0011` | no: a digit follows `001` |
//!
//! A test **covers** a requirement when it names it, it ran and passed on the candidate commit,
//! and it did **not** pass in the test run of the base commit. The report says which of three
//! reasons applies ([`Basis`]): the test is new, it failed on the base commit, or it was ignored
//! on the base commit. A test that already passed on the base commit proves nothing about the
//! change, so it does not count, whatever its name.
//!
//! A requirement with no covering test fails the gate. The two ways to fail are told apart
//! ([`Coverage::already_passing`]): no passed test names the requirement, or the only tests that
//! name it passed before the change.
//!
//! Both test runs are the supervisor's own observations. The caller must hand in the run of the
//! base commit: when there is none, the caller reports `BLOCKED` and never calls this module.
//!
//! # A job that needs no new behavior
//!
//! A refactor or a documentation job may have requirements that the code already met. The gate
//! does not pass them on the old tests, and it has no exemption. The kind of a request is chosen
//! by the intake classifier, which is an agent, and the specification contract has no field in
//! which the person who approves it could say "this requirement needs no new test"; an exemption
//! read from either would be a bypass that an agent can choose. Such a job passes the gate the
//! same way as any other: the change adds a test, named after the requirement, that pins the
//! behavior the requirement asks to keep. Until a person can record that decision in the frozen
//! specification, a job that adds no such test is `FAILED` here.
//!
//! # What this gate still cannot prove
//!
//! * **That a covering test asserts anything.** An empty new test named `fr_001_x` is a new
//!   passed test, and it counts. The independent code reviewer is told to open every covering
//!   test the report names and to report one that asserts nothing, cannot fail or does not
//!   exercise the scenario. That is a judgment of a model and not a measurement.
//! * **That a new test would fail without the change.** The baseline is the base commit's own
//!   tests on the base commit's code. The new tests are not run against the old code, so a new
//!   test that would have passed before the change counts all the same.
//! * **That a test is new in more than its name.** Tests are matched by binary and name. A copy
//!   of an old test under a new name is a new test here. (A renamed or moved test is not: the
//!   old name is then missing from the candidate's run, and `test-file-protection` fails.)
//!
//! Mutation testing of the diff and acceptance tests that the builder never sees would close
//! these. They are designed elsewhere and are not part of this gate.

use std::collections::BTreeMap;

/// A requirement of the frozen specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// The identifier as the specification wrote it, such as `FR-001`.
    pub id: String,
    /// The scenarios that show it works, such as `AS-001`.
    pub scenarios: Vec<String>,
}

/// What the test run of the base commit says about one test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Before {
    /// It ran and passed.
    Passed,
    /// It ran and failed.
    Failed,
    /// It was ignored and did not run.
    Ignored,
}

/// Why a passed test counts as evidence for this change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// The test does not appear in the run of the base commit.
    NewTest,
    /// The test failed on the base commit and passes now.
    FailedBefore,
    /// The test was ignored on the base commit and passes now.
    IgnoredBefore,
}

impl Basis {
    /// The words a report uses for this basis.
    #[must_use]
    pub const fn words(self) -> &'static str {
        match self {
            Self::NewTest => "new test",
            Self::FailedBefore => "failed on the base commit",
            Self::IgnoredBefore => "ignored on the base commit",
        }
    }
}

/// One test that covers a requirement, and why it counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Covering {
    /// The test, as the test run names it.
    pub test: String,
    /// Why it counts.
    pub basis: Basis,
}

/// The evidence for one requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    /// The identifier of the requirement.
    pub requirement: String,
    /// The tests that cover it.
    pub covering: Vec<Covering>,
    /// The passed tests that name it and do not count, because they passed on the base commit.
    pub already_passing: Vec<String>,
}

impl Coverage {
    /// True when at least one test covers the requirement.
    #[must_use]
    pub fn is_covered(&self) -> bool {
        !self.covering.is_empty()
    }
}

/// The form of an identifier that a test name carries: lower case, with every character that is
/// not a letter or a digit written as an underscore.
fn token(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// True when `name` holds `wanted` as a whole token.
fn holds(name: &str, wanted: &str) -> bool {
    if wanted.is_empty() {
        return false;
    }
    let name = token(name);
    let wanted = token(wanted);
    name.match_indices(&wanted).any(|(start, _)| {
        let before = name[..start].chars().next_back();
        let after = name[start + wanted.len()..].chars().next();
        before.is_none_or(|c| !c.is_ascii_alphanumeric())
            && after.is_none_or(|c| !c.is_ascii_alphanumeric())
    })
}

/// True when the test carries the identifier of the requirement or of one of its scenarios.
fn names(test: &str, requirement: &Requirement) -> bool {
    holds(test, &requirement.id)
        || requirement
            .scenarios
            .iter()
            .any(|scenario| holds(test, scenario))
}

/// The evidence for every requirement, in the order given.
///
/// `passed_tests` are the tests that passed on the candidate commit. `baseline` is the whole
/// test run of the base commit, by the same names; a test that is absent from it is new.
#[must_use]
pub fn coverage(
    requirements: &[Requirement],
    passed_tests: &[&str],
    baseline: &BTreeMap<String, Before>,
) -> Vec<Coverage> {
    requirements
        .iter()
        .map(|requirement| {
            let mut covering = Vec::new();
            let mut already_passing = Vec::new();
            for test in passed_tests.iter().filter(|test| names(test, requirement)) {
                let basis = match baseline.get(*test) {
                    None => Basis::NewTest,
                    Some(Before::Failed) => Basis::FailedBefore,
                    Some(Before::Ignored) => Basis::IgnoredBefore,
                    Some(Before::Passed) => {
                        already_passing.push((*test).to_owned());
                        continue;
                    }
                };
                covering.push(Covering {
                    test: (*test).to_owned(),
                    basis,
                });
            }
            Coverage {
                requirement: requirement.id.clone(),
                covering,
                already_passing,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirement(id: &str, scenarios: &[&str]) -> Requirement {
        Requirement {
            id: id.to_owned(),
            scenarios: scenarios.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn baseline(tests: &[(&str, Before)]) -> BTreeMap<String, Before> {
        tests
            .iter()
            .map(|(name, before)| ((*name).to_owned(), *before))
            .collect()
    }

    /// The requirements with no covering test, when nothing ran on the base commit.
    fn uncovered(requirements: &[Requirement], passed: &[&str]) -> Vec<String> {
        coverage(requirements, passed, &BTreeMap::new())
            .into_iter()
            .filter(|found| !found.is_covered())
            .map(|found| found.requirement)
            .collect()
    }

    #[test]
    fn a_new_test_named_after_a_requirement_covers_it() {
        let reqs = [requirement("FR-001", &[]), requirement("FR-002", &[])];
        let tests = ["tests/it.rs::fr_001_counts_a_line"];
        let found = coverage(&reqs, &tests, &BTreeMap::new());
        assert_eq!(
            found[0].covering,
            [Covering {
                test: "tests/it.rs::fr_001_counts_a_line".to_owned(),
                basis: Basis::NewTest,
            }]
        );
        assert!(found[0].is_covered());
        assert!(!found[1].is_covered());
        assert!(found[1].already_passing.is_empty());
    }

    #[test]
    fn a_test_that_passed_on_the_base_commit_does_not_cover_the_requirement() {
        let reqs = [requirement("FR-001", &[])];
        let found = coverage(
            &reqs,
            &["t::fr_001_old"],
            &baseline(&[("t::fr_001_old", Before::Passed)]),
        );
        assert!(!found[0].is_covered());
        assert_eq!(found[0].already_passing, ["t::fr_001_old"]);
    }

    #[test]
    fn a_test_that_failed_or_was_ignored_on_the_base_commit_covers_with_that_basis() {
        let reqs = [requirement("FR-001", &[]), requirement("FR-002", &[])];
        let found = coverage(
            &reqs,
            &["t::fr_001_fixed", "t::fr_002_enabled"],
            &baseline(&[
                ("t::fr_001_fixed", Before::Failed),
                ("t::fr_002_enabled", Before::Ignored),
            ]),
        );
        assert_eq!(found[0].covering[0].basis, Basis::FailedBefore);
        assert_eq!(found[1].covering[0].basis, Basis::IgnoredBefore);
    }

    #[test]
    fn an_old_test_beside_a_new_one_leaves_the_requirement_covered_by_the_new_one_only() {
        let reqs = [requirement("FR-001", &[])];
        let found = coverage(
            &reqs,
            &["t::fr_001_old", "t::fr_001_new"],
            &baseline(&[("t::fr_001_old", Before::Passed)]),
        );
        assert_eq!(found[0].covering.len(), 1);
        assert_eq!(found[0].covering[0].test, "t::fr_001_new");
        assert_eq!(found[0].already_passing, ["t::fr_001_old"]);
    }

    #[test]
    fn the_same_name_in_another_test_binary_is_another_test() {
        let reqs = [requirement("FR-001", &[])];
        let found = coverage(
            &reqs,
            &["tests/new.rs::fr_001_x"],
            &baseline(&[("tests/old.rs::fr_001_x", Before::Passed)]),
        );
        assert_eq!(found[0].covering[0].basis, Basis::NewTest);
    }

    #[test]
    fn a_test_named_after_a_scenario_covers_the_requirement() {
        let reqs = [requirement("FR-002", &["AS-004"])];
        assert!(uncovered(&reqs, &["tests/it.rs::as_004_empty_input"]).is_empty());
    }

    #[test]
    fn a_longer_number_does_not_cover_a_shorter_one() {
        let reqs = [requirement("FR-001", &[])];
        assert_eq!(uncovered(&reqs, &["t::fr_0011_other"]), ["FR-001"]);
        assert_eq!(uncovered(&reqs, &["t::xfr_001"]), ["FR-001"]);
        assert!(uncovered(&reqs, &["t::fr_001"]).is_empty());
    }

    #[test]
    fn names_from_other_test_runners_follow_the_same_token_rule() {
        let reqs = [requirement("FR-001", &["AS-004"])];
        for name in [
            "tests.test_count::test_fr_001_counts_a_line",
            "tests.test_count::test_counts[FR-001]",
            "word count FR-001 counts a line",
            "word count fr-001 counts a line",
            "example.com/wc::Test_FR_001_CountsALine",
            "com.example.FR_001_Test::countsALine",
            "com.example.CountTest::as_004_emptyInput",
            "FR-001",
        ] {
            assert!(uncovered(&reqs, &[name]).is_empty(), "{name}");
        }
        for name in [
            "com.example.CountTest::fr001CountsALine",
            "example.com/wc::TestFR_001_CountsALine",
            "example.com/wc::Test_FR_001CountsALine",
            "tests.test_count::test_fr_0011",
            "tests.test_count::test_xfr_001",
            "word count FR-0010 counts a line",
        ] {
            assert_eq!(uncovered(&reqs, &[name]), ["FR-001"], "{name}");
        }
    }

    #[test]
    fn the_letter_case_of_the_requirement_identifier_does_not_matter() {
        let lower = [requirement("fr-001", &[])];
        assert!(uncovered(&lower, &["t::FR_001_x"]).is_empty());
        let upper = [requirement("FR-001", &[])];
        assert!(uncovered(&upper, &["t::Fr_001_x"]).is_empty());
    }

    #[test]
    fn no_passed_test_covers_nothing() {
        assert_eq!(uncovered(&[requirement("FR-001", &[])], &[]), ["FR-001"]);
    }
}
