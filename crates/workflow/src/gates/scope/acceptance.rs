//! Acceptance-scenario evidence: every requirement of the frozen specification has a covering
//! test result.
//!
//! A requirement is covered when at least one test **that ran and passed** in the verified test
//! run names the requirement or one of its scenarios. A test names a requirement by carrying its
//! identifier in the test's own name, in the usual way of a code identifier: `FR-001` is
//! `fr_001`, so `tests/it.rs::fr_001_counts_a_line` covers `FR-001`. A name matches only as a
//! whole token, so `fr_0011` does not cover `FR-001`.
//!
//! A requirement without a passed covering test is a failure of the gate. The result of the
//! match is evidence only because the test run it reads was observed by the supervisor.

/// A requirement of the frozen specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// The identifier as the specification wrote it, such as `FR-001`.
    pub id: String,
    /// The scenarios that show it works, such as `AS-001`.
    pub scenarios: Vec<String>,
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

/// The identifiers of the requirements that no passed test covers, in the order given.
#[must_use]
pub fn uncovered<'a>(requirements: &'a [Requirement], passed_tests: &[&str]) -> Vec<&'a str> {
    requirements
        .iter()
        .filter(|requirement| {
            !passed_tests.iter().any(|test| {
                holds(test, &requirement.id)
                    || requirement
                        .scenarios
                        .iter()
                        .any(|scenario| holds(test, scenario))
            })
        })
        .map(|requirement| requirement.id.as_str())
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

    #[test]
    fn a_test_named_after_a_requirement_covers_it() {
        let reqs = [requirement("FR-001", &[]), requirement("FR-002", &[])];
        let tests = ["tests/it.rs::fr_001_counts_a_line"];
        assert_eq!(uncovered(&reqs, &tests), vec!["FR-002"]);
    }

    #[test]
    fn a_test_named_after_a_scenario_covers_the_requirement() {
        let reqs = [requirement("FR-002", &["AS-004"])];
        assert!(uncovered(&reqs, &["tests/it.rs::as_004_empty_input"]).is_empty());
    }

    #[test]
    fn a_longer_number_does_not_cover_a_shorter_one() {
        let reqs = [requirement("FR-001", &[])];
        assert_eq!(uncovered(&reqs, &["t::fr_0011_other"]), vec!["FR-001"]);
        assert_eq!(uncovered(&reqs, &["t::xfr_001"]), vec!["FR-001"]);
        assert!(uncovered(&reqs, &["t::fr_001"]).is_empty());
    }

    #[test]
    fn no_passed_test_covers_nothing() {
        assert_eq!(
            uncovered(&[requirement("FR-001", &[])], &[]),
            vec!["FR-001"]
        );
    }
}
