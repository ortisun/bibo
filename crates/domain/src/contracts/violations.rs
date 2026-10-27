//! Rule breaks found in a document that has the right shape.
//!
//! A JSON schema can say that a field is a string or that a list is not empty. It can also say
//! "if the outcome is PASSED, every command must have exited with code 0", with `if` and `then`
//! keywords. The Rust types express the first kind in their field types. The second kind is a
//! [`Violation`], found after the document has been read.

use std::fmt;

/// One broken rule: where it is and what is wrong, in plain English.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The field the rule is about, written like `findings[0].severity`.
    pub path: String,
    /// What is wrong and what would make it right.
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// Every rule a document breaks. Empty means the document is valid.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Violations(Vec<Violation>);

impl Violations {
    /// A collection with no violations.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Records a broken rule.
    pub fn push(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.0.push(Violation {
            path: path.into(),
            message: message.into(),
        });
    }

    /// Records a broken rule when `holds` is false.
    pub fn require(&mut self, holds: bool, path: impl Into<String>, message: impl Into<String>) {
        if !holds {
            self.push(path, message);
        }
    }

    /// True when nothing is broken.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The violations, in the order they were found.
    pub fn iter(&self) -> std::slice::Iter<'_, Violation> {
        self.0.iter()
    }

    /// `Ok` when nothing is broken, otherwise the violations.
    ///
    /// # Errors
    /// Returns `self` when it holds at least one violation.
    pub fn into_result(self) -> Result<(), Self> {
        if self.0.is_empty() { Ok(()) } else { Err(self) }
    }
}

impl<'a> IntoIterator for &'a Violations {
    type Item = &'a Violation;
    type IntoIter = std::slice::Iter<'a, Violation>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl fmt::Display for Violations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.as_slice() {
            [] => f.write_str("no rule is broken"),
            [one] => write!(f, "the document breaks a rule: {one}"),
            many => {
                write!(f, "the document breaks {} rules: ", many.len())?;
                for (index, violation) in many.iter().enumerate() {
                    if index > 0 {
                        f.write_str("; ")?;
                    }
                    write!(f, "{violation}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Violations {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_collection_is_a_success() {
        assert_eq!(Violations::new().into_result(), Ok(()));
    }

    #[test]
    fn violations_read_as_one_sentence_each() {
        let mut found = Violations::new();
        found.push(
            "outcome",
            "a PASSED report needs every command to exit with code 0",
        );
        assert_eq!(
            found.to_string(),
            "the document breaks a rule: outcome: a PASSED report needs every command to exit with code 0"
        );
        found.require(false, "reason", "say why");
        assert!(
            found
                .to_string()
                .starts_with("the document breaks 2 rules: outcome: ")
        );
        assert!(found.to_string().ends_with("; reason: say why"));
    }

    #[test]
    fn a_holding_rule_records_nothing() {
        let mut found = Violations::new();
        found.require(true, "x", "never shown");
        assert!(found.is_empty());
    }
}
