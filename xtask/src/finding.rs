//! One rule violation, printed as `error[RULE]: where: what`.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// A rule id from the rules file (`DEP-01`) or the negative-test catalog (`ST-03`), or
    /// `LAYOUT` when the workspace does not match the rules file.
    pub rule: String,
    /// A path relative to the workspace root, with an optional `:line`.
    pub location: String,
    pub message: String,
}

impl Finding {
    pub fn new(rule: &str, location: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            rule: rule.to_string(),
            location: location.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "error[{}]: {}: {}",
            self.rule, self.location, self.message
        )
    }
}
