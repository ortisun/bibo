//! The error type shared by the value types.
//!
//! Every message is plain English and names the kind of value, a short excerpt of what was
//! offered, and the rule that it broke. The excerpt is cut short so that an error never repeats a
//! large or sensitive input in full.

/// How many characters of an offered value an error message shows.
const EXCERPT_LIMIT: usize = 60;

/// A text, number or collection did not meet the rule for its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueError {
    what: &'static str,
    /// A quoted excerpt of the offered value, when there is a short value to show.
    shown: Option<String>,
    rule: String,
}

impl std::fmt::Display for ValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.shown {
            Some(shown) => write!(f, "{shown} is not a valid {}: {}", self.what, self.rule),
            None => write!(f, "this {} is not valid: {}", self.what, self.rule),
        }
    }
}

impl std::error::Error for ValueError {}

impl ValueError {
    /// Describes a rejected value. `what` names the type in plain words, for example `slug`.
    #[must_use]
    pub fn new(what: &'static str, offered: &str, rule: impl Into<String>) -> Self {
        Self {
            what,
            shown: Some(excerpt(offered)),
            rule: rule.into(),
        }
    }

    /// Describes a rejected value that is too large or too structured to quote, such as a list.
    #[must_use]
    pub fn unquoted(what: &'static str, rule: impl Into<String>) -> Self {
        Self {
            what,
            shown: None,
            rule: rule.into(),
        }
    }

    /// The kind of value that was rejected, for example `slug`.
    #[must_use]
    pub const fn what(&self) -> &'static str {
        self.what
    }

    /// The rule that the value broke.
    #[must_use]
    pub fn rule(&self) -> &str {
        &self.rule
    }
}

/// A quoted, escaped, length-limited copy of `offered`.
fn excerpt(offered: &str) -> String {
    let mut shown: String = offered
        .chars()
        .take(EXCERPT_LIMIT)
        .flat_map(char::escape_debug)
        .collect();
    if offered.chars().nth(EXCERPT_LIMIT).is_some() {
        shown.push_str("...");
    }
    format!("\"{shown}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_input_is_cut_and_marked() {
        let error = ValueError::new("slug", &"x".repeat(500), "too long");
        let message = error.to_string();
        assert!(
            message.ends_with("...\" is not a valid slug: too long") || message.contains("...")
        );
        assert!(message.len() < 120, "{message}");
    }

    #[test]
    fn control_characters_are_escaped() {
        let error = ValueError::new("slug", "a\nb", "no newlines");
        assert_eq!(
            error.to_string(),
            "\"a\\nb\" is not a valid slug: no newlines"
        );
    }
}
