//! Why a tool call gave no result, in words short enough for a model and safe to show anyone.

use std::fmt;

/// The closed set of reasons a call fails. Each renders as one short sentence. None carries the
/// connection settings, a password or a driver message about the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolFailure {
    /// The input was refused before it reached the database (empty, too long, a NUL byte).
    Refused(String),
    /// The database refused the statement. `code` is the SQLSTATE; `message` is the server's
    /// primary message, already redacted.
    Database {
        /// The five-character SQLSTATE.
        code: String,
        /// The server's message, redacted.
        message: String,
    },
    /// The statement ran past the statement timeout or the call deadline and was cancelled.
    Timeout,
    /// The database could not be reached, or the connection was lost.
    Unavailable,
    /// This server has answered as many calls as its budget allows.
    CallBudgetSpent {
        /// The budget.
        limit: u64,
    },
    /// The result could not be redacted, so it was withheld.
    RedactionFailed,
}

impl fmt::Display for ToolFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::Database { code, message } => write!(f, "database error {code}: {message}"),
            Self::Timeout => f.write_str(
                "the statement ran past its time limit and was cancelled; narrow the query or add a filter",
            ),
            Self::Unavailable => f.write_str("the database is not reachable"),
            Self::CallBudgetSpent { limit } => {
                write!(f, "the call budget of this server ({limit} calls) is spent")
            }
            Self::RedactionFailed => {
                f.write_str("the result could not be checked for secrets, so it was withheld")
            }
        }
    }
}

impl std::error::Error for ToolFailure {}
