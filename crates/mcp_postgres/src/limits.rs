//! The caps of ADR 0021, decision 4, item 4.

use std::time::Duration;

/// What one server instance allows. The defaults are the values of ADR 0021.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Rows returned by one query at most. A caller may ask for fewer, never more.
    pub max_rows: usize,
    /// Bytes of one tool result at most, the truncation marker included.
    pub max_result_bytes: usize,
    /// `SET LOCAL statement_timeout` of every call.
    pub statement_timeout: Duration,
    /// `SET LOCAL lock_timeout` of every call.
    pub lock_timeout: Duration,
    /// Calls this server answers in its life. One server serves one troubleshooting run in the
    /// gateway, or one engineer's session as a binary.
    pub max_calls: u64,
    /// Bytes of SQL text a caller may send.
    pub max_sql_bytes: usize,
    /// How long establishing a connection may take.
    pub connect_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows: 200,
            max_result_bytes: 64 * 1024,
            statement_timeout: Duration::from_secs(5),
            lock_timeout: Duration::from_secs(1),
            max_calls: 300,
            max_sql_bytes: 16 * 1024,
            connect_timeout: Duration::from_secs(5),
        }
    }
}

impl Limits {
    /// The wall clock of a whole call: the statement timeout plus room for connecting and the
    /// rollback. Past it the call is abandoned and its query cancelled.
    pub fn call_deadline(&self) -> Duration {
        self.statement_timeout
            .saturating_mul(2)
            .saturating_add(self.connect_timeout)
    }

    /// The milliseconds for `SET LOCAL`, never zero (zero would mean no limit).
    pub(crate) fn statement_timeout_ms(&self) -> u128 {
        self.statement_timeout.as_millis().max(1)
    }

    /// The milliseconds for `SET LOCAL lock_timeout`, never zero.
    pub(crate) fn lock_timeout_ms(&self) -> u128 {
        self.lock_timeout.as_millis().max(1)
    }
}
