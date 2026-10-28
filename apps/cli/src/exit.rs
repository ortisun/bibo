//! The exit codes, and how an HTTP status maps to one.

/// How a command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Done.
    Ok,
    /// The command was not understood, or a local check failed.
    Failed,
    /// The API refused the request.
    Refused,
    /// The API is not ready or asked to try later, or a check could not run.
    Blocked,
    /// The API could not be reached.
    Unreachable,
}

impl Exit {
    /// The process exit code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Failed => 1,
            Self::Refused => 2,
            Self::Blocked => 3,
            Self::Unreachable => 4,
        }
    }

    /// The exit for an HTTP status.
    #[must_use]
    pub const fn of_status(status: u16) -> Self {
        match status {
            200..=299 => Self::Ok,
            // Slow down, or the service cannot answer now: try again later.
            429 | 500..=599 => Self::Blocked,
            400..=499 => Self::Refused,
            _ => Self::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_codes_are_distinct() {
        let all = [
            Exit::Ok,
            Exit::Failed,
            Exit::Refused,
            Exit::Blocked,
            Exit::Unreachable,
        ];
        let mut codes: Vec<u8> = all.iter().map(|e| e.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }

    #[test]
    fn a_status_maps_to_refused_blocked_or_done() {
        for (status, expected) in [
            (200, Exit::Ok),
            (202, Exit::Ok),
            (400, Exit::Refused),
            (401, Exit::Refused),
            (403, Exit::Refused),
            (404, Exit::Refused),
            (409, Exit::Refused),
            (429, Exit::Blocked),
            (503, Exit::Blocked),
            (500, Exit::Blocked),
            (302, Exit::Failed),
        ] {
            assert_eq!(Exit::of_status(status), expected, "{status}");
        }
    }
}
