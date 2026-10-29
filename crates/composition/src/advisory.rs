//! The date of the advisory database, read from a file.
//!
//! The audit runs offline inside the image, and with the tool's offline flag it neither checks how
//! old its database is nor prints a date. The date is therefore a fact the image build records
//! (the day the database was copied in), and this source reads it from `advisory_database.date_file`
//! ([`AdvisoryDatabase`]). The gate requires a date: an audit against a database of unknown age is
//! not a clean audit.
//!
//! # What it promises
//!
//! It answers a date only when the file is a regular file (not a link), holds at most 64 bytes, and
//! the single line in it is a UTC time (`2026-10-28T09:00:00Z`) or a day (`2026-10-28`, read as
//! the start of that day) that is not in the future. Anything else is unknown: a missing file, a
//! file that cannot be read, a link, a long file, text that is not a date, and a date after the
//! clock's now (a date in the future cannot be true). The file is read at every call, so a rebuilt
//! image that rewrites it is seen without a restart, and a deleted one turns the answer unknown.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::Clock;
use factory_workflow::gates::supply_chain::facts::AdvisoryDatabase;

/// The most bytes the date file may hold.
const MAX_BYTES: u64 = 64;

/// The date of the advisory database, from a file.
#[derive(Clone)]
pub struct FileAdvisoryDatabase {
    path: PathBuf,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for FileAdvisoryDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileAdvisoryDatabase")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl FileAdvisoryDatabase {
    /// A source that reads `path` and judges it against `clock`.
    #[must_use]
    pub fn new(path: PathBuf, clock: Arc<dyn Clock>) -> Self {
        Self { path, clock }
    }

    /// The date in the file, or `None`.
    fn read(&self) -> Option<Timestamp> {
        let meta = std::fs::symlink_metadata(&self.path).ok()?;
        if !meta.is_file() || meta.len() > MAX_BYTES {
            return None;
        }
        let text = std::fs::read_to_string(&self.path).ok()?;
        let line = text.trim();
        if line.is_empty() || line.contains('\n') {
            return None;
        }
        let stamp = if line.len() == 10 {
            format!("{line}T00:00:00Z")
        } else {
            line.to_owned()
        };
        let date = Timestamp::parse(&stamp).ok()?;
        (date <= self.clock.now()).then_some(date)
    }
}

#[async_trait]
impl AdvisoryDatabase for FileAdvisoryDatabase {
    fn fidelity(&self) -> Fidelity {
        // It reports what the file says, and says nothing when the file says nothing. It cannot
        // make a pass the image did not record.
        Fidelity::Real
    }

    async fn updated_at(&self) -> Option<Timestamp> {
        self.read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    struct Now;
    impl Clock for Now {
        fn now(&self) -> Timestamp {
            Timestamp::parse("2026-10-28T12:00:00Z").expect("a time")
        }
        fn fidelity(&self) -> Fidelity {
            Fidelity::Fake
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("advisory-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    fn source(path: &Path) -> FileAdvisoryDatabase {
        FileAdvisoryDatabase::new(path.to_path_buf(), Arc::new(Now))
    }

    #[test]
    fn a_time_and_a_day_are_read_and_anything_else_is_unknown() {
        let dir = scratch("read");
        let file = dir.join("date");
        for (text, want) in [
            ("2026-10-28T09:00:00Z\n", Some("2026-10-28T09:00:00Z")),
            ("2026-10-21", Some("2026-10-21T00:00:00Z")),
            ("  2026-10-21  \n", Some("2026-10-21T00:00:00Z")),
            ("", None),
            ("yesterday", None),
            ("2026-10-28T09:00:00Z\n2026-10-29T09:00:00Z\n", None),
            // A date after the clock's now cannot be true.
            ("2026-10-29T09:00:00Z", None),
            ("2027-01-01", None),
            // Longer than the cap.
            (&"2026-10-21".repeat(8), None),
        ] {
            std::fs::write(&file, text).expect("write");
            let got = source(&file).read();
            assert_eq!(
                got,
                want.map(|w| Timestamp::parse(w).expect("a time")),
                "{text:?}"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_missing_file_and_a_link_are_unknown() {
        let dir = scratch("missing");
        assert_eq!(source(&dir.join("absent")).read(), None);
        let target = dir.join("real");
        std::fs::write(&target, "2026-10-21").expect("write");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("link");
        assert_eq!(source(&link).read(), None);
        assert!(source(&target).read().is_some());
        assert_eq!(source(&dir).read(), None, "a directory is not a date file");
        let _ = std::fs::remove_dir_all(dir);
    }
}
