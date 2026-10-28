//! Counts the migrations of the repository and hands the number to the crate, so that the
//! readiness report can compare the schema the database has with the schema this build expects.
//!
//! The storage crate refuses to start on a database that is behind (`StartupError::SchemaBehind`).
//! That is the start-up gate. The readiness report is the gate while the process runs: a
//! migration can be reverted, or a restore can bring back an older schema, and then the process
//! must say it is not ready. For that it needs the expected number, and the store has no public
//! accessor for it. Counting the directories here keeps the crate free of a change to `storage`.

use std::fs;
use std::path::Path;

fn main() {
    let migrations = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    println!("cargo:rerun-if-changed={}", migrations.display());
    let count = fs::read_dir(&migrations)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().join("up.sql").is_file())
                .count()
        })
        .unwrap_or(0);
    println!("cargo:rustc-env=FACTORY_EXPECTED_MIGRATIONS={count}");
}
