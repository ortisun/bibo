//! `cargo xtask check-generated`: the files that a script generates are current.
//!
//! Which scripts, and how to regenerate each file, are in the `generated_artifacts` list of the
//! rules file. The commands run from the repository root, with no shell. A command that exits
//! with a failure means the file is stale; a command that cannot start (a missing `python3`)
//! means the check could not run, and that is reported separately so it is never read as a pass.

use crate::finding::Finding;
use crate::source_scans::GeneratedArtifact;
use std::path::Path;
use std::process::Command;

pub enum Outcome {
    Current,
    Stale(Finding),
    /// The command could not start. The message says what was missing.
    Blocked(String),
}

pub fn run(root: &Path, artifact: &GeneratedArtifact) -> Outcome {
    let Some((program, arguments)) = artifact.check.split_first() else {
        return Outcome::Blocked(format!(
            "the check for {} is an empty command",
            artifact.name
        ));
    };
    match Command::new(program)
        .args(arguments)
        .current_dir(root)
        .output()
    {
        Err(error) => Outcome::Blocked(format!(
            "cannot start {program} for {}: {error}",
            artifact.name
        )),
        Ok(output) if output.status.success() => Outcome::Current,
        Ok(output) => {
            let said = String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr);
            Outcome::Stale(Finding::new(
                "GENERATED",
                artifact.check.join(" "),
                format!(
                    "{} is stale ({}). Regenerate it with: {}",
                    artifact.name,
                    said.trim().lines().last().unwrap_or("the check failed"),
                    artifact.regenerate
                ),
            ))
        }
    }
}
