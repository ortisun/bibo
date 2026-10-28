//! A wiring that is a program.
//!
//! The composition package can bring its wiring in two ways. It can link this library and
//! implement [`Wiring`](crate::runner::Wiring) in Rust. Or it can provide a program, and this module
//! runs it. The program contract is small, so that it does not depend on any Rust type here:
//!
//! * `PROGRAM protection` prints the protection of the default branch of the fixture remote as one
//!   JSON object (the fields of [`ProtectionFacts`]).
//! * `PROGRAM run SCENARIO_ID` drives the scenario against the real adapters and prints the
//!   evidence as one JSON object on standard output (the fields of [`RunEvidence`]).
//! * When it cannot run it prints one line `BLOCKED: <reason>` for each missing item on standard
//!   error and exits with code 3.
//!
//! The environment variables of [`crate::preflight::REAL_NEEDS`] are passed on unchanged.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::evidence::{ProtectionFacts, RunEvidence};
use crate::runner::{Blocked, Wiring};
use crate::scenarios::Scenario;

/// The environment variable that names the program.
pub const PROGRAM_VARIABLE: &str = "FACTORY_E2E_COMPOSED";

/// A wiring that runs a program.
pub struct External {
    program: PathBuf,
}

impl External {
    /// A wiring for the program named by the environment, or the reason there is none.
    ///
    /// # Errors
    /// [`Blocked`] when the variable is not set or names a file that does not exist.
    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Self, Blocked> {
        let Some(path) = lookup(PROGRAM_VARIABLE).filter(|p| !p.trim().is_empty()) else {
            return Err(Blocked::because(format!(
                "the composed wiring is not available: set {PROGRAM_VARIABLE} to the program that the composition package builds (see tests/end_to_end/README.md)"
            )));
        };
        let program = PathBuf::from(path);
        if !program.is_file() {
            return Err(Blocked::because(format!(
                "{PROGRAM_VARIABLE} names {}, which is not a file",
                program.display()
            )));
        }
        Ok(Self { program })
    }

    fn call(&self, args: &[&str]) -> Result<String, Blocked> {
        let output = Command::new(&self.program)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| {
                Blocked::because(format!("{} did not start: {error}", self.program.display()))
            })?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        match output.status.code() {
            Some(0) => Ok(String::from_utf8_lossy(&output.stdout).into_owned()),
            Some(3) => {
                let reasons: Vec<String> = stderr
                    .lines()
                    .filter_map(|line| line.strip_prefix("BLOCKED:").map(|r| r.trim().to_owned()))
                    .collect();
                Err(Blocked(if reasons.is_empty() {
                    vec![format!(
                        "{} exited with 3 and named nothing",
                        self.program.display()
                    )]
                } else {
                    reasons
                }))
            }
            other => Err(Blocked::because(format!(
                "{} {} exited with {:?}: {}",
                self.program.display(),
                args.join(" "),
                other,
                stderr.lines().last().unwrap_or_default()
            ))),
        }
    }
}

impl Wiring for External {
    fn name(&self) -> &'static str {
        "composed"
    }

    fn real(&self) -> bool {
        true
    }

    fn protection(&mut self) -> Result<ProtectionFacts, Blocked> {
        let text = self.call(&["protection"])?;
        serde_json::from_str(&text).map_err(|error| {
            Blocked::because(format!("the protection output is not valid: {error}"))
        })
    }

    fn run(&mut self, scenario: &Scenario) -> Result<RunEvidence, Blocked> {
        let text = self.call(&["run", scenario.id])?;
        serde_json::from_str(&text)
            .map_err(|error| Blocked::because(format!("the evidence output is not valid: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_variable_means_blocked_with_the_name_of_the_variable() {
        let Err(Blocked(reasons)) = External::from_lookup(&|_| None) else {
            panic!("expected a block");
        };
        assert!(reasons[0].contains(PROGRAM_VARIABLE));
    }

    #[test]
    fn a_missing_file_means_blocked() {
        let lookup = |name: &str| (name == PROGRAM_VARIABLE).then(|| "/no/such/program".to_owned());
        let Err(Blocked(reasons)) = External::from_lookup(&lookup) else {
            panic!("expected a block");
        };
        assert!(reasons[0].contains("not a file"));
    }
}
