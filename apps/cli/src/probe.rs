//! `probe`: the checks that can be made in process, and an honest list of the ones that cannot.
//!
//! The command starts no process (rule DEP-10: only the sandbox crate starts `docker` or `git`, and
//! only the runtime crate starts an agent tool), so it cannot run `claude --version` itself. What it
//! can do is run the start-up checks the composition library runs for the worker (the policy from
//! the protected checkout, the sandbox image catalog, the redactor) and list, with `BLOCKED:` lines,
//! each adapter and each seam method the composition cannot assemble, and the two agent runtimes
//! whose capability record needs a probe inside the sandbox.
//!
//! A line begins with `OK:`, `FAILED:` or `BLOCKED:`. `FAILED` is exit code 1. Any `BLOCKED` line and no
//! `FAILED` is exit code 3. A `BLOCKED` is never a pass.

use std::path::Path;

use factory_composition::assemble::{blocked_adapters, blocked_seams};
use factory_composition::profile::Profile;
use factory_composition::redaction::redactor_from_policy;
use factory_composition::startup::{check_image_catalog, load_policy};

use crate::exit::Exit;

/// The agent runtimes whose capability record the factory keeps (ADR 0005).
pub const RUNTIMES: [&str; 2] = ["claude", "codex"];

/// What `probe` printed and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The lines, in order.
    pub lines: Vec<String>,
    /// The exit.
    pub exit: Exit,
}

/// Runs the checks.
#[must_use]
pub fn run(profile: Profile, protected_checkout: &Path, images_catalog: Option<&Path>) -> Probe {
    let mut lines = Vec::new();
    let mut failed = false;
    let mut blocked = false;

    match load_policy(protected_checkout, &[]) {
        Ok(policies) => {
            lines.push(format!(
                "OK: policy: loaded from the protected checkout, hash {}",
                policies.hash.as_str()
            ));
            match redactor_from_policy(&policies.security) {
                Ok(_) => lines.push("OK: redactor: built from the policy".to_owned()),
                Err(error) => {
                    failed = true;
                    lines.push(format!("FAILED: redactor: {error}"));
                }
            }
        }
        Err(error) => {
            failed = true;
            lines.push(format!("FAILED: policy: {error}"));
        }
    }

    match images_catalog {
        None => {
            blocked = true;
            lines.push(
                "BLOCKED: sandbox images: no catalog was named; pass --images-catalog to check the pinned images"
                    .to_owned(),
            );
        }
        Some(path) => match std::fs::read_to_string(path) {
            Err(_) => {
                failed = true;
                lines.push(format!(
                    "FAILED: sandbox images: {} cannot be read",
                    path.display()
                ));
            }
            Ok(text) => match check_image_catalog(&text, None) {
                Ok(report) => lines.push(format!(
                    "OK: sandbox images: the catalog is usable ({report:?})"
                )),
                Err(error) => {
                    failed = true;
                    lines.push(format!("FAILED: sandbox images: {error}"));
                }
            },
        },
    }

    for runtime in RUNTIMES {
        blocked = true;
        lines.push(format!(
            "BLOCKED: runtime {runtime}: its capability record is read by a probe inside the agent sandbox, which needs the pinned image and a model credential; this command starts no process"
        ));
    }
    for item in blocked_adapters(profile) {
        blocked = true;
        lines.push(format!("BLOCKED: {}: {}", item.port.label(), item.reason));
    }
    for item in blocked_seams() {
        blocked = true;
        lines.push(format!("BLOCKED: {}: {}", item.seam, item.reason));
    }

    let exit = if failed {
        Exit::Failed
    } else if blocked {
        lines.push("BLOCKED is not a pass: the checks that could run passed, and the ones above could not run.".to_owned());
        Exit::Blocked
    } else {
        Exit::Ok
    };
    Probe { lines, exit }
}
