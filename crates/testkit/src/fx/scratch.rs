//! A scratch folder whose paths a sandbox spec may mount.
//!
//! `policies/security.yaml` (`sandbox.forbidden_mount_sources`) refuses a workspace, an output or
//! a token directory under `/var`, `/home`, `/usr` and a few more. Where a test keeps such a
//! directory therefore depends on the host:
//!
//! * The system temporary directory is under `/var` on macOS (`/var/folders/...`), so it is
//!   refused there.
//! * The repository's `target/` is under `/home` on most Linux machines, a GitHub runner
//!   included (`/home/runner/work/...`), so it is refused there.
//!
//! [`mountable_scratch`] takes the repository's `target/` when the policy allows it and the
//! canonical `/tmp` otherwise (`/tmp` on Linux, `/private/tmp` on macOS), which the policy allows
//! on both. A test that once wrote `root().join("target/<name>")` writes
//! `mountable_scratch("<name>")`.

use std::path::{Path, PathBuf};

use crate::fixtures::sandbox_policy;

/// The folder under which a test keeps the directories it hands to a sandbox spec: the
/// repository's `target/<name>` when the policy allows that path as a mount source, else
/// `<canonical /tmp>/factory-test-scratch/<name>`. The folder is not created.
///
/// # Panics
/// When neither the repository root nor `/tmp` can be resolved, which only a broken host does.
#[must_use]
pub fn mountable_scratch(name: &str) -> PathBuf {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root resolves");
    let target = repository.join("target");
    if is_mountable(&target) {
        return target.join(name);
    }
    Path::new("/tmp")
        .canonicalize()
        .expect("/tmp resolves")
        .join("factory-test-scratch")
        .join(name)
}

/// True when `path` is not, and is not under, a forbidden mount source of the test policy, by the
/// same rule as `SandboxSpec::validate` (`/` forbids only itself).
#[must_use]
pub fn is_mountable(path: &Path) -> bool {
    let text = path.to_string_lossy();
    !sandbox_policy()
        .forbidden_mount_sources
        .iter()
        .any(|listed| {
            *text == **listed || (listed != "/" && text.starts_with(&format!("{listed}/")))
        })
}

#[cfg(test)]
mod tests {
    use super::{is_mountable, mountable_scratch};
    use std::path::Path;

    #[test]
    fn the_scratch_folder_is_one_the_policy_lets_a_sandbox_mount() {
        let scratch = mountable_scratch("scratch-self-test");
        assert!(is_mountable(&scratch), "{}", scratch.display());
        assert!(scratch.ends_with("scratch-self-test"));
    }

    #[test]
    fn the_paths_that_broke_each_host_are_refused_and_tmp_is_not() {
        assert!(!is_mountable(Path::new(
            "/home/runner/work/bibo/bibo/target"
        )));
        assert!(!is_mountable(Path::new("/var/folders/zz/T")));
        assert!(is_mountable(Path::new("/tmp/factory-test-scratch")));
        assert!(is_mountable(Path::new("/private/tmp/factory-test-scratch")));
        assert!(is_mountable(Path::new("/Users/someone/bibo/target")));
        // "/" forbids itself only, and a name that merely starts like a forbidden one is allowed.
        assert!(!is_mountable(Path::new("/")));
        assert!(is_mountable(Path::new("/variable/work")));
    }
}
