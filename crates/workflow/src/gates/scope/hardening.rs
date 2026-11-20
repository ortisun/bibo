//! Paths and patch details that the path policy does not name but that must not be ordinary (RR-14,
//! RR-15, RR-16).
//!
//! `policies/security.yaml` lists the sensitive files by glob: most of the dependency manifests at the
//! root only, and the files of one ecosystem. Three kinds of change slip between those globs and are
//! read here, in code, on top of the policy (the result is joined with the policy's, never instead of
//! it):
//!
//! * **Vendored code** (RR-16): a directory of crates, `vendor/` or `third_party/`, is source that is
//!   built and run, and a change inside it is a change of a dependency that no manifest shows. So is
//!   a `.cargo-checksum.json`, which `cargo vendor` writes next to each crate.
//! * **Dependency files of other places and other ecosystems** (RR-14): nested manifests and lock
//!   files of every package manager the policy knows, below the root as well, and the files that
//!   change where a package comes from (`.gitmodules`, `.npmrc`, `go.work`).
//! * **Files that run on the machine of whoever opens the branch** (RR-15): a dev container, editor
//!   tasks, a git hook manager, a `Makefile`, a `direnv` file, a CI definition of another system. The
//!   reviewer is that person.
//!
//! Names are compared without regard to case: a case-only rename (`Cargo.toml` to `cargo.toml`)
//! leaves a file that a case-insensitive checkout still reads as the manifest.
//!
//! The details of the patch that a list of paths does not carry are read from its headers
//! ([`PatchSignals`]): a submodule bump is a dependency change, a symbolic link and a change of mode
//! are not ordinary, a binary file cannot be read by the reviewer, and a patch whose headers could
//! not be read is not a patch that is known to be small.

use super::patch::{self, GITLINK_MODE, PatchFact, SYMLINK_MODE};

/// What a path is, beyond what the policy says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Inside a directory of vendored crates, or the checksum file of one.
    Vendored,
    /// A manifest, a lock file or a file that decides where a package comes from.
    DependencyFile,
    /// A file that runs on the machine of whoever opens the branch, or builds in an editor.
    RunsOnReviewer,
    /// A definition of a container or of a pipeline.
    Infrastructure,
}

/// The directories, at the root of the repository or below `.cargo/`, that hold other people's code.
const VENDOR_DIRECTORIES: [&str; 6] = [
    "vendor",
    "vendors",
    "vendored",
    "third_party",
    "third-party",
    "thirdparty",
];

/// The names of dependency files, at any depth.
const DEPENDENCY_NAMES: [&str; 32] = [
    "cargo.toml",
    "cargo.lock",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "yarn.lock",
    ".yarnrc",
    ".yarnrc.yml",
    ".npmrc",
    "pyproject.toml",
    "pipfile",
    "pipfile.lock",
    "uv.lock",
    "poetry.lock",
    "setup.py",
    "go.mod",
    "go.sum",
    "go.work",
    "go.work.sum",
    "gemfile",
    "gemfile.lock",
    "pom.xml",
    "composer.json",
    "composer.lock",
    "directory.build.props",
    "nuget.config",
    "rust-toolchain",
    "rust-toolchain.toml",
    ".gitmodules",
    "deny.toml",
];

/// The names of files that run on a reviewer's machine, at any depth.
const RUNS_ON_REVIEWER_NAMES: [&str; 17] = [
    "lefthook.yml",
    "lefthook.yaml",
    ".lefthook.yml",
    ".pre-commit-config.yaml",
    "makefile",
    "gnumakefile",
    "justfile",
    "taskfile.yml",
    "taskfile.yaml",
    ".envrc",
    ".mise.toml",
    "mise.toml",
    ".tool-versions",
    ".gitpod.yml",
    "tasks.json",
    "launch.json",
    "devcontainer.json",
];

/// The names of pipeline definitions of other systems.
const PIPELINE_NAMES: [&str; 6] = [
    ".gitlab-ci.yml",
    "jenkinsfile",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    ".drone.yml",
    ".travis.yml",
];

fn components(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .map(str::to_ascii_lowercase)
        .collect()
}

/// True when the path is inside a directory of vendored crates, or is the checksum file of one.
#[must_use]
pub fn is_vendored(path: &str) -> bool {
    let parts = components(path);
    let Some((name, directories)) = parts.split_last() else {
        return false;
    };
    if name == ".cargo-checksum.json" {
        return true;
    }
    match directories {
        [first, ..] if VENDOR_DIRECTORIES.contains(&first.as_str()) => true,
        [cargo, vendor, ..]
            if cargo == ".cargo" && VENDOR_DIRECTORIES.contains(&vendor.as_str()) =>
        {
            true
        }
        _ => false,
    }
}

/// What the path is, beyond what the policy says. `None` for an ordinary path.
#[must_use]
pub fn classify(path: &str) -> Option<Kind> {
    if is_vendored(path) {
        return Some(Kind::Vendored);
    }
    let parts = components(path);
    let (name, directories) = parts.split_last()?;
    let name = name.as_str();
    let in_directory = |wanted: &str| directories.iter().any(|part| part == wanted);
    if DEPENDENCY_NAMES.contains(&name)
        || (name.starts_with("requirements") && name.ends_with(".txt"))
        || (name.starts_with("build.gradle") || name.starts_with("settings.gradle"))
        || name == "gradle.properties"
        || name.ends_with(".csproj")
        || name.ends_with(".fsproj")
        || name.ends_with(".vbproj")
        || (in_directory(".cargo") && !directories.is_empty())
    {
        return Some(Kind::DependencyFile);
    }
    if in_directory(".devcontainer")
        || in_directory(".husky")
        || in_directory(".githooks")
        || in_directory(".vscode")
        || in_directory(".idea")
        || in_directory(".circleci")
        || RUNS_ON_REVIEWER_NAMES.contains(&name)
        || name.ends_with(".code-workspace")
        || (in_directory(".github") && name.starts_with("codespaces"))
    {
        return Some(Kind::RunsOnReviewer);
    }
    if PIPELINE_NAMES.contains(&name) {
        return Some(Kind::Infrastructure);
    }
    None
}

/// What the headers of a patch show that a list of changed paths does not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PatchSignals {
    /// A submodule (a gitlink) is added, moved or removed: a dependency changes.
    pub submodule: bool,
    /// A symbolic link is added or changed, or a file becomes one.
    pub symlink: bool,
    /// The mode of a file changes (the executable bit, say).
    pub mode_change: bool,
    /// A binary file is added or changed.
    pub binary: bool,
    /// A header could not be read, so the facts are not the whole story.
    pub unreadable: bool,
}

impl PatchSignals {
    /// True when the patch shows nothing special.
    #[must_use]
    pub const fn is_ordinary(&self) -> bool {
        !(self.submodule || self.symlink || self.mode_change || self.binary || self.unreadable)
    }

    /// Reads the headers of a patch.
    #[must_use]
    pub fn of(patch: &[u8]) -> Self {
        let facts = patch::parse(patch);
        let mut signals = Self {
            unreadable: !facts.understood(),
            ..Self::default()
        };
        for fact in facts.files() {
            signals.note(fact);
        }
        let text = String::from_utf8_lossy(patch);
        signals.binary = text
            .lines()
            .any(|line| line.starts_with("GIT binary patch") || is_binary_marker(line));
        signals
    }

    fn note(&mut self, fact: &PatchFact) {
        for mode in [fact.old_mode, fact.new_mode].into_iter().flatten() {
            match PatchFact::kind_of(mode) {
                GITLINK_MODE => self.submodule = true,
                SYMLINK_MODE => self.symlink = true,
                _ => {}
            }
        }
        if let (Some(old), Some(new)) = (fact.old_mode, fact.new_mode)
            && old != new
        {
            self.mode_change = true;
        }
    }
}

/// `Binary files a/x and b/x differ`.
fn is_binary_marker(line: &str) -> bool {
    line.starts_with("Binary files ") && line.ends_with(" differ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vendored_directory_and_a_checksum_file_are_vendored_at_any_case() {
        for path in [
            "vendor/serde/src/lib.rs",
            "Vendor/serde/src/lib.rs",
            "third_party/foo/src/lib.rs",
            "third-party/foo/x.c",
            ".cargo/vendor/serde/src/lib.rs",
            "vendor/serde/.cargo-checksum.json",
            "crates/x/vendor-dir/.CARGO-CHECKSUM.JSON",
        ] {
            assert!(is_vendored(path), "{path}");
        }
        for path in [
            "src/vendor/mod.rs",
            "docs/vendor.md",
            "crates/x/src/lib.rs",
            "vendorish/x.rs",
            "my_vendor/x.rs",
        ] {
            assert!(!is_vendored(path), "{path}");
        }
    }

    #[test]
    fn dependency_files_are_seen_at_any_depth_in_any_case() {
        for path in [
            "services/api/requirements.txt",
            "services/api/requirements-dev.txt",
            "tools/go.mod",
            "tools/go.sum",
            "backend/pyproject.toml",
            "web/package-lock.json",
            "web/yarn.lock",
            "web/pnpm-lock.yaml",
            "app/Gemfile",
            "app/pom.xml",
            "Pipfile",
            "Pipfile.lock",
            "go.work",
            "web/.npmrc",
            ".gitmodules",
            "crates/x/cargo.toml",
            "CARGO.LOCK",
            "app/build.gradle.kts",
            "src/App/App.csproj",
            "rust-toolchain.toml",
            ".cargo/config.toml",
        ] {
            assert_eq!(classify(path), Some(Kind::DependencyFile), "{path}");
        }
    }

    #[test]
    fn files_that_run_on_a_reviewers_machine_are_seen() {
        for path in [
            ".devcontainer/devcontainer.json",
            ".devcontainer/Dockerfile",
            ".vscode/tasks.json",
            ".vscode/settings.json",
            "lefthook.yml",
            ".husky/pre-commit",
            ".githooks/pre-push",
            "Makefile",
            "tools/Makefile",
            ".envrc",
            ".pre-commit-config.yaml",
            "project.code-workspace",
        ] {
            assert_eq!(classify(path), Some(Kind::RunsOnReviewer), "{path}");
        }
        assert_eq!(classify(".gitlab-ci.yml"), Some(Kind::Infrastructure));
    }

    #[test]
    fn an_ordinary_source_file_is_not_classified() {
        for path in [
            "src/lib.rs",
            "docs/guide.md",
            "crates/x/src/main.rs",
            "README.md",
        ] {
            assert_eq!(classify(path), None, "{path}");
        }
    }

    #[test]
    fn the_headers_of_a_patch_show_a_submodule_a_link_a_mode_and_a_binary_file() {
        let patch = "diff --git a/lib b/lib\nindex 1..2 160000\n--- a/lib\n+++ b/lib\n@@ -1 +1 @@\n-Subproject commit aaaa\n+Subproject commit bbbb\n";
        // The mode of a gitlink appears in the extended headers when it is new or changed.
        let new_submodule = "diff --git a/lib b/lib\nnew file mode 160000\nindex 0..1\n--- /dev/null\n+++ b/lib\n@@ -0,0 +1 @@\n+Subproject commit aaaa\n";
        assert!(PatchSignals::of(new_submodule.as_bytes()).submodule);
        assert!(!PatchSignals::of(patch.as_bytes()).symlink);
        let link = "diff --git a/l b/l\nnew file mode 120000\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+target\n";
        assert!(PatchSignals::of(link.as_bytes()).symlink);
        let chmod = "diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n";
        assert!(PatchSignals::of(chmod.as_bytes()).mode_change);
        let binary = "diff --git a/x.bin b/x.bin\nnew file mode 100644\nBinary files /dev/null and b/x.bin differ\n";
        assert!(PatchSignals::of(binary.as_bytes()).binary);
        let plain = "diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n@@ -1 +1 @@\n-a\n+b\n";
        assert!(PatchSignals::of(plain.as_bytes()).is_ordinary());
        assert!(PatchSignals::of(b"diff --git broken\n").unreadable);
    }
}
