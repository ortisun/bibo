//! DEP-05: the inner crates may not call the clock, the filesystem, the network or process
//! spawning. Clippy enforces it from `clippy.toml`, and clippy ignores a path it cannot resolve.
//! These tests prove the rendered ban list works by compiling a scratch crate under it, and prove
//! that `check-architecture` notices an inner crate whose own file lost an entry.

mod common;

use common::Fixture;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use xtask::clippy_bans::{BANS, BanKind, listed_bans, render_clippy_toml, scratch_source};

mod clippy_bans {
    use super::*;

    /// Variables that change where cargo builds or what clippy reads. A scratch crate must see
    /// none of the caller's values.
    const INHERITED_BUILD_VARIABLES: [&str; 6] = [
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET_DIR",
        "CLIPPY_CONF_DIR",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
    ];

    /// Remove the caller's build variables from `command` and give it its own target directory.
    fn scrub_build_environment(command: &mut Command, target_dir: &Path) {
        for name in INHERITED_BUILD_VARIABLES {
            command.env_remove(name);
        }
        command
            .env("CARGO_TARGET_DIR", target_dir)
            .env("CARGO_NET_OFFLINE", "true");
    }

    /// A scratch crate in a temporary directory, linted with the repository's toolchain.
    struct Scratch {
        dir: PathBuf,
    }

    impl Scratch {
        fn new(label: &str, clippy_toml: Option<&str>, source: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("xtask-clippy-{}-{label}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("src")).expect("create the scratch crate");
            fs::write(
                dir.join("Cargo.toml"),
                "[package]\nname = \"scratch\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n",
            )
            .expect("write the manifest");
            fs::write(dir.join("src/lib.rs"), source).expect("write the source");
            if let Some(text) = clippy_toml {
                fs::write(dir.join("clippy.toml"), text).expect("write clippy.toml");
            }
            // Lint with the same toolchain as the workspace.
            let toolchain = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rust-toolchain.toml");
            fs::copy(&toolchain, dir.join("rust-toolchain.toml"))
                .expect("copy rust-toolchain.toml");
            let scratch = Self { dir };
            scratch.require_clippy();
            scratch
        }

        /// Clippy must be installed for the pinned toolchain. If it is not, the test reports
        /// BLOCKED instead of passing without having proved anything.
        fn require_clippy(&self) {
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let output = Command::new(cargo)
                .args(["clippy", "--version"])
                .current_dir(&self.dir)
                .output()
                .expect("run cargo");
            assert!(
                output.status.success(),
                "BLOCKED: clippy is not available for the pinned toolchain:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        /// Run clippy and return its exit code and the lint diagnostics as (code, line, message).
        ///
        /// Each scratch crate gets its own target directory and a clean environment (F-23).
        /// Cargo derives the fingerprint of a path package from its path inside its own
        /// workspace, so two scratch crates that share one target directory share one cache
        /// entry, and clippy replays the diagnostics of whichever ran first. A caller who sets
        /// `CARGO_TARGET_DIR` (a shared build cache, or CI) must not change what these tests see.
        fn clippy(&self) -> (Option<i32>, Vec<(String, u64, String)>) {
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let mut command = Command::new(cargo);
            command
                .args(["clippy", "--message-format=json", "--", "-D", "warnings"])
                .current_dir(&self.dir);
            scrub_build_environment(&mut command, &self.dir.join("target"));
            let output = command.output().expect("run cargo clippy");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut diagnostics = Vec::new();
            for line in stdout.lines() {
                let Ok(message) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                if message["reason"] != "compiler-message" {
                    continue;
                }
                let m = &message["message"];
                let code = m["code"]["code"].as_str().unwrap_or_default().to_string();
                let primary = m["spans"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|s| s["is_primary"] == true);
                let line_number = primary.and_then(|s| s["line_start"].as_u64()).unwrap_or(0);
                diagnostics.push((
                    code,
                    line_number,
                    m["message"].as_str().unwrap_or_default().to_string(),
                ));
            }
            (output.status.code(), diagnostics)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn lint_for(kind: BanKind) -> &'static str {
        match kind {
            BanKind::Method => "clippy::disallowed_methods",
            BanKind::Type => "clippy::disallowed_types",
        }
    }

    #[test]
    fn every_ban_in_the_rendered_file_fires_in_a_scratch_crate() {
        assert!(!BANS.is_empty(), "the ban list is empty");
        let scratch = Scratch::new("fires", Some(&render_clippy_toml()), &scratch_source());
        let (code, diagnostics) = scratch.clippy();
        assert!(
            matches!(code, Some(c) if c != 0),
            "clippy should fail the scratch crate: {code:?} {diagnostics:?}"
        );
        let mut silent = Vec::new();
        for (index, ban) in BANS.iter().enumerate() {
            let line = index as u64 + 2; // line 1 is the header
            let fired = diagnostics.iter().any(|(lint, at, message)| {
                *at == line && lint == lint_for(ban.kind) && message.contains(ban.path)
            });
            if !fired {
                silent.push(ban.path);
            }
        }
        assert!(
            silent.is_empty(),
            "these bans did not fire: {silent:?}\nall diagnostics: {diagnostics:#?}"
        );
    }

    #[test]
    fn every_ban_fires_under_the_clippy_toml_each_inner_crate_actually_has() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for name in xtask::clippy_bans::INNER_CRATES {
            let path = root.join("crates").join(name).join("clippy.toml");
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let scratch = Scratch::new(&format!("real-{name}"), Some(&text), &scratch_source());
            let (_, diagnostics) = scratch.clippy();
            let silent: Vec<&str> = BANS
                .iter()
                .enumerate()
                .filter(|(index, ban)| {
                    let line = *index as u64 + 2;
                    !diagnostics.iter().any(|(lint, at, message)| {
                        *at == line && lint == lint_for(ban.kind) && message.contains(ban.path)
                    })
                })
                .map(|(_, ban)| ban.path)
                .collect();
            assert!(
                silent.is_empty(),
                "{name}: these bans did not fire: {silent:?}"
            );
        }
    }

    #[test]
    fn the_same_crate_passes_when_it_uses_nothing_banned() {
        let scratch = Scratch::new(
            "clean",
            Some(&render_clippy_toml()),
            "pub fn ok() -> u32 { 1 + 1 }\n",
        );
        let (code, diagnostics) = scratch.clippy();
        assert_eq!(
            code,
            Some(0),
            "a crate that uses no banned item must pass: {diagnostics:?}"
        );
    }

    #[test]
    fn without_the_clippy_toml_nothing_fires() {
        let scratch = Scratch::new("off", None, &scratch_source());
        let (_, diagnostics) = scratch.clippy();
        let disallowed: Vec<_> = diagnostics
            .iter()
            .filter(|(lint, _, _)| lint.starts_with("clippy::disallowed"))
            .collect();
        assert!(
            disallowed.is_empty(),
            "the bans must come from clippy.toml alone: {disallowed:?}"
        );
    }

    #[test]
    fn a_misspelt_path_bans_nothing_and_xtask_catches_it() {
        let misspelt =
            render_clippy_toml().replace("std::fs::read_to_string", "std::fs::raed_to_string");
        let scratch = Scratch::new(
            "typo",
            Some(&misspelt),
            "pub fn r() { let _ = std::fs::read_to_string(\"x\"); }\n",
        );
        let (_, diagnostics) = scratch.clippy();
        assert!(
            !diagnostics
                .iter()
                .any(|(lint, _, m)| lint.starts_with("clippy::disallowed")
                    && m.contains("read_to_string")),
            "clippy was expected to ignore the misspelt path: {diagnostics:?}"
        );
        let listed = listed_bans(&misspelt).expect("the file parses");
        assert!(!listed.contains(&(BanKind::Method, "std::fs::read_to_string".to_string())));
    }

    #[test]
    fn the_rendered_file_lists_every_ban_once() {
        let listed = listed_bans(&render_clippy_toml()).expect("the rendered file parses");
        let expected: BTreeSet<(BanKind, String)> =
            BANS.iter().map(|b| (b.kind, b.path.to_string())).collect();
        assert_eq!(listed, expected);
        assert_eq!(expected.len(), BANS.len(), "a path is listed twice in BANS");
    }

    #[test]
    fn the_bans_cover_the_clock_the_filesystem_the_network_and_processes() {
        let paths: Vec<&str> = BANS.iter().map(|b| b.path).collect();
        for needle in [
            "std::time::SystemTime::now",
            "std::time::Instant::now",
            "std::fs::read_to_string",
            "std::fs::File",
            "std::net::TcpStream",
            "std::process::Command::new",
            "std::process::Command",
        ] {
            assert!(paths.contains(&needle), "{needle} is not banned");
        }
    }

    mod dep_05_inner_crates_carry_the_ban_list {
        use super::*;

        #[test]
        fn a_crate_with_the_full_ban_list_passes() {
            Fixture::baseline("dep05-ok").run().assert_passes();
        }

        #[test]
        fn an_inner_crate_without_a_clippy_toml_fails() {
            let mut fx = Fixture::baseline("dep05-missing");
            fx.without_clippy_toml("domain");
            fx.run()
                .assert_violation_mentions("DEP-05", "crates/domain/clippy.toml");
        }

        #[test]
        fn each_of_the_four_inner_crates_needs_the_file() {
            for name in xtask::clippy_bans::INNER_CRATES {
                let mut fx = Fixture::baseline("dep05-each");
                fx.without_clippy_toml(name);
                fx.run()
                    .assert_violation_mentions("DEP-05", &format!("crates/{name}/clippy.toml"));
            }
        }

        #[test]
        fn a_file_that_dropped_a_ban_fails_and_names_it() {
            let mut fx = Fixture::baseline("dep05-dropped");
            let without = render_clippy_toml()
                .lines()
                .filter(|line| !line.contains("\"std::process::Command::new\""))
                .collect::<Vec<_>>()
                .join("\n");
            fx.file("crates/workflow/clippy.toml", &without);
            fx.run()
                .assert_violation_mentions("DEP-05", "std::process::Command::new");
        }

        #[test]
        fn a_misspelt_path_counts_as_a_missing_ban() {
            let mut fx = Fixture::baseline("dep05-typo");
            fx.file(
                "crates/ports/clippy.toml",
                &render_clippy_toml().replace("std::fs::read_to_string", "std::fs::raed_to_string"),
            );
            fx.run()
                .assert_violation_mentions("DEP-05", "std::fs::read_to_string");
        }

        #[test]
        fn extra_entries_are_allowed() {
            let mut fx = Fixture::baseline("dep05-extra");
            let extended = format!("allow-unwrap-in-tests = true\n\n{}", render_clippy_toml())
            .replace("disallowed-methods = [", "disallowed-methods = [\n    { path = \"uuid::Uuid::new_v4\", reason = \"use IdGenerator\" },");
            fx.file("crates/domain/clippy.toml", &extended);
            fx.run().assert_passes();
        }

        #[test]
        fn a_file_the_check_cannot_read_fails() {
            let mut fx = Fixture::baseline("dep05-unreadable");
            fx.file(
                "crates/domain/clippy.toml",
                "disallowed-methods = \"not a list\"\n",
            );
            fx.run().assert_violation_mentions("DEP-05", "cannot read");
        }

        #[test]
        fn crates_outside_the_four_need_no_file() {
            // The baseline has storage and sandbox without one.
            Fixture::baseline("dep05-adapter")
                .run()
                .assert_no_violation("DEP-05");
        }
    }
}
