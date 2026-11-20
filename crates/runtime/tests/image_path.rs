//! The `PATH` each runtime starts its tool with, against the agent image it runs in.
//!
//! A runtime starts its tool with a fixed environment (`env -i`), so the image's own `PATH` does
//! not reach it. In the thirty-first real run the builder's `PATH` left out the image's Rust
//! toolchain, `cargo` was "command not found", and no test of the change could run. These tests
//! read the image definition and hold each runtime's `PATH` to it.

use std::path::Path;

/// The directories of the `ENV PATH=` line of the agent image's Dockerfile, in order.
fn image_path() -> Vec<String> {
    let dockerfile =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/sandbox-images/agent/Dockerfile");
    let text = std::fs::read_to_string(&dockerfile).expect("the agent image's Dockerfile");
    let line = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("ENV PATH="))
        .expect("the agent image sets PATH");
    line.split(':').map(str::to_owned).collect()
}

fn dirs(path: &str) -> Vec<&str> {
    path.split(':').collect()
}

#[test]
fn every_directory_a_runtime_starts_with_is_one_the_image_lists() {
    let image = image_path();
    for (runtime, path) in [
        ("claude", factory_runtime::claude::DEFAULT_PATH),
        ("codex", factory_runtime::codex::DEFAULT_PATH),
    ] {
        for dir in dirs(path) {
            assert!(
                image.iter().any(|listed| listed == dir),
                "{runtime}: {dir} is not in the image's PATH {image:?}"
            );
        }
    }
}

#[test]
fn the_toolchain_of_the_image_comes_first_for_every_runtime() {
    let image = image_path();
    let toolchain = image
        .iter()
        .find(|dir| dir.starts_with("/opt/rust"))
        .expect("the agent image puts a Rust toolchain on its PATH");
    for (runtime, path) in [
        ("claude", factory_runtime::claude::DEFAULT_PATH),
        ("codex", factory_runtime::codex::DEFAULT_PATH),
    ] {
        assert_eq!(
            dirs(path).first().copied(),
            Some(toolchain.as_str()),
            "{runtime} starts with the toolchain"
        );
    }
}

#[test]
fn the_configured_defaults_are_the_named_paths() {
    assert_eq!(
        factory_runtime::claude::ClaudeCodeConfig::default().path,
        factory_runtime::claude::DEFAULT_PATH
    );
    assert_eq!(
        factory_runtime::codex::CodexConfig::default().path,
        factory_runtime::codex::DEFAULT_PATH
    );
}
