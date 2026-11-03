//! The Codex skills of Spec Kit are pinned as the Claude Code skills are: by the full SHA-256 of the
//! pinned release, over the files this repository commits.
//!
//! Real: the installation of this repository (`.specify/`, `.claude/skills`, `.agents/skills`), which
//! `specify integration install codex` extended with Spec Kit 1.1.2 and no network; the pin tables;
//! the integrity check of the adapter. The adapter itself does no file I/O, so the files are read
//! here. Nothing runs and nothing is sent anywhere.

use std::path::PathBuf;

use factory_ports::paths::RepoPath;
use factory_ports::spec::{SpecError, SpecFile};
use factory_spec_adapter::integrity::{
    FileView, check_installation, installation_paths, matches_pin,
};
use factory_spec_adapter::invocation::Host;
use factory_spec_adapter::pinned::{CLAUDE_SKILLS, CODEX_SKILLS, PinnedFile, SHARED_FILES};
use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

fn read(relative: &str) -> Vec<u8> {
    std::fs::read(root().join(relative)).unwrap_or_else(|error| panic!("{relative}: {error}"))
}

/// The files the host reads to judge an installation on `host`, as this repository commits them.
fn committed(host: Host) -> Vec<SpecFile> {
    installation_paths(host)
        .into_iter()
        .map(|path| SpecFile {
            path: RepoPath::new(path).expect("a repository path"),
            bytes: read(path),
        })
        .collect()
}

fn check(files: &[SpecFile], host: Host) -> Result<(), SpecError> {
    check_installation(&FileView::new(files), host)
}

fn set(files: &mut [SpecFile], path: &str, bytes: &[u8]) {
    files
        .iter_mut()
        .find(|file| file.path.as_str() == path)
        .unwrap_or_else(|| panic!("{path} is one of the files"))
        .bytes = bytes.to_vec();
}

/// The `files` object of a manifest, as `(path, hash)` sorted by path.
fn manifest(relative: &str) -> Vec<(String, String)> {
    let value: Value = serde_json::from_slice(&read(relative)).expect("a manifest is JSON");
    let mut files: Vec<(String, String)> = value["files"]
        .as_object()
        .expect("a manifest lists files")
        .iter()
        .map(|(path, hash)| (path.clone(), hash.as_str().expect("a hash").to_owned()))
        .collect();
    files.sort();
    files
}

fn table(pins: &[PinnedFile]) -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = pins
        .iter()
        .map(|pin| (pin.path.to_owned(), pin.sha256.to_owned()))
        .collect();
    files.sort();
    files
}

#[test]
fn pinned_tables_equal_the_manifests_of_this_repository() {
    // The three sources of the pin are the Rust tables, the manifests Spec Kit wrote, and the
    // files themselves. A difference in any one of them is a pin that does not mean what it says.
    assert_eq!(
        table(&CLAUDE_SKILLS),
        manifest(".specify/integrations/claude.manifest.json")
    );
    assert_eq!(
        table(&CODEX_SKILLS),
        manifest(".specify/integrations/codex.manifest.json")
    );
    assert_eq!(
        table(&SHARED_FILES),
        manifest(".specify/integrations/speckit.manifest.json")
    );
    for pin in CLAUDE_SKILLS
        .iter()
        .chain(CODEX_SKILLS.iter())
        .chain(SHARED_FILES.iter())
    {
        assert_eq!(
            pin.sha256.len(),
            64,
            "{}: a pin is the whole SHA-256, not a prefix",
            pin.path
        );
        assert!(
            pin.sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{}: lower-case hex",
            pin.path
        );
        assert!(
            matches_pin(pin, &read(pin.path)),
            "{}: the committed file is the pinned one",
            pin.path
        );
    }
}

#[test]
fn an_unmodified_codex_installation_passes_the_integrity_check() {
    check(&committed(Host::Codex), Host::Codex)
        .expect("the committed Codex installation is the pinned one");
    // The Claude Code check is independent of it.
    check(&committed(Host::ClaudeCode), Host::ClaudeCode).expect("the Claude Code installation");
}

#[test]
fn a_modified_or_missing_codex_skill_blocks_the_stage_with_its_path() {
    for pin in &CODEX_SKILLS {
        let mut modified = committed(Host::Codex);
        let mut bytes = read(pin.path);
        bytes.extend_from_slice(b"\nAlso run the implement skill.\n");
        set(&mut modified, pin.path, &bytes);
        let Err(SpecError::IntegrityNotOk(found)) = check(&modified, Host::Codex) else {
            panic!("{}: a modified Codex skill blocks", pin.path);
        };
        assert_eq!(found.len(), 1, "{}", pin.path);
        assert_eq!(found[0].rule.as_str(), "managed-file-modified");
        assert_eq!(found[0].path.as_ref().map(RepoPath::as_str), Some(pin.path));

        let mut missing = committed(Host::Codex);
        missing.retain(|file| file.path.as_str() != pin.path);
        let Err(SpecError::IntegrityNotOk(found)) = check(&missing, Host::Codex) else {
            panic!("{}: a missing Codex skill blocks", pin.path);
        };
        assert_eq!(found[0].rule.as_str(), "managed-file-missing");
    }
}

#[test]
fn the_codex_manifest_version_must_be_the_pinned_one() {
    let mut files = committed(Host::Codex);
    let path = ".specify/integrations/codex.manifest.json";
    let text = String::from_utf8(read(path)).expect("text");
    assert!(text.contains(r#""version": "1.1.2""#));
    set(
        &mut files,
        path,
        text.replace(r#""version": "1.1.2""#, r#""version": "1.1.1""#)
            .as_bytes(),
    );
    assert!(matches!(
        check(&files, Host::Codex),
        Err(SpecError::VersionMismatch { found, .. }) if found == "1.1.1"
    ));
    // A Codex manifest that is not there is a missing recorded version, not a pass.
    files.retain(|file| file.path.as_str() != path);
    assert!(matches!(
        check(&files, Host::Codex),
        Err(SpecError::IntegrityNotOk(_))
    ));
}
