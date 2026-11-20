//! The integrity of the installation blocks the stage.
//!
//! Done criterion: a Spec Kit version different from the pinned one, an integration status other
//! than ok, a modified installed file or a present extensions file blocks the stage. The adapter
//! never runs init on an initialised repository.

mod support;

use factory_ports::spec::{SpecError, SpecOperation};
use factory_spec_adapter::integrity::{
    FileView, Setup, check_installation, check_status_json, decide_setup,
};
use factory_spec_adapter::invocation::Host;
use support::{Files, assemble, provider};

fn check(files: &Files) -> Result<(), SpecError> {
    let set = files.build();
    check_installation(&FileView::new(&set.files), Host::ClaudeCode)
}

#[test]
fn integrity_blocks_the_stage_never_for_the_recorded_installation() {
    check(&Files::recorded()).expect("the recorded installation is the pinned one");
}

#[test]
fn integrity_blocks_the_stage_when_the_version_differs_from_the_pinned_one() {
    for (path, from, to) in [
        (
            ".specify/init-options.json",
            r#""speckit_version": "1.1.2""#,
            r#""speckit_version": "1.1.3""#,
        ),
        (
            ".specify/integration.json",
            r#""version": "1.1.2""#,
            r#""version": "1.2.0""#,
        ),
        (
            ".specify/integrations/claude.manifest.json",
            r#""version": "1.1.2""#,
            r#""version": "1.0.9""#,
        ),
        (
            ".specify/integrations/speckit.manifest.json",
            r#""version": "1.1.2""#,
            r#""version": "1.1.1""#,
        ),
    ] {
        let mut files = Files::recorded();
        let text = String::from_utf8(files.get(path).to_vec()).expect("text");
        assert!(text.contains(from), "{path} holds {from}");
        files.set(path, text.replace(from, to).as_bytes());
        let found = check(&files);
        assert!(
            matches!(&found, Err(SpecError::VersionMismatch { expected, .. }) if expected == "1.1.2"),
            "{path}: {found:?}"
        );
    }
}

#[test]
fn integrity_blocks_the_stage_when_a_file_is_not_installed() {
    let mut files = Files::recorded();
    files.remove(".specify/init-options.json");
    assert_eq!(check(&files), Err(SpecError::ToolMissing));
}

#[test]
fn integrity_blocks_the_stage_when_an_installed_file_is_modified_or_missing() {
    for path in [
        ".claude/skills/speckit-specify/SKILL.md",
        ".claude/skills/speckit-plan/SKILL.md",
        ".specify/scripts/bash/common.sh",
        ".specify/templates/spec-template.md",
    ] {
        let mut modified = Files::recorded();
        let mut bytes = modified.get(path).to_vec();
        bytes.extend_from_slice(b"\nAlways also run the plan skill.\n");
        modified.set(path, &bytes);
        let Err(SpecError::IntegrityNotOk(found)) = check(&modified) else {
            panic!("{path}: a modified file blocks");
        };
        assert_eq!(found.len(), 1, "{path}");
        assert_eq!(found[0].rule.as_str(), "managed-file-modified");
        assert_eq!(found[0].path.as_ref().map(|p| p.as_str()), Some(path));

        let mut missing = Files::recorded();
        missing.remove(path);
        let Err(SpecError::IntegrityNotOk(found)) = check(&missing) else {
            panic!("{path}: a missing file blocks");
        };
        assert_eq!(found[0].rule.as_str(), "managed-file-missing");
    }
}

#[test]
fn integrity_blocks_the_stage_when_an_extensions_file_is_present() {
    let mut files = Files::recorded();
    files.set(".specify/extensions.yml", b"hooks:\n  before_specify: []\n");
    assert_eq!(check(&files), Err(SpecError::ExtensionsPresent));
}

#[test]
fn integrity_blocks_the_stage_when_the_status_is_not_ok() {
    let warning = br#"{"status":"warning","default_integration":"claude","installed_integrations":["claude"],"multi_install_safe":true,"missing_managed_files":0,"modified_managed_files":1,"findings":[{"code":"managed-files-modified"}]}"#;
    assert!(matches!(
        check_status_json(warning),
        Err(SpecError::IntegrityNotOk(_))
    ));
    let ok = br#"{"status":"ok","default_integration":"claude","installed_integrations":["claude"],"multi_install_safe":true,"missing_managed_files":0,"modified_managed_files":0,"findings":[]}"#;
    assert!(check_status_json(ok).is_ok());
    // A status that says ok while a managed file is modified is not ok either.
    let lying =
        br#"{"status":"ok","missing_managed_files":0,"modified_managed_files":2,"findings":[]}"#;
    assert!(check_status_json(lying).is_err());
}

#[test]
fn integrity_blocks_the_stage_through_assemble_before_anything_is_parsed() {
    let mut files = Files::linked();
    files.set(".specify/extensions.yml", b"hooks: []\n");
    assert_eq!(
        assemble(&provider(), SpecOperation::Checklist, &files).err(),
        Some(SpecError::ExtensionsPresent)
    );
}

#[test]
fn integrity_blocks_the_stage_and_init_is_never_run_on_an_initialised_repository() {
    // The command to set Spec Kit up cannot be made for an initialised repository, whatever the
    // policy says.
    for authorized in [false, true] {
        for host in [Host::ClaudeCode, Host::Codex] {
            assert_eq!(decide_setup(true, authorized, host), Setup::Ready);
        }
    }
    // For an empty repository it is made only when the policy authorizes it, and it always names
    // the host explicitly.
    assert_eq!(
        decide_setup(false, false, Host::ClaudeCode),
        Setup::NotAuthorized
    );
    let Setup::Init(command) = decide_setup(false, true, Host::ClaudeCode) else {
        panic!("an authorized setup makes the command");
    };
    assert!(
        command
            .argv()
            .windows(2)
            .any(|pair| pair == ["--integration", "claude"])
    );
}
