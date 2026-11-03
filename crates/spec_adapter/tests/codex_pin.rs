//! The Codex integration beside the Claude Code one: what the adapter reads from
//! `.specify/integration.json`, and that a pin is the whole SHA-256.
//!
//! The files of this repository's installation are embedded at compile time, because the adapter does
//! no file I/O. The tests that read the whole installation from disk are in
//! `crates/composition/tests/spec_pins.rs`.

use factory_spec_adapter::integrity::{matches_pin, skill_table};
use factory_spec_adapter::invocation::{Host, IntegrationConfig, InvocationError};
use factory_spec_adapter::pinned::PinnedFile;

const INTEGRATION: &[u8] = include_bytes!("../../../.specify/integration.json");
const CODEX_SPECIFY: &[u8] = include_bytes!("../../../.agents/skills/speckit-specify/SKILL.md");

#[test]
fn the_codex_skills_are_ten_files_under_the_codex_root_and_the_claude_skills_under_theirs() {
    for host in Host::ALL {
        let pins = skill_table(host);
        assert_eq!(pins.len(), 10, "{host:?}");
        let prefix = format!("{}/speckit-", host.skill_root());
        assert!(
            pins.iter().all(|pin| pin.path.starts_with(&prefix)),
            "{host:?}"
        );
        assert!(
            pins.iter().all(|pin| pin.path.ends_with("/SKILL.md")),
            "{host:?}"
        );
    }
}

#[test]
fn a_pin_cut_to_sixteen_characters_matches_nothing() {
    // The old table pinned the first 16 characters. The comparison now takes all 64, so a pin that
    // is only the beginning of the right hash is no pin.
    let pin = skill_table(Host::Codex)
        .iter()
        .find(|pin| pin.path == ".agents/skills/speckit-specify/SKILL.md")
        .expect("the specify skill is pinned");
    assert!(matches_pin(pin, CODEX_SPECIFY), "the committed skill");
    let cut = PinnedFile {
        path: pin.path,
        sha256: &pin.sha256[..16],
    };
    assert!(!matches_pin(&cut, CODEX_SPECIFY));
    let mut changed = CODEX_SPECIFY.to_vec();
    changed.push(b'\n');
    assert!(!matches_pin(pin, &changed), "one more byte is another file");
}

#[test]
fn this_repository_records_both_integrations_with_claude_code_as_the_default() {
    let configs = IntegrationConfig::parse_installed(INTEGRATION).expect("the installation file");
    let hosts: Vec<Host> = configs.iter().map(|config| config.host).collect();
    assert_eq!(hosts, [Host::ClaudeCode, Host::Codex], "default first");
    assert!(
        configs
            .iter()
            .all(|config| config.separator.as_char() == '-' && config.version == "1.1.2")
    );
    // `parse` still answers for the default alone, as every caller before this change expected.
    let default = IntegrationConfig::parse(INTEGRATION).expect("default");
    assert_eq!(default.host, Host::ClaudeCode);
}

#[test]
fn an_installed_integration_that_is_not_in_the_host_table_is_refused() {
    let bytes = br#"{"version":"1.1.2","integration":"claude","installed_integrations":["claude","gemini"],"integration_settings":{"claude":{"invoke_separator":"-"},"gemini":{"invoke_separator":"-"}}}"#;
    assert_eq!(
        IntegrationConfig::parse_installed(bytes),
        Err(InvocationError::UnsupportedHost)
    );
    // The default alone still reads, because that is all `parse` has ever promised.
    assert!(IntegrationConfig::parse(bytes).is_ok());
    // An installed host with no separator recorded is not guessed.
    let no_separator = br#"{"version":"1.1.2","integration":"claude","installed_integrations":["claude","codex"],"integration_settings":{"claude":{"invoke_separator":"-"}}}"#;
    assert_eq!(
        IntegrationConfig::parse_installed(no_separator),
        Err(InvocationError::BadConfiguration)
    );
    // Entries that are not strings, or a list that is not a list.
    for text in [
        r#"{"version":"1.1.2","integration":"claude","installed_integrations":[7],"integration_settings":{"claude":{"invoke_separator":"-"}}}"#,
        r#"{"version":"1.1.2","integration":"claude","installed_integrations":"claude","integration_settings":{"claude":{"invoke_separator":"-"}}}"#,
    ] {
        assert_eq!(
            IntegrationConfig::parse_installed(text.as_bytes()),
            Err(InvocationError::BadConfiguration),
            "{text}"
        );
    }
    // An older file without the list holds the default only, and a repeated key is read once.
    let older = br#"{"version":"1.1.2","integration":"claude","integration_settings":{"claude":{"invoke_separator":"-"}}}"#;
    assert_eq!(
        IntegrationConfig::parse_installed(older)
            .expect("one")
            .len(),
        1
    );
    let repeated = br#"{"version":"1.1.2","integration":"claude","installed_integrations":["claude","claude"],"integration_settings":{"claude":{"invoke_separator":"-"}}}"#;
    assert_eq!(
        IntegrationConfig::parse_installed(repeated)
            .expect("one")
            .len(),
        1
    );
}
