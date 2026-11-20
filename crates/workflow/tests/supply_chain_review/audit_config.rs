//! Attack: the candidate configures the scanner that judges it.
//!
//! `cargo audit` reads `.cargo/audit.toml` from the directory it runs in, which is the
//! candidate's checkout. A file there can `ignore` advisories, point `[database] path` at a
//! database the candidate wrote, or turn the yanked check off. The gate does not treat the file
//! as a dependency file (`CargoFormat::kind_of` returns `None` for it, and `Side::of` drops what
//! `kind_of` does not know), does not diff it, and does not read the `settings.ignore` field that
//! the tool prints back.
//!
//! Reproduced with the real tool, cargo-audit 0.22.2, offline, against a scratch advisory
//! database that holds one advisory (RUSTSEC-2020-0001, patched in 2.0.0) and a lockfile that
//! locks `somecrate 1.0.0`:
//!
//! ```text
//! $ cargo audit --json --no-fetch --no-yanked --db ./advisory-db
//! ... "vulnerabilities":{"found":true,"count":1,...}
//! $ printf '[advisories]\nignore = ["RUSTSEC-2020-0001"]\n' > .cargo/audit.toml
//! $ cargo audit --json --no-fetch --no-yanked --db ./advisory-db ; echo $?
//! ... "settings":{...,"ignore":["RUSTSEC-2020-0001"],...},
//!     "vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}
//! 0
//! ```
//!
//! The gate reads the second output as a clean audit and reports the advisory gate `PASSED`.

use factory_domain::vocabulary::GateOutcome;
use factory_workflow::gates::supply_chain::cargo::CargoFormat;
use factory_workflow::gates::supply_chain::facts::StaticRegistry;
use factory_workflow::gates::supply_chain::findings::check;
use factory_workflow::gates::supply_chain::model::{DependencyFormat, FileKind};
use factory_workflow::gates::supply_chain::report::gate;
use factory_workflow::gates::supply_chain::tools::{AuditRefused, parse_audit};

use crate::files::{base, judge, with};
use crate::world::{AuditScript, Script, World, metadata};

const AUDIT_TOML_IGNORING_AN_ADVISORY: &str = "[advisories]\nignore = [\"RUSTSEC-2020-0001\"]\n";

/// The output of the real tool when the project configuration ignores the advisory. Shortened to
/// the fields the parser reads and the field that gives the game away.
const OUTPUT_WITH_AN_IGNORE: &str = r#"{"database":{"advisory-count":1,"last-commit":null,"last-updated":null},"lockfile":{"dependency-count":2},"settings":{"target_arch":[],"target_os":[],"severity":null,"ignore":["RUSTSEC-2020-0001"],"informational_warnings":["unmaintained","unsound","notice"]},"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}"#;

#[test]
fn sc5_the_audit_configuration_of_the_project_is_a_dependency_file() {
    assert_eq!(
        CargoFormat.kind_of(".cargo/audit.toml"),
        Some(FileKind::BuildConfig)
    );
}

#[test]
fn sc5_a_new_audit_configuration_that_ignores_an_advisory_fails_the_integrity_gate() {
    let head = with(base(), ".cargo/audit.toml", AUDIT_TOML_IGNORING_AN_ADVISORY);
    let integrity = judge(&base(), &head);
    assert!(
        integrity.has_violation(),
        "a candidate file that silences the scanner was ignored: {:?}",
        integrity.findings
    );
}

/// Defence in depth on the output side: the tool prints what it ignored. A clean answer that
/// ignored something is not a clean audit.
#[test]
fn sc5_an_audit_that_ignored_an_advisory_is_not_a_clean_audit() {
    assert_eq!(
        parse_audit(OUTPUT_WITH_AN_IGNORE),
        Err(AuditRefused::Configured),
        "the document says `ignore: [RUSTSEC-2020-0001]` and `found: false`"
    );
}

/// The other settings that hide an advisory are refused the same way, and settings that hide
/// nothing are read.
#[test]
fn sc5_every_setting_that_hides_an_advisory_is_refused() {
    let with = |settings: &str| {
        format!(
            r#"{{"settings":{settings},"vulnerabilities":{{"found":false,"count":0,"list":[]}},"warnings":{{}}}}"#
        )
    };
    for hiding in [
        r#"{"ignore":["RUSTSEC-2020-0001"]}"#,
        r#"{"severity":"high"}"#,
        r#"{"target_os":["linux"]}"#,
        r#"{"target_arch":["x86_64"]}"#,
    ] {
        assert_eq!(
            parse_audit(&with(hiding)),
            Err(AuditRefused::Configured),
            "{hiding}"
        );
    }
    for shape in [r#"{"ignore":"RUSTSEC-2020-0001"}"#, r#"{"target_os":7}"#] {
        assert_eq!(
            parse_audit(&with(shape)),
            Err(AuditRefused::Unreadable),
            "{shape}"
        );
    }
    for fine in [
        "{}",
        r#"{"ignore":[],"target_arch":[],"target_os":[],"severity":null}"#,
    ] {
        assert!(parse_audit(&with(fine)).is_ok(), "{fine}");
    }
}

/// The configuration files of the scanners are compared as text: any difference fails the gate,
/// whatever the file says, and a file equal to the base commit's is accepted (it is the base
/// commit's configuration, and the audit runs in a checkout of the candidate).
#[test]
fn sc5_a_scanner_configuration_cannot_be_added_edited_or_removed_by_the_candidate() {
    for path in ["deny.toml", "audit.toml", ".cargo/deny.toml"] {
        let added = judge(&base(), &with(base(), path, "[anything]\nat = \"all\"\n"));
        assert!(
            added.has(check::SCANNER_CONFIG),
            "{path}: {:?}",
            added.findings
        );

        let with_file = with(base(), path, "[a]\nb = 1\n");
        let edited = judge(&with_file, &with(base(), path, "[a]\nb = 2\n"));
        assert!(edited.has(check::SCANNER_CONFIG), "{path}");

        let removed = judge(&with_file, &base());
        assert!(removed.has(check::SCANNER_CONFIG), "{path}");

        let same = judge(&with_file, &with_file);
        assert!(
            !same.has(check::SCANNER_CONFIG),
            "{path}: {:?}",
            same.findings
        );
    }
}

/// An unchanged `.cargo/audit.toml` is the base commit's own and raises nothing; a changed one
/// fails the gate.
#[test]
fn sc5_an_audit_configuration_equal_to_the_base_commit_s_raises_nothing() {
    let with_file = with(base(), ".cargo/audit.toml", AUDIT_TOML_IGNORING_AN_ADVISORY);
    assert!(!judge(&with_file, &with_file).has_violation());
    let other = with(base(), ".cargo/audit.toml", "[advisories]\nignore = []\n");
    assert!(judge(&with_file, &other).has_violation());
}

/// Through the whole gate: an audit that answered clean while ignoring an advisory is BLOCKED,
/// never PASSED, and says why.
#[tokio::test]
async fn sc5_the_gate_does_not_pass_an_audit_that_ignored_an_advisory() {
    let world = World::new();
    world.tools.set(Script {
        metadata: metadata(&[("serde", "1.0.101", Some("MIT OR Apache-2.0"), false)]),
        audit: AuditScript::Ignoring,
        ..Script::default()
    });
    let ran = world
        .gate(
            &base(),
            &crate::freshness::head_upgrading_serde(),
            &StaticRegistry::new(),
            &[],
            false,
        )
        .await
        .expect("the gate runs");
    assert!(ran.done.scanned);
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Blocked);
    assert!(
        ran.missing(gate::ADVISORIES).contains("default settings"),
        "{}",
        ran.missing(gate::ADVISORIES)
    );
}
