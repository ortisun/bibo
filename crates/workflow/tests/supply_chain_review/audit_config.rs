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

use factory_workflow::gates::supply_chain::cargo::CargoFormat;
use factory_workflow::gates::supply_chain::model::{DependencyFormat, FileKind};
use factory_workflow::gates::supply_chain::tools::parse_audit;

use crate::files::{base, judge, with};

const AUDIT_TOML_IGNORING_AN_ADVISORY: &str = "[advisories]\nignore = [\"RUSTSEC-2020-0001\"]\n";

/// The output of the real tool when the project configuration ignores the advisory. Shortened to
/// the fields the parser reads and the field that gives the game away.
const OUTPUT_WITH_AN_IGNORE: &str = r#"{"database":{"advisory-count":1,"last-commit":null,"last-updated":null},"lockfile":{"dependency-count":2},"settings":{"target_arch":[],"target_os":[],"severity":null,"ignore":["RUSTSEC-2020-0001"],"informational_warnings":["unmaintained","unsound","notice"]},"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}"#;

#[test]
#[ignore = "confirmed defect SC-5: the audit tool's own configuration file is not a dependency file"]
fn sc5_the_audit_configuration_of_the_project_is_a_dependency_file() {
    assert_eq!(
        CargoFormat.kind_of(".cargo/audit.toml"),
        Some(FileKind::BuildConfig)
    );
}

#[test]
#[ignore = "confirmed defect SC-5: a new audit configuration that ignores an advisory passes the integrity gate"]
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
#[ignore = "confirmed defect SC-5: an audit answer that lists ignored advisories is read as clean"]
fn sc5_an_audit_that_ignored_an_advisory_is_not_a_clean_audit() {
    assert!(
        parse_audit(OUTPUT_WITH_AN_IGNORE).is_err(),
        "the document says `ignore: [RUSTSEC-2020-0001]` and `found: false`"
    );
}
