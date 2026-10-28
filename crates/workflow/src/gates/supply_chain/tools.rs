//! The commands of the Cargo ecosystem that this gate runs, and how their output is read.
//!
//! Every command is an argument vector that passes through the command policy of the profile it
//! runs in before it runs ([`run`](super::run)). The vectors here are what the gate asks for; the
//! policy decides whether it may and adds the forced arguments (`--locked` for `cargo fetch`).
//!
//! | Command | Profile | Reads |
//! |---|---|---|
//! | `cargo fetch` | `fetch_deps` | nothing: it downloads the locked packages and runs no build script |
//! | `cargo metadata --format-version 1` | `fetch_deps` | `license`, and the `custom-build` and `proc-macro` targets of each package |
//! | `cargo audit --json --no-fetch` | `verify` | the advisories found, from a database that is already on the image |
//! | the SBOM tool | `verify` | a CycloneDX document, kept as the artifact of the command |
//!
//! The output of `cargo audit` was observed with cargo-audit 0.22.2: exit code 0 and
//! `vulnerabilities.found == false` for a clean lockfile, exit code 1 and `found == true` with a
//! `list` of `advisory` and `package` entries otherwise. The output of `cargo metadata` follows
//! the documented format version 1. The SBOM tool is **not** installed on the machine where this
//! was written; its command line is data ([`SbomTool`]) and is unverified.

use serde_json::Value;

use super::model::plain;

/// The fetch command. The policy adds `--locked`.
pub const FETCH: [&str; 2] = ["cargo", "fetch"];

/// The command that lists packages with their licenses and targets. The policy adds `--locked`.
pub const METADATA: [&str; 4] = ["cargo", "metadata", "--format-version", "1"];

/// Asks the audit tool for its version, to learn whether it is there.
pub const AUDIT_PROBE: [&str; 3] = ["cargo", "audit", "--version"];

/// The audit. `--no-fetch` because the `verify` sandbox has no network: the advisory database
/// must already be on the image or in a cache, and a missing database makes the tool fail,
/// which blocks the gate.
pub const AUDIT: [&str; 4] = ["cargo", "audit", "--json", "--no-fetch"];

/// The most packages read from the metadata of one project.
const MAX_PACKAGES: usize = 50_000;

/// The most advisories named in one report.
pub const MAX_ADVISORIES: usize = 50;

/// The SBOM tool, as data. The default is `cargo sbom`, which writes the document to standard
/// output so that the supervisor keeps it as the command's artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomTool {
    /// Asks for the version.
    pub probe: Vec<String>,
    /// Writes a CycloneDX JSON document to standard output.
    pub argv: Vec<String>,
}

impl Default for SbomTool {
    fn default() -> Self {
        let words = |list: &[&str]| list.iter().map(|word| (*word).to_owned()).collect();
        Self {
            probe: words(&["cargo", "sbom", "--version"]),
            argv: words(&["cargo", "sbom", "--output-format", "cyclone_dx_json_1_6"]),
        }
    }
}

/// What `cargo metadata` says about one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageMeta {
    /// The package name.
    pub name: String,
    /// The version.
    pub version: String,
    /// The license expression the package declares.
    pub license: Option<String>,
    /// The package has a build script.
    pub build_script: bool,
    /// The package is a procedural macro.
    pub proc_macro: bool,
}

impl PackageMeta {
    /// True when the package runs code at build time.
    #[must_use]
    pub fn runs_at_build(&self) -> bool {
        self.build_script || self.proc_macro
    }
}

/// Output that cannot be read as what the tool is meant to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the output of the tool is not in the expected form")]
pub struct Unreadable;

/// Reads the output of `cargo metadata --format-version 1`.
///
/// # Errors
/// [`Unreadable`] when the text is not that document.
pub fn parse_metadata(stdout: &str) -> Result<Vec<PackageMeta>, Unreadable> {
    let doc: Value = serde_json::from_str(stdout).map_err(|_| Unreadable)?;
    let packages = doc
        .get("packages")
        .and_then(Value::as_array)
        .ok_or(Unreadable)?;
    if packages.len() > MAX_PACKAGES {
        return Err(Unreadable);
    }
    packages
        .iter()
        .map(|package| {
            let text = |key: &str| package.get(key).and_then(Value::as_str);
            let kinds: Vec<&str> = package
                .get("targets")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|target| target.get("kind").and_then(Value::as_array))
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            Ok(PackageMeta {
                name: text("name").ok_or(Unreadable)?.to_owned(),
                version: text("version").ok_or(Unreadable)?.to_owned(),
                license: text("license").map(str::to_owned),
                build_script: kinds.contains(&"custom-build"),
                proc_macro: kinds.contains(&"proc-macro"),
            })
        })
        .collect()
}

/// One advisory the audit found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    /// The advisory identifier, such as `RUSTSEC-2021-0003`.
    pub id: String,
    /// The package.
    pub package: String,
    /// The version of the package.
    pub version: String,
}

/// What `cargo audit --json` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditResult {
    /// The vulnerabilities, at most [`MAX_ADVISORIES`] of them named.
    pub advisories: Vec<Advisory>,
    /// How many vulnerabilities the tool counted.
    pub count: u64,
    /// How many warnings (unmaintained, unsound, yanked) the tool listed.
    pub warnings: u64,
}

/// Reads the output of `cargo audit --json`.
///
/// # Errors
/// [`Unreadable`] when the text is not the document, or says `found` and lists none, or the count
/// does not agree with the list.
pub fn parse_audit(stdout: &str) -> Result<AuditResult, Unreadable> {
    let doc: Value = serde_json::from_str(stdout).map_err(|_| Unreadable)?;
    let vulns = doc.get("vulnerabilities").ok_or(Unreadable)?;
    let found = vulns
        .get("found")
        .and_then(Value::as_bool)
        .ok_or(Unreadable)?;
    let count = vulns
        .get("count")
        .and_then(Value::as_u64)
        .ok_or(Unreadable)?;
    let list = vulns
        .get("list")
        .and_then(Value::as_array)
        .ok_or(Unreadable)?;
    if found != (count > 0) || u64::try_from(list.len()).ok() != Some(count) {
        return Err(Unreadable);
    }
    let advisories = list
        .iter()
        .take(MAX_ADVISORIES)
        .map(|entry| {
            let text = |value: Option<&Value>, key: &str| {
                value
                    .and_then(|v| v.get(key))
                    .and_then(Value::as_str)
                    .map(|s| plain(s, 80))
            };
            Ok(Advisory {
                id: text(entry.get("advisory"), "id").ok_or(Unreadable)?,
                package: text(entry.get("package"), "name")
                    .or_else(|| text(entry.get("advisory"), "package"))
                    .ok_or(Unreadable)?,
                version: text(entry.get("package"), "version").unwrap_or_default(),
            })
        })
        .collect::<Result<Vec<_>, Unreadable>>()?;
    let warnings = doc
        .get("warnings")
        .and_then(Value::as_object)
        .map(|kinds| {
            kinds
                .values()
                .filter_map(Value::as_array)
                .map(|list| u64::try_from(list.len()).unwrap_or(u64::MAX))
                .fold(0_u64, u64::saturating_add)
        })
        .unwrap_or(0);
    Ok(AuditResult {
        advisories,
        count,
        warnings,
    })
}

/// True when `stdout` is a CycloneDX document.
#[must_use]
pub fn is_cyclonedx(stdout: &str) -> bool {
    serde_json::from_str::<Value>(stdout)
        .ok()
        .and_then(|doc| {
            doc.get("bomFormat")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|format| format == "CycloneDX")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_gives_licenses_and_build_code() {
        let text = r#"{"packages":[
            {"name":"a","version":"1.0.0","license":"MIT","targets":[{"kind":["lib"]},{"kind":["custom-build"]}]},
            {"name":"m","version":"0.1.0","license":null,"targets":[{"kind":["proc-macro"]}]},
            {"name":"p","version":"2.0.0","license":"MIT OR Apache-2.0","targets":[{"kind":["lib"]}]}
        ],"workspace_members":[],"version":1}"#;
        let packages = parse_metadata(text).expect("metadata");
        assert_eq!(packages.len(), 3);
        assert!(packages[0].build_script && !packages[0].proc_macro);
        assert!(packages[1].proc_macro && packages[1].license.is_none());
        assert!(!packages[2].runs_at_build());
        assert!(parse_metadata("{}").is_err());
        assert!(parse_metadata("not json").is_err());
        assert!(parse_metadata(r#"{"packages":[{"name":"a"}]}"#).is_err());
    }

    #[test]
    fn a_clean_audit_and_a_dirty_one_are_read_as_cargo_audit_prints_them() {
        let clean = r#"{"database":{"advisory-count":1381},"lockfile":{"dependency-count":1},"settings":{},"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}"#;
        let result = parse_audit(clean).expect("clean");
        assert_eq!(result.count, 0);
        assert!(result.advisories.is_empty());

        let dirty = r#"{"vulnerabilities":{"found":true,"count":1,"list":[{"advisory":{"id":"RUSTSEC-2021-0003","package":"smallvec"},"versions":{},"package":{"name":"smallvec","version":"0.6.9"}}]},"warnings":{"unmaintained":[{"kind":"unmaintained"}]}}"#;
        let result = parse_audit(dirty).expect("dirty");
        assert_eq!(result.count, 1);
        assert_eq!(result.advisories[0].id, "RUSTSEC-2021-0003");
        assert_eq!(result.advisories[0].package, "smallvec");
        assert_eq!(result.advisories[0].version, "0.6.9");
        assert_eq!(result.warnings, 1);
    }

    #[test]
    fn an_audit_document_that_does_not_add_up_is_not_read() {
        for text in [
            "",
            "{}",
            r#"{"vulnerabilities":{"found":false,"count":2,"list":[]}}"#,
            r#"{"vulnerabilities":{"found":true,"count":0,"list":[]}}"#,
            r#"{"vulnerabilities":{"found":true,"count":1,"list":[]}}"#,
            r#"{"vulnerabilities":{"found":true,"count":1,"list":[{"nothing":1}]}}"#,
        ] {
            assert!(parse_audit(text).is_err(), "{text}");
        }
    }

    #[test]
    fn only_a_cyclonedx_document_is_an_sbom() {
        assert!(is_cyclonedx(
            r#"{"bomFormat":"CycloneDX","specVersion":"1.6"}"#
        ));
        assert!(!is_cyclonedx(r#"{"spdxVersion":"SPDX-2.3"}"#));
        assert!(!is_cyclonedx("garbage"));
    }
}
