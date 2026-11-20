//! The register of contract checks and the deliberate defects that make each one fail.
//!
//! A contract check that no wrong fake can fail may pass for the wrong reason. The review of
//! `ports-v1` found 65 of 132 checks that no test ever made fail. The rule since ports-v1.1: every
//! check of every suite is named by at least one seeded defect of its fake, or carries a waiver
//! with a reason and a trigger. This module lists, for each suite, its checks, the defect table of
//! its fake and its waivers. `crates/testkit/tests/contract_register.rs` reads it and fails when a
//! check is in neither table, when a table names a check that does not exist, or when a waiver has
//! no reason or no trigger. The tests in `crates/testkit/tests/*_contract.rs` run each suite
//! against each defect and require the named checks to fail.

use super::Waiver;

/// One suite, as the register sees it.
pub struct SuiteEntry {
    /// The suite's name.
    pub suite: &'static str,
    /// The names of its checks.
    pub checks: Vec<&'static str>,
    /// The seeded defects of its fake: the defect's name, and the checks that must fail with it.
    pub defects: Vec<(String, &'static [&'static str])>,
    /// The checks that no defect can fail, with why.
    pub waivers: &'static [Waiver],
}

fn defects<D: std::fmt::Debug>(
    table: &'static [(D, &'static [&'static str])],
) -> Vec<(String, &'static [&'static str])> {
    table
        .iter()
        .map(|(defect, names)| (format!("{defect:?}"), *names))
        .collect()
}

/// Every suite with a fake and a defect table.
#[must_use]
pub fn all() -> Vec<SuiteEntry> {
    vec![
        SuiteEntry {
            suite: "store",
            checks: super::store::checks().iter().map(|c| c.name).collect(),
            defects: defects(crate::store::DEFECTS),
            waivers: super::store::WAIVERS,
        },
        SuiteEntry {
            suite: "artifact",
            checks: super::artifact::checks().iter().map(|c| c.name).collect(),
            defects: defects(crate::artifact::DEFECTS),
            waivers: super::artifact::WAIVERS,
        },
        SuiteEntry {
            suite: "sandbox",
            checks: super::sandbox::checks().iter().map(|c| c.name).collect(),
            defects: defects(crate::sandbox::DEFECTS),
            waivers: super::sandbox::WAIVERS,
        },
        SuiteEntry {
            suite: "workspace",
            checks: super::workspace::checks().iter().map(|c| c.name).collect(),
            defects: defects(crate::workspace::DEFECTS),
            waivers: super::workspace::WAIVERS,
        },
        SuiteEntry {
            suite: "agent",
            checks: super::agent::checks().iter().map(|c| c.name).collect(),
            defects: defects(crate::agent::DEFECTS),
            waivers: super::agent::WAIVERS,
        },
        SuiteEntry {
            suite: "broker",
            checks: super::broker::checks().iter().map(|c| c.name).collect(),
            defects: defects(crate::broker::DEFECTS),
            waivers: super::broker::WAIVERS,
        },
        SuiteEntry {
            suite: "router",
            checks: super::router::checks().iter().map(|c| c.name).collect(),
            defects: defects(crate::router::DEFECTS),
            waivers: super::router::WAIVERS,
        },
        SuiteEntry {
            suite: "registry",
            checks: super::registry::checks().iter().map(|c| c.name).collect(),
            defects: defects(crate::registry::DEFECTS),
            waivers: super::registry::WAIVERS,
        },
        SuiteEntry {
            suite: "change host",
            checks: super::githost::change_host_checks()
                .iter()
                .map(|c| c.name)
                .collect(),
            defects: defects(crate::githost::CHANGE_HOST_DEFECTS),
            waivers: super::githost::WAIVERS,
        },
        SuiteEntry {
            suite: "issue source",
            checks: super::githost::issue_source_checks()
                .iter()
                .map(|c| c.name)
                .collect(),
            defects: defects(crate::githost::ISSUE_SOURCE_DEFECTS),
            waivers: super::githost::ISSUE_SOURCE_WAIVERS,
        },
        SuiteEntry {
            suite: "issue status writer",
            checks: super::issue_status::issue_status_checks()
                .iter()
                .map(|c| c.name)
                .collect(),
            defects: defects(crate::issue_status::ISSUE_STATUS_DEFECTS),
            waivers: super::issue_status::WAIVERS,
        },
        SuiteEntry {
            suite: "project rules host",
            checks: super::project_rules::project_rules_checks()
                .iter()
                .map(|c| c.name)
                .collect(),
            defects: defects(crate::project_rules::PROJECT_RULES_DEFECTS),
            waivers: super::project_rules::WAIVERS,
        },
        SuiteEntry {
            suite: "webhook verifier",
            checks: super::webhook::checks().iter().map(|c| c.name).collect(),
            defects: defects(crate::webhook::DEFECTS),
            waivers: super::webhook::WAIVERS,
        },
        SuiteEntry {
            suite: "process runner",
            checks: super::process::checks().iter().map(|c| c.name).collect(),
            defects: defects(crate::process::DEFECTS),
            waivers: super::process::WAIVERS,
        },
    ]
}
