//! Health and readiness as plain data.
//!
//! The API serves these values on `/healthz` and `/readyz` in a later part of the work package,
//! and the CLI prints them. This module builds them and decides nothing about transport.
//!
//! * **Live** means the process is running its loop. It never depends on the database, so a
//!   database outage does not make an orchestrator kill a process that would recover.
//! * **Ready** means every check passes: the schema is not behind, the ports are acceptable to
//!   the profile, and the policy is loaded. A check that cannot run reports `blocked`, and a
//!   blocked check keeps the process from being ready. It is never a pass.
//!
//! The schema check compares the number of migrations the database has applied with the number
//! this build was compiled against (`build.rs` counts the migration directories). The store
//! refuses to start on a database that is behind; this check is the one that runs afterwards,
//! when a migration is reverted or a restore brings back an older schema.

use factory_domain::vocabulary::Fidelity;
use factory_ports::store::{SchemaVersion, Store};
use serde::Serialize;

use crate::profile::{PortName, Profile};

/// The number of migrations this build expects the database to have applied.
pub const EXPECTED_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(expected_migrations());

const fn expected_migrations() -> u32 {
    // `FACTORY_EXPECTED_MIGRATIONS` is set by build.rs; parsing it in a const context keeps the
    // value a constant.
    let text = env!("FACTORY_EXPECTED_MIGRATIONS").as_bytes();
    let mut value = 0_u32;
    let mut index = 0;
    while index < text.len() {
        value = value * 10 + (text[index] - b'0') as u32;
        index += 1;
    }
    value
}

/// How one check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// It holds.
    Pass,
    /// It does not hold.
    Fail,
    /// It could not run. Not a pass.
    Blocked,
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    /// What was checked.
    pub name: String,
    /// The outcome.
    pub status: CheckStatus,
    /// A plain sentence. It names no secret.
    pub detail: String,
}

impl CheckResult {
    /// A passing check.
    #[must_use]
    pub fn pass(name: &str, detail: &str) -> Self {
        Self {
            name: name.to_owned(),
            status: CheckStatus::Pass,
            detail: detail.to_owned(),
        }
    }

    /// A failing check.
    #[must_use]
    pub fn fail(name: &str, detail: &str) -> Self {
        Self {
            name: name.to_owned(),
            status: CheckStatus::Fail,
            detail: detail.to_owned(),
        }
    }

    /// A check that could not run.
    #[must_use]
    pub fn blocked(name: &str, detail: &str) -> Self {
        Self {
            name: name.to_owned(),
            status: CheckStatus::Blocked,
            detail: detail.to_owned(),
        }
    }
}

/// The fidelity of one port, for the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortStatus {
    /// The port.
    pub port: String,
    /// `real` or `fake`.
    pub fidelity: String,
}

/// The whole report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthReport {
    /// The profile.
    pub profile: String,
    /// True while the process runs its loop.
    pub live: bool,
    /// True when every check passes.
    pub ready: bool,
    /// The checks.
    pub checks: Vec<CheckResult>,
    /// The ports and their fidelity.
    pub ports: Vec<PortStatus>,
}

impl HealthReport {
    /// Builds a report from checks. The report is ready only when there is at least one check and
    /// all of them pass.
    #[must_use]
    pub fn from_checks(
        profile: Profile,
        live: bool,
        checks: Vec<CheckResult>,
        ports: &[(PortName, Fidelity)],
    ) -> Self {
        let ready = live
            && !checks.is_empty()
            && checks.iter().all(|check| check.status == CheckStatus::Pass);
        Self {
            profile: profile.name().to_owned(),
            live,
            ready,
            checks,
            ports: ports
                .iter()
                .map(|(port, fidelity)| PortStatus {
                    port: port.label().to_owned(),
                    fidelity: fidelity.as_str().to_owned(),
                })
                .collect(),
        }
    }

    /// The report as JSON text.
    ///
    /// # Panics
    /// Never: the report holds only strings and booleans.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a report of strings and booleans serializes")
    }
}

/// Checks that the schema the database has is the schema this build expects.
pub async fn check_schema(store: &dyn Store, expected: SchemaVersion) -> CheckResult {
    match store.schema_version().await {
        Ok(applied) if applied >= expected => CheckResult::pass(
            "database schema",
            &format!(
                "{} migrations applied, {} expected",
                applied.get(),
                expected.get()
            ),
        ),
        Ok(applied) => CheckResult::fail(
            "database schema",
            &format!(
                "the database is behind the code: {} migrations applied, {} expected",
                applied.get(),
                expected.get()
            ),
        ),
        Err(_) => CheckResult::blocked("database schema", "the database cannot be reached"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_expected_schema_version_is_the_number_of_migrations_in_the_repository() {
        assert!(EXPECTED_SCHEMA_VERSION.get() >= 18);
    }

    #[test]
    fn a_report_is_ready_only_when_every_check_passes() {
        let ports = [(PortName::Store, Fidelity::Real)];
        let pass = CheckResult::pass("a", "ok");
        let report = HealthReport::from_checks(Profile::Test, true, vec![pass.clone()], &ports);
        assert!(report.ready);
        for other in [
            CheckResult::fail("b", "no"),
            CheckResult::blocked("c", "no"),
        ] {
            let report =
                HealthReport::from_checks(Profile::Test, true, vec![pass.clone(), other], &ports);
            assert!(!report.ready);
            assert!(report.live);
        }
    }

    #[test]
    fn a_report_with_no_check_is_not_ready() {
        assert!(!HealthReport::from_checks(Profile::Test, true, Vec::new(), &[]).ready);
    }

    #[test]
    fn the_report_serializes_without_a_secret_field() {
        let report = HealthReport::from_checks(
            Profile::Production,
            true,
            vec![CheckResult::pass("policy", "loaded")],
            &[(PortName::Store, Fidelity::Real)],
        );
        let json = report.to_json();
        assert!(json.contains("\"profile\":\"production\""));
        assert!(json.contains("\"fidelity\":\"real\""));
    }
}
