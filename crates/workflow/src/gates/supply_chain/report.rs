//! From what was found and observed to the four gate reports.
//!
//! | Gate | `PASSED` | `FAILED` | `BLOCKED` | `NOT_APPLICABLE` |
//! |---|---|---|---|---|
//! | `dependency-integrity` | the files of the candidate agree with the base commit's | a rule of [`integrity`](super::integrity) is broken | the base commit's files cannot be read | the project has no dependency file |
//! | `dependency-review` | no new direct dependency, or each has its recorded decision and the fetched packages are fine | a license off the list, an invalid request, or a fetch that the lockfile does not survive | a decision is missing, or the fetch could not run | |
//! | `dependency-advisories` | the audit found nothing | the audit found advisories | the audit tool is not there, or its answer cannot be used, or an earlier gate did not pass | the dependency set did not change |
//! | `sbom` | a CycloneDX document was made | | the tool is not there and the job requires an SBOM, or it ran and made nothing usable | the dependency set did not change; the tool is not there and the job does not require an SBOM |
//!
//! A gate that did not run because an earlier one did not pass is `BLOCKED`, as in the validation
//! stage, and never `PASSED`. Every sentence in a report is built from validated fields, and goes
//! through the redactor before it is kept.

use factory_domain::contracts::GateReport;
use factory_domain::contracts::gate_report::{
    BlockedCode, Failure, GateCommand, GateEnvironment, GateWarning, NotApplicableCode,
    NotApplicableDecider, SandboxNetwork, ToolVersion,
};
use factory_domain::ids::GateReportId;
use factory_domain::redaction::Redactor;
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_ports::clock::IdGenerator;

use super::facts::DatabaseAge;
use super::findings::{Finding, check};
use super::integrity::BaseUnreadable;
use super::model::plain;
use super::review::{Conclusion, Need, Plan, flag_phrase};
use super::run::{AuditEnd, Blocker, FetchEnd, Fetched, SbomEnd, Scanned, Seen};
use crate::gates::command::report::{
    Draft, Outcome, ReportContext, ReportError, build, failure, in_process_environment,
    not_compared, observed_command, sandbox_environment, sandbox_info, tool_version, warning,
};

/// The identifiers of the gates of this package.
pub mod gate {
    /// The lockfile, source and configuration checks.
    pub const INTEGRITY: &str = "dependency-integrity";
    /// The decision on each new direct dependency, the license rule, and the fetch.
    pub const REVIEW: &str = "dependency-review";
    /// The audit.
    pub const ADVISORIES: &str = "dependency-advisories";
    /// The software bill of materials.
    pub const SBOM: &str = "sbom";
    /// Every gate of this package, in report order.
    pub const ALL: [&str; 4] = [INTEGRITY, REVIEW, ADVISORIES, SBOM];
}

/// The most failures one report lists.
const MOST_FAILURES: usize = 50;

/// What a report says in place of a sentence that looked like a secret.
const WITHHELD: &str = "A sentence was withheld here because it looked like a secret.";

/// Everything the reports are made from.
pub struct Evaluation<'a> {
    /// The plan, or the file of the base commit that could not be read.
    pub plan: Result<&'a Plan, &'a BaseUnreadable>,
    /// The fetch, when it ran.
    pub fetched: Option<&'a Fetched>,
    /// What the metadata of the fetched packages added to the review.
    pub conclusion: Option<&'a Conclusion>,
    /// The scan, when it ran.
    pub scanned: Option<&'a Scanned>,
    /// True when the job requires an SBOM (a release or a high-risk job).
    pub sbom_required: bool,
    /// How old the advisory database the audit read is.
    pub database: DatabaseAge,
}

/// Builds the reports of one run.
pub struct Reporter<'a> {
    /// What every report shares.
    pub cx: ReportContext,
    /// New report identifiers.
    pub ids: &'a dyn IdGenerator,
    /// The time of the run, for a report of a gate that ran no command.
    pub now: Timestamp,
    /// The redactor of the factory.
    pub redactor: &'a Redactor,
    /// The digest of the fetch image.
    pub fetch_image: Sha256Digest,
    /// The architecture of the fetch image.
    pub fetch_arch: String,
    /// The digest of the verify image.
    pub verify_image: Sha256Digest,
    /// The architecture of the verify image.
    pub verify_arch: String,
}

/// Where the review stands. It decides the review report and whether the later gates ran.
enum Review {
    /// The integrity checks refused the change, or the base could not be read.
    NotReached,
    /// A rule is broken.
    Failed(Vec<Finding>),
    /// `cargo fetch` refused the lockfile.
    FetchRefused(i32),
    /// Something is missing.
    Blocked(BlockedCode, String),
    /// The review is satisfied. `fetched` is true when packages were fetched and read.
    Clean { fetched: bool },
}

fn review_state(ev: &Evaluation<'_>) -> Review {
    let Ok(plan) = ev.plan else {
        return Review::NotReached;
    };
    if plan.integrity.has_violation() {
        return Review::NotReached;
    }
    let broken: Vec<Finding> = plan
        .findings
        .iter()
        .filter(|f| f.is_violation())
        .cloned()
        .collect();
    if !broken.is_empty() {
        return Review::Failed(broken);
    }
    let awaiting = plan.awaiting();
    if !awaiting.is_empty() {
        return Review::Blocked(
            BlockedCode::PolicyUnresolvable,
            format!(
                "a recorded human decision for: {}",
                awaiting
                    .iter()
                    .map(|need| describe(need))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        );
    }
    if !plan.integrity.lock_changed() {
        return Review::Clean { fetched: false };
    }
    let Some(fetched) = ev.fetched else {
        return Review::Blocked(
            BlockedCode::DependencyUnavailable,
            "a fetch of the changed dependencies".to_owned(),
        );
    };
    match &fetched.end {
        FetchEnd::Refused { code } => return Review::FetchRefused(*code),
        FetchEnd::Blocked(blocker) => {
            return Review::Blocked(blocker.code, blocker.missing.clone());
        }
        FetchEnd::Described(_) => {}
    }
    let Some(conclusion) = ev.conclusion else {
        return Review::Blocked(
            BlockedCode::DependencyUnavailable,
            "the licenses and build code of the fetched packages".to_owned(),
        );
    };
    let broken: Vec<Finding> = conclusion
        .findings
        .iter()
        .filter(|f| f.is_violation())
        .cloned()
        .collect();
    if !broken.is_empty() {
        return Review::Failed(broken);
    }
    if !conclusion.escalated.is_empty() {
        let names: Vec<String> = conclusion
            .escalated
            .iter()
            .map(|subject| {
                format!(
                    "{} {}",
                    plain(&subject.name, 80),
                    plain(&subject.version, 40)
                )
            })
            .collect();
        return Review::Blocked(
            BlockedCode::PolicyUnresolvable,
            format!(
                "a security approver's decision, because build code comes in with: {}",
                names.join(", ")
            ),
        );
    }
    Review::Clean { fetched: true }
}

/// A line for a person: the dependency, who must decide, and why.
fn describe(need: &Need) -> String {
    let who = need.designation.as_str();
    let why: Vec<String> = need.flags.iter().map(flag_phrase).collect();
    let name = plain(&need.subject.name, 80);
    let version = plain(&need.subject.version, 40);
    if why.is_empty() {
        format!("{name} {version} ({who})")
    } else {
        format!("{name} {version} ({who}: {})", why.join(", "))
    }
}

fn fix_for(check_id: &str) -> &'static str {
    match check_id {
        check::UPDATE_ONLY => "Check that the update was meant, and run the full tests.",
        check::BUILD_CODE => "Ask a security reviewer to read the build script or macro.",
        check::SUSPECT_NAME => "Check that the package is the one meant, not a look-alike.",
        _ => "Read the finding and decide whether the change is meant.",
    }
}

impl Reporter<'_> {
    fn id(&self) -> GateReportId {
        GateReportId::from_uuid(self.ids.new_uuid())
    }

    /// A sentence, or the fixed text when it looks like a secret.
    fn clean(&self, text: &str) -> String {
        match self.redactor.contains_secret(text.as_bytes()) {
            Ok(false) => text.to_owned(),
            _ => WITHHELD.to_owned(),
        }
    }

    fn failures(&self, findings: &[Finding]) -> Result<Vec<Failure>, ReportError> {
        findings
            .iter()
            .take(MOST_FAILURES)
            .map(|found| {
                failure(
                    found.check,
                    &self.clean(&found.message),
                    found.path.as_deref().map(|path| (path, None)),
                )
            })
            .collect()
    }

    fn warnings(&self, findings: &[Finding]) -> Result<Vec<GateWarning>, ReportError> {
        findings
            .iter()
            .filter(|found| !found.is_violation())
            .take(MOST_FAILURES)
            .map(|found| {
                warning(
                    found.check,
                    &self.clean(&found.message),
                    fix_for(found.check),
                )
            })
            .collect()
    }

    fn in_process(&self) -> Result<GateEnvironment, ReportError> {
        in_process_environment(self.cx.fidelity)
    }

    fn sandbox(
        &self,
        id: &str,
        image: &Sha256Digest,
        arch: &str,
        network: SandboxNetwork,
        seen: &[Seen],
    ) -> Result<GateEnvironment, ReportError> {
        let versions: Vec<ToolVersion> = seen
            .iter()
            .filter(|step| step.argv.last().map(String::as_str) == Some("--version"))
            .filter_map(|step| {
                step.stdout
                    .as_deref()
                    .and_then(|out| tool_version(out).ok())
            })
            .collect();
        let mut info = sandbox_info(id, image.clone(), arch)?;
        info.network = network;
        Ok(sandbox_environment(self.cx.fidelity, info, versions))
    }

    fn commands(seen: &[Seen]) -> Result<Vec<GateCommand>, ReportError> {
        seen.iter()
            .map(|step| observed_command(&step.argv, None, &step.exec))
            .collect()
    }

    fn times(&self, seen: &[Seen]) -> (Timestamp, Timestamp) {
        let start = seen
            .iter()
            .map(|s| s.exec.started_at)
            .min()
            .unwrap_or(self.now);
        let end = seen
            .iter()
            .map(|s| s.exec.finished_at)
            .max()
            .unwrap_or(self.now);
        (start, end)
    }

    #[allow(clippy::too_many_arguments)]
    fn make(
        &self,
        gate_id: &str,
        title: &str,
        reason: &str,
        environment: GateEnvironment,
        seen: &[Seen],
        warnings: Vec<GateWarning>,
        outcome: Outcome,
    ) -> Result<GateReport, ReportError> {
        let (started, finished) = self.times(seen);
        // A passed report of a sandbox gate must record the tool it used. When the probe gave no
        // version the contract refuses the report, and the gate is blocked instead.
        let outcome = if matches!(outcome, Outcome::Passed) && environment.tool_versions.is_empty()
        {
            Outcome::Blocked(
                BlockedCode::ToolProbeFailed,
                "the version of the tool that ran".to_owned(),
            )
        } else {
            outcome
        };
        build(
            &self.cx,
            self.id(),
            Draft {
                gate: gate_id.to_owned(),
                title: title.to_owned(),
                reason: self.clean(reason),
                started,
                finished,
                environment,
                commands: Self::commands(seen)?,
                warnings,
                baseline: not_compared(),
                outcome,
            },
        )
    }

    fn blocked(
        &self,
        gate_id: &str,
        title: &str,
        code: BlockedCode,
        missing: &str,
        reason: &str,
    ) -> Result<GateReport, ReportError> {
        self.make(
            gate_id,
            title,
            reason,
            self.in_process()?,
            &[],
            Vec::new(),
            Outcome::Blocked(code, self.clean(missing)),
        )
    }

    fn not_applicable(
        &self,
        gate_id: &str,
        title: &str,
        code: NotApplicableCode,
        by: NotApplicableDecider,
        why: &str,
    ) -> Result<GateReport, ReportError> {
        self.make(
            gate_id,
            title,
            why,
            self.in_process()?,
            &[],
            Vec::new(),
            Outcome::NotApplicable {
                code,
                decided_by: by,
                justification: why.to_owned(),
            },
        )
    }

    fn base_unreadable(&self, gate_id: &str, title: &str) -> Result<GateReport, ReportError> {
        self.blocked(
            gate_id,
            title,
            BlockedCode::PolicyUnresolvable,
            "dependency files of the base commit that can be read",
            "A dependency file of the protected base commit could not be read, so the change cannot be judged against it.",
        )
    }

    fn not_run(&self, gate_id: &str, title: &str) -> Result<GateReport, ReportError> {
        self.blocked(
            gate_id,
            title,
            BlockedCode::DependencyUnavailable,
            "an earlier dependency check that passed",
            "The gate did not run, because an earlier dependency check did not pass first.",
        )
    }

    /// The four reports of a run that touched no dependency file: nothing to compare, decide or
    /// scan, decided by a deterministic rule.
    ///
    /// # Errors
    /// [`ReportError`] when a report would break the contract. That is a fault of the factory.
    pub fn untouched(&self) -> Result<Vec<GateReport>, ReportError> {
        const WHY: &str = "The change touches no dependency file, so there is nothing to compare, decide or scan.";
        [
            (
                gate::INTEGRITY,
                "Dependency files agree with the base commit",
            ),
            (gate::REVIEW, "New dependencies are decided and licensed"),
            (gate::ADVISORIES, "No known advisory in the dependencies"),
            (gate::SBOM, "Software bill of materials"),
        ]
        .into_iter()
        .map(|(id, title)| {
            self.not_applicable(
                id,
                title,
                NotApplicableCode::NoMatchingFiles,
                NotApplicableDecider::DeterministicRule,
                WHY,
            )
        })
        .collect()
    }

    /// The four reports of a run that could not start: each says what was missing.
    ///
    /// # Errors
    /// [`ReportError`] when a report would break the contract. That is a fault of the factory.
    pub fn cannot_run(
        &self,
        code: BlockedCode,
        missing: &str,
        reason: &str,
    ) -> Result<Vec<GateReport>, ReportError> {
        [
            (
                gate::INTEGRITY,
                "Dependency files agree with the base commit",
            ),
            (gate::REVIEW, "New dependencies are decided and licensed"),
            (gate::ADVISORIES, "No known advisory in the dependencies"),
            (gate::SBOM, "Software bill of materials"),
        ]
        .into_iter()
        .map(|(id, title)| self.blocked(id, title, code, missing, reason))
        .collect()
    }

    /// The four reports, in the order of [`gate::ALL`].
    ///
    /// # Errors
    /// [`ReportError`] when a report would break the contract. That is a fault of the factory.
    pub fn reports(&self, ev: &Evaluation<'_>) -> Result<Vec<GateReport>, ReportError> {
        Ok(vec![
            self.integrity(ev)?,
            self.review(ev)?,
            self.advisories(ev)?,
            self.sbom(ev)?,
        ])
    }

    fn integrity(&self, ev: &Evaluation<'_>) -> Result<GateReport, ReportError> {
        const TITLE: &str = "Dependency files agree with the base commit";
        let Ok(plan) = ev.plan else {
            return self.base_unreadable(gate::INTEGRITY, TITLE);
        };
        let found = &plan.integrity;
        let head = &found.head;
        if found.findings.is_empty()
            && head.locks.is_empty()
            && head.manifests.is_empty()
            && head.configs.is_empty()
            && head.scanners.is_empty()
        {
            return self.not_applicable(
                gate::INTEGRITY,
                TITLE,
                NotApplicableCode::NoMatchingFiles,
                NotApplicableDecider::DeterministicRule,
                "The project has no dependency file, so there is nothing to compare.",
            );
        }
        let violations: Vec<Finding> = found
            .findings
            .iter()
            .filter(|f| f.is_violation())
            .cloned()
            .collect();
        let warnings = self.warnings(&found.findings)?;
        if violations.is_empty() {
            let reason = if found.lock_changed() {
                "The dependency files agree with the base commit: no source, checksum, version or configuration rule is broken."
            } else {
                "The change adds no dependency and changes no lockfile, source or build configuration."
            };
            self.make(
                gate::INTEGRITY,
                TITLE,
                reason,
                self.in_process()?,
                &[],
                warnings,
                Outcome::Passed,
            )
        } else {
            self.make(
                gate::INTEGRITY,
                TITLE,
                "The dependency files break a rule of the supply chain policy.",
                self.in_process()?,
                &[],
                Vec::new(),
                Outcome::Failed(self.failures(&violations)?),
            )
        }
    }

    fn review(&self, ev: &Evaluation<'_>) -> Result<GateReport, ReportError> {
        const TITLE: &str = "New dependencies are decided and licensed";
        if ev.plan.is_err() {
            return self.base_unreadable(gate::REVIEW, TITLE);
        }
        let fetch_seen: &[Seen] = ev.fetched.map_or(&[], |f| f.seen.as_slice());
        match review_state(ev) {
            Review::NotReached => self.not_run(gate::REVIEW, TITLE),
            Review::Failed(findings) => self.review_environment(
                ev,
                "A new dependency breaks the license rule or is not a valid request.",
                Vec::new(),
                Outcome::Failed(self.failures(&findings)?),
            ),
            Review::FetchRefused(code) => {
                let message = format!(
                    "cargo fetch with --locked ended with exit code {code}: the lockfile does not match the manifests or the registry."
                );
                self.review_environment(
                    ev,
                    "The locked packages could not be fetched as the lockfile says.",
                    Vec::new(),
                    Outcome::Failed(vec![failure("fetch-refused", &message, None)?]),
                )
            }
            Review::Blocked(code, missing) => self.make(
                gate::REVIEW,
                TITLE,
                "The review cannot pass yet: something it needs is missing, and nothing was approved on its behalf.",
                if fetch_seen.is_empty() {
                    self.in_process()?
                } else {
                    self.fetch_environment(ev)?
                },
                fetch_seen,
                Vec::new(),
                Outcome::Blocked(code, self.clean(&missing)),
            ),
            Review::Clean { fetched } => {
                let mut warnings = Vec::new();
                if let Ok(plan) = ev.plan {
                    for need in &plan.needs {
                        if let Some(approval) = &need.approval {
                            warnings.push(warning(
                                "dependency-approved",
                                &self.clean(&format!(
                                    "{} {} was approved by person {} as {} under policy {} (allowlist {}): {}",
                                    plain(&need.subject.name, 80),
                                    plain(&need.subject.version, 40),
                                    approval.approver,
                                    approval.designation,
                                    approval.policy_hash,
                                    plain(&approval.allowlist_version, 80),
                                    plain(&approval.reason, 300),
                                )),
                                "Keep the decision with the evidence of this run.",
                            )?);
                        }
                    }
                    warnings.extend(self.warnings(&plan.findings)?);
                }
                if let Some(conclusion) = ev.conclusion {
                    warnings.extend(self.warnings(&conclusion.findings)?);
                }
                let reason = if fetched {
                    "Every new direct dependency has a recorded decision, and the licenses of the fetched packages are on the allow list."
                } else {
                    "The change adds no new package, so there is nothing to decide or license."
                };
                let environment = if fetched {
                    self.fetch_environment(ev)?
                } else {
                    self.in_process()?
                };
                self.make(gate::REVIEW, TITLE, reason, environment, if fetched { fetch_seen } else { &[] }, warnings, Outcome::Passed)
            }
        }
    }

    fn review_environment(
        &self,
        ev: &Evaluation<'_>,
        reason: &str,
        warnings: Vec<GateWarning>,
        outcome: Outcome,
    ) -> Result<GateReport, ReportError> {
        let seen: &[Seen] = ev.fetched.map_or(&[], |f| f.seen.as_slice());
        let environment = if seen.is_empty() {
            self.in_process()?
        } else {
            self.fetch_environment(ev)?
        };
        self.make(
            gate::REVIEW,
            "New dependencies are decided and licensed",
            reason,
            environment,
            seen,
            warnings,
            outcome,
        )
    }

    fn fetch_environment(&self, ev: &Evaluation<'_>) -> Result<GateEnvironment, ReportError> {
        match ev.fetched {
            Some(fetched) => self.sandbox(
                &fetched.sandbox_id,
                &self.fetch_image,
                &self.fetch_arch,
                SandboxNetwork::Allowlist,
                &fetched.seen,
            ),
            None => self.in_process(),
        }
    }

    /// The common start of the two scan gates: `Some(report)` when the gate did not run or does
    /// not apply, `None` when the scan result is to be read.
    fn scan_precondition(
        &self,
        ev: &Evaluation<'_>,
        gate_id: &str,
        title: &str,
    ) -> Result<Option<GateReport>, ReportError> {
        let Ok(plan) = ev.plan else {
            return self.base_unreadable(gate_id, title).map(Some);
        };
        if !matches!(review_state(ev), Review::Clean { .. }) {
            return self.not_run(gate_id, title).map(Some);
        }
        if !plan.integrity.lock_changed() {
            return self
                .not_applicable(
                    gate_id,
                    title,
                    NotApplicableCode::NoMatchingFiles,
                    NotApplicableDecider::DeterministicRule,
                    "The dependency set did not change, so there is nothing new to scan.",
                )
                .map(Some);
        }
        if ev.scanned.is_none() {
            return self
                .blocked(
                    gate_id,
                    title,
                    BlockedCode::DependencyUnavailable,
                    "a scan of the changed dependencies",
                    "The scan did not run, so it gave no result.",
                )
                .map(Some);
        }
        Ok(None)
    }

    fn verify_environment(
        &self,
        scanned: &Scanned,
        seen: &[Seen],
    ) -> Result<GateEnvironment, ReportError> {
        self.sandbox(
            &scanned.sandbox_id,
            &self.verify_image,
            &self.verify_arch,
            SandboxNetwork::None,
            seen,
        )
    }

    fn advisories(&self, ev: &Evaluation<'_>) -> Result<GateReport, ReportError> {
        const TITLE: &str = "No known advisory in the dependencies";
        if let Some(report) = self.scan_precondition(ev, gate::ADVISORIES, TITLE)? {
            return Ok(report);
        }
        let Some(scanned) = ev.scanned else {
            return self.not_run(gate::ADVISORIES, TITLE);
        };
        let seen = scanned.audit_seen.as_slice();
        match &scanned.audit {
            AuditEnd::Blocked(Blocker { code, missing }) => self.make(
                gate::ADVISORIES,
                TITLE,
                "The audit could not run or gave no usable answer, and a missing audit is never a clean one.",
                self.verify_environment(scanned, seen)?,
                seen,
                Vec::new(),
                Outcome::Blocked(*code, self.clean(missing)),
            ),
            // A clean answer from a database of unknown age or beyond the limit is not a clean
            // audit: with `--no-fetch` the tool checks nothing about the age and prints no date.
            AuditEnd::Clean(_) if !matches!(ev.database, DatabaseAge::Fresh { .. }) => {
                let (code, missing, reason) = match ev.database {
                    DatabaseAge::Stale { days, limit } => (
                        BlockedCode::DependencyUnavailable,
                        format!("an advisory database updated within the last {limit} day(s) (this one is {days} day(s) old)"),
                        format!("The audit found nothing, but its advisory database is more than {limit} day(s) old, so the answer says nothing about advisories published since."),
                    ),
                    _ => (
                        BlockedCode::DependencyUnavailable,
                        "the date of the advisory database the audit read".to_owned(),
                        "The audit found nothing, but nothing says how old its advisory database is, and an audit that cannot say so is not a clean one.".to_owned(),
                    ),
                };
                self.make(
                    gate::ADVISORIES,
                    TITLE,
                    &reason,
                    self.verify_environment(scanned, seen)?,
                    seen,
                    Vec::new(),
                    Outcome::Blocked(code, self.clean(&missing)),
                )
            }
            AuditEnd::Clean(result) => {
                let warnings = if result.warnings > 0 {
                    vec![warning(
                        "audit-warnings",
                        &format!("The audit lists {} warning(s) such as unmaintained or yanked packages.", result.warnings),
                        "Read the audit output and decide whether a replacement is due.",
                    )?]
                } else {
                    Vec::new()
                };
                let age = match ev.database {
                    DatabaseAge::Fresh { days } => days,
                    _ => 0,
                };
                self.make(
                    gate::ADVISORIES,
                    TITLE,
                    &format!("The audit found no advisory against the locked packages, in an advisory database updated {age} day(s) ago."),
                    self.verify_environment(scanned, seen)?,
                    seen,
                    warnings,
                    Outcome::Passed,
                )
            }
            AuditEnd::Found(result) => {
                let failures = result
                    .advisories
                    .iter()
                    .map(|advisory| {
                        failure(
                            "advisory-found",
                            &self.clean(&format!(
                                "The advisory {} applies to {} {}.",
                                advisory.id, advisory.package, advisory.version
                            )),
                            None,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.make(
                    gate::ADVISORIES,
                    TITLE,
                    &format!("The audit found {} advisory(ies) against the locked packages.", result.count),
                    self.verify_environment(scanned, seen)?,
                    seen,
                    Vec::new(),
                    Outcome::Failed(failures),
                )
            }
        }
    }

    fn sbom(&self, ev: &Evaluation<'_>) -> Result<GateReport, ReportError> {
        const TITLE: &str = "Software bill of materials";
        if let Some(report) = self.scan_precondition(ev, gate::SBOM, TITLE)? {
            return Ok(report);
        }
        let Some(scanned) = ev.scanned else {
            return self.not_run(gate::SBOM, TITLE);
        };
        let seen = scanned.sbom_seen.as_slice();
        match &scanned.sbom {
            SbomEnd::Made => self.make(
                gate::SBOM,
                TITLE,
                "A CycloneDX document was made from the locked packages and kept as the output of the command.",
                self.verify_environment(scanned, seen)?,
                seen,
                Vec::new(),
                Outcome::Passed,
            ),
            SbomEnd::Unavailable(_) if !ev.sbom_required => self.not_applicable(
                gate::SBOM,
                TITLE,
                NotApplicableCode::PolicyExcludesGate,
                NotApplicableDecider::Policy,
                "The SBOM tool cannot run here, and supply_chain.sbom requires an SBOM only for a release or a high-risk job, which this is not.",
            ),
            SbomEnd::Unavailable(blocker) | SbomEnd::Unusable(blocker) => self.make(
                gate::SBOM,
                TITLE,
                "No usable SBOM was made, and none is made up in its place.",
                self.verify_environment(scanned, seen)?,
                seen,
                Vec::new(),
                Outcome::Blocked(blocker.code, self.clean(&blocker.missing)),
            ),
        }
    }
}
