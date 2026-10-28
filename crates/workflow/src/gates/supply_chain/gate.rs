//! The whole gate, from the files of two commits to four gate reports.
//!
//! [`run`] is what the validation stage calls once it holds the dependency files of the base
//! commit and of the candidate. It does the steps in the only order that is safe:
//!
//! 1. compare the files ([`integrity`](super::integrity)); a refused change stops here, and no
//!    sandbox is made;
//! 2. ask the registry source for the facts of each new direct dependency, and the policy engine
//!    what each needs ([`Plan`]);
//! 3. only when every new direct dependency has its recorded decision, fetch in the `fetch_deps`
//!    sandbox and read the metadata;
//! 4. only when the review is satisfied, run the audit and the SBOM tool in a `verify` sandbox;
//! 5. build the four reports ([`Reporter`]).
//!
//! It also returns the decisions as ledger evidence ([`Plan::evidence`]). The stage stores that
//! document, and the recorded approvals it hands back to the next run are what let step 3 start.

use factory_domain::contracts::GateReport;
use factory_domain::values::Timestamp;
use factory_ports::paths::CommitSha;
use serde_json::Value;

use super::approval::DependencyApproval;
use super::facts::RegistryMetadata;
use super::integrity::{BaseUnreadable, Context, inspect};
use super::model::{DependencyFormat, Side, normalize};
use super::report::{Evaluation, Reporter};
use super::review::{Conclusion, Plan, RegistryTable, Settings, conclude};
use super::run::{Io, SupplyChainConfig, fetch, scan};
use crate::gates::command::report::{ReportContext, image_digest};
use crate::handlers::StageError;

/// What the gate reads besides the ports.
pub struct Inputs<'a> {
    /// The package manager's way of writing dependency files.
    pub format: &'a dyn DependencyFormat,
    /// The dependency files at the base commit of the protected branch.
    pub base: &'a Side,
    /// The dependency files of the candidate.
    pub head: &'a Side,
    /// The candidate commit, which the sandboxes check out.
    pub head_commit: &'a CommitSha,
    /// The decisions recorded for this job so far.
    pub approvals: &'a [DependencyApproval],
    /// Where the facts about the new packages come from.
    pub registry: &'a dyn RegistryMetadata,
    /// What every report shares: the run, the definition, the binding.
    pub report: ReportContext,
}

/// The result of one run.
pub struct Done {
    /// The four reports, in the order of [`gate::ALL`](super::report::gate::ALL).
    pub reports: Vec<GateReport>,
    /// The decisions as ledger evidence. Absent when the base commit could not be read.
    pub evidence: Option<Value>,
    /// Whether a fetch container was made.
    pub fetched: bool,
    /// Whether a scan container was made.
    pub scanned: bool,
}

/// Runs the gate.
///
/// # Errors
/// [`StageError`] when the environment is missing or unsafe, the call was cancelled, or a report
/// would break the contract of the gate report (a fault of the factory).
pub async fn run(io: &Io<'_>, inputs: &Inputs<'_>) -> Result<Done, StageError> {
    let cfg: &SupplyChainConfig = io.cfg;
    let now: Timestamp = io.ports.clock.now();
    let popular = &cfg.popular;
    let cx = Context {
        internal_names: &cfg.internal_names,
        popular,
    };
    let integrity = match inspect(inputs.format, inputs.base, inputs.head, &cx) {
        Ok(integrity) => integrity,
        Err(unreadable) => return unreadable_base(io, inputs, &unreadable, now),
    };

    // The facts of each new direct dependency. A source that knows nothing returns the default
    // record, which the policy reads as the worst answer.
    let mut registry = RegistryTable::new();
    if !integrity.has_violation() {
        for entry in &integrity.new_direct {
            let record = inputs
                .registry
                .lookup(&entry.package.name, &entry.package.version)
                .await;
            registry.insert(normalize(&entry.package.name), record);
        }
    }
    let settings = Settings {
        dependency: &cfg.policy.dependency,
        licenses: &cfg.licenses,
        internal_names: &cfg.internal_names,
        popular,
        now,
    };
    let plan = Plan::new(integrity, &registry, inputs.approvals, &settings);

    let fetched = if plan.may_fetch() {
        Some(fetch(io, &plan, inputs.head_commit).await?)
    } else {
        None
    };
    let conclusion: Option<Conclusion> = fetched.as_ref().and_then(|done| match &done.end {
        super::run::FetchEnd::Described(metadata) => Some(conclude(&plan, metadata, &cfg.licenses)),
        _ => None,
    });
    let review_clean = fetched.is_some()
        && conclusion
            .as_ref()
            .is_some_and(|c| !c.has_violation() && c.escalated.is_empty());
    let scanned = if review_clean {
        Some(scan(io, &plan, inputs.head_commit).await?)
    } else {
        None
    };

    let evaluation = Evaluation {
        plan: Ok(&plan),
        fetched: fetched.as_ref(),
        conclusion: conclusion.as_ref(),
        scanned: scanned.as_ref(),
        sbom_required: cfg.sbom.required,
    };
    let reports = reporter(io, inputs, now)?
        .reports(&evaluation)
        .map_err(|_| StageError::Internal)?;
    Ok(Done {
        reports,
        evidence: Some(plan.evidence()),
        fetched: fetched.is_some(),
        scanned: scanned.is_some(),
    })
}

fn unreadable_base(
    io: &Io<'_>,
    inputs: &Inputs<'_>,
    unreadable: &BaseUnreadable,
    now: Timestamp,
) -> Result<Done, StageError> {
    let evaluation = Evaluation {
        plan: Err(unreadable),
        fetched: None,
        conclusion: None,
        scanned: None,
        sbom_required: io.cfg.sbom.required,
    };
    let reports = reporter(io, inputs, now)?
        .reports(&evaluation)
        .map_err(|_| StageError::Internal)?;
    Ok(Done {
        reports,
        evidence: None,
        fetched: false,
        scanned: false,
    })
}

fn reporter<'a>(
    io: &'a Io<'_>,
    inputs: &Inputs<'_>,
    now: Timestamp,
) -> Result<Reporter<'a>, StageError> {
    let cfg = io.cfg;
    let digest = |image: &factory_ports::sandbox::ImageDigest| {
        image_digest(image.reference()).map_err(|_| StageError::Internal)
    };
    Ok(Reporter {
        cx: inputs.report.clone(),
        ids: io.ports.ids,
        now,
        redactor: &cfg.redactor,
        fetch_image: digest(&cfg.fetch.image)?,
        fetch_arch: cfg.fetch.arch.clone(),
        verify_image: digest(&cfg.verify.image)?,
        verify_arch: cfg.verify.arch.clone(),
    })
}
