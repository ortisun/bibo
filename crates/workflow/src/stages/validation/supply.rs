//! The dependency and supply chain gates inside the validation stage.
//!
//! [`reports`] is the only place the stage calls [`gate::run`](crate::gates::supply_chain::gate::run).
//! It decides whether the gates run, reads the dependency files of the base commit and of the
//! candidate from the object store on the host, and hands the gate what it needs. The stage always
//! makes the four reports (`dependency-integrity`, `dependency-review`, `dependency-advisories`,
//! `sbom`):
//!
//! | Situation | Reports |
//! |---|---|
//! | A host-side rule refused the change or could not run | all four `BLOCKED`: the gate runs a container, and none is made for a change the host refused |
//! | The change touches no dependency file, and neither the policy (`supply_chain.dependency_gates.run_when`) nor the settings say "always" | all four `NOT_APPLICABLE`; nothing is read, nothing is made |
//! | A dependency file is a link or a submodule, a listing is cut, a file is unreadable or too big | all four `BLOCKED` with what is missing |
//! | Otherwise | the gate runs: integrity first, then the decision on each new direct dependency, then the fetch and the scan |
//!
//! # How a person is asked
//!
//! A new direct dependency with no recorded decision makes `dependency-review` `BLOCKED` with the
//! code `policy_unresolvable`, and no container is made. The report names the package, the
//! version and the designation that must decide. The engine ends the stage run as blocked; the
//! decision itself is the per-dependency approval (`add_new_direct_dependency`, recorded through
//! the policy engine and read back through [`RecordedApprovals`]), and the rerun is the operator's
//! `UnblockRerun`. An override of the block is **not** the way: it would pass the stage without a
//! decision bound to a package, a version and a checksum.

use factory_domain::contracts::GateReport;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::policy::dependency::RunWhen;
use factory_domain::scope::TenantScope;
use factory_domain::values::Sha256Digest;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{CommitSha, RepoGlob, RepoPath};
use factory_ports::workspace::{JobRepo, ReadView, WorkspaceError};
use serde_json::Value;

use super::config::{DependencyReadLimits, RunSupplyChain, ValidationConfig};
use super::gather::Gathered;
use crate::gates::command::report::ReportContext;
use crate::gates::scope::hardening;
use crate::gates::scope::patch::{GITLINK_MODE, PatchFact, SYMLINK_MODE};
use crate::gates::supply_chain::cargo::CargoFormat;
use crate::gates::supply_chain::gate::{self, Inputs, Skip};
use crate::gates::supply_chain::model::{DependencyFormat, FileKind, Side};
use crate::gates::supply_chain::run::{Io, SupplyChainConfig};
use crate::handlers::{StageError, StagePorts};

/// What the stage holds when it runs the dependency gates.
pub struct Context<'a> {
    /// The configuration of the stage.
    pub cfg: &'a ValidationConfig,
    /// The ports of the stage.
    pub ports: StagePorts<'a>,
    /// The tenant, for reading what the supervisor stored.
    pub scope: TenantScope,
    /// Trips when the engine cancels the attempt.
    pub cancel: &'a dyn CancelSignal,
    /// The job.
    pub job: factory_domain::ids::JobId,
    /// The attempt the sandboxes belong to.
    pub attempt: factory_domain::ids::AttemptId,
    /// The object store of the job.
    pub repo: &'a dyn JobRepo,
    /// The protected branch tip.
    pub base: &'a CommitSha,
    /// The commit under test.
    pub head: &'a CommitSha,
    /// The change, as the host read it.
    pub gathered: &'a Gathered,
    /// True when every host-side rule passed. Only then may a container be made.
    pub host_clean: bool,
    /// What every report shares.
    pub report: ReportContext,
    /// The hash of the policy bundle in force.
    pub policy_hash: &'a Sha256Digest,
}

/// The four reports, and the decisions as ledger evidence when the gate ran.
pub struct Outcome {
    /// The reports, in the order of the gates.
    pub reports: Vec<GateReport>,
    /// The review's decisions: what each new dependency is and who decided. Absent when the gate
    /// did not run.
    pub evidence: Option<Value>,
}

fn blocked(
    x: &Context<'_>,
    io: &Io<'_>,
    code: BlockedCode,
    missing: &str,
    reason: &str,
) -> Result<Outcome, StageError> {
    let reports = gate::skipped(
        io,
        &x.report,
        &Skip::Blocked {
            code,
            missing,
            reason,
        },
    )?;
    Ok(Outcome {
        reports,
        evidence: None,
    })
}

/// Makes the four reports of the dependency gates.
///
/// # Errors
/// [`StageError::Cancelled`] when the attempt was cancelled, [`StageError::Internal`] for a fault
/// of the factory, and the errors of a sandbox when the gate runs one.
pub async fn reports(x: &Context<'_>) -> Result<Outcome, StageError> {
    let seams = &x.cfg.supply_chain;
    let settings = &seams.settings;
    let config = SupplyChainConfig {
        policy: x.cfg.policy.clone(),
        path_rules: x.cfg.path_rules.clone(),
        holdouts: x.cfg.holdouts.clone(),
        fetch: settings.fetch.clone(),
        verify: x.cfg.sandbox.clone(),
        redactor: x.cfg.redactor.clone(),
        licenses: settings.licenses.clone(),
        popular: settings.popular.clone(),
        internal_names: settings.internal_names.clone(),
        sbom: settings.sbom.clone(),
        advisory_db_max_age_days: settings.advisory_db_max_age_days,
        bounds: settings.bounds,
    };
    let io = Io {
        ports: x.ports,
        scope: x.scope,
        cfg: &config,
        cancel: x.cancel,
        job: x.job,
        attempt: x.attempt,
    };
    let format = CargoFormat;

    if !x.host_clean {
        return blocked(
            x,
            &io,
            BlockedCode::DependencyUnavailable,
            "host-side checks that passed",
            "The dependency gates did not run, because a host-side check of the change did not pass first.",
        );
    }
    // Vendored code is built and run, and a change inside it is a change of a dependency that no
    // manifest shows (RR-16). It counts as touching a dependency file.
    let vendored = x
        .gathered
        .files
        .iter()
        .find(|file| hardening::is_vendored(&file.path));
    let touched = vendored.is_some()
        || x.gathered
            .files
            .iter()
            .any(|file| format.kind_of(&file.path).is_some());
    // The policy says when the gates run. The configuration may tighten that and never loosen it.
    let always = settings.run == RunSupplyChain::Always
        || x.cfg.policy.dependency.run_when() == RunWhen::Always;
    if !always && !touched {
        return Ok(Outcome {
            reports: gate::skipped(&io, &x.report, &Skip::Untouched)?,
            evidence: None,
        });
    }
    if let Some(file) = vendored {
        // There is no package to decide on: the code is not the published crate, and no checksum of
        // a registry vouches for it. A person with the security designation reviews the change
        // outside the factory, or the builder drops it.
        return blocked(
            x,
            &io,
            BlockedCode::PolicyUnresolvable,
            "a security review of the vendored code",
            &format!(
                "The change edits vendored code at {}, which no dependency decision covers.",
                crate::gates::supply_chain::model::plain(&file.path, 200)
            ),
        );
    }
    if let Some(path) = linked_dependency_file(&format, x.gathered) {
        return blocked(
            x,
            &io,
            BlockedCode::PolicyUnresolvable,
            "dependency files that are regular files",
            &format!(
                "The change makes {path} a symbolic link or a submodule, and a tool follows a link out of the file the gate read."
            ),
        );
    }

    let limits = settings.limits;
    let sides = match (
        read_side(x.repo, &format, x.base, &limits, x.cancel).await?,
        read_side(x.repo, &format, x.head, &limits, x.cancel).await?,
    ) {
        (Ok(base), Ok(head)) => (base, head),
        (Err(problem), _) | (_, Err(problem)) => {
            return blocked(
                x,
                &io,
                BlockedCode::DependencyUnavailable,
                "every dependency file of both commits, read in full",
                problem.sentence(),
            );
        }
    };
    let (base, head) = sides;

    let approvals = seams.approvals.for_job(x.scope.tenant_id(), x.job).await;
    let inputs = Inputs {
        format: &format,
        base: &base,
        head: &head,
        head_commit: x.head,
        approvals: &approvals,
        registry: &*seams.registry,
        advisory_db: &*seams.advisory_db,
        policy_hash: x.policy_hash,
        report: x.report.clone(),
    };
    let done = gate::run(&io, &inputs).await?;
    Ok(Outcome {
        reports: done.reports,
        evidence: done.evidence,
    })
}

/// The first dependency file of the change that is or was a symbolic link or a gitlink.
fn linked_dependency_file(format: &dyn DependencyFormat, gathered: &Gathered) -> Option<String> {
    let facts = gathered.facts.as_ref()?;
    let linked = |mode: Option<u32>| {
        mode.is_some_and(|mode| {
            let kind = PatchFact::kind_of(mode);
            kind == SYMLINK_MODE || kind == GITLINK_MODE
        })
    };
    facts
        .files()
        .iter()
        .filter(|fact| {
            format.kind_of(&fact.new_path).is_some() || format.kind_of(&fact.old_path).is_some()
        })
        .find(|fact| linked(fact.old_mode) || linked(fact.new_mode))
        .map(|fact| crate::gates::supply_chain::model::plain(&fact.new_path, 200))
}

/// Why the dependency files of a commit could not be read. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadProblem {
    /// The listing of the tree reached its limit, so it may be cut.
    Cut,
    /// The listing or a read failed.
    Failed,
    /// A file is above the size limit, or the files together are, or there are too many.
    TooBig,
    /// A file is not text.
    NotText,
}

impl ReadProblem {
    fn sentence(self) -> &'static str {
        match self {
            Self::Cut => {
                "The list of the files of a commit reached its limit, so it may be cut, and a cut list is not a project with fewer dependency files."
            }
            Self::Failed => {
                "The dependency files of a commit could not be listed or read from the object store, so the change cannot be judged."
            }
            Self::TooBig => {
                "The dependency files of a commit are more or larger than the gate reads, so the change cannot be judged."
            }
            Self::NotText => {
                "A dependency file of a commit is not text, so the change cannot be judged."
            }
        }
    }
}

/// Reads every dependency file of `commit` from the object store. A build script is recorded by
/// its path only: its text is never read, because cargo runs it and the gate only needs to know
/// that it exists.
async fn read_side(
    repo: &dyn JobRepo,
    format: &dyn DependencyFormat,
    commit: &CommitSha,
    limits: &DependencyReadLimits,
    cancel: &dyn CancelSignal,
) -> Result<Result<Side, ReadProblem>, StageError> {
    let everything = RepoGlob::new("**").map_err(|_| StageError::Internal)?;
    let listed = match repo
        .list_at(commit, &everything, limits.max_paths, ReadView::Trusted)
        .await
    {
        Ok(listed) => listed,
        Err(WorkspaceError::Cancelled) => return Err(StageError::Cancelled),
        Err(_) => return Ok(Err(ReadProblem::Failed)),
    };
    if listed.len() >= limits.max_paths {
        return Ok(Err(ReadProblem::Cut));
    }
    let wanted: Vec<(RepoPath, FileKind)> = listed
        .into_iter()
        .filter_map(|path| format.kind_of(path.as_str()).map(|kind| (path, kind)))
        .collect();
    if wanted.len() > limits.max_files {
        return Ok(Err(ReadProblem::TooBig));
    }
    let mut files: Vec<(String, String)> = Vec::with_capacity(wanted.len());
    let mut total: u64 = 0;
    for (path, kind) in wanted {
        if cancel.is_cancelled() {
            return Err(StageError::Cancelled);
        }
        if kind == FileKind::BuildScript {
            files.push((path.as_str().to_owned(), String::new()));
            continue;
        }
        let bytes = match repo
            .read_file_at(commit, &path, limits.max_file_bytes, ReadView::Trusted)
            .await
        {
            Ok(bytes) => bytes,
            Err(WorkspaceError::Cancelled) => return Err(StageError::Cancelled),
            Err(WorkspaceError::TooLarge) => return Ok(Err(ReadProblem::TooBig)),
            Err(_) => return Ok(Err(ReadProblem::Failed)),
        };
        total = total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if total > limits.max_total_bytes {
            return Ok(Err(ReadProblem::TooBig));
        }
        let Ok(text) = String::from_utf8(bytes) else {
            return Ok(Err(ReadProblem::NotText));
        };
        files.push((path.as_str().to_owned(), text));
    }
    Ok(Ok(Side::of(
        format,
        files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str())),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::scope::patch;

    fn gathered(patch_text: &str) -> Gathered {
        Gathered {
            files: Vec::new(),
            facts: Some(patch::parse(patch_text.as_bytes())),
            listed: true,
        }
    }

    #[test]
    fn a_dependency_file_that_becomes_a_link_or_a_submodule_is_found() {
        let link = "diff --git a/Cargo.lock b/Cargo.lock\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/Cargo.lock\n@@ -0,0 +1 @@\n+version=4\n\\ No newline at end of file\n";
        let submodule = "diff --git a/crates/a/Cargo.toml b/crates/a/Cargo.toml\nnew file mode 160000\nindex 0000000..2222222\n--- /dev/null\n+++ b/crates/a/Cargo.toml\n@@ -0,0 +1 @@\n+Subproject commit 3333333333333333333333333333333333333333\n";
        assert_eq!(
            linked_dependency_file(&CargoFormat, &gathered(link)).as_deref(),
            Some("Cargo.lock")
        );
        assert_eq!(
            linked_dependency_file(&CargoFormat, &gathered(submodule)).as_deref(),
            Some("crates/a/Cargo.toml")
        );
    }

    #[test]
    fn a_link_that_is_not_a_dependency_file_and_a_plain_edit_are_not_reported() {
        let other = "diff --git a/docs/link b/docs/link\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/docs/link\n@@ -0,0 +1 @@\n+x\n\\ No newline at end of file\n";
        let mode = "diff --git a/Cargo.lock b/Cargo.lock\nold mode 100644\nnew mode 100755\n";
        assert_eq!(linked_dependency_file(&CargoFormat, &gathered(other)), None);
        assert_eq!(linked_dependency_file(&CargoFormat, &gathered(mode)), None);
    }
}
