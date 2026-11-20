//! What the factory writes into a project's history follows the project's git conventions.
//!
//! A project that keeps `.factory/repository.json` (written by the installer) asks for
//! Conventional Commits: each commit the factory makes, and the title of its pull request, starts
//! with `type(scope): `, with a type and a scope the project allows and within its length limit.
//! The type follows the work: the kind of request the intake classifier found
//! (`normalized-request.request_kind`), or the kind of task (tests are `test`, documentation is
//! `docs`). The rules are in [`factory_domain::policy::git_conventions`].
//!
//! The settings are read from the job's object store, at a commit of the job (the base, or a commit
//! the factory made on top of it). `.factory/**` is a protected path, so no commit of the job can
//! have changed them. A project without the file keeps the messages the factory wrote before.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::task_dag::TaskKind;
use factory_domain::policy::git_conventions::{
    GitConventions, MAX_SETTINGS_BYTES, SETTINGS_PATH, type_for_request,
};
use factory_domain::scope::TenantScope;
use factory_domain::vocabulary::StageKind;
use factory_ports::paths::{CommitSha, RepoPath};
use factory_ports::workspace::{ReadView, WorkspaceError};

use crate::handlers::{StageContext, StageError};

/// The name of the intake output that holds the request kind.
const NORMALIZED_REQUEST: &str = "normalized-request";

/// The settings of a project, with the commit type of the job's request.
#[derive(Debug, Clone)]
pub struct Conventions {
    settings: GitConventions,
    request_type: &'static str,
}

impl Conventions {
    /// Conventions from settings and the intake classifier's request kind.
    #[must_use]
    pub fn new(settings: GitConventions, request_kind: Option<&str>) -> Self {
        Self {
            settings,
            request_type: type_for_request(request_kind.unwrap_or("feature")),
        }
    }

    /// The commit type of the job's request: `feat`, `fix`, `docs`, `refactor` or `chore`.
    #[must_use]
    pub fn request_type(&self) -> &'static str {
        self.request_type
    }

    /// The type for one task of the plan: tests are `test`, documentation is `docs`, configuration
    /// and data are `chore`, everything else is the type of the request.
    #[must_use]
    pub fn task_type(&self, kind: Option<TaskKind>) -> &'static str {
        match kind {
            Some(TaskKind::Test) => "test",
            Some(TaskKind::Documentation) => "docs",
            Some(TaskKind::Configuration | TaskKind::Data) => "chore",
            _ => self.request_type,
        }
    }

    /// A Conventional Commits header for this project.
    #[must_use]
    pub fn header(&self, preferred_type: &str, scope: Option<&str>, subject: &str) -> String {
        self.settings.header(preferred_type, scope, subject)
    }

    /// A whole commit message: the header, a blank line and the body.
    #[must_use]
    pub fn message(
        &self,
        preferred_type: &str,
        scope: Option<&str>,
        subject: &str,
        body: &str,
    ) -> String {
        let body = body.trim_end();
        let header = self.header(preferred_type, scope, subject);
        if body.is_empty() {
            format!("{header}\n")
        } else {
            format!("{header}\n\n{body}\n")
        }
    }

    /// The title of the pull request: the header of the request's type around `title`.
    #[must_use]
    pub fn title(&self, title: &str) -> String {
        self.header(self.request_type, None, title)
    }
}

/// The project's conventions at `commit`, or `None` when the project keeps no settings.
///
/// # Errors
/// [`StageError::Blocked`] with `policy_unresolvable` when the settings are there and not valid
/// (the repository intelligence stage refuses them first, so this means they were read wrongly),
/// and with `dependency_unavailable` when the object store or the intake output cannot be read.
pub async fn load(
    ctx: &StageContext<'_>,
    commit: &CommitSha,
) -> Result<Option<Conventions>, StageError> {
    let unavailable = || StageError::Blocked(BlockedCode::DependencyUnavailable);
    let repo = ctx
        .ports
        .workspaces
        .repo(ctx.identity.job)
        .await
        .map_err(|_| unavailable())?;
    let path = RepoPath::new(SETTINGS_PATH).map_err(|_| StageError::Internal)?;
    let bytes = match repo
        .read_file_at(commit, &path, MAX_SETTINGS_BYTES, ReadView::Trusted)
        .await
    {
        Ok(bytes) => bytes,
        Err(WorkspaceError::PathNotFound(_)) => return Ok(None),
        Err(_) => return Err(unavailable()),
    };
    let settings = GitConventions::parse(&bytes).map_err(|rejected| {
        tracing::warn!("{rejected}");
        StageError::Blocked(BlockedCode::PolicyUnresolvable)
    })?;
    Ok(Some(Conventions::new(
        settings,
        request_kind(ctx).await?.as_deref(),
    )))
}

/// The request kind the intake classifier wrote, read from the stored output of the passed intake
/// run. `None` when the job has no such run (a job built in a test).
async fn request_kind(ctx: &StageContext<'_>) -> Result<Option<String>, StageError> {
    let found = ctx.upstream.iter().rev().find_map(|run| {
        (run.kind == StageKind::Intake)
            .then(|| {
                run.outputs
                    .iter()
                    .find(|o| o.name.as_str() == NORMALIZED_REQUEST)
            })
            .flatten()
    });
    let Some(output) = found else {
        return Ok(None);
    };
    let bytes = ctx
        .ports
        .artifacts
        .get(&TenantScope::new(ctx.identity.tenant), &output.artifact)
        .await
        .map_err(|_| StageError::Blocked(BlockedCode::DependencyUnavailable))?;
    Ok(serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|doc| doc.get("request_kind")?.as_str().map(str::to_owned)))
}

/// The commit message: the project's convention when it has one, else `plain`.
#[must_use]
pub fn message_or(
    conventions: Option<&Conventions>,
    preferred_type: &str,
    scope: Option<&str>,
    subject: &str,
    body: &str,
    plain: String,
) -> String {
    conventions.map_or(plain, |c| c.message(preferred_type, scope, subject, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(types: &str) -> GitConventions {
        let text = format!(
            r#"{{"schema":"factory-repository-settings/1","repository":{{"owner":"acme","name":"widgets"}},"project_board":null,
            "commits":{{"convention":"conventional-commits","types":{types},"scopes":[],"require_scope":false,"header_max_length":72}},
            "gitflow":{{"closing_mode":"develop","main_branch":"main","develop_branch":"develop",
            "prefixes":{{"feature":["feature/","factory/"],"bugfix":["bugfix/"],"release":["release/"],"hotfix":["hotfix/"],"support":["support/"]}},
            "additional_flows":[]}}}}"#
        );
        GitConventions::parse(text.as_bytes()).expect("valid settings")
    }

    const ALL: &str =
        r#"["build","chore","ci","docs","feat","fix","perf","refactor","revert","style","test"]"#;

    #[test]
    fn the_request_kind_picks_the_type_and_tasks_refine_it() {
        let fix = Conventions::new(settings(ALL), Some("bugfix"));
        assert_eq!(fix.request_type(), "fix");
        assert_eq!(fix.task_type(Some(TaskKind::CodeChange)), "fix");
        assert_eq!(fix.task_type(Some(TaskKind::Test)), "test");
        assert_eq!(fix.task_type(Some(TaskKind::Documentation)), "docs");
        assert_eq!(fix.task_type(Some(TaskKind::Configuration)), "chore");
        assert_eq!(fix.task_type(None), "fix");
        assert_eq!(Conventions::new(settings(ALL), None).request_type(), "feat");
    }

    #[test]
    fn messages_and_titles() {
        let c = Conventions::new(settings(ALL), Some("feature"));
        assert_eq!(
            c.message(
                "docs",
                Some("spec"),
                "write the specification: specify step",
                "Committed by the factory.\n"
            ),
            "docs(spec): write the specification: specify step\n\nCommitted by the factory.\n"
        );
        assert_eq!(
            c.message("test", None, "Cover the --json flag.", ""),
            "test: Cover the --json flag\n"
        );
        assert_eq!(
            c.title("Count words in standard input"),
            "feat: Count words in standard input"
        );
        let narrow = Conventions::new(settings(r#"["fix","chore"]"#), Some("feature"));
        assert_eq!(narrow.title("x"), "chore: x");
        assert_eq!(
            message_or(None, "feat", None, "x", "y", "Plain\n".to_owned()),
            "Plain\n"
        );
    }
}
