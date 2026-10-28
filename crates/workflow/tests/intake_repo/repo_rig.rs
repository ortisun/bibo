//! What the repository stage runs over: a Rust fixture repository on a fake remote, a workspace
//! provider that records every read, a sandbox whose `cargo` is a program the test controls, and
//! the seams of the stage.
//!
//! `fixtures/repos/word-count` is owned by another work package and is not merged, so the fixture
//! is written here, with the shape the work package describes: a Cargo project, a CODEOWNERS file,
//! a protected `.github` directory, a project manifest and the files that must never reach model
//! context (an environment file, a private key and a secret-bearing configuration).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::contracts::{Contract, ProjectManifest};
use factory_domain::ids::{AttemptId, JobId, TenantId};
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{
    BranchName, CommitSha, PathMode, PathRule, PathRules, RepoGlob, RepoPath, RepoRef,
};
use factory_ports::sandbox::{SandboxProfile, SandboxSpec};
use factory_ports::workspace::{
    FetchTarget, FetchedBase, JobRepo, PatchExport, PushTarget, ReadView, Workspace,
    WorkspaceError, WorkspaceMounts, WorkspaceProvider, WorkspaceRequest,
};
use factory_testkit::fixtures::{Ids, sandbox_spec};
use factory_testkit::sandbox::ProgramOutput;
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::stages::intake::SeamError;
use factory_workflow::stages::repo_intel::{
    JobRepository, ManifestProblem, ProjectManifestParser, TargetRepository, VerifySandboxSpecs,
};

const MANIFEST: &str =
    include_str!("../../../../schemas/examples/project-manifest/valid/word-count-minimal.json");

/// A secret-shaped string, built at run time so that no literal in the source looks like one.
/// It matches the `github_token_classic` pattern of the policy.
pub fn canary_token() -> String {
    format!("{}{}_{}", "gh", "p", "abcdefghijklmnopqrstuvwxyz0123456789")
}

/// Another canary, for the key file.
pub fn canary_key() -> String {
    format!("{}{} PRIVATE KEY{}", "-----BEGIN ", "OPENSSH", "-----")
}

/// The files of the fixture, as `(path, content)`.
pub fn word_count() -> Vec<(String, String)> {
    let files: Vec<(&str, String)> = vec![
        (
            "Cargo.toml",
            "[package]\nname = \"word-count\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"
                .to_owned(),
        ),
        ("Cargo.lock", "# generated\nversion = 4\n".to_owned()),
        (
            "src/main.rs",
            "fn main() {\n    word_count::run();\n}\n".to_owned(),
        ),
        ("src/lib.rs", "pub fn run() {}\n".to_owned()),
        (
            "src/count.rs",
            "pub fn count(text: &str) -> usize { text.split_whitespace().count() }\n".to_owned(),
        ),
        ("tests/count.rs", "#[test]\nfn counts() {}\n".to_owned()),
        (
            "README.md",
            "# Word count\n\nA small command line tool that counts words.\n".to_owned(),
        ),
        (
            "CODEOWNERS",
            "# Who owns what\n* @example-org/maintainers\n/src/ @example-org/core\n".to_owned(),
        ),
        (
            ".github/workflows/ci.yml",
            "name: ci\non: push\n".to_owned(),
        ),
        (".factory/project.yaml", MANIFEST.to_owned()),
        (
            "docs/adr/0001-record-decisions.md",
            "# Record architecture decisions\n\nWe keep a record.\n".to_owned(),
        ),
        // The files that must never reach model context.
        (".env", format!("API_TOKEN={}\n", canary_token())),
        ("id_rsa", format!("{}\nabc\n", canary_key())),
        (
            "config/secrets.json",
            format!("{{\"token\": \"{}\"}}\n", canary_token()),
        ),
    ];
    files
        .into_iter()
        .map(|(path, content)| (path.to_owned(), content))
        .collect()
}

/// The path rules of the fixture: secret-bearing files are hidden, and CI, the factory's own
/// directory and the owners file are protected.
pub fn rules() -> PathRules {
    let mode = |group: &str, glob: &str, mode: PathMode| {
        (
            group.to_owned(),
            PathRule::Mode {
                glob: RepoGlob::new(glob).expect("a glob"),
                mode,
            },
        )
    };
    PathRules::new(vec![
        mode("secrets", ".env", PathMode::Hidden),
        mode("secrets", ".env.*", PathMode::Hidden),
        mode("secrets", "**/id_rsa*", PathMode::Hidden),
        mode("secrets", "**/*.pem", PathMode::Hidden),
        mode("secrets", "config/secrets.*", PathMode::Hidden),
        mode("ci_workflows", ".github/**", PathMode::DenyWrite),
        mode("factory", ".factory/**", PathMode::DenyWrite),
        mode("owners", "CODEOWNERS", PathMode::DenyWrite),
    ])
}

/// What the stage asked of the repository, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// A file read: the path and the view.
    Read(String, bool),
    /// A listing: the glob and whether the view was the trusted one.
    List(String, bool),
}

/// Records what is read through it.
#[derive(Default)]
pub struct Reads(Mutex<Vec<Access>>);

impl Reads {
    pub fn all(&self) -> Vec<Access> {
        self.0.lock().expect("lock").clone()
    }

    /// The paths whose content was read.
    pub fn read_paths(&self) -> Vec<String> {
        self.all()
            .into_iter()
            .filter_map(|a| match a {
                Access::Read(path, _) => Some(path),
                Access::List(..) => None,
            })
            .collect()
    }
}

struct RecordingRepo {
    inner: Box<dyn JobRepo>,
    reads: Arc<Reads>,
}

#[async_trait]
impl JobRepo for RecordingRepo {
    async fn read_file_at(
        &self,
        commit: &CommitSha,
        path: &RepoPath,
        max_bytes: u64,
        view: ReadView,
    ) -> Result<Vec<u8>, WorkspaceError> {
        self.reads.0.lock().expect("lock").push(Access::Read(
            path.as_str().to_owned(),
            matches!(view, ReadView::Trusted),
        ));
        self.inner.read_file_at(commit, path, max_bytes, view).await
    }

    async fn list_at(
        &self,
        commit: &CommitSha,
        glob: &RepoGlob,
        limit: usize,
        view: ReadView,
    ) -> Result<Vec<RepoPath>, WorkspaceError> {
        self.reads.0.lock().expect("lock").push(Access::List(
            glob.as_str().to_owned(),
            matches!(view, ReadView::Trusted),
        ));
        self.inner.list_at(commit, glob, limit, view).await
    }

    async fn export_patch(
        &self,
        base: &CommitSha,
        head: &CommitSha,
        max_bytes: u64,
        cancel: &dyn CancelSignal,
    ) -> Result<PatchExport, WorkspaceError> {
        self.inner.export_patch(base, head, max_bytes, cancel).await
    }

    async fn push(
        &self,
        target: &PushTarget,
        commit: &CommitSha,
        cancel: &dyn CancelSignal,
    ) -> Result<(), WorkspaceError> {
        self.inner.push(target, commit, cancel).await
    }
}

/// The fake workspace provider, with every read of the job's repository recorded.
pub struct RecordingWorkspaces {
    inner: FakeWorkspaceProvider,
    pub reads: Arc<Reads>,
}

impl RecordingWorkspaces {
    pub fn new(inner: FakeWorkspaceProvider) -> Self {
        Self {
            inner,
            reads: Arc::new(Reads::default()),
        }
    }
}

#[async_trait]
impl WorkspaceProvider for RecordingWorkspaces {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn fetch(
        &self,
        job: JobId,
        target: &FetchTarget,
        branch: &BranchName,
        cancel: &dyn CancelSignal,
    ) -> Result<FetchedBase, WorkspaceError> {
        self.inner.fetch(job, target, branch, cancel).await
    }

    async fn create(
        &self,
        req: WorkspaceRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn Workspace>, WorkspaceError> {
        self.inner.create(req, cancel).await
    }

    async fn repo(&self, job: JobId) -> Result<Box<dyn JobRepo>, WorkspaceError> {
        Ok(Box::new(RecordingRepo {
            inner: self.inner.repo(job).await?,
            reads: Arc::clone(&self.reads),
        }))
    }

    async fn dispose_job(&self, job: JobId) -> Result<(), WorkspaceError> {
        self.inner.dispose_job(job).await
    }

    async fn sweep_orphans(
        &self,
        live: &[AttemptId],
        live_jobs: &[JobId],
    ) -> Result<Vec<AttemptId>, WorkspaceError> {
        self.inner.sweep_orphans(live, live_jobs).await
    }
}

/// The repository of every job: the fixture, on `main`.
pub struct FixedRepository {
    pub repo: RepoRef,
}

#[async_trait]
impl JobRepository for FixedRepository {
    async fn of(&self, _tenant: TenantId, _job: JobId) -> Result<TargetRepository, SeamError> {
        Ok(TargetRepository {
            repo: self.repo.clone(),
            branch: BranchName::new("main").map_err(|_| SeamError::Unavailable)?,
        })
    }
}

/// The `verify` sandbox spec of the testkit, over the mounts of the workspace.
pub struct TestVerifySpecs;

impl VerifySandboxSpecs for TestVerifySpecs {
    fn verify_spec(
        &self,
        job: JobId,
        attempt: AttemptId,
        mounts: WorkspaceMounts,
    ) -> Result<SandboxSpec, SeamError> {
        let mut spec = sandbox_spec(&Ids::new(), SandboxProfile::Verify);
        spec.job = job;
        spec.attempt = attempt;
        spec.mounts.workspace = mounts;
        Ok(spec)
    }
}

/// Reads the project manifest. The fixture file holds JSON, which is YAML too; the real parser is
/// `DefinitionLoader::project_manifest` of `factory-contracts`.
pub struct JsonManifests;

impl ProjectManifestParser for JsonManifests {
    fn parse(&self, _file: &str, bytes: &[u8]) -> Result<ProjectManifest, ManifestProblem> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| ManifestProblem("not UTF-8".to_owned()))?;
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| ManifestProblem("not JSON".to_owned()))?;
        ProjectManifest::from_json_value(value).map_err(|e| ManifestProblem(e.to_string()))
    }
}

/// What `cargo` does in the fake image.
#[derive(Clone)]
pub struct CargoBehavior(pub CallLog);

/// The commands the fake `cargo` was asked to run, with the exit code it gave.
pub type CallLog = Arc<Mutex<Vec<(Vec<String>, i32)>>>;

impl CargoBehavior {
    /// A cargo that succeeds.
    pub fn working() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    /// The commands it was asked to run, with the exit code it gave.
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.0
            .lock()
            .expect("lock")
            .iter()
            .map(|(a, _)| a.clone())
            .collect()
    }

    pub fn program(
        &self,
        fail_on: Option<&'static str>,
    ) -> impl Fn(&[String], &[u8]) -> ProgramOutput + Send + Sync + 'static {
        let calls = Arc::clone(&self.0);
        move |argv, _| {
            let code = match (fail_on, argv.get(1)) {
                (Some(sub), Some(given)) if sub == given => 101,
                _ => 0,
            };
            calls.lock().expect("lock").push((argv.to_vec(), code));
            ProgramOutput {
                exit_code: Some(code),
                stdout: if code == 0 {
                    b"test result: ok. 1 passed\n".to_vec()
                } else {
                    Vec::new()
                },
                stderr: if code == 0 {
                    Vec::new()
                } else {
                    b"error: the baseline is red\n".to_vec()
                },
            }
        }
    }
}

/// Puts the fixture on the remote's `main` and returns the commit.
pub fn publish(remote: &FakeRemote, repo: &RepoRef, files: &[(String, String)]) -> CommitSha {
    let borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();
    remote.commit_on_branch(repo, &BranchName::new("main").expect("a branch"), &borrowed)
}
