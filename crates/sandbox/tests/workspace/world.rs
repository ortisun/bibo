//! A world for the adapter-only tests: a scratch root, a remote repository and a provider over
//! them, with the knobs a test turns (the process runner, the limits, the rules).
#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use factory_ports::paths::{BranchName, CommitSha, PathRules};
use factory_ports::process::ProcessRunner;
use factory_ports::workspace::{
    CommitRequest, FetchCredential, FetchTarget, PushCredential, PushTarget, WorkspaceProvider,
    WorkspacePurpose, WorkspaceRequest,
};
use factory_sandbox::SystemProcessRunner;
use factory_sandbox::workspace::{
    AuditLimits, GitWorkspace, GitWorkspaceProvider, PathPolicyLayer,
};
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::clock::FakeCancel;
use factory_testkit::contracts::workspace::{FIXTURE_FILES, fixture_rules};

use crate::harness::{Remote, TestGit, provider_over, settings};
use crate::support::{self, Scratch};

/// What a test can change about its world.
pub struct Options {
    pub runner: Option<Arc<dyn ProcessRunner>>,
    pub limits: AuditLimits,
    pub rules: PathRules,
    pub files: Vec<(String, String)>,
    pub layer: Option<PathPolicyLayer>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            runner: None,
            limits: AuditLimits::default(),
            rules: fixture_rules(),
            files: FIXTURE_FILES
                .iter()
                .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
                .collect(),
            layer: None,
        }
    }
}

/// A scratch root, a remote repository and a provider over them.
pub struct World {
    pub scratch: Scratch,
    pub root: PathBuf,
    pub remote: Arc<Remote>,
    pub provider: GitWorkspaceProvider,
    pub artifacts: Arc<InMemoryArtifactStore>,
    pub rules: PathRules,
}

impl World {
    pub async fn new() -> Self {
        Self::with(Options::default()).await
    }

    pub async fn with(options: Options) -> Self {
        let scratch = Scratch::new("ws-world");
        let root = scratch.path().join("root");
        fs::create_dir_all(&root).expect("root");
        let system: Arc<dyn ProcessRunner> = Arc::new(SystemProcessRunner::new());
        let files: Vec<(&str, &str)> = options
            .files
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let remote = Arc::new(
            Remote::create(scratch.path(), TestGit::new(Arc::clone(&system)), &files).await,
        );
        let artifacts = Arc::new(InMemoryArtifactStore::new());
        let mut settings = settings(&root, &remote);
        settings.limits = options.limits;
        let runner = options.runner.unwrap_or(system);
        let mut provider = provider_over(
            settings,
            runner,
            Arc::clone(&artifacts),
            options.rules.clone(),
        );
        if let Some(layer) = options.layer {
            provider = provider.with_path_policy(layer);
        }
        Self {
            scratch,
            root,
            remote,
            provider,
            artifacts,
            rules: options.rules,
        }
    }

    pub fn fetch_target(&self) -> FetchTarget {
        FetchTarget {
            repo: self.remote.repo.clone(),
            // Built at run time so that no credential-shaped literal sits in the source.
            credential: FetchCredential::new(format!("{}-{}", "read", "credential")),
        }
    }

    pub fn push_target(&self, branch: &str) -> PushTarget {
        PushTarget {
            repo: self.remote.repo.clone(),
            branch: BranchName::new(branch).expect("a branch"),
            credential: PushCredential::new(format!("{}-{}", "write", "credential")),
        }
    }

    pub async fn fetch(&self, n: u128) -> CommitSha {
        self.provider
            .fetch(
                support::job(n),
                &self.fetch_target(),
                &BranchName::new("main").expect("a branch"),
                &FakeCancel::new(),
            )
            .await
            .expect("fetch")
            .commit
    }

    /// Fetches for job `n` and opens an agent workspace for attempt `n` at the tip.
    pub async fn open(&self, n: u128) -> (GitWorkspace, CommitSha) {
        let base = self.fetch(n).await;
        let workspace = self.open_at(n, n, &base, WorkspacePurpose::Agent).await;
        (workspace, base)
    }

    pub async fn open_at(
        &self,
        job: u128,
        attempt: u128,
        base: &CommitSha,
        purpose: WorkspacePurpose,
    ) -> GitWorkspace {
        self.try_open_at(job, attempt, base, purpose)
            .await
            .expect("create")
    }

    pub async fn try_open_at(
        &self,
        job: u128,
        attempt: u128,
        base: &CommitSha,
        purpose: WorkspacePurpose,
    ) -> Result<GitWorkspace, factory_ports::workspace::WorkspaceError> {
        self.provider
            .create_workspace(
                WorkspaceRequest {
                    job: support::job(job),
                    attempt: support::attempt(attempt),
                    base: base.clone(),
                    rules: self.rules.clone(),
                    purpose,
                },
                &FakeCancel::new(),
            )
            .await
    }
}

pub fn commit_request(message: &str) -> CommitRequest {
    CommitRequest {
        message: message.to_owned(),
        author_name: "Factory".to_owned(),
        author_email: "factory@example.invalid".to_owned(),
    }
}

/// The real git, for the spawn recorder to hand over to.
pub fn real_git() -> PathBuf {
    [
        "/usr/bin/git",
        "/usr/local/bin/git",
        "/opt/homebrew/bin/git",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
    .expect("a git executable")
}
