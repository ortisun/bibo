//! The real-git harness for the workspace tests: a local bare repository as the remote, the
//! provider over a scratch root, and the `WorkspaceSubject` the contract suite needs.
#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::redaction::{PatternAction, Redactor};
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{BranchName, CommitSha, PathRules, RepoRef};
use factory_ports::process::{
    EnvValue, ProcessRunner, Program, SpawnError, SpawnOutput, SpawnRequest,
};
use factory_ports::workspace::{Workspace, WorkspaceMounts, WorkspaceProvider};
use factory_sandbox::SystemProcessRunner;
use factory_sandbox::workspace::{GitWorkspaceProvider, RemoteLocation, WorkspaceSettings};
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::clock::{FakeCancel, FakeClock};
use factory_testkit::contracts::workspace::{
    FIXTURE_FILES, TreeEdit, WorkspaceSubject, fixture_rules,
};

use crate::support::Scratch;

/// Real git for the test's own setup (the remote and the seed clone). Not the code under test.
#[derive(Clone)]
pub struct TestGit {
    runner: Arc<dyn ProcessRunner>,
}

impl TestGit {
    pub fn new(runner: Arc<dyn ProcessRunner>) -> Self {
        Self { runner }
    }

    pub async fn run(&self, cwd: &Path, args: &[&str]) -> String {
        let plain = |k: &str, v: &str| (k.to_owned(), EnvValue::Plain(v.to_owned()));
        let mut full = vec![
            "-c".to_owned(),
            "protocol.file.allow=always".to_owned(),
            "-c".to_owned(),
            "init.defaultBranch=main".to_owned(),
        ];
        full.extend(args.iter().map(|a| (*a).to_owned()));
        let out = self
            .runner
            .run(
                SpawnRequest {
                    program: Program::Git,
                    args: full,
                    cwd: Some(cwd.to_path_buf()),
                    env: vec![
                        plain("GIT_CONFIG_NOSYSTEM", "1"),
                        plain("GIT_CONFIG_GLOBAL", "/dev/null"),
                        plain("GIT_TERMINAL_PROMPT", "0"),
                        plain("GIT_AUTHOR_NAME", "Seed"),
                        plain("GIT_AUTHOR_EMAIL", "seed@example.invalid"),
                        plain("GIT_COMMITTER_NAME", "Seed"),
                        plain("GIT_COMMITTER_EMAIL", "seed@example.invalid"),
                    ],
                    stdin: None,
                    timeout: std::time::Duration::from_secs(60),
                    max_output_bytes: 8 * 1024 * 1024,
                },
                &FakeCancel::new(),
            )
            .await
            .expect("git started");
        assert_eq!(
            out.exit_code,
            Some(0),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

/// Writes `files` into `dir`, creating parents.
pub fn write_files(dir: &Path, files: &[(&str, &str)]) {
    for (path, text) in files {
        let target = dir.join(path);
        fs::create_dir_all(target.parent().expect("a parent")).expect("parents");
        fs::write(target, text).expect("a file");
    }
}

/// A remote repository on disk and a clone to add commits with.
pub struct Remote {
    pub base: PathBuf,
    pub bare: PathBuf,
    pub seed: PathBuf,
    pub repo: RepoRef,
    git: TestGit,
}

impl Remote {
    pub async fn create(parent: &Path, git: TestGit, files: &[(&str, &str)]) -> Self {
        let repo = RepoRef::parse("example-org/fixture").expect("a repository");
        let base = parent.join("remotes");
        let bare = base.join("example-org").join("fixture.git");
        fs::create_dir_all(&bare).expect("remote dir");
        git.run(&bare, &["init", "--bare", "--quiet"]).await;
        let seed = parent.join("seed");
        fs::create_dir_all(&seed).expect("seed dir");
        git.run(&seed, &["init", "--quiet"]).await;
        write_files(&seed, files);
        git.run(&seed, &["add", "-A"]).await;
        git.run(&seed, &["commit", "--quiet", "-m", "seed"]).await;
        let url = format!("file://{}", bare.display());
        git.run(&seed, &["push", "--quiet", &url, "main:refs/heads/main"])
            .await;
        Self {
            base,
            bare,
            seed,
            repo,
            git,
        }
    }

    pub fn url(&self) -> String {
        format!("file://{}", self.bare.display())
    }

    /// Adds a commit on top of `main` and returns its id.
    pub async fn advance(&self, files: &[(&str, &str)]) -> CommitSha {
        write_files(&self.seed, files);
        self.git.run(&self.seed, &["add", "-A"]).await;
        self.git
            .run(&self.seed, &["commit", "--quiet", "-m", "advance"])
            .await;
        self.git
            .run(
                &self.seed,
                &["push", "--quiet", &self.url(), "main:refs/heads/main"],
            )
            .await;
        let sha = self.git.run(&self.seed, &["rev-parse", "HEAD"]).await;
        CommitSha::parse(sha.trim()).expect("a commit id")
    }

    /// Points the remote branch `name` at the tip of `main`.
    pub async fn push_branch(&self, name: &str) {
        let spec = format!("main:refs/heads/{name}");
        self.git
            .run(&self.seed, &["push", "--quiet", &self.url(), &spec])
            .await;
    }

    pub async fn branch_tip(&self, branch: &str) -> Option<CommitSha> {
        let name = format!("refs/heads/{branch}");
        let out = self
            .git
            .runner
            .run(
                SpawnRequest {
                    program: Program::Git,
                    args: vec![
                        "--git-dir".to_owned(),
                        self.bare.display().to_string(),
                        "rev-parse".to_owned(),
                        "--verify".to_owned(),
                        "--quiet".to_owned(),
                        name,
                    ],
                    cwd: Some(self.base.clone()),
                    env: Vec::new(),
                    stdin: None,
                    timeout: std::time::Duration::from_secs(30),
                    max_output_bytes: 4096,
                },
                &FakeCancel::new(),
            )
            .await
            .expect("git started");
        if out.exit_code != Some(0) {
            return None;
        }
        CommitSha::parse(String::from_utf8_lossy(&out.stdout).trim()).ok()
    }
}

/// A runner that can advance the remote right after the next `fetch` finishes, so that the
/// branch moves while the adapter is still checking it.
pub struct MovingRunner {
    inner: Arc<dyn ProcessRunner>,
    armed: Mutex<Option<Advance>>,
}

/// A commit to add to the remote: where and which files.
type Advance = (Arc<Remote>, Vec<(String, String)>);

impl MovingRunner {
    pub fn new(inner: Arc<dyn ProcessRunner>) -> Self {
        Self {
            inner,
            armed: Mutex::new(None),
        }
    }

    pub fn arm(&self, remote: Arc<Remote>, files: Vec<(String, String)>) {
        *self.armed.lock().expect("lock") = Some((remote, files));
    }
}

#[async_trait]
impl ProcessRunner for MovingRunner {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn run(
        &self,
        req: SpawnRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<SpawnOutput, SpawnError> {
        let is_fetch = req.args.iter().any(|a| a == "fetch");
        let result = self.inner.run(req, cancel).await;
        if is_fetch {
            let armed = self.armed.lock().expect("lock").take();
            if let Some((remote, files)) = armed {
                let pairs: Vec<(&str, &str)> = files
                    .iter()
                    .map(|(a, b)| (a.as_str(), b.as_str()))
                    .collect();
                remote.advance(&pairs).await;
            }
        }
        result
    }
}

pub fn redactor() -> Arc<Redactor> {
    Arc::new(
        Redactor::builder()
            .pattern("github-token", "ghs_[A-Za-z0-9]{36}", PatternAction::Block)
            .build()
            .expect("a redactor"),
    )
}

/// The settings the tests share. Limits are the policy's, except where a test lowers one.
pub fn settings(root: &Path, remote: &Remote) -> WorkspaceSettings {
    WorkspaceSettings::new(
        root.to_path_buf(),
        RemoteLocation::Directory {
            base: remote.base.clone(),
        },
    )
}

pub fn provider_over(
    settings: WorkspaceSettings,
    runner: Arc<dyn ProcessRunner>,
    artifacts: Arc<InMemoryArtifactStore>,
    rules: PathRules,
) -> GitWorkspaceProvider {
    GitWorkspaceProvider::new(
        settings,
        runner,
        artifacts,
        redactor(),
        Arc::new(FakeClock::new()),
        rules,
    )
}

/// A directory on a case-sensitive file system. A check that writes `.GitHub` next to `.github`
/// means something only there. Linux hosts are case-sensitive already. On macOS the default file
/// system is not, so a disk image formatted as case-sensitive APFS is attached for the run and
/// detached when the value is dropped. When neither works the caller gets BLOCKED, not a pass.
pub struct CaseSensitiveVolume {
    dir: PathBuf,
    mount: Option<PathBuf>,
    _scratch: Scratch,
}

fn is_case_sensitive(dir: &Path) -> bool {
    let probe = dir.join("CaseProbe");
    fs::write(&probe, b"x").expect("a probe file");
    let sensitive = !dir.join("caseprobe").exists();
    let _ = fs::remove_file(probe);
    sensitive
}

#[allow(
    clippy::disallowed_methods,
    reason = "a test helper that attaches and detaches a case-sensitive disk image; not product code"
)]
fn hdiutil(args: &[&str]) -> bool {
    std::process::Command::new("hdiutil")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

impl CaseSensitiveVolume {
    pub fn mount() -> Self {
        let scratch = Scratch::new("cs-volume");
        if is_case_sensitive(scratch.path()) {
            return Self {
                dir: scratch.path().to_path_buf(),
                mount: None,
                _scratch: scratch,
            };
        }
        let image = scratch.path().join("volume");
        let mount = scratch.path().join("mnt");
        fs::create_dir(&mount).expect("a mount point");
        let image_text = image.display().to_string();
        let sparse = format!("{image_text}.sparseimage");
        let mount_text = mount.display().to_string();
        let made = hdiutil(&[
            "create",
            "-size",
            "256m",
            "-fs",
            "Case-sensitive APFS",
            "-volname",
            "wscs",
            "-type",
            "SPARSE",
            &image_text,
        ]) && hdiutil(&["attach", &sparse, "-mountpoint", &mount_text, "-nobrowse"]);
        if !made || !is_case_sensitive(&mount) {
            panic!(
                "BLOCKED: this host file system is not case-sensitive and a case-sensitive disk image could not be attached"
            );
        }
        Self {
            dir: mount.clone(),
            mount: Some(mount),
            _scratch: scratch,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Drop for CaseSensitiveVolume {
    fn drop(&mut self) {
        if let Some(mount) = &self.mount {
            let _ = hdiutil(&["detach", "-force", &mount.display().to_string()]);
        }
    }
}

static SUBJECTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The subject of the workspace contract suite over real git.
pub struct GitSubject {
    _scratch: Option<Scratch>,
    root: PathBuf,
    remote: Arc<Remote>,
    runner: Arc<MovingRunner>,
    artifacts: Arc<InMemoryArtifactStore>,
    provider: GitWorkspaceProvider,
    branch: BranchName,
}

impl GitSubject {
    /// A subject in a fresh directory of the normal scratch area.
    pub async fn new() -> Self {
        let scratch = Scratch::new("ws-contract");
        let base = scratch.path().to_path_buf();
        Self::build(Some(scratch), base).await
    }

    /// A subject in a fresh directory below `parent`, for a case-sensitive volume.
    pub async fn new_in(parent: &Path) -> Self {
        let n = SUBJECTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let base = parent.join(format!("subject-{}-{n}", std::process::id()));
        fs::create_dir_all(&base).expect("a subject directory");
        Self::build(None, base).await
    }

    async fn build(scratch: Option<Scratch>, base: PathBuf) -> Self {
        let root = base.join("root");
        fs::create_dir_all(&root).expect("root");
        let system: Arc<dyn ProcessRunner> = Arc::new(SystemProcessRunner::new());
        let git = TestGit::new(Arc::clone(&system));
        let remote = Arc::new(Remote::create(&base, git, &FIXTURE_FILES).await);
        let runner = Arc::new(MovingRunner::new(system));
        let artifacts = Arc::new(InMemoryArtifactStore::new());
        let provider = provider_over(
            settings(&root, &remote),
            Arc::clone(&runner) as Arc<dyn ProcessRunner>,
            Arc::clone(&artifacts),
            fixture_rules(),
        );
        Self {
            _scratch: scratch,
            root,
            remote,
            runner,
            artifacts,
            provider,
            branch: BranchName::new("main").expect("a branch"),
        }
    }
}

#[async_trait]
impl WorkspaceSubject for GitSubject {
    fn provider(&self) -> &dyn WorkspaceProvider {
        &self.provider
    }

    fn repo(&self) -> RepoRef {
        self.remote.repo.clone()
    }

    fn branch(&self) -> BranchName {
        self.branch.clone()
    }

    async fn edit_sandbox_tree(
        &self,
        workspace: &dyn Workspace,
        edit: TreeEdit,
    ) -> Result<(), String> {
        let dir = workspace.mounts().workspace;
        edit_tree(&dir, edit)
    }

    async fn pushed_commit(&self, _repo: &RepoRef, branch: &BranchName) -> Option<CommitSha> {
        self.remote.branch_tip(branch.as_str()).await
    }

    async fn directories_exist(&self, mounts: &WorkspaceMounts) -> bool {
        mounts.workspace.exists() || mounts.out.exists()
    }

    async fn restart(&self) -> Box<dyn WorkspaceProvider> {
        Box::new(provider_over(
            settings(&self.root, &self.remote),
            Arc::new(SystemProcessRunner::new()),
            Arc::clone(&self.artifacts),
            fixture_rules(),
        ))
    }

    async fn advance_remote_branch(&self, files: &[(&str, &str)]) -> CommitSha {
        self.remote.advance(files).await
    }

    async fn move_remote_branch_during_next_fetch(&self, files: &[(&str, &str)]) -> bool {
        self.runner.arm(
            Arc::clone(&self.remote),
            files
                .iter()
                .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
                .collect(),
        );
        true
    }
}

/// Changes a checkout directory as the sandbox would.
pub fn edit_tree(dir: &Path, edit: TreeEdit) -> Result<(), String> {
    let io = |e: std::io::Error| e.to_string();
    match edit {
        TreeEdit::Write(path, bytes) => {
            let target = dir.join(path.as_str());
            fs::create_dir_all(target.parent().ok_or("no parent")?).map_err(io)?;
            if target.exists() {
                fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).map_err(io)?;
            }
            fs::write(target, bytes).map_err(io)
        }
        TreeEdit::Delete(path) => match fs::remove_file(dir.join(path.as_str())) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        },
        TreeEdit::Symlink { path, target } => {
            let at = dir.join(path.as_str());
            fs::create_dir_all(at.parent().ok_or("no parent")?).map_err(io)?;
            let _ = fs::remove_file(&at);
            symlink(target, at).map_err(io)
        }
        TreeEdit::Gitlink(path) => {
            let at = dir.join(path.as_str());
            fs::create_dir_all(&at).map_err(io)?;
            fs::write(at.join(".git"), b"gitdir: ../.git/modules/x\n").map_err(io)
        }
        TreeEdit::NestedGit(path) => {
            let at = dir.join(path.as_str()).join(".git");
            fs::create_dir_all(&at).map_err(io)?;
            fs::write(
                at.join("config"),
                b"[core]\n\trepositoryformatversion = 0\n",
            )
            .map_err(io)
        }
    }
}
