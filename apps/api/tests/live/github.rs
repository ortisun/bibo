//! A labelled FAKE GitHub server over a real bare git repository.
//!
//! **Fidelity: fake.** The server is FX-GH of the test kit (the REST subset the factory uses, App
//! JWTs, installation tokens narrowed per repository and permission, issues, pull requests), with a
//! small front for the routes FX-GH does not have (the rules of the default branch, check runs).
//! The real GitHub adapter talks to it over loopback HTTP.
//!
//! What makes it more than FX-GH: the commits are real. The workspace of the worker clones from and
//! pushes to a bare repository in a local directory (`sandbox.remote.directory`), so the worker's
//! git, not this server, decides what a commit id is. FX-GH invents its own identifiers, so the
//! front keeps the two apart: before it answers a request it looks at the branches of the bare
//! repository, gives each new tip a FX-GH commit, and then says the real id in every answer and
//! the FX-GH id to FX-GH. The adapter, the engine and the stages only ever see real commit ids.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, PoisonError};

use factory_testkit::fx::github::{FakeGithub, User};
use factory_testkit::fx::http::{HttpRequest, HttpResponse, HttpServer};
use serde_json::{Value, json};

/// A check run, as the front keeps it.
#[derive(Debug, Clone)]
pub struct CheckRun {
    pub id: u64,
    pub name: String,
    pub head_sha: String,
    pub status: String,
    pub conclusion: Option<String>,
    pub app_id: u64,
}

#[derive(Default)]
struct Front {
    /// FX-GH commit id and the real one it stands for, oldest first.
    shas: Vec<(String, String)>,
    checks: Vec<CheckRun>,
    rules: Option<Value>,
}

/// The running fake.
pub struct GitHub {
    pub fake: FakeGithub,
    server: HttpServer,
    front: Arc<Mutex<Front>>,
    pub bare: PathBuf,
}

fn lock(front: &Mutex<Front>) -> std::sync::MutexGuard<'_, Front> {
    front.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs `git` in `dir` and returns its standard output. The environment is the test's own; the
/// repositories are scratch repositories of this run.
pub fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Live Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Live Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Makes the bare repository `<base>/<owner>/<name>.git` with a `main` branch holding `files`, and
/// returns its path and the commit `main` points at.
pub fn make_remote(base: &Path, repo: &str, files: &[(String, String)]) -> (PathBuf, String) {
    let bare = base.join(format!("{repo}.git"));
    std::fs::create_dir_all(&bare).expect("the remote directory");
    git(&bare, &["init", "--bare", "--initial-branch=main", "."]);
    let work = base.join(format!("{}-seed", repo.replace('/', "-")));
    std::fs::create_dir_all(&work).expect("the seed directory");
    git(&work, &["init", "--initial-branch=main", "."]);
    for (path, text) in files {
        let target = work.join(path);
        std::fs::create_dir_all(target.parent().expect("a parent")).expect("directories");
        std::fs::write(target, text).expect("a file");
    }
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "The fixture repository"]);
    git(
        &work,
        &["push", "-q", bare.to_str().expect("a path"), "main"],
    );
    let main = git(&bare, &["rev-parse", "refs/heads/main"]);
    let _ = std::fs::remove_dir_all(work);
    (bare, main)
}

impl GitHub {
    /// Starts the fake. `repo` is `owner/name`; `bare` is its bare repository; `people` are the
    /// accounts the issue source will meet (`login`, numeric id). The clock is the real one, so
    /// that the JWTs of the adapter and the tokens of the fake agree.
    pub fn start(
        repo: &str,
        installation: u64,
        bare: PathBuf,
        people: &[(&str, u64)],
        clock: Arc<dyn factory_ports::clock::Clock>,
    ) -> Self {
        let fake = FakeGithub::with_clock(clock);
        fake.add_repo(repo, "main");
        let owner = repo.split('/').next().expect("owner/name");
        fake.add_installation(installation, owner, &[repo]);
        for (login, id) in people {
            fake.add_user(User::person(login, *id, "write", "MEMBER"));
        }
        let front = Arc::new(Mutex::new(Front::default()));
        let app = fake.app().id;
        lock(&front).rules = Some(strong_rules(app));
        let server = {
            let fake = fake.clone();
            let front = Arc::clone(&front);
            let bare = bare.clone();
            let repo = repo.to_owned();
            HttpServer::start("live-fake-github", move |request| {
                handle(&fake, &front, &bare, &repo, request)
            })
            .expect("the fake GitHub starts")
        };
        Self {
            fake,
            server,
            front,
            bare,
        }
    }

    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// The check runs the adapter published, as the front keeps them.
    pub fn checks(&self) -> Vec<CheckRun> {
        lock(&self.front).checks.clone()
    }

    /// The real commit a branch of the bare repository points at, if it exists.
    pub fn tip(&self, branch: &str) -> Option<String> {
        let found = Command::new("git")
            .current_dir(&self.bare)
            .args([
                "rev-parse",
                "--verify",
                "-q",
                &format!("refs/heads/{branch}"),
            ])
            .output()
            .ok()?;
        found
            .status
            .success()
            .then(|| String::from_utf8_lossy(&found.stdout).trim().to_owned())
    }

    /// Replaces the rules the fake reports for the default branch. A deliberate break only.
    pub fn set_rules(&self, rules: Value) {
        lock(&self.front).rules = Some(rules);
    }
}

/// Rules that satisfy `policies/security.yaml`: a pull request with a review of the code owners,
/// stale approvals dismissed, the two checks of the factory pinned to the App, no force push and
/// no deletion.
pub fn strong_rules(app_id: u64) -> Value {
    json!([
        {"type": "pull_request", "parameters": {
            "dismiss_stale_reviews_on_push": true, "require_code_owner_review": true,
            "require_last_push_approval": false, "required_approving_review_count": 1,
            "required_review_thread_resolution": false},
         "ruleset_source_type": "Repository", "ruleset_source": "live/fixture", "ruleset_id": 101},
        {"type": "required_status_checks", "parameters": {
            "strict_required_status_checks_policy": false,
            "required_status_checks": [
                {"context": "factory-validation", "integration_id": app_id},
                {"context": "factory-review", "integration_id": app_id}]},
         "ruleset_source_type": "Repository", "ruleset_source": "live/fixture", "ruleset_id": 101},
        {"type": "non_fast_forward", "ruleset_source_type": "Repository",
         "ruleset_source": "live/fixture", "ruleset_id": 101},
        {"type": "deletion", "ruleset_source_type": "Repository",
         "ruleset_source": "live/fixture", "ruleset_id": 101}
    ])
}

// ---- the front ---------------------------------------------------------------------------------

/// Gives every branch tip of the bare repository a FX-GH commit, and remembers which.
fn sync(fake: &FakeGithub, front: &Mutex<Front>, bare: &Path, repo: &str) {
    let Ok(listing) = Command::new("git")
        .current_dir(bare)
        .args([
            "for-each-ref",
            "--format=%(refname:short) %(objectname)",
            "refs/heads",
        ])
        .output()
    else {
        return;
    };
    for line in String::from_utf8_lossy(&listing.stdout).lines() {
        let Some((branch, real)) = line.split_once(' ') else {
            continue;
        };
        let mut guard = lock(front);
        let known = fake
            .branch_sha(repo, branch)
            .is_some_and(|fx| guard.shas.iter().any(|(f, r)| *f == fx && r == real));
        if !known {
            let fx = fake.push_commit(repo, branch);
            guard.shas.push((fx, real.to_owned()));
        }
    }
}

fn to_fake(front: &Mutex<Front>, text: &str) -> String {
    let guard = lock(front);
    let mut out = text.to_owned();
    for (fx, real) in &guard.shas {
        out = out.replace(real.as_str(), fx);
    }
    out
}

fn to_real(front: &Mutex<Front>, text: &str) -> String {
    let guard = lock(front);
    let mut out = text.to_owned();
    for (fx, real) in &guard.shas {
        out = out.replace(fx.as_str(), real);
    }
    out
}

fn handle(
    fake: &FakeGithub,
    front: &Mutex<Front>,
    bare: &Path,
    repo: &str,
    request: &HttpRequest,
) -> HttpResponse {
    sync(fake, front, bare, repo);
    let segments: Vec<&str> = request.path().trim_matches('/').split('/').collect();
    let method = request.method.as_str();
    // The routes FX-GH does not have. Each is answered after FX-GH has judged the credential, by
    // asking it for the repository with the same Authorization header.
    let probed = |owner: &str, name: &str| -> Option<HttpResponse> {
        let probe = HttpRequest {
            method: "GET".to_owned(),
            target: format!("/repos/{owner}/{name}"),
            version: "HTTP/1.1".to_owned(),
            headers: request
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("authorization"))
                .cloned()
                .collect(),
            body: Vec::new(),
            peer: request.peer,
        };
        let response = fake.handle(&probe);
        (response.status != 200).then_some(response)
    };
    match (method, segments.as_slice()) {
        ("GET", ["repos", owner, name, "rules", "branches", _]) => {
            if let Some(refused) = probed(owner, name) {
                return refused;
            }
            let rules = lock(front).rules.clone().unwrap_or_else(|| json!([]));
            HttpResponse::json(200, &rules)
        }
        ("POST", ["repos", owner, name, "check-runs"]) => {
            if let Some(refused) = probed(owner, name) {
                return refused;
            }
            let sent: Value = request.json().unwrap_or(Value::Null);
            let app = fake.app().id;
            let mut guard = lock(front);
            let id = 9_000 + guard.checks.len() as u64;
            let run = CheckRun {
                id,
                name: sent["name"].as_str().unwrap_or_default().to_owned(),
                head_sha: sent["head_sha"].as_str().unwrap_or_default().to_owned(),
                status: sent["status"].as_str().unwrap_or("queued").to_owned(),
                conclusion: sent["conclusion"].as_str().map(str::to_owned),
                app_id: app,
            };
            guard.checks.push(run.clone());
            HttpResponse::json(201, &check_json(&run))
        }
        ("PATCH", ["repos", owner, name, "check-runs", id]) => {
            if let Some(refused) = probed(owner, name) {
                return refused;
            }
            let sent: Value = request.json().unwrap_or(Value::Null);
            let mut guard = lock(front);
            let Some(run) = guard.checks.iter_mut().find(|c| c.id.to_string() == *id) else {
                return HttpResponse::json(404, &json!({"message": "Not Found"}));
            };
            if let Some(status) = sent["status"].as_str() {
                status.clone_into(&mut run.status);
            }
            run.conclusion = sent["conclusion"].as_str().map(str::to_owned);
            HttpResponse::json(200, &check_json(run))
        }
        ("GET", ["repos", owner, name, "commits", sha, "check-runs"]) => {
            if let Some(refused) = probed(owner, name) {
                return refused;
            }
            let wanted = request.query_param("check_name");
            let runs: Vec<Value> = lock(front)
                .checks
                .iter()
                .filter(|c| c.head_sha == *sha)
                .filter(|c| wanted.as_ref().is_none_or(|n| &c.name == n))
                .map(check_json)
                .collect();
            HttpResponse::json(200, &json!({"total_count": runs.len(), "check_runs": runs}))
        }
        _ => {
            // Real commit ids in, FX-GH ids to FX-GH, real ids back out.
            let mut forwarded = HttpRequest {
                method: request.method.clone(),
                target: to_fake(front, &request.target),
                version: request.version.clone(),
                headers: request.headers.clone(),
                body: to_fake(front, &String::from_utf8_lossy(&request.body)).into_bytes(),
                peer: request.peer,
            };
            // A body that changed length would make a content-length header lie.
            forwarded
                .headers
                .retain(|(name, _)| !name.eq_ignore_ascii_case("content-length"));
            let mut response = fake.handle(&forwarded);
            let rewritten = to_real(front, &String::from_utf8_lossy(&response.body));
            response.body = rewritten.into_bytes();
            response
        }
    }
}

fn check_json(run: &CheckRun) -> Value {
    json!({"id": run.id, "name": run.name, "head_sha": run.head_sha, "external_id": "",
        "status": run.status, "conclusion": run.conclusion, "app": {"id": run.app_id}})
}
