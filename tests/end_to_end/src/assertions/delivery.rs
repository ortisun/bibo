//! Assertions about what reached GitHub and who decided: A3, A9 and A10.

use crate::check::{Env, Verdict};
use crate::evidence::RunEvidence;

use super::support::{
    is_documentation_path, job_reached, mentions_issue, passed_at, text_at, the_passed_run,
};

/// A3: the pull request exists on GitHub, is a draft, links the issue, and its head branch holds
/// the code and the documentation commits.
#[must_use]
pub fn a3(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "A3";
    let github = &ev.github;
    let [pr] = github.pull_requests.as_slice() else {
        return Verdict::fail(
            ID,
            format!(
                "GitHub holds {} pull requests from the job, and it must hold exactly one",
                github.pull_requests.len()
            ),
        );
    };
    if !pr.draft {
        return Verdict::fail(ID, format!("pull request #{} is not a draft", pr.number));
    }
    if pr.state != "open" {
        return Verdict::fail(
            ID,
            format!("pull request #{} is {}, not open", pr.number, pr.state),
        );
    }
    if !mentions_issue(&pr.body, ev.job.issue_number) {
        return Verdict::fail(
            ID,
            format!(
                "the body of pull request #{} does not link issue #{}",
                pr.number, ev.job.issue_number
            ),
        );
    }
    let Some(tip) = github.head_commits.last() else {
        return Verdict::fail(ID, "the head branch has no commit since the base");
    };
    if tip.sha != pr.head_sha {
        return Verdict::fail(
            ID,
            format!(
                "the branch tip {} is not the head {} of the pull request",
                tip.sha, pr.head_sha
            ),
        );
    }
    let touches_code = |paths: &[String]| {
        paths
            .iter()
            .any(|path| path.starts_with("src/") || path.starts_with("tests/"))
    };
    let last_code = github
        .head_commits
        .iter()
        .rposition(|commit| touches_code(&commit.paths));
    let Some(last_code) = last_code else {
        return Verdict::fail(
            ID,
            "no commit on the head branch changes code (src/ or tests/)",
        );
    };
    let documentation_after_code = github.head_commits[last_code + 1..].iter().any(|commit| {
        !commit.paths.is_empty() && commit.paths.iter().all(|path| is_documentation_path(path))
    });
    if !documentation_after_code {
        return Verdict::fail(
            ID,
            "no commit that changes only documentation follows the last code commit on the head branch",
        );
    }
    Verdict::pass(
        ID,
        format!(
            "pull request #{} is an open draft that links issue #{}, and its head branch has {} commits: code, then documentation",
            pr.number,
            ev.job.issue_number,
            github.head_commits.len()
        ),
    )
}

/// A9: the job waited in `WAITING_FOR_HUMAN` until an authorized approval, then completed. The pull
/// request was not merged and the base branch is unchanged.
#[must_use]
pub fn a9(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "A9";
    let Some(approval) = the_passed_run(ev, "APPROVAL") else {
        return Verdict::fail(ID, "APPROVAL has no single PASSED run");
    };
    let waited = ev
        .timeline
        .iter()
        .filter(|entry| {
            entry.subject == "stage_run"
                && entry.subject_id == approval.id
                && entry.to == "WAITING_FOR_HUMAN"
        })
        .map(|entry| entry.seq)
        .min();
    let Some(waited) = waited else {
        return Verdict::fail(ID, "the APPROVAL run never waited for a person");
    };
    let Some(approved) = passed_at(ev, approval) else {
        return Verdict::fail(ID, "the timeline never shows APPROVAL passing");
    };
    if approved <= waited {
        return Verdict::fail(
            ID,
            format!(
                "APPROVAL passed at position {approved}, not after it began waiting at {waited}"
            ),
        );
    }
    let job_waited = ev.timeline.iter().any(|entry| {
        entry.subject == "job"
            && entry.to == "WAITING_FOR_HUMAN"
            && entry.seq >= waited
            && entry.seq < approved
    });
    if !job_waited {
        return Verdict::fail(
            ID,
            "the job itself was never WAITING_FOR_HUMAN while APPROVAL waited",
        );
    }
    match job_reached(ev, "COMPLETED") {
        Some(done) if done > approved => {}
        Some(done) => {
            return Verdict::fail(
                ID,
                format!(
                    "the job completed at position {done}, not after the approval at {approved}"
                ),
            );
        }
        None => return Verdict::fail(ID, "the timeline never shows the job completing"),
    }
    let approvals: Vec<_> = ev
        .audit
        .iter()
        .filter(|record| record.action == "approval_granted_or_rejected.granted")
        .collect();
    // A job has two gates a person decides: the specification draft and the pull request. Each
    // leaves a granted record. Every one of them must be a person other than the requester, and
    // the last one is the approval of the pull request, whose judgment the ledger must hold under
    // the APPROVAL run.
    for record in &approvals {
        if record.actor == ev.job.requester {
            return Verdict::fail(ID, "the requester approved their own request");
        }
        if !record.actor.starts_with("human:") {
            return Verdict::fail(
                ID,
                format!(
                    "the approval was recorded for {}, which is not a person",
                    record.actor
                ),
            );
        }
    }
    let Some(record) = approvals.last().copied() else {
        return Verdict::fail(
            ID,
            "the audit stream holds 0 approval records, and it must hold one for the pull request",
        );
    };
    let approver_id = record.actor.trim_start_matches("human:");
    // The audit record names who. The ledger holds the judgment and the role that allowed it.
    let judged = ev.ledger.iter().any(|entry| {
        text_at(entry, "/metadata/stage_run_id") == Some(approval.id.as_str())
            && text_at(entry, "/claim/kind") == Some("expert_judgment")
            && entry
                .pointer("/evidence")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|items| {
                    items.iter().any(|item| {
                        text_at(item, "/attestor/role") == Some("approver")
                            && text_at(item, "/attestor/principal_id") == Some(approver_id)
                    })
                })
    });
    if !judged {
        return Verdict::fail(
            ID,
            format!(
                "the ledger does not hold the approver's judgment by {approver_id} with the approver role"
            ),
        );
    }
    let [pr] = ev.github.pull_requests.as_slice() else {
        return Verdict::fail(ID, "there is no single pull request to check");
    };
    if pr.merged {
        return Verdict::fail(ID, format!("pull request #{} was merged", pr.number));
    }
    if ev.github.base_sha_before != ev.github.base_sha_after {
        return Verdict::fail(
            ID,
            format!(
                "the base branch moved from {} to {}",
                ev.github.base_sha_before, ev.github.base_sha_after
            ),
        );
    }
    Verdict::pass(
        ID,
        format!(
            "APPROVAL waited from position {waited}, {} approved at {approved}, the job then completed, pull request #{} is not merged and the base branch did not move",
            record.actor, pr.number
        ),
    )
}

/// The permissions the policy forbids the factory's App to hold
/// (`policies/security.yaml`, `credentials.github_app.permissions_forbidden`). `administration`
/// left this list on 2026-11-12: the owner allowed `administration: read` for the classic
/// protection read of the preflight, and [`a10`] refuses any other level of it.
pub const FORBIDDEN_PERMISSIONS: [&str; 9] = [
    "workflows",
    "secrets",
    "environments",
    "deployments",
    "pages",
    "packages",
    "repository_hooks",
    "organization_administration",
    "members",
];

/// A10: no code path called merge or deploy, and the token used had no merge permission.
///
/// GitHub gives a merge to a token with `contents: write` and `pull_requests: write` unless the
/// branch protection stops it. So "no merge permission" is shown two ways: no token holds a
/// permission the policy forbids, and the protection of the base branch requires a pull request
/// and a review and does not let the App bypass them.
#[must_use]
pub fn a10(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "A10";
    let github = &ev.github;
    for request in &github.requests {
        let path = request.path.to_ascii_lowercase();
        let writes = !matches!(request.method.as_str(), "GET" | "HEAD");
        if writes
            && (path.ends_with("/merge")
                || path.contains("/merge/")
                || path.contains("auto_merge")
                || path.contains("automerge"))
        {
            return Verdict::fail(
                ID,
                format!(
                    "the factory sent {} {}, which merges",
                    request.method, request.path
                ),
            );
        }
        if writes
            && (path.contains("/deployments")
                || path.contains("/dispatches")
                || path.contains("/releases"))
        {
            return Verdict::fail(
                ID,
                format!(
                    "the factory sent {} {}, which deploys or releases",
                    request.method, request.path
                ),
            );
        }
        if writes && path.contains(&format!("/git/refs/heads/{}", github.base_branch)) {
            return Verdict::fail(
                ID,
                format!(
                    "the factory wrote to the base branch with {} {}",
                    request.method, request.path
                ),
            );
        }
    }
    if github.pull_requests.iter().any(|pr| pr.merged) {
        return Verdict::fail(ID, "a pull request from the job is merged");
    }
    if github.tokens.is_empty() {
        return Verdict::fail(
            ID,
            "no installation token is recorded, so the permissions cannot be judged",
        );
    }
    for token in &github.tokens {
        for name in token.permissions.keys() {
            if FORBIDDEN_PERMISSIONS.contains(&name.as_str()) {
                return Verdict::fail(
                    ID,
                    format!("token {} holds the forbidden permission {name}", token.id),
                );
            }
        }
        if let Some(level) = token.permissions.get("administration")
            && level != "read"
        {
            return Verdict::fail(
                ID,
                format!(
                    "token {} holds administration: {level}, above the read the policy allows",
                    token.id
                ),
            );
        }
        if token.repositories.len() != 1 {
            return Verdict::fail(
                ID,
                format!(
                    "token {} is narrowed to {} repositories, and it must be exactly one",
                    token.id,
                    token.repositories.len()
                ),
            );
        }
    }
    for pr in &github.pull_requests {
        if !pr.head_branch.starts_with("factory/") {
            return Verdict::fail(
                ID,
                format!("the head branch {} is not under factory/", pr.head_branch),
            );
        }
    }
    match &github.protection {
        Some(protection) => {
            if !protection.require_pull_request || protection.required_approvals == 0 {
                return Verdict::fail(
                    ID,
                    "the base branch does not require a pull request and a review, so the token could merge",
                );
            }
            if protection.app_may_bypass {
                return Verdict::fail(
                    ID,
                    "the factory's App may bypass the protection of the base branch",
                );
            }
        }
        None => {
            return Verdict::fail(
                ID,
                "the protection of the base branch was not read, so a merge cannot be ruled out",
            );
        }
    }
    Verdict::pass(
        ID,
        format!(
            "{} requests, none merges or deploys; {} token(s) hold no forbidden permission; the base branch needs a review the App cannot bypass",
            github.requests.len(),
            github.tokens.len()
        ),
    )
}
