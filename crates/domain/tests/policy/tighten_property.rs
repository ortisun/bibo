//! The property behind NT-POL-02: take the real policy, change it at random places in random ways,
//! and whenever the checker accepts the change, every evaluator must answer at least as strictly as
//! it does under the real policy. A failure names the key that was changed, so the direction the
//! checker has wrong for that key can be fixed in `tighten.rs`.
//!
//! The answers of the real policy are computed once. An answer is a number where a larger number
//! is looser: an allowed path is 1 and a refused one 0, an allowed command 2, a question to a
//! human 1 and a denial 0, and so on.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::LazyLock;

use factory_domain::policy::authority::{
    ActionContext, ActionVerdict, Actor, ActorKind, Allowlist, AllowlistEntry, AutonomyLevel,
    ChangeFacts,
};
use factory_domain::policy::budget::{Metric, Scope};
use factory_domain::policy::commands::CommandVerdict;
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::policy::egress::EgressProfileId;
use factory_domain::policy::paths::{ChangeEvidence, Operation};
use factory_domain::policy::risk::RiskFacts;
use factory_domain::policy::tighten::{check_approval, check_security};
use factory_domain::policy::tools::GrantRequest;
use factory_domain::policy::{
    ApprovalPolicy, PolicyEngine, RepoKind, SandboxProfileKind, SecurityPolicy,
};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::RiskTier;
use proptest::prelude::*;
use serde_json::Value;

use crate::support::{approval, approval_json, security, security_json};

/// A small deterministic generator, so a failure prints a case that can be replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap_or(1)).unwrap_or(0)
    }
}

fn pointers(value: &Value, here: &str, out: &mut Vec<String>) {
    out.push(here.to_owned());
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let escaped = k.replace('~', "~0").replace('/', "~1");
                pointers(v, &format!("{here}/{escaped}"), out);
            }
        }
        Value::Array(list) => {
            for (i, v) in list.iter().enumerate() {
                pointers(v, &format!("{here}/{i}"), out);
            }
        }
        _ => {}
    }
}

fn strings_of(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::String(s) => {
            out.insert(s.clone());
        }
        Value::Array(list) => list.iter().for_each(|v| strings_of(v, out)),
        Value::Object(map) => map.values().for_each(|v| strings_of(v, out)),
        _ => {}
    }
}

fn index_of(pick: u64, len: usize) -> usize {
    usize::try_from(pick >> 8).unwrap_or(0) % len.max(1)
}

/// Changes one node of a document in one random way.
fn mutate(root: &mut Value, pointer: &str, rng: &mut Rng, pool: &[String]) {
    if pointer.is_empty() {
        return;
    }
    let Some(node) = root.pointer_mut(pointer) else {
        return;
    };
    let pick = rng.next();
    match node {
        Value::Bool(b) => *b = !*b,
        Value::Number(n) => {
            let new: Value = if let Some(u) = n.as_u64() {
                match pick % 5 {
                    0 => 0u64.into(),
                    1 => (u / 2).into(),
                    2 => (u.saturating_mul(2) + 1).into(),
                    3 => (u + 1).into(),
                    _ => u.saturating_sub(1).into(),
                }
            } else {
                let f = n.as_f64().unwrap_or(0.0);
                match pick % 4 {
                    0 => 0.0.into(),
                    1 => (f / 2.0).into(),
                    2 => (f * 2.0 + 1.0).into(),
                    _ => (f + 0.5).into(),
                }
            };
            *node = new;
        }
        Value::String(s) => {
            let replacement = match pick % 5 {
                0 => pool
                    .get(index_of(pick, pool.len()))
                    .cloned()
                    .unwrap_or_default(),
                1 => format!("{s}x"),
                2 => String::new(),
                3 => format!("!{s}"),
                _ => "**".to_owned(),
            };
            *s = replacement;
        }
        Value::Array(list) => match pick % 6 {
            0 if !list.is_empty() => {
                let at = index_of(pick, list.len());
                list.remove(at);
            }
            1 if !list.is_empty() => {
                let copy = list[index_of(pick, list.len())].clone();
                list.push(copy);
            }
            2 => list.clear(),
            3 => {
                let s = pool
                    .get(index_of(pick, pool.len()))
                    .cloned()
                    .unwrap_or_default();
                list.push(Value::String(s));
            }
            4 => list.push(Value::String("!.env.example".to_owned())),
            _ => list.push(Value::String("*".to_owned())),
        },
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            if !keys.is_empty() {
                map.remove(&keys[index_of(pick, keys.len())]);
            }
        }
        Value::Null => {}
    }
}

// ---------------------------------------------------------------------------------------------
// What the evaluators are asked
// ---------------------------------------------------------------------------------------------

const PROBE_LINES: [&str; 39] = [
    "cargo test",
    "cargo build",
    "cargo test -- --nocapture",
    "cargo fetch",
    "cargo publish",
    "cargo test --config x=y",
    "cargo metadata",
    "rustc main.rs",
    "rustfmt main.rs",
    "node a.js",
    "node -e 1",
    "npm test",
    "npm run build",
    "npm install x",
    "npx something",
    "python a.py",
    "python -c 1",
    "pytest tests",
    "pytest -p x",
    "ruff check .",
    "mypy .",
    "go test ./...",
    "go test -exec x",
    "sh -c id",
    "bash a.sh",
    "git push",
    "git status",
    "curl http://x",
    "docker run x",
    "rm -rf /",
    "rm -rf ./target",
    "sudo id",
    "nc x 1",
    "env",
    "make all",
    "cat /proc/self/environ",
    "specify init",
    "pip install x",
    "tmux",
];

const PROBE_PATHS: [&str; 24] = [
    "src/lib.rs",
    "tests/unit.rs",
    "tests/fixtures/a.json",
    "tests/holdout/x",
    ".env",
    ".env.example",
    "keys/server.pem",
    ".github/workflows/ci.yml",
    ".github",
    "scripts/ci.sh",
    ".cargo/config.toml",
    "clippy.toml",
    "AGENTS.md",
    ".claude/settings.json",
    ".factory/x.yaml",
    "policies/security.yaml",
    "agents/a/b.md",
    "Cargo.toml",
    "Dockerfile",
    "crates/policy/x.rs",
    "build.rs",
    "a/b/c.snap",
    "evals/run.py",
    ".gitmodules",
];

const PROBE_OPS: [Operation; 4] = [
    Operation::Read,
    Operation::Add,
    Operation::Modify {
        gained_lines_only: false,
    },
    Operation::Delete,
];

const ALL_TOOLS: [&str; 14] = [
    "fs.read",
    "fs.list",
    "fs.search",
    "fs.write",
    "fs.delete",
    "exec.run",
    "exec.shell",
    "vcs.read",
    "vcs.commit",
    "deps.request",
    "net.fetch",
    "spec.read",
    "report.submit",
    "github.write",
];

const ROLES: [&str; 6] = [
    "builder",
    "qa",
    "research",
    "intake",
    "planner",
    "code_reviewer",
];

const HOSTS: [&str; 12] = [
    "index.crates.io",
    "static.crates.io",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "proxy.golang.org",
    "sum.golang.org",
    "model-broker.sandbox.internal",
    "github.com",
    "evil.example",
    "registry.example.org",
    "api.anthropic.com",
];

const ADDRESSES: [&str; 10] = [
    "127.0.0.1",
    "10.1.1.1",
    "169.254.169.254",
    "192.168.0.9",
    "100.64.0.1",
    "::1",
    "fc00::1",
    "8.8.8.8",
    "140.82.112.3",
    "2606:4700::1",
];

/// A looseness number for a ceiling: bigger is looser, a missing ceiling is the loosest.
fn scale(value: Option<f64>) -> u64 {
    // Ceilings are small; a thousandth of a unit is finer than any policy value.
    value.map_or(u64::MAX, |v| {
        let scaled = v * 1000.0;
        if scaled.is_finite() && scaled >= 0.0 {
            // Truncation is what is wanted: the probe is a number to compare, not a value to use.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let n = scaled as u64;
            n
        } else {
            u64::MAX
        }
    })
}

/// The answers of the security evaluators, as looseness numbers, with a label for each.
fn security_snapshot(e: &PolicyEngine) -> Vec<(u64, String)> {
    let mut out: Vec<(u64, String)> = Vec::new();
    let evidence = ChangeEvidence::default();
    for repo in [RepoKind::Target, RepoKind::Factory] {
        for path in PROBE_PATHS {
            for op in PROBE_OPS {
                let allowed = e.paths.check(repo, path, op, None, &evidence).is_allowed();
                out.push((
                    u64::from(allowed),
                    format!("path {path} {op:?} in {repo:?}"),
                ));
            }
        }
    }
    for line in PROBE_LINES {
        let words: Vec<String> = line.split(' ').map(str::to_owned).collect();
        for profile in SandboxProfileKind::ALL {
            let loose = match e.commands.evaluate(&words, profile) {
                CommandVerdict::Allowed(_) => 2,
                CommandVerdict::RequireHuman { .. } => 1,
                CommandVerdict::Denied(_) => 0,
            };
            out.push((loose, format!("command {line:?} under {profile:?}")));
        }
    }
    let manifest: Vec<String> = ALL_TOOLS.iter().map(|s| (*s).to_owned()).collect();
    for role in ROLES {
        for profile in [
            None,
            Some(SandboxProfileKind::Agent),
            Some(SandboxProfileKind::Verify),
            Some(SandboxProfileKind::FetchDeps),
        ] {
            let set = e.tools.grant(&GrantRequest {
                manifest_allowed: &manifest,
                stage_needs: &manifest,
                role,
                profile,
            });
            for tool in ALL_TOOLS {
                let cap = set
                    .granted()
                    .get(tool)
                    .map(|g| g.caps.map_or(u64::MAX, |c| c.max_calls_per_task));
                // Not granted is 0; granted is its call cap plus one, so a raised cap is looser.
                out.push((
                    cap.map_or(0, |c| c.saturating_add(1)),
                    format!("tool {tool} for {role} in {profile:?}"),
                ));
            }
        }
    }
    for profile in [
        EgressProfileId::None,
        EgressProfileId::FetchDeps,
        EgressProfileId::Agent,
    ] {
        for host in HOSTS {
            for port in [443u16, 8443, 80] {
                for method in ["GET", "HEAD", "POST"] {
                    let allowed = e.egress.check(profile, host, port, method).is_allowed();
                    out.push((
                        u64::from(allowed),
                        format!("egress {profile:?} {host}:{port} {method}"),
                    ));
                }
            }
        }
    }
    for text in ADDRESSES {
        let ip: IpAddr = text.parse().expect("address");
        out.push((
            u64::from(e.egress.check_address(ip).is_allowed()),
            format!("address {text}"),
        ));
    }
    for scope in [Scope::Task, Scope::Job, Scope::RepoDay, Scope::OrgDay] {
        for metric in [
            Metric::Usd,
            Metric::InputTokens,
            Metric::OutputTokens,
            Metric::Turns,
            Metric::ToolCalls,
            Metric::WallClockSeconds,
            Metric::JobsStarted,
            Metric::DelegationDepth,
        ] {
            out.push((
                scale(e.budget.ceiling(scope, metric)),
                format!("ceiling {scope:?} {metric:?}"),
            ));
        }
    }
    let limits = e.budget.rework_limits();
    out.push((u64::from(limits.code.get()), "rework cap, code".to_owned()));
    out.push((
        u64::from(limits.documentation.get()),
        "rework cap, documentation".to_owned(),
    ));
    out.push((
        u64::from(e.budget.repair_cap().get()),
        "repair cap".to_owned(),
    ));
    for gate in [
        "protected_path_check",
        "secret_scan",
        "lint_gate",
        "evidence_binding",
        "stage_profile_check",
    ] {
        out.push((
            u64::from(!e.authority.is_nonwaivable_gate(gate)),
            format!("gate {gate} is waivable"),
        ));
    }
    out
}

fn tenant() -> factory_domain::ids::TenantId {
    factory_domain::ids::TenantId::parse("018f3a00-0000-7000-8000-00000000c001").expect("tenant")
}

fn people() -> Allowlist {
    let entry = |id: u64, designations: &[Designation]| AllowlistEntry {
        tenant: tenant(),
        github_user_id: GithubUserId::new(id).expect("id"),
        login: format!("user{id}"),
        designations: designations.iter().copied().collect(),
        repositories: None,
        expires_at: None,
    };
    Allowlist::new(
        "sha256:probe",
        vec![
            entry(1, &[Designation::Requester]),
            entry(2, &[Designation::Approver]),
            entry(3, &[Designation::SecurityApprover]),
            entry(4, &[Designation::OrgAdmin]),
            entry(5, &[Designation::Operator]),
            entry(6, &[Designation::RepoAdmin]),
        ],
    )
    .expect("list")
}

/// The answers of the approval evaluators, as looseness numbers.
fn approval_snapshot(e: &PolicyEngine) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let list = people();
    let tenant = tenant();
    let now = Timestamp::parse("2026-10-27T12:00:00Z").expect("time");
    let actions: Vec<String> = approval()
        .actions
        .iter()
        .map(|a| a.id.clone())
        .chain([
            "unknown_action".to_owned(),
            "force_push_to_default_branch".to_owned(),
        ])
        .collect();
    let low = ChangeFacts {
        risk_tier: RiskTier::Low,
        protected_path_change: false,
        sensitive_file_change: false,
        new_dependency: false,
    };
    let hot = ChangeFacts {
        risk_tier: RiskTier::Critical,
        protected_path_change: true,
        sensitive_file_change: true,
        new_dependency: true,
    };
    for action in &actions {
        for level in AutonomyLevel::ALL {
            for id in 1..=6u64 {
                for change in [low, hot] {
                    for requester in [None, Some(1u64), Some(id)] {
                        let actor = Actor {
                            github_user_id: GithubUserId::new(id).expect("id"),
                            login: "x",
                            kind: ActorKind::User,
                            github_permission: None,
                            author_association: None,
                        };
                        let verdict = e.authority.authorize_action(&ActionContext {
                            action,
                            level,
                            tenant: &tenant,
                            repository: "acme/widgets",
                            actor: &actor,
                            allowlist: &list,
                            now: &now,
                            requester: requester.and_then(GithubUserId::new),
                            change,
                            require_designation: None,
                            step_up_done: true,
                            solo: factory_domain::policy::solo::SoloFact::NONE,
                        });
                        // No human needed is the loosest, a human the next, a refusal the strictest.
                        let loose = match verdict {
                            ActionVerdict::NoHumanNeeded { .. } => 2,
                            ActionVerdict::Authorized(_) => 1,
                            ActionVerdict::Denied(_) => 0,
                        };
                        out.push((loose, format!("action {action} at {level:?} by {id} (requester {requester:?}, critical {})", change.protected_path_change)));
                    }
                }
            }
        }
    }
    for configured in AutonomyLevel::ALL {
        for preflight in [true, false] {
            out.push((
                e.authority.effective_level(configured, preflight) as u64,
                format!("effective level for {configured:?}, preflight {preflight}"),
            ));
        }
    }
    for tier in [
        RiskTier::Low,
        RiskTier::Medium,
        RiskTier::High,
        RiskTier::Critical,
    ] {
        // A higher number of approvals is stricter, so the looseness is its distance below 100.
        out.push((
            100u64.saturating_sub(u64::from(
                e.authority
                    .required_approvals(tier, factory_domain::policy::solo::SoloFact::NONE)
                    .min(100),
            )),
            format!("approvals for {tier:?}"),
        ));
    }
    for name in [
        "force_push_to_default_branch",
        "bypass_branch_protection",
        "disable_audit_logging",
    ] {
        out.push((
            u64::from(!e.authority.is_never_allowed(name)),
            format!("{name} is possible"),
        ));
    }
    let probes = [
        RiskFacts {
            docs_only: true,
            ..RiskFacts::default()
        },
        RiskFacts {
            multi_module_change: true,
            ..RiskFacts::default()
        },
        RiskFacts {
            new_dependency: true,
            ..RiskFacts::default()
        },
        RiskFacts {
            sensitive_file_change: true,
            ..RiskFacts::default()
        },
        RiskFacts {
            protected_path_change: true,
            ..RiskFacts::default()
        },
        RiskFacts::default(),
    ];
    for facts in probes {
        for claim in [None, Some(RiskTier::Low)] {
            let a = e.risk.assess(&facts, claim);
            // A lower tier is looser. `Low` is 3 and `Critical` 0.
            out.push((
                3 - (a.tier as u64).min(3),
                format!("risk tier for {facts:?}, claim {claim:?}"),
            ));
            out.push((
                100u64.saturating_sub(u64::from(a.required_approvals.min(100))),
                format!("risk approvals for {facts:?}"),
            ));
        }
    }
    out
}

static BASE_ENGINE: LazyLock<PolicyEngine> =
    LazyLock::new(|| PolicyEngine::new(&security(), &approval()).expect("builds"));
static BASE_SECURITY: LazyLock<Vec<(u64, String)>> =
    LazyLock::new(|| security_snapshot(&BASE_ENGINE));
static BASE_APPROVAL: LazyLock<Vec<(u64, String)>> =
    LazyLock::new(|| approval_snapshot(&BASE_ENGINE));

fn looser(base: &[(u64, String)], tight: &[(u64, String)]) -> Option<String> {
    base.iter()
        .zip(tight)
        .find(|((b, _), (t, _))| t > b)
        .map(|((b, label), (t, _))| format!("{label}: the project gives {t} where the central policy gives {b} (larger is looser)"))
}

struct Outcome {
    refused: usize,
    unbuildable: usize,
    accepted_changed: usize,
    sections: BTreeSet<String>,
}

fn run_mutations(seed: u64, count: usize, approval_side: bool) -> Result<Outcome, String> {
    let base_json = if approval_side {
        approval_json()
    } else {
        security_json()
    };
    let (mut paths_list, mut pool) = (Vec::new(), BTreeSet::new());
    pointers(&base_json, "", &mut paths_list);
    strings_of(&base_json, &mut pool);
    let pool: Vec<String> = pool.into_iter().collect();
    let mut rng = Rng(seed | 1);
    let mut out = Outcome {
        refused: 0,
        unbuildable: 0,
        accepted_changed: 0,
        sections: BTreeSet::new(),
    };
    for _ in 0..count {
        let mut json = base_json.clone();
        let edits = 1 + rng.below(3);
        let mut touched = Vec::new();
        for _ in 0..edits {
            let at = paths_list[rng.below(paths_list.len())].clone();
            mutate(&mut json, &at, &mut rng, &pool);
            touched.push(at);
        }
        if json == base_json {
            continue;
        }
        let (security_doc, approval_doc, verdict) = if approval_side {
            match serde_json::from_value::<ApprovalPolicy>(json) {
                Ok(project) => (
                    security(),
                    project.clone(),
                    check_approval(&approval(), &project),
                ),
                Err(_) => continue,
            }
        } else {
            match serde_json::from_value::<SecurityPolicy>(json) {
                Ok(project) => (
                    project.clone(),
                    approval(),
                    check_security(&security(), &project),
                ),
                Err(_) => continue,
            }
        };
        if verdict.is_err() {
            out.refused += 1;
            continue;
        }
        let Ok(tight) = PolicyEngine::new(&security_doc, &approval_doc) else {
            out.unbuildable += 1;
            continue;
        };
        out.accepted_changed += 1;
        for t in &touched {
            if let Some(section) = t.trim_start_matches('/').split('/').next() {
                out.sections.insert(section.to_owned());
            }
        }
        let (base, now) = if approval_side {
            (&*BASE_APPROVAL, approval_snapshot(&tight))
        } else {
            (&*BASE_SECURITY, security_snapshot(&tight))
        };
        if let Some(why) = looser(base, &now) {
            return Err(format!(
                "{why}\n  changed at {touched:?} (seed {seed}, approval side {approval_side})"
            ));
        }
    }
    Ok(out)
}

#[test]
fn an_accepted_security_change_is_never_looser_for_any_evaluator() {
    let outcome = run_mutations(0x5eed_0001, 1700, false).unwrap_or_else(|why| panic!("{why}"));
    // The test must exercise acceptance, not only refusal.
    assert!(
        outcome.accepted_changed >= 30,
        "only {} changes were accepted",
        outcome.accepted_changed
    );
    assert!(
        outcome.refused > outcome.accepted_changed,
        "refused {}",
        outcome.refused
    );
    assert!(outcome.sections.len() >= 8, "{:?}", outcome.sections);
    eprintln!(
        "security: refused {}, unbuildable {}, accepted {}",
        outcome.refused, outcome.unbuildable, outcome.accepted_changed
    );
}

#[test]
fn an_accepted_approval_change_is_never_looser_for_any_evaluator() {
    let outcome = run_mutations(0x5eed_0002, 1500, true).unwrap_or_else(|why| panic!("{why}"));
    assert!(
        outcome.accepted_changed >= 30,
        "only {} changes were accepted",
        outcome.accepted_changed
    );
    assert!(
        outcome.refused > outcome.accepted_changed,
        "refused {}",
        outcome.refused
    );
    eprintln!(
        "approval: refused {}, unbuildable {}, accepted {}",
        outcome.refused, outcome.unbuildable, outcome.accepted_changed
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 6, ..ProptestConfig::default() })]

    #[test]
    fn tightening_never_allows_more_for_any_seed(seed in any::<u64>(), approval_side in any::<bool>()) {
        if let Err(why) = run_mutations(seed, 80, approval_side) {
            prop_assert!(false, "{}", why);
        }
    }
}
