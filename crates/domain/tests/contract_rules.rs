//! The rules that the schemas write with `if` and `then`, one change at a time.
//!
//! Each case starts from a valid example, changes one thing, and says whether the result must be
//! accepted or rejected, and for rejections which rule must be named. Most schemas' own invalid
//! examples cover one rule each. These cases cover the other branches of the same rules, and
//! the accepted side of each rule, so a rule that is too strict fails as loudly as one that is too
//! loose.

mod support;

use factory_domain::contracts::{Contract, GateReport, StageContract};
use serde::Deserialize;
use serde_json::{Value, json};
use support::example_index::EXAMPLES;
use support::registry::round_trip_value;

enum Expect {
    Accepted,
    /// Rejected, and the message must contain this text.
    Rejected(&'static str),
}
use Expect::{Accepted, Rejected};

struct Case {
    name: &'static str,
    /// `<schema>/<example file>` of the valid example to start from.
    base: &'static str,
    change: fn(&mut Value),
    expect: Expect,
}

fn base_document(key: &str) -> (&'static str, Value) {
    let (schema, file) = key.split_once('/').expect("schema/file");
    let example = EXAMPLES
        .iter()
        .find(|e| e.valid && e.schema == schema && e.file == file)
        .unwrap_or_else(|| panic!("no valid example {key}"));
    (example.schema, serde_json::from_str(example.text).unwrap())
}

/// Sets the value at a JSON pointer. The parent must exist. An object key is added if missing.
fn put(document: &mut Value, pointer: &str, value: Value) {
    let (parent, key) = pointer.rsplit_once('/').expect("a pointer");
    let parent = if parent.is_empty() {
        &mut *document
    } else {
        document
            .pointer_mut(parent)
            .unwrap_or_else(|| panic!("no parent for {pointer}"))
    };
    match parent {
        Value::Object(map) => {
            map.insert(key.to_owned(), value);
        }
        Value::Array(items) => items[key.parse::<usize>().unwrap()] = value,
        other => panic!("cannot set {pointer} inside {other}"),
    }
}

fn remove(document: &mut Value, pointer: &str) {
    let (parent, key) = pointer.rsplit_once('/').expect("a pointer");
    let parent = document
        .pointer_mut(parent)
        .unwrap_or_else(|| panic!("no parent for {pointer}"));
    match parent {
        Value::Object(map) => {
            map.remove(key)
                .unwrap_or_else(|| panic!("{pointer} is not there"));
        }
        other => panic!("cannot remove {pointer} from {other}"),
    }
}

const GOOD_UUID: &str = "018f3a95-0099-7a99-8b99-1c99d99e99f9";

#[allow(clippy::too_many_lines)]
fn cases() -> Vec<Case> {
    vec![
        // ---- evidence ledger entry --------------------------------------------------------------
        Case {
            name: "a later entry without the previous hash",
            base: "evidence-ledger-entry/approver-accepts-residual-risk.json",
            change: |d| put(d, "/prev_entry_hash", Value::Null),
            expect: Rejected("every entry after the first must carry the hash"),
        },
        Case {
            name: "a simulation result resting only on a test report",
            base: "evidence-ledger-entry/approver-accepts-residual-risk.json",
            change: |d| put(d, "/claim/kind", json!("simulation_result")),
            expect: Rejected("a simulation result needs an artifact, an experiment or a benchmark"),
        },
        Case {
            name: "a simulation result resting on a benchmark",
            base: "evidence-ledger-entry/approver-accepts-residual-risk.json",
            change: |d| {
                put(d, "/claim/kind", json!("simulation_result"));
                put(
                    d,
                    "/evidence",
                    json!([{ "type": "benchmark", "name": "replay-latency", "result": "12 ms", "environment": "A laptop running only the replay, with nothing else open." }]),
                );
            },
            expect: Accepted,
        },
        Case {
            name: "an expert judgment with no attestor",
            base: "evidence-ledger-entry/approver-accepts-residual-risk.json",
            change: |d| put(d, "/evidence", json!([])),
            expect: Rejected("an expert judgment needs a named attestor"),
        },
        Case {
            name: "a simulated component in production mode",
            base: "evidence-ledger-entry/sandbox-verification-first-entry.json",
            change: |d| {
                remove(d, "/claim/assurance_level");
                put(d, "/metadata/recorded_by/fidelity", json!("simulated"));
            },
            expect: Rejected("only when the job runs in test mode"),
        },
        Case {
            name: "a simulated component in test mode",
            base: "evidence-ledger-entry/sandbox-verification-first-entry.json",
            change: |d| {
                remove(d, "/claim/assurance_level");
                put(d, "/metadata/recorded_by/fidelity", json!("simulated"));
                put(d, "/metadata/execution_mode", json!("test"));
            },
            expect: Accepted,
        },
        // ---- stage contract ---------------------------------------------------------------------
        Case {
            name: "a network allow list with no hosts",
            base: "stage-contract/specification-stage.json",
            change: |d| {
                put(d, "/capabilities/permissions/network", json!("allowlist"));
                put(d, "/capabilities/permissions/network_allowlist", json!([]));
            },
            expect: Rejected("a network allow list needs at least one host"),
        },
        Case {
            name: "a network allow list that is missing",
            base: "stage-contract/specification-stage.json",
            change: |d| put(d, "/capabilities/permissions/network", json!("allowlist")),
            expect: Rejected("a network allow list needs at least one host"),
        },
        Case {
            name: "a network allow list with a host",
            base: "stage-contract/specification-stage.json",
            change: |d| {
                put(d, "/capabilities/permissions/network", json!("allowlist"));
                put(
                    d,
                    "/capabilities/permissions/network_allowlist",
                    json!(["api.example.org"]),
                );
            },
            expect: Accepted,
        },
        Case {
            name: "a gate evaluator that names no gate",
            base: "stage-contract/specification-stage.json",
            change: |d| put(d, "/evaluator", json!({ "kind": "deterministic_gate" })),
            expect: Rejected("an evaluator that uses gates must name at least one gate"),
        },
        Case {
            name: "a gate evaluator with an empty gate list",
            base: "stage-contract/specification-stage.json",
            change: |d| {
                put(
                    d,
                    "/evaluator",
                    json!({ "kind": "deterministic_gate", "gate_ids": [] }),
                )
            },
            expect: Rejected("an evaluator that uses gates must name at least one gate"),
        },
        Case {
            name: "a gate evaluator with a gate",
            base: "stage-contract/specification-stage.json",
            change: |d| {
                put(
                    d,
                    "/evaluator",
                    json!({ "kind": "deterministic_gate", "gate_ids": ["build"] }),
                )
            },
            expect: Accepted,
        },
        Case {
            name: "a reviewer evaluator that names no reviewer",
            base: "stage-contract/specification-stage.json",
            change: |d| {
                put(
                    d,
                    "/evaluator",
                    json!({ "kind": "independent_reviewer", "reviewer_must_not_see": ["builder_self_assessment"] }),
                );
            },
            expect: Rejected("must name the reviewer agent"),
        },
        Case {
            name: "a reviewer evaluator with no list of hidden inputs",
            base: "stage-contract/specification-stage.json",
            change: |d| {
                put(
                    d,
                    "/evaluator",
                    json!({ "kind": "independent_reviewer", "reviewer_agent": { "id": "code-reviewer", "version": "1.0.0" } }),
                );
            },
            expect: Rejected("builder_self_assessment"),
        },
        Case {
            name: "a human evaluator needs nothing more",
            base: "stage-contract/specification-stage.json",
            change: |d| put(d, "/evaluator", json!({ "kind": "human" })),
            expect: Accepted,
        },
        Case {
            name: "an input from a person marked trusted",
            base: "stage-contract/specification-stage.json",
            change: |d| {
                put(d, "/inputs/0/provenance/source", json!("human"));
                put(d, "/inputs/0/trust", json!("trusted_internal"));
            },
            expect: Rejected("inputs[0].trust"),
        },
        Case {
            name: "an input from a previous stage marked trusted",
            base: "stage-contract/specification-stage.json",
            change: |d| {
                put(d, "/inputs/0/provenance/source", json!("previous_stage"));
                put(d, "/inputs/0/trust", json!("trusted_internal"));
            },
            expect: Accepted,
        },
        Case {
            name: "the implementation stage on the host tool bridge",
            base: "stage-contract/specification-stage.json",
            change: |d| {
                put(d, "/metadata/stage_kind", json!("IMPLEMENTATION"));
                put(d, "/capabilities/placement", json!("host_tool_bridge"));
            },
            expect: Rejected("capabilities.placement"),
        },
        Case {
            name: "the implementation stage with no placement",
            base: "stage-contract/specification-stage.json",
            change: |d| {
                put(d, "/metadata/stage_kind", json!("IMPLEMENTATION"));
                remove(d, "/capabilities/placement");
            },
            expect: Rejected("capabilities.placement"),
        },
        Case {
            name: "the implementation stage in the sandbox",
            base: "stage-contract/specification-stage.json",
            change: |d| put(d, "/metadata/stage_kind", json!("IMPLEMENTATION")),
            expect: Accepted,
        },
        Case {
            name: "an external write with a compensating action",
            base: "stage-contract/specification-stage.json",
            change: |d| {
                put(d, "/idempotency/side_effects", json!("external_write"));
                put(
                    d,
                    "/idempotency/compensating_action",
                    json!("Close the draft pull request and delete the branch."),
                );
            },
            expect: Accepted,
        },
        Case {
            name: "more attempts than the schema allows",
            base: "stage-contract/specification-stage.json",
            change: |d| put(d, "/timeout_and_retries/max_attempts", json!(11)),
            expect: Rejected("from 1 to 10"),
        },
        Case {
            name: "the same tool granted twice",
            base: "stage-contract/specification-stage.json",
            change: |d| {
                put(
                    d,
                    "/capabilities/granted_tools",
                    json!(["read-file", "read-file"]),
                )
            },
            expect: Rejected("more than once"),
        },
        Case {
            name: "a negative money limit",
            base: "stage-contract/specification-stage.json",
            change: |d| put(d, "/budget/max_cost_usd", json!(-0.5)),
            expect: Rejected("at least 0"),
        },
        // ---- specification contract -------------------------------------------------------------
        Case {
            name: "a superseded specification that never says when it was approved",
            base: "specification-contract/approved-json-output-flag.json",
            change: |d| {
                put(d, "/metadata/status", json!("superseded"));
                remove(d, "/metadata/approved_at");
            },
            expect: Rejected("metadata.approved_at"),
        },
        Case {
            name: "a superseded specification",
            base: "specification-contract/approved-json-output-flag.json",
            change: |d| put(d, "/metadata/status", json!("superseded")),
            expect: Accepted,
        },
        Case {
            name: "an approved specification with a deferred blocking question",
            base: "specification-contract/approved-json-output-flag.json",
            change: |d| {
                put(
                    d,
                    "/open_questions",
                    json!([{ "id": "Q-001", "question": "Should the JSON keys appear in a fixed documented order?", "blocking": true, "status": "deferred" }]),
                );
            },
            expect: Accepted,
        },
        Case {
            name: "a revision with no feature directory",
            base: "specification-contract/approved-revision-two.json",
            change: |d| remove(d, "/provenance/feature_directory"),
            expect: Rejected("provenance.feature_directory"),
        },
        // ---- task plan ----------------------------------------------------------------------------
        Case {
            name: "a plan of sixty-one tasks",
            base: "task-dag/json-output-flag-plan.json",
            change: |d| {
                let first = d["tasks"][0].clone();
                put(d, "/tasks", Value::Array(vec![first; 61]));
            },
            expect: Rejected("at most 60 tasks"),
        },
        Case {
            name: "a plan of sixty tasks",
            base: "task-dag/json-output-flag-plan.json",
            change: |d| {
                let first = d["tasks"][0].clone();
                put(d, "/tasks", Value::Array(vec![first; 60]));
            },
            expect: Accepted,
        },
        Case {
            name: "a task that owns an interface and no files",
            base: "task-dag/json-output-flag-plan.json",
            change: |d| {
                remove(d, "/tasks/0/owned_files");
                put(d, "/tasks/0/owned_interfaces", json!(["output-format"]));
            },
            expect: Accepted,
        },
        // ---- gate report --------------------------------------------------------------------------
        Case {
            name: "a passed report with a command that timed out",
            base: "gate-report/build-and-test-passed.json",
            change: |d| put(d, "/commands/0/timed_out", json!(true)),
            expect: Rejected("commands[0].timed_out"),
        },
        Case {
            name: "a passed report that regressed against the baseline",
            base: "gate-report/build-and-test-passed.json",
            change: |d| put(d, "/baseline_comparison/delta", json!("regressed")),
            expect: Rejected("baseline_comparison.delta"),
        },
        Case {
            name: "a passed report with no tool versions",
            base: "gate-report/build-and-test-passed.json",
            change: |d| put(d, "/environment/tool_versions", json!([])),
            expect: Rejected("versions of the tools"),
        },
        Case {
            name: "a passed report that lists failures",
            base: "gate-report/build-and-test-passed.json",
            change: |d| {
                put(
                    d,
                    "/failures",
                    json!([{ "check_id": "unit-tests", "message": "Two tests failed in the output module." }]),
                );
            },
            expect: Rejected("lists no failures"),
        },
        Case {
            name: "a passed sandbox report with no commands",
            base: "gate-report/build-and-test-passed.json",
            change: |d| put(d, "/commands", json!([])),
            expect: Rejected("at least one command"),
        },
        Case {
            name: "a passed in-process report with no commands",
            base: "gate-report/build-and-test-passed.json",
            change: |d| {
                put(d, "/commands", json!([]));
                put(d, "/environment/executor_kind", json!("in_process"));
                remove(d, "/environment/sandbox");
            },
            expect: Accepted,
        },
        Case {
            name: "a failed report with no failures",
            base: "gate-report/build-and-test-passed.json",
            change: |d| put(d, "/outcome", json!("FAILED")),
            expect: Rejected("must list at least one failure"),
        },
        Case {
            name: "a failed report with a failure",
            base: "gate-report/build-and-test-passed.json",
            change: |d| {
                put(d, "/outcome", json!("FAILED"));
                put(
                    d,
                    "/failures",
                    json!([{ "check_id": "unit-tests", "message": "Two tests failed in the output module." }]),
                );
            },
            expect: Accepted,
        },
        Case {
            name: "a not-applicable report with no reason",
            base: "gate-report/build-and-test-passed.json",
            change: |d| {
                put(d, "/outcome", json!("NOT_APPLICABLE"));
                put(d, "/commands", json!([]));
            },
            expect: Rejected("must say why the gate does not apply"),
        },
        Case {
            name: "a not-applicable report that ran commands",
            base: "gate-report/build-and-test-passed.json",
            change: |d| {
                put(d, "/outcome", json!("NOT_APPLICABLE"));
                put(
                    d,
                    "/not_applicable_reason",
                    json!({ "code": "no_matching_files", "justification": "The change touches no Rust files, so the build gate has nothing to check.", "decided_by": "deterministic_rule" }),
                );
            },
            expect: Rejected("runs no commands"),
        },
        Case {
            name: "a not-applicable report",
            base: "gate-report/build-and-test-passed.json",
            change: |d| {
                put(d, "/outcome", json!("NOT_APPLICABLE"));
                put(d, "/commands", json!([]));
                put(
                    d,
                    "/not_applicable_reason",
                    json!({ "code": "no_matching_files", "justification": "The change touches no Rust files, so the build gate has nothing to check.", "decided_by": "deterministic_rule" }),
                );
            },
            expect: Accepted,
        },
        Case {
            name: "an agent deciding that a gate does not apply",
            base: "gate-report/build-and-test-passed.json",
            change: |d| {
                put(d, "/outcome", json!("NOT_APPLICABLE"));
                put(d, "/commands", json!([]));
                put(
                    d,
                    "/not_applicable_reason",
                    json!({ "code": "no_matching_files", "justification": "The agent thinks the build gate is not needed here.", "decided_by": "agent" }),
                );
            },
            expect: Rejected("not a valid not applicable decider"),
        },
        Case {
            name: "a blocked reason on a passed report",
            base: "gate-report/build-and-test-passed.json",
            change: |d| {
                put(
                    d,
                    "/blocked_reason",
                    json!({ "code": "tool_unavailable", "missing": ["cargo"] }),
                );
            },
            expect: Rejected("only a BLOCKED report carries a blocked reason"),
        },
        Case {
            name: "a sandbox command report that does not describe its sandbox",
            base: "gate-report/build-and-test-passed.json",
            change: |d| remove(d, "/environment/sandbox"),
            expect: Rejected("describe the sandbox"),
        },
        Case {
            name: "a command that did not run but has an exit code",
            base: "gate-report/security-scan-blocked-tool-missing.json",
            change: |d| put(d, "/commands/0/executed", json!(false)),
            expect: Rejected("did not run has no exit code"),
        },
        Case {
            name: "a command that ran but has no exit code",
            base: "gate-report/security-scan-blocked-tool-missing.json",
            change: |d| put(d, "/commands/0/exit_code", Value::Null),
            expect: Rejected("a command that ran has an exit code"),
        },
        Case {
            name: "a command whose exit code key is missing",
            base: "gate-report/security-scan-blocked-tool-missing.json",
            change: |d| remove(d, "/commands/0/exit_code"),
            expect: Rejected("missing field `exit_code`"),
        },
        // ---- review verdict -----------------------------------------------------------------------
        Case {
            name: "changes required that rest on a low finding",
            base: "review-verdict/changes-required-missing-test.json",
            change: |d| put(d, "/findings/0/severity", json!("low")),
            expect: Rejected("medium severity or above"),
        },
        Case {
            name: "a block with no blocker",
            base: "review-verdict/changes-required-missing-test.json",
            change: |d| put(d, "/verdict", json!("BLOCK")),
            expect: Rejected("at least one blocker finding"),
        },
        Case {
            name: "a block with a blocker",
            base: "review-verdict/changes-required-missing-test.json",
            change: |d| {
                put(d, "/verdict", json!("BLOCK"));
                put(d, "/findings/0/severity", json!("blocker"));
            },
            expect: Accepted,
        },
        Case {
            name: "a pass that carries a medium finding",
            base: "review-verdict/changes-required-missing-test.json",
            change: |d| put(d, "/verdict", json!("PASS")),
            expect: Accepted,
        },
        Case {
            name: "a pass that carries a high finding",
            base: "review-verdict/changes-required-missing-test.json",
            change: |d| {
                put(d, "/verdict", json!("PASS"));
                put(d, "/findings/0/severity", json!("high"));
            },
            expect: Rejected("findings[0].severity"),
        },
        Case {
            name: "a fake reviewer runtime in production",
            base: "review-verdict/changes-required-missing-test.json",
            change: |d| put(d, "/metadata/reviewer/runtime/fidelity", json!("fake")),
            expect: Rejected("fake reviewer runtime"),
        },
        Case {
            name: "a fake reviewer runtime in test mode",
            base: "review-verdict/changes-required-missing-test.json",
            change: |d| {
                put(d, "/metadata/reviewer/runtime/fidelity", json!("fake"));
                put(d, "/metadata/execution_mode", json!("test"));
            },
            expect: Accepted,
        },
        Case {
            name: "a finding with a confidence above one",
            base: "review-verdict/changes-required-missing-test.json",
            change: |d| put(d, "/findings/0/confidence", json!(1.5)),
            expect: Rejected("number from 0 to 1"),
        },
        // ---- agent manifest -----------------------------------------------------------------------
        Case {
            name: "an agent that executes commands but has no shell wrapper",
            base: "agent-manifest/builder.json",
            change: |d| put(d, "/permissions/shell", json!("none")),
            expect: Rejected("sandboxed typed wrapper"),
        },
        Case {
            name: "a read-only agent that may write files",
            base: "agent-manifest/specification-reviewer-read-only.json",
            change: |d| put(d, "/permissions/filesystem/write", json!(["specs/**"])),
            expect: Rejected("may write no files"),
        },
        Case {
            name: "a delegation depth of four",
            base: "agent-manifest/builder.json",
            change: |d| put(d, "/resource_limits/max_delegation_depth", json!(4)),
            expect: Rejected("from 0 to 3"),
        },
        Case {
            name: "a pass rate of zero",
            base: "agent-manifest/builder.json",
            change: |d| put(d, "/evaluation_suite/min_pass_rate", json!(0)),
            expect: Rejected("above 0 and at most 1"),
        },
        Case {
            name: "a pass rate of exactly one",
            base: "agent-manifest/builder.json",
            change: |d| put(d, "/evaluation_suite/min_pass_rate", json!(1)),
            expect: Accepted,
        },
        Case {
            name: "a pass rate above one",
            base: "agent-manifest/builder.json",
            change: |d| put(d, "/evaluation_suite/min_pass_rate", json!(1.01)),
            expect: Rejected("above 0 and at most 1"),
        },
        Case {
            name: "a cost limit of zero",
            base: "agent-manifest/builder.json",
            change: |d| put(d, "/resource_limits/max_cost_usd", json!(0)),
            expect: Rejected("number above 0"),
        },
        // ---- domain capability profile ------------------------------------------------------------
        Case {
            name: "a draft profile with no review and no probes",
            base: "domain-capability-profile/general-software-active.json",
            change: |d| {
                put(d, "/status", json!("draft"));
                remove(d, "/review");
                remove(d, "/tool_probes");
            },
            expect: Accepted,
        },
        Case {
            name: "a reviewed profile with no probes",
            base: "domain-capability-profile/general-software-active.json",
            change: |d| {
                put(d, "/status", json!("reviewed"));
                remove(d, "/tool_probes");
            },
            expect: Accepted,
        },
        Case {
            name: "an active profile with an empty list of probes",
            base: "domain-capability-profile/general-software-active.json",
            change: |d| put(d, "/tool_probes", json!([])),
            expect: Accepted,
        },
        // ---- project manifest ---------------------------------------------------------------------
        Case {
            name: "a shell given by its path",
            base: "project-manifest/word-count-minimal.json",
            change: |d| put(d, "/gates/0/argv/0", json!("/bin/sh")),
            expect: Rejected("must not start a shell"),
        },
        Case {
            name: "a shell in capital letters",
            base: "project-manifest/word-count-minimal.json",
            change: |d| put(d, "/gates/0/argv/0", json!("BASH")),
            expect: Rejected("must not start a shell"),
        },
        Case {
            name: "a shell named later in the command",
            base: "project-manifest/word-count-minimal.json",
            change: |d| put(d, "/gates/0/argv", json!(["cargo", "run", "--", "bash"])),
            expect: Accepted,
        },
        Case {
            name: "a relative sandbox working directory",
            base: "project-manifest/word-count-minimal.json",
            change: |d| put(d, "/sandbox/workdir", json!("workspace")),
            expect: Rejected("absolute path"),
        },
        Case {
            name: "a sandbox working directory that climbs",
            base: "project-manifest/word-count-minimal.json",
            change: |d| put(d, "/sandbox/workdir", json!("/workspace/../etc")),
            expect: Rejected("no `..`"),
        },
        Case {
            name: "a gate working directory inside the repository",
            base: "project-manifest/word-count-minimal.json",
            change: |d| put(d, "/gates/0/cwd", json!("crates/domain")),
            expect: Accepted,
        },
        Case {
            name: "a gate working directory at the repository root",
            base: "project-manifest/word-count-minimal.json",
            change: |d| put(d, "/gates/0/cwd", json!("")),
            expect: Accepted,
        },
        Case {
            name: "a gate working directory that climbs out of the repository",
            base: "project-manifest/word-count-minimal.json",
            change: |d| put(d, "/gates/0/cwd", json!("../outside")),
            expect: Rejected("no `..`"),
        },
        Case {
            name: "an absolute gate working directory",
            base: "project-manifest/word-count-minimal.json",
            change: |d| put(d, "/gates/0/cwd", json!("/etc")),
            expect: Rejected("relative to the repository"),
        },
        // ---- evidence manifest --------------------------------------------------------------------
        Case {
            name: "production readiness both reached and not reached",
            base: "evidence-manifest/json-output-flag-draft-pr.json",
            change: |d| {
                put(
                    d,
                    "/assurance/attained/0",
                    json!({ "level": "PRODUCTION_READY", "ledger_entry_id": GOOD_UUID }),
                );
            },
            expect: Rejected("exactly one"),
        },
        Case {
            name: "a blocked gate with its decision recorded",
            base: "evidence-manifest/json-output-flag-draft-pr.json",
            change: |d| {
                put(d, "/gate_reports/0/outcome", json!("BLOCKED"));
                put(
                    d,
                    "/gate_reports/0/disposition_ledger_entry_id",
                    json!(GOOD_UUID),
                );
            },
            expect: Accepted,
        },
        Case {
            name: "a fake adapter in a test-mode manifest",
            base: "evidence-manifest/json-output-flag-draft-pr.json",
            change: |d| {
                put(d, "/metadata/execution_mode", json!("test"));
                put(d, "/adapters/0/fidelity", json!("fake"));
            },
            expect: Accepted,
        },
        Case {
            name: "a risk score above one hundred",
            base: "evidence-manifest/json-output-flag-draft-pr.json",
            change: |d| put(d, "/risk/score", json!(101)),
            expect: Rejected("from 0 to 100"),
        },
        // ---- domain event -------------------------------------------------------------------------
        Case {
            name: "an event whose cause key is missing",
            base: "domain-event/job-admitted-first-event.json",
            change: |d| remove(d, "/causation_id"),
            expect: Rejected("missing field `causation_id`"),
        },
        Case {
            name: "an event whose payload is a list",
            base: "domain-event/job-admitted-first-event.json",
            change: |d| put(d, "/payload", json!([])),
            expect: Rejected("invalid type"),
        },
        Case {
            name: "an aggregate version of zero",
            base: "domain-event/job-admitted-first-event.json",
            change: |d| put(d, "/aggregate/version", json!(0)),
            expect: Rejected("at least 1"),
        },
        Case {
            name: "an event with a trace parent",
            base: "domain-event/job-admitted-first-event.json",
            change: |d| {
                put(
                    d,
                    "/traceparent",
                    json!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
                );
            },
            expect: Accepted,
        },
        Case {
            name: "an event with a malformed trace parent",
            base: "domain-event/job-admitted-first-event.json",
            change: |d| put(d, "/traceparent", json!("00-4BF92F35-00f067aa0ba902b7-01")),
            expect: Rejected("traceparent"),
        },
    ]
}

#[test]
fn every_rule_branch_behaves_as_the_schema_says() {
    let mut problems = Vec::new();
    for case in cases() {
        let (schema, mut document) = base_document(case.base);
        // The base example itself must be accepted, or the case proves nothing.
        assert!(
            round_trip_value(schema, &document).is_ok(),
            "the base example {} is not valid",
            case.base
        );
        (case.change)(&mut document);
        let outcome = round_trip_value(schema, &document);
        match (&case.expect, outcome) {
            (Accepted, Ok(_)) => {}
            (Accepted, Err(message)) => {
                problems.push(format!(
                    "{}: should be accepted but was rejected: {message}",
                    case.name
                ));
            }
            (Rejected(_), Ok(_)) => {
                problems.push(format!(
                    "{}: should be rejected but was accepted",
                    case.name
                ));
            }
            (Rejected(expected), Err(message)) if message.contains(expected) => {}
            (Rejected(expected), Err(message)) => problems.push(format!(
                "{}: rejected, but not for the stated rule (looked for `{expected}`): {message}",
                case.name
            )),
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

#[test]
fn every_case_changes_its_base_example() {
    for case in cases() {
        let (_, original) = base_document(case.base);
        let mut changed = original.clone();
        (case.change)(&mut changed);
        assert_ne!(original, changed, "{}: the change does nothing", case.name);
    }
}

// ---- the validating path is the only one ------------------------------------------------------------

#[test]
fn calling_deserialize_with_the_trait_in_scope_still_checks_the_rules() {
    // Before the wire struct, `StageContract::deserialize(value)` could resolve to a generated
    // inherent method that skipped the checks. It must resolve to the checking implementation.
    let (_, mut document) = base_document("stage-contract/specification-stage.json");
    put(
        &mut document,
        "/metadata/stage_kind",
        json!("IMPLEMENTATION"),
    );
    remove(&mut document, "/capabilities/placement");
    let outcome = StageContract::deserialize(document);
    assert!(
        outcome.is_err(),
        "an implementation stage with no sandbox placement was accepted"
    );
}

#[test]
fn a_value_built_or_changed_in_code_can_be_checked_with_validate() {
    let (_, document) = base_document("gate-report/build-and-test-passed.json");
    let mut report = GateReport::from_json_value(document).unwrap();
    assert_eq!(report.validate(), Ok(()));

    // The fields are public, so code can build a report that breaks a rule. `validate` finds it.
    report.outcome = factory_domain::vocabulary::GateOutcome::Blocked;
    let violations = report.validate().unwrap_err();
    let text = violations.to_string();
    assert!(
        text.contains("blocked_reason: a BLOCKED report must say what was missing"),
        "{text}"
    );
    assert_eq!(violations.iter().count(), 1);
}

#[test]
fn several_broken_rules_are_reported_together() {
    let (_, mut document) = base_document("gate-report/build-and-test-passed.json");
    put(&mut document, "/outcome", json!("BLOCKED"));
    put(&mut document, "/environment/fidelity", json!("fake"));
    let message = GateReport::from_json_value(document)
        .unwrap_err()
        .to_string();
    assert!(message.contains("2 rules"), "{message}");
    assert!(
        message.contains("environment.fidelity") && message.contains("blocked_reason"),
        "{message}"
    );
}
