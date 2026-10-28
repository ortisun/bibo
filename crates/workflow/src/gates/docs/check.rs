//! The checks of the Documentation Quality Gate, as pure functions.
//!
//! Each check answers with one of four outcomes (policy section 9.2):
//!
//! * **Passed**: every part of the check that applies ran, and succeeded.
//! * **Failed**: it ran and found a violation. Every violation is a [`Finding`] with its place.
//! * **Blocked**: a part that the check needs could not run. A tool that is absent is blocked,
//!   **never passed**.
//! * **NotApplicable**: there is nothing for the check to look at in this change, with the rule
//!   that says so. A check that was merely skipped is not "not applicable".
//!
//! The checks that need a program to run (the examples, the help output, the diagram parser) do
//! not run it. The stage runs it in the verify sandbox and hands in what the supervisor saw as
//! [`Observations`]. A check that needs an observation that is not there is blocked.

use std::collections::{BTreeMap, BTreeSet};

use factory_domain::contracts::gate_report::{BlockedCode, NotApplicableCode};
use factory_ports::sandbox::ExecResult;

use super::claims::{self, Claim, ClaimKind, Example};
use super::links::{self, Tree};
use super::markdown::scan;
use super::plan::{DocPlan, ItemKind};

/// The gate ids of the Documentation Quality Gate, one report for each. The readability gate has
/// its own id (`readability-gate`).
pub const LINKS: &str = "docs-links";
/// Examples run and print what the page says.
pub const EXAMPLES: &str = "docs-examples";
/// Named commands, flags and variables exist.
pub const COMMANDS: &str = "docs-commands";
/// Every user-visible or breaking change is documented.
pub const COVERAGE: &str = "docs-change-coverage";
/// Diagrams parse.
pub const DIAGRAMS: &str = "docs-diagrams";
/// Every planned page exists and says what the plan asked for.
pub const PAGES: &str = "docs-required-pages";
/// The changelog entry exists.
pub const CHANGELOG: &str = "docs-changelog";
/// No secret-shaped text in the documents.
pub const SECRETS: &str = "docs-secrets";
/// The documents were written for the code that is there now.
pub const BINDING: &str = "docs-binding";

/// Every gate id of this module, in the order the reports are made.
pub const ALL: [&str; 9] = [
    BINDING, PAGES, CHANGELOG, COVERAGE, LINKS, COMMANDS, EXAMPLES, DIAGRAMS, SECRETS,
];

/// The outcome of one check, with what a report must say about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every part that applies ran and succeeded.
    Passed,
    /// A part ran and found a violation.
    Failed,
    /// A part that the check needs could not run.
    Blocked {
        /// The category.
        code: BlockedCode,
        /// What was missing.
        missing: String,
    },
    /// There is nothing to check, by a recorded rule.
    NotApplicable {
        /// The category.
        code: NotApplicableCode,
        /// The rule and what it saw, in a sentence.
        justification: String,
    },
}

/// A violation, or a note, at a place in a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The id of the rule, a slug.
    pub check: &'static str,
    /// The page.
    pub file: Option<String>,
    /// The line.
    pub line: Option<usize>,
    /// What was found, in plain English. It names no secret.
    pub message: String,
}

/// A command the supervisor ran, as it saw it.
#[derive(Debug, Clone)]
pub struct Ran {
    /// The vector that ran.
    pub argv: Vec<String>,
    /// How it ended.
    pub exec: ExecResult,
    /// Standard output, as the supervisor stored it after redaction.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl Ran {
    fn succeeded(&self) -> bool {
        self.exec.exit_code == Some(0) && !self.exec.timed_out
    }
}

/// What the stage could observe for a check that needs a program.
#[derive(Debug, Clone)]
pub enum Observed<T> {
    /// The check does not need it.
    NotNeeded,
    /// It was needed and could not be had: the tool is absent, or the program does not build.
    Absent {
        /// What was missing, such as `cargo` or `the built program`.
        missing: String,
    },
    /// It ran.
    Seen(T),
}

/// One diagram block the parser looked at.
#[derive(Debug, Clone)]
pub struct DiagramRun {
    /// The page.
    pub file: String,
    /// The line of the opening fence.
    pub line: usize,
    /// The parser's run.
    pub ran: Ran,
}

/// What the sandbox showed.
#[derive(Debug, Clone)]
pub struct Observations {
    /// The sandbox that ran the commands, when one was made.
    pub sandbox_id: Option<String>,
    /// The help text of the program.
    pub help: Observed<Ran>,
    /// The examples and their runs.
    pub examples: Observed<Vec<(Example, Option<Ran>)>>,
    /// The diagram blocks and the parser's runs.
    pub diagrams: Observed<Vec<DiagramRun>>,
}

impl Observations {
    /// Nothing needed a program, and none was run.
    #[must_use]
    pub fn none() -> Self {
        Self {
            sandbox_id: None,
            help: Observed::NotNeeded,
            examples: Observed::NotNeeded,
            diagrams: Observed::NotNeeded,
        }
    }
}

/// What the checks read about the branch.
pub struct Inputs<'a> {
    /// The documentation plan.
    pub plan: &'a DocPlan,
    /// Every path of the tree at the documentation head.
    pub files: &'a BTreeSet<String>,
    /// The text of every Markdown page at the documentation head.
    pub pages: &'a BTreeMap<String, String>,
    /// The Markdown pages that changed between the base commit and the documentation head.
    pub changed_docs: &'a BTreeSet<String>,
    /// The lines added to the changelog between the base commit and the documentation head.
    pub changelog_added: &'a str,
    /// The environment variable names the source contains at the documentation head.
    pub source_env: &'a BTreeSet<String>,
    /// The head commit of the code now.
    pub code_head_now: &'a str,
    /// The head commit of the code that the documentation commit was made over.
    pub written_over: &'a str,
    /// The secret scanner: `Some(true)` for text that holds a secret, `None` when the scanner
    /// could not run.
    pub secret: &'a (dyn Fn(&str) -> Option<bool> + Sync),
}

/// The result of one check.
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// The gate id.
    pub gate: &'static str,
    /// What a person reads.
    pub title: &'static str,
    /// The outcome.
    pub verdict: Verdict,
    /// Why, in plain English.
    pub reason: String,
    /// The violations, for a failed check.
    pub findings: Vec<Finding>,
    /// Notes that do not stop the check.
    pub warnings: Vec<Finding>,
    /// The commands the check ran.
    pub commands: Vec<Ran>,
    /// Lines the evidence hash covers.
    pub evidence: Vec<String>,
}

impl CheckResult {
    fn new(gate: &'static str, title: &'static str, verdict: Verdict, reason: String) -> Self {
        Self {
            gate,
            title,
            verdict,
            reason,
            findings: Vec::new(),
            warnings: Vec::new(),
            commands: Vec::new(),
            evidence: Vec::new(),
        }
    }

    fn decided(
        gate: &'static str,
        title: &'static str,
        findings: Vec<Finding>,
        ok: String,
        bad: String,
    ) -> Self {
        let failed = !findings.is_empty();
        let mut result = Self::new(
            gate,
            title,
            if failed {
                Verdict::Failed
            } else {
                Verdict::Passed
            },
            if failed { bad } else { ok },
        );
        result.findings = findings;
        result
    }

    fn blocked(
        gate: &'static str,
        title: &'static str,
        code: BlockedCode,
        missing: String,
        reason: String,
    ) -> Self {
        Self::new(gate, title, Verdict::Blocked { code, missing }, reason)
    }

    fn not_applicable(
        gate: &'static str,
        title: &'static str,
        code: NotApplicableCode,
        why: &str,
    ) -> Self {
        Self::new(
            gate,
            title,
            Verdict::NotApplicable {
                code,
                justification: why.to_owned(),
            },
            why.to_owned(),
        )
    }
}

fn finding(check: &'static str, file: &str, line: usize, message: String) -> Finding {
    Finding {
        check,
        file: Some(file.to_owned()),
        line: Some(line),
        message,
    }
}

fn changed_pages<'a>(inputs: &'a Inputs<'_>) -> Vec<(&'a str, &'a str)> {
    inputs
        .changed_docs
        .iter()
        .filter_map(|path| {
            inputs
                .pages
                .get(path)
                .map(|text| (path.as_str(), text.as_str()))
        })
        .collect()
}

/// A diagram block found in the changed pages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagramBlock {
    /// The page.
    pub file: String,
    /// The line of the opening fence.
    pub line: usize,
    /// The diagram source.
    pub source: String,
}

/// What the changed pages need a program for.
#[derive(Debug, Clone, Default)]
pub struct Needs {
    /// The help text is needed because a page names a flag or a command.
    pub help: bool,
    /// The examples to run.
    pub examples: Vec<Example>,
    /// The diagrams to parse.
    pub diagrams: Vec<DiagramBlock>,
}

/// Reads the changed pages and says what the sandbox must run.
#[must_use]
pub fn needs(inputs: &Inputs<'_>) -> Needs {
    let pages = changed_pages(inputs);
    let program = inputs.plan.program.as_deref().unwrap_or("");
    let named = if program.is_empty() {
        Vec::new()
    } else {
        claims::claims(&pages, program)
    };
    let mut result = Needs {
        help: named
            .iter()
            .any(|claim| matches!(claim.kind, ClaimKind::Flag | ClaimKind::Command)),
        examples: if program.is_empty() {
            Vec::new()
        } else {
            claims::examples(&pages, program)
        },
        diagrams: Vec::new(),
    };
    for (path, text) in &pages {
        for block in scan(text).blocks.iter().filter(|b| b.lang == "mermaid") {
            result.diagrams.push(DiagramBlock {
                file: (*path).to_owned(),
                line: block.line,
                source: block.body.clone(),
            });
        }
    }
    result
}

/// Runs every check.
#[must_use]
pub fn run(inputs: &Inputs<'_>, seen: &Observations) -> Vec<CheckResult> {
    vec![
        binding(inputs),
        pages(inputs),
        changelog(inputs),
        coverage(inputs),
        links_check(inputs),
        commands(inputs, seen),
        examples(inputs, seen),
        diagrams(inputs, seen),
        secrets(inputs),
    ]
}

/// The documents were written for the code that is there now. A plan or a documentation commit
/// for another head is stale: the claims on the pages were checked against code that changed.
fn binding(inputs: &Inputs<'_>) -> CheckResult {
    let mut findings = Vec::new();
    if inputs.plan.binding.code_head != inputs.code_head_now {
        findings.push(Finding {
            check: "docs-stale",
            file: None,
            line: None,
            message: "The documentation plan was made for an earlier version of the code, so the documents must be written and checked again.".to_owned(),
        });
    }
    if inputs.written_over != inputs.code_head_now {
        findings.push(Finding {
            check: "docs-stale",
            file: None,
            line: None,
            message: "The documentation commit was made over an earlier version of the code, so the documents must be written and checked again.".to_owned(),
        });
    }
    let mut result = CheckResult::decided(
        BINDING,
        "Documents match the current code",
        findings,
        "The plan and the documentation commit were made for the code as it is now.".to_owned(),
        "The documents were written for code that has since changed.".to_owned(),
    );
    result.evidence = vec![
        format!("plan_code_head={}", inputs.plan.binding.code_head),
        format!("written_over={}", inputs.written_over),
        format!("code_head_now={}", inputs.code_head_now),
    ];
    result
}

fn pages(inputs: &Inputs<'_>) -> CheckResult {
    let title = "Required documents exist";
    if let Some(rule) = &inputs.plan.not_applicable {
        return CheckResult::not_applicable(
            PAGES,
            title,
            NotApplicableCode::ChangeTypeExcludesGate,
            &format!(
                "The impact policy requires no document: rule {}.",
                rule.rule
            ),
        );
    }
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut checked = 0usize;
    for item in inputs
        .plan
        .items
        .iter()
        .filter(|item| item.kind != ItemKind::Changelog)
    {
        checked += 1;
        let text = inputs.pages.get(&item.page);
        evidence.push(format!("page={}", item.page));
        if !inputs.files.contains(&item.page) || text.is_none() {
            findings.push(Finding {
                check: "page-missing",
                file: Some(item.page.clone()),
                line: None,
                message: format!(
                    "The plan asks for the page {} and it does not exist.",
                    item.page
                ),
            });
            continue;
        }
        let text = text.map_or("", String::as_str);
        if text.trim().is_empty() {
            findings.push(Finding {
                check: "page-empty",
                file: Some(item.page.clone()),
                line: None,
                message: format!("The page {} is empty.", item.page),
            });
            continue;
        }
        if item.kind != ItemKind::Check && !inputs.changed_docs.contains(&item.page) {
            findings.push(Finding {
                check: "page-unchanged",
                file: Some(item.page.clone()),
                line: None,
                message: format!(
                    "The plan asks for a change to {} and the page is as it was.",
                    item.page
                ),
            });
            continue;
        }
        for term in &item.terms {
            if !text.contains(term.as_str()) {
                findings.push(Finding {
                    check: "page-lacks-term",
                    file: Some(item.page.clone()),
                    line: None,
                    message: format!(
                        "The page {} does not mention {term}, which the plan requires.",
                        item.page
                    ),
                });
            }
        }
    }
    let mut result = CheckResult::decided(
        PAGES,
        title,
        findings,
        format!("All {checked} planned pages exist, are not empty and say what the plan asks."),
        "A planned page is missing, empty, unchanged or leaves out what the plan requires."
            .to_owned(),
    );
    result.evidence = evidence;
    result
}

fn changelog(inputs: &Inputs<'_>) -> CheckResult {
    let title = "Changelog entry exists";
    let Some(item) = inputs
        .plan
        .items
        .iter()
        .find(|item| item.kind == ItemKind::Changelog)
    else {
        return CheckResult::not_applicable(
            CHANGELOG,
            title,
            NotApplicableCode::ChangeTypeExcludesGate,
            "The impact policy requires no changelog entry for this change.",
        );
    };
    let mut findings = Vec::new();
    let added = inputs.changelog_added;
    if !inputs.changed_docs.contains("CHANGELOG.md") || added.trim().is_empty() {
        findings.push(Finding {
            check: "changelog-missing",
            file: Some("CHANGELOG.md".to_owned()),
            line: None,
            message: "The change needs a changelog entry and the changelog has no new line."
                .to_owned(),
        });
    } else {
        for term in &item.terms {
            if !added.contains(term.as_str()) {
                findings.push(Finding {
                    check: "changelog-lacks-term",
                    file: Some("CHANGELOG.md".to_owned()),
                    line: None,
                    message: format!("The changelog entry does not mention {term}."),
                });
            }
        }
        if inputs.plan.breaking && !added.to_lowercase().contains("breaking") {
            findings.push(Finding {
                check: "changelog-not-breaking",
                file: Some("CHANGELOG.md".to_owned()),
                line: None,
                message: "The change breaks something users rely on and the changelog entry is not marked as breaking.".to_owned(),
            });
        }
    }
    let mut result = CheckResult::decided(
        CHANGELOG,
        title,
        findings,
        "The changelog has an entry that names the change.".to_owned(),
        "The changelog entry is missing or leaves out what the change did.".to_owned(),
    );
    result.evidence = vec![format!("added_bytes={}", added.len())];
    result
}

/// No user-visible or breaking change goes undocumented: each new flag or variable is named in a
/// changed document, and a breaking change has its upgrade note.
fn coverage(inputs: &Inputs<'_>) -> CheckResult {
    let title = "Every visible change is documented";
    let interface = &inputs.plan.interface;
    if inputs.plan.not_applicable.is_some() || !(interface.user_visible() || inputs.plan.breaking) {
        return CheckResult::not_applicable(
            COVERAGE,
            title,
            NotApplicableCode::ChangeTypeExcludesGate,
            "The change adds, removes or renames no flag or environment variable, so no visible change needs coverage.",
        );
    }
    let text: String = changed_pages(inputs)
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n");
    let mut findings = Vec::new();
    for name in interface.new_flags.iter().chain(&interface.new_env) {
        if !text.contains(name.as_str()) {
            findings.push(Finding {
                check: "change-undocumented",
                file: None,
                line: None,
                message: format!("The change adds {name} and no document that changed names it."),
            });
        }
    }
    if inputs.plan.breaking
        && !inputs
            .plan
            .items
            .iter()
            .filter(|item| item.kind == ItemKind::Upgrade)
            .any(|item| inputs.changed_docs.contains(&item.page))
    {
        findings.push(Finding {
            check: "change-undocumented",
            file: None,
            line: None,
            message: "The change breaks something users rely on and there is no upgrade note."
                .to_owned(),
        });
    }
    let mut result = CheckResult::decided(
        COVERAGE,
        title,
        findings,
        "Every new flag and variable is documented, and a breaking change has its upgrade note."
            .to_owned(),
        "A visible or breaking change has no documentation.".to_owned(),
    );
    result.evidence = interface
        .new_flags
        .iter()
        .chain(&interface.new_env)
        .map(|name| format!("name={name}"))
        .collect();
    result
}

fn links_check(inputs: &Inputs<'_>) -> CheckResult {
    let title = "Internal links and anchors resolve";
    let pages = changed_pages(inputs);
    let tree = Tree {
        files: inputs.files,
        pages: inputs.pages,
    };
    let report = links::check(&pages, &tree);
    if report.internal_checked == 0 {
        let external = report.external_unchecked.len();
        return CheckResult::not_applicable(
            LINKS,
            title,
            NotApplicableCode::NoMatchingFiles,
            &if external == 0 {
                "The changed documents contain no links.".to_owned()
            } else {
                format!(
                    "The changed documents contain no internal links. {external} external link(s) were not checked, because the gate does not fetch them, and none is reported as valid."
                )
            },
        );
    }
    let findings = report
        .broken
        .iter()
        .map(|broken| {
            finding(
                "link-broken",
                &broken.file,
                broken.line,
                format!(
                    "The link to {} does not resolve: {}.",
                    broken.target, broken.reason
                ),
            )
        })
        .collect();
    let external = report.external_unchecked.len();
    let note = format!(
        "{external} external link(s) were not checked: the gate does not fetch them, and none is reported as valid."
    );
    let mut result = CheckResult::decided(
        LINKS,
        title,
        findings,
        format!(
            "{} internal link(s) resolve. {note}",
            report.internal_checked
        ),
        format!(
            "{} internal link(s) do not resolve. {note}",
            report.broken.len()
        ),
    );
    result.evidence = vec![
        format!("internal_checked={}", report.internal_checked),
        format!("external_unchecked={external}"),
    ];
    result.evidence.extend(
        report
            .external_unchecked
            .iter()
            .map(|target| format!("external_not_checked={target}")),
    );
    if external > 0 {
        result.warnings.push(Finding {
            check: "external-links-not-checked",
            file: None,
            line: None,
            message: note,
        });
    }
    result
}

fn commands(inputs: &Inputs<'_>, seen: &Observations) -> CheckResult {
    let title = "Named commands, flags and variables exist";
    let program = inputs.plan.program.as_deref().unwrap_or("");
    let pages = changed_pages(inputs);
    let named = if program.is_empty() {
        Vec::new()
    } else {
        claims::claims(&pages, program)
    };
    if named.is_empty() {
        return CheckResult::not_applicable(
            COMMANDS,
            title,
            NotApplicableCode::NoMatchingFiles,
            "No changed document names a command, a flag or an environment variable of the program.",
        );
    }
    let needs_help = named
        .iter()
        .any(|claim| matches!(claim.kind, ClaimKind::Flag | ClaimKind::Command));
    let (help, command): (Option<&str>, Vec<Ran>) = match &seen.help {
        Observed::Seen(ran) if ran.succeeded() => (Some(ran.stdout.as_str()), vec![ran.clone()]),
        Observed::Seen(ran) if needs_help => {
            return blocked_with(
                COMMANDS,
                title,
                BlockedCode::ToolProbeFailed,
                "the help output of the program",
                "The program did not print its help text, so the names in the documents could not be compared with it.",
                vec![ran.clone()],
            );
        }
        Observed::Absent { missing } if needs_help => {
            return blocked_with(
                COMMANDS,
                title,
                BlockedCode::ToolUnavailable,
                missing,
                "The program could not be built or run, so the names in the documents could not be compared with its help text.",
                Vec::new(),
            );
        }
        Observed::NotNeeded if needs_help => {
            return blocked_with(
                COMMANDS,
                title,
                BlockedCode::DependencyUnavailable,
                "the help output of the program",
                "The documents name flags or commands and no help output was captured.",
                Vec::new(),
            );
        }
        _ => (None, Vec::new()),
    };
    let missing = claims::invented(&named, help, inputs.source_env);
    let findings = missing
        .iter()
        .map(|claim: &Claim| {
            let what = match claim.kind {
                ClaimKind::Flag => "flag",
                ClaimKind::Command => "command",
                ClaimKind::EnvVar => "environment variable",
            };
            finding(
                "name-invented",
                &claim.file,
                claim.line,
                format!(
                    "The page names the {what} {}, and neither the help output nor the source has it.",
                    claim.name
                ),
            )
        })
        .collect();
    let mut result = CheckResult::decided(
        COMMANDS,
        title,
        findings,
        format!(
            "All {} name(s) the documents use exist in the program.",
            named.len()
        ),
        "A document names a command, flag or variable that the program does not have.".to_owned(),
    );
    result.commands = command;
    result.evidence = named
        .iter()
        .map(|claim| format!("name={}:{}", claim.file, claim.name))
        .collect();
    result
}

fn blocked_with(
    gate: &'static str,
    title: &'static str,
    code: BlockedCode,
    missing: &str,
    reason: &str,
    commands: Vec<Ran>,
) -> CheckResult {
    let mut result = CheckResult::blocked(gate, title, code, missing.to_owned(), reason.to_owned());
    result.commands = commands;
    result
}

fn examples(inputs: &Inputs<'_>, seen: &Observations) -> CheckResult {
    let title = "Examples run and print what the page says";
    let _ = inputs;
    let runs = match &seen.examples {
        Observed::NotNeeded => {
            return CheckResult::not_applicable(
                EXAMPLES,
                title,
                NotApplicableCode::NoMatchingFiles,
                "No changed document shows a command of the program to run.",
            );
        }
        Observed::Absent { missing } => {
            return blocked_with(
                EXAMPLES,
                title,
                BlockedCode::ToolUnavailable,
                missing,
                "The program could not be built or run, so the examples were not run.",
                Vec::new(),
            );
        }
        Observed::Seen(runs) => runs,
    };
    let mut findings = Vec::new();
    let mut commands = Vec::new();
    for (example, ran) in runs {
        let Some(ran) = ran.as_ref().filter(|_| example.runnable) else {
            findings.push(finding(
                "example-not-runnable",
                &example.file,
                example.line,
                format!(
                    "The example `{}` needs a shell, and the gate runs one command without a shell. Show it as a single command.",
                    example.written
                ),
            ));
            continue;
        };
        commands.push(ran.clone());
        if ran.exec.timed_out || ran.exec.exit_code != Some(0) {
            findings.push(finding(
                "example-failed",
                &example.file,
                example.line,
                format!(
                    "The example `{}` did not finish with exit code 0 (it ended with {}).",
                    example.written,
                    ran.exec
                        .exit_code
                        .map_or_else(|| "no exit code".to_owned(), |code| code.to_string())
                ),
            ));
            continue;
        }
        if let Some(expected) = &example.expected
            && claims::normalized(expected) != claims::normalized(&ran.stdout)
        {
            findings.push(finding(
                "example-output-differs",
                &example.file,
                example.line,
                format!(
                    "The example `{}` prints different output from the page: the page shows {:?} and the program printed {:?}.",
                    example.written,
                    claims::normalized(expected),
                    claims::normalized(&ran.stdout)
                ),
            ));
        }
    }
    if runs.is_empty() {
        return CheckResult::not_applicable(
            EXAMPLES,
            title,
            NotApplicableCode::NoMatchingFiles,
            "No changed document shows a command of the program to run.",
        );
    }
    let mut result = CheckResult::decided(
        EXAMPLES,
        title,
        findings,
        format!(
            "All {} example(s) ran with exit code 0 and printed what the page shows.",
            runs.len()
        ),
        "An example does not run, or prints something other than what the page shows.".to_owned(),
    );
    result.commands = commands;
    result.evidence = runs
        .iter()
        .map(|(example, _)| {
            format!(
                "example={}:{}:{}",
                example.file, example.line, example.written
            )
        })
        .collect();
    result
}

fn diagrams(inputs: &Inputs<'_>, seen: &Observations) -> CheckResult {
    let title = "Diagrams parse";
    let blocks = needs(inputs).diagrams;
    if blocks.is_empty() {
        return CheckResult::not_applicable(
            DIAGRAMS,
            title,
            NotApplicableCode::NoMatchingFiles,
            "No changed document holds a diagram.",
        );
    }
    let runs = match &seen.diagrams {
        Observed::Seen(runs) => runs,
        Observed::Absent { missing } => {
            return blocked_with(
                DIAGRAMS,
                title,
                BlockedCode::ToolUnavailable,
                missing,
                "The documents hold diagrams and the diagram parser is not available in the sandbox, so no diagram was checked.",
                Vec::new(),
            );
        }
        Observed::NotNeeded => {
            return blocked_with(
                DIAGRAMS,
                title,
                BlockedCode::DependencyUnavailable,
                "a diagram parser",
                "The documents hold diagrams and no parser was run.",
                Vec::new(),
            );
        }
    };
    let findings: Vec<Finding> = runs
        .iter()
        .filter(|run| !run.ran.succeeded())
        .map(|run| {
            finding(
                "diagram-invalid",
                &run.file,
                run.line,
                "The diagram does not parse.".to_owned(),
            )
        })
        .collect();
    let mut result = CheckResult::decided(
        DIAGRAMS,
        title,
        findings,
        format!(
            "{} diagram(s) were syntax-checked. They were not rendered.",
            runs.len()
        ),
        "A diagram does not parse.".to_owned(),
    );
    result.commands = runs.iter().map(|run| run.ran.clone()).collect();
    result
}

fn secrets(inputs: &Inputs<'_>) -> CheckResult {
    let title = "No secrets in the documents";
    let pages = changed_pages(inputs);
    if pages.is_empty() {
        return CheckResult::not_applicable(
            SECRETS,
            title,
            NotApplicableCode::NoMatchingFiles,
            "No document changed, so there is no document text to scan. The change itself is scanned by the validation stage.",
        );
    }
    let mut findings = Vec::new();
    for (path, text) in &pages {
        match (inputs.secret)(text) {
            Some(false) => {}
            Some(true) => findings.push(Finding {
                check: "secret-found",
                file: Some((*path).to_owned()),
                line: None,
                message: format!(
                    "The page {path} holds text shaped like a secret. The value is not shown here."
                ),
            }),
            None => {
                return CheckResult::blocked(
                    SECRETS,
                    title,
                    BlockedCode::ToolUnavailable,
                    "the secret scanner".to_owned(),
                    "The secret scanner could not run, so the documents were not scanned."
                        .to_owned(),
                );
            }
        }
    }
    let mut result = CheckResult::decided(
        SECRETS,
        title,
        findings,
        format!(
            "{} page(s) were scanned and none holds a secret.",
            pages.len()
        ),
        "A document holds text shaped like a secret.".to_owned(),
    );
    result.evidence = pages
        .iter()
        .map(|(path, _)| format!("scanned={path}"))
        .collect();
    result
}

#[cfg(test)]
mod tests {
    use super::super::plan::{Binding, ChangedFile, Facts, Kind, derive};
    use super::*;

    fn plan_for(added: &str, removed: &str) -> DocPlan {
        derive(
            &Facts {
                changed: vec![ChangedFile {
                    path: "src/main.rs".to_owned(),
                    kind: Kind::Modified,
                    added: vec![added.to_owned()],
                    removed: if removed.is_empty() {
                        Vec::new()
                    } else {
                        vec![removed.to_owned()]
                    },
                }],
                existing_pages: ["README.md".to_owned()].into(),
                program: Some("wc-rs".to_owned()),
                profile: "rust-command-line-tool".to_owned(),
                ..Facts::default()
            },
            Binding {
                base_commit: "a".repeat(40),
                code_head: "b".repeat(40),
                specification_sha256: format!("sha256:{}", "c".repeat(64)),
            },
        )
    }

    struct Tree2 {
        files: BTreeSet<String>,
        pages: BTreeMap<String, String>,
        changed: BTreeSet<String>,
        env: BTreeSet<String>,
        head: String,
    }

    fn tree2(readme: &str, changelog: &str) -> Tree2 {
        let pages: BTreeMap<String, String> = [
            ("README.md".to_owned(), readme.to_owned()),
            ("CHANGELOG.md".to_owned(), changelog.to_owned()),
        ]
        .into();
        Tree2 {
            files: pages.keys().cloned().collect(),
            changed: pages.keys().cloned().collect(),
            pages,
            env: BTreeSet::new(),
            head: "b".repeat(40),
        }
    }

    fn inputs<'a>(plan: &'a DocPlan, t: &'a Tree2, added: &'a str) -> Inputs<'a> {
        Inputs {
            plan,
            files: &t.files,
            pages: &t.pages,
            changed_docs: &t.changed,
            changelog_added: added,
            source_env: &t.env,
            code_head_now: &t.head,
            written_over: &t.head,
            secret: &|_| Some(false),
        }
    }

    fn outcome<'a>(results: &'a [CheckResult], gate: &str) -> &'a CheckResult {
        results.iter().find(|r| r.gate == gate).expect("a result")
    }

    #[test]
    fn a_page_without_a_required_term_and_a_missing_changelog_fail() {
        let plan = plan_for("a == \"--json\"", "");
        let t = tree2("# Tool\n\nPrints counts.\n", "");
        let results = run(&inputs(&plan, &t, ""), &Observations::none());
        assert_eq!(outcome(&results, PAGES).verdict, Verdict::Failed);
        assert_eq!(outcome(&results, CHANGELOG).verdict, Verdict::Failed);
        assert_eq!(outcome(&results, COVERAGE).verdict, Verdict::Failed);
    }

    #[test]
    fn a_documented_flag_with_a_changelog_entry_passes_the_page_checks() {
        let plan = plan_for("a == \"--json\"", "");
        let t = tree2(
            "# Tool\n\nUse `--json` to print JSON.\n",
            "- Added `--json`.\n",
        );
        let results = run(
            &inputs(&plan, &t, "- Added `--json`.\n"),
            &Observations::none(),
        );
        for gate in [PAGES, CHANGELOG, COVERAGE, BINDING] {
            assert_eq!(outcome(&results, gate).verdict, Verdict::Passed, "{gate}");
        }
    }

    #[test]
    fn a_breaking_change_needs_a_marked_entry_and_an_upgrade_note() {
        let plan = plan_for("", "a == \"--old\"");
        let t = tree2(
            "# Tool\n\nThe `--old` flag is gone.\n",
            "- Removed `--old`.\n",
        );
        let results = run(
            &inputs(&plan, &t, "- Removed `--old`.\n"),
            &Observations::none(),
        );
        assert_eq!(outcome(&results, CHANGELOG).verdict, Verdict::Failed);
        assert_eq!(outcome(&results, PAGES).verdict, Verdict::Failed);
        assert_eq!(outcome(&results, COVERAGE).verdict, Verdict::Failed);
    }

    #[test]
    fn a_stale_plan_fails_the_binding() {
        let plan = plan_for("a == \"--json\"", "");
        let t = tree2("# T\n", "");
        let mut input = inputs(&plan, &t, "");
        let newer = "d".repeat(40);
        input.code_head_now = &newer;
        assert_eq!(binding(&input).verdict, Verdict::Failed);
    }

    #[test]
    fn a_missing_tool_is_blocked_and_nothing_to_check_is_not_applicable() {
        let plan = plan_for("a == \"--json\"", "");
        let t = tree2("# T\n\nUse `--json`.\n\n```mermaid\ngraph TD\n```\n", "");
        let absent = Observations {
            sandbox_id: None,
            help: Observed::Absent {
                missing: "cargo".to_owned(),
            },
            examples: Observed::NotNeeded,
            diagrams: Observed::Absent {
                missing: "the diagram parser".to_owned(),
            },
        };
        let results = run(&inputs(&plan, &t, ""), &absent);
        assert!(matches!(
            outcome(&results, COMMANDS).verdict,
            Verdict::Blocked { .. }
        ));
        assert!(matches!(
            outcome(&results, DIAGRAMS).verdict,
            Verdict::Blocked { .. }
        ));
        assert!(matches!(
            outcome(&results, EXAMPLES).verdict,
            Verdict::NotApplicable { .. }
        ));
        assert!(matches!(
            outcome(&results, LINKS).verdict,
            Verdict::NotApplicable { .. }
        ));
    }

    #[test]
    fn a_secret_is_a_failure_and_a_scanner_that_cannot_run_is_blocked() {
        let plan = plan_for("a == \"--json\"", "");
        let t = tree2("# T\n\nUse `--json`.\n", "");
        let mut input = inputs(&plan, &t, "");
        input.secret = &|_| Some(true);
        let failed = secrets(&input);
        assert_eq!(failed.verdict, Verdict::Failed);
        assert!(failed.findings.iter().all(|f| !f.message.contains("---")));
        input.secret = &|_| None;
        assert!(matches!(secrets(&input).verdict, Verdict::Blocked { .. }));
    }
}
