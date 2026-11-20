//! Which workflows of a target repository are exposed to the factory's branches (threat T-48).
//!
//! The factory pushes agent-written code to a branch `factory/job-<id>` of the customer's own
//! repository and opens a draft pull request to the default branch. A workflow that either of
//! those starts runs that code before a person has read it. This module reads one workflow file
//! and says whether it is *exposed*: started by the factory's push or pull request, with
//! something worth stealing in reach. The protection preflight
//! (`factory_composition::preflight`) calls it for every workflow file of the default branch.
//!
//! It is deterministic and fails closed: a file that cannot be read, or that has a shape this
//! module does not know, is exposed with the reason `unreadable`.
//!
//! # The rules
//!
//! UNVERIFIED against the real GitHub: **every rule in this section**. Each is written from
//! GitHub's documentation ("Workflow syntax for GitHub Actions", "Events that trigger workflows",
//! "Using secrets in GitHub Actions", "Automatic token authentication") and none was exercised:
//! this project has run no workflow on GitHub. Where the documentation leaves a doubt the rule
//! takes the reading that marks more workflows as exposed.
//!
//! **Started by the factory** (rule S). A workflow is started when its `on` names:
//!
//! * `push`, unless its branch filters leave the factory's branches out. No `branches` and no
//!   `branches-ignore` means every branch, except that a `push` with only `tags` or `tags-ignore`
//!   does not run for a push to a branch. A `branches` list starts the workflow when one of its
//!   patterns could match a name that begins with `factory/`. A `branches-ignore` list leaves the
//!   factory out only when it holds one of `factory/**`, `factory/*`, `factory/job-*` or `**`
//!   and no pattern that begins with `!`. Path filters are ignored: the agent chooses the paths.
//! * `pull_request` or `pull_request_target`, unless its base branch filters leave the default
//!   branch out. No filter means every base branch. A `branches` list starts the workflow when
//!   one of its patterns could match the default branch. A `branches-ignore` list leaves the
//!   default branch out only when it holds the exact name of the default branch or `**`, and no
//!   pattern that begins with `!`. The `types` filter is ignored.
//! * `create`, `pull_request_review` or `pull_request_review_comment`, which have no branch
//!   filter and run for the factory's branch or pull request.
//!
//! "Could match" is decided without a glob engine. A pattern made only of letters, digits, `.`,
//! `_`, `-` and `/` matches its own text. Any other pattern is cut at its first special
//! character (and one character earlier when that character is `?`, which makes the one before
//! it optional), and the pattern could match unless what is left disagrees with the start of the
//! name. A list that takes branches back out with `!` is therefore read as if the `!` lines were
//! not there.
//!
//! **Something in reach** (rule R). A started workflow is exposed when any of these holds:
//!
//! * `uses_secrets`: a scalar anywhere in the file reads the `secrets` context for a name other
//!   than `GITHUB_TOKEN` (`secrets.NAME`, `secrets[...]`, or `secrets` passed whole to a
//!   function). Comments are not read. A shell line such as `cat secrets.txt` is taken for a
//!   reference: the rule does not parse expressions.
//! * `write_permissions`: `permissions` at the top or in a job is `write-all`, or gives `write`
//!   to a scope, or holds a value other than `read` and `none`.
//! * `permissions_not_declared`: a job has no `permissions` and the top level has none either.
//!   The token then has the default of the repository or the organization, which may be write
//!   and which the factory cannot read.
//! * `self_hosted_runner`: a job's `runs-on` holds the label `self-hosted`.
//! * `runner_unknown`: a job's `runs-on` is an expression (`${{ matrix.os }}` too), a runner
//!   group, or a label that does not begin with `ubuntu-`, `windows-` or `macos-`.
//! * `pull_request_target`: the workflow is started by `pull_request_target`.
//! * `calls_reusable_workflow`: a job calls a reusable workflow, whose runner and permissions
//!   this module does not read. `inherits_secrets` is added when the call says
//!   `secrets: inherit`.
//!
//! A job behind an `environment:` is judged like any other. An environment with required
//! reviewers would hold its secrets back, and the factory cannot read environment protection
//! with the permissions it has, so it does not count on it.
//!
//! # The reader
//!
//! The policy reader of this crate ([`crate::yaml`]) cannot read real workflow files: it refuses
//! the plain key `on` (a YAML 1.1 boolean) and a key with no value (`pull_request:`), and both
//! are in most workflows. This module therefore has a reader of its own over the same event
//! parser. It keeps every scalar as text, takes an empty value as "nothing", and still refuses
//! what would make two readers disagree: anchors, aliases, tags, the merge key, a duplicate key,
//! a key that is not a scalar, a directive, a second document, and anything over the limits
//! below. GitHub accepts anchors and aliases in workflows; a workflow that uses them is
//! `unreadable` here.

use std::collections::BTreeSet;

use factory_ports::githost::{ExposedWorkflow, WorkflowExposureReason, WorkflowFile};
use saphyr_parser::{Event, Parser, ScalarStyle};

/// The largest workflow file that is read. GitHub's own limit is not documented here; a larger
/// file is `unreadable`.
const MAX_BYTES: usize = 512 * 1024;
/// The deepest nesting that is read.
const MAX_DEPTH: usize = 32;
/// The most values one file may hold.
const MAX_NODES: usize = 50_000;

/// The start of every branch the factory pushes (`factory_branch_pattern` in
/// `policies/security.yaml`, `job_branch` in the composition crate).
const FACTORY_PREFIX: &str = "factory/";

/// The `branches-ignore` patterns that are taken to cover every factory branch.
const IGNORES_THE_FACTORY: [&str; 4] = ["factory/**", "factory/*", "factory/job-*", "**"];

/// Judges every workflow file and returns the exposed ones, ordered by path. `default_branch` is
/// the branch the factory opens its pull requests against.
#[must_use]
pub fn exposed_workflows(files: &[WorkflowFile], default_branch: &str) -> Vec<ExposedWorkflow> {
    let mut exposed: Vec<ExposedWorkflow> = files
        .iter()
        .filter_map(|file| classify(&file.path, file.text.as_deref(), default_branch))
        .collect();
    exposed.sort_by(|a, b| a.path.cmp(&b.path));
    exposed
}

/// Judges one workflow file. `None` means the factory's push and pull request do not start it,
/// or start it with nothing in reach. A `text` of `None` (the host could not give the file) and a
/// text this module cannot read are exposed as `unreadable`.
#[must_use]
pub fn classify(path: &str, text: Option<&str>, default_branch: &str) -> Option<ExposedWorkflow> {
    let reasons = match text.and_then(read) {
        Some(root) => reasons_of(&root, default_branch),
        None => BTreeSet::from([WorkflowExposureReason::Unreadable]),
    };
    (!reasons.is_empty()).then(|| ExposedWorkflow {
        path: path.to_owned(),
        reasons: reasons.into_iter().collect(),
    })
}

// ------------------------------------------------------------------------------------------
// Reading
// ------------------------------------------------------------------------------------------

/// A value of a workflow file. Every scalar is text: this module never needs a number.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// An empty value, `~` or `null`.
    Nothing,
    /// A scalar.
    Text(String),
    /// A sequence.
    Seq(Vec<Node>),
    /// A mapping, in the order written. Keys are unique.
    Map(Vec<(String, Node)>),
}

impl Node {
    fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Map(entries) => entries
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }
}

enum Frame {
    Seq(Vec<Node>),
    Map {
        entries: Vec<(String, Node)>,
        key: Option<String>,
    },
}

fn is_nothing(text: &str) -> bool {
    matches!(text, "" | "~" | "null" | "Null" | "NULL")
}

/// A line that starts with `%` before the first line of content is a directive.
fn has_directive(text: &str) -> bool {
    text.lines()
        .map(str::trim_end)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .is_some_and(|line| line.starts_with('%'))
}

fn attach(stack: &mut [Frame], root: &mut Option<Node>, node: Node) {
    match stack.last_mut() {
        None => *root = Some(node),
        Some(Frame::Seq(items)) => items.push(node),
        Some(Frame::Map { entries, key }) => {
            if let Some(name) = key.take() {
                entries.push((name, node));
            }
        }
    }
}

/// Reads one workflow file, or refuses it. See the module notes for what is refused.
fn read(text: &str) -> Option<Node> {
    if text.len() > MAX_BYTES || has_directive(text) {
        return None;
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut root = None;
    let mut documents = 0_usize;
    let mut nodes = 0_usize;
    for item in Parser::new_from_str(text) {
        let (event, _) = item.ok()?;
        let expects_key = matches!(stack.last(), Some(Frame::Map { key: None, .. }));
        match event {
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
            Event::DocumentStart(_) => {
                documents += 1;
                if documents > 1 {
                    return None;
                }
            }
            Event::Alias(_) => return None,
            Event::Scalar(value, style, anchor, tag) => {
                nodes += 1;
                if anchor != 0 || tag.is_some() || nodes > MAX_NODES {
                    return None;
                }
                let plain = style == ScalarStyle::Plain;
                if expects_key {
                    if plain && (value == "<<" || is_nothing(&value)) {
                        return None;
                    }
                    let Some(Frame::Map { entries, key }) = stack.last_mut() else {
                        return None;
                    };
                    if entries.iter().any(|(name, _)| *name == *value) {
                        return None;
                    }
                    *key = Some(value.into_owned());
                } else if plain && is_nothing(&value) {
                    attach(&mut stack, &mut root, Node::Nothing);
                } else {
                    attach(&mut stack, &mut root, Node::Text(value.into_owned()));
                }
            }
            Event::SequenceStart(anchor, tag) | Event::MappingStart(anchor, tag)
                if anchor != 0 || tag.is_some() =>
            {
                return None;
            }
            Event::SequenceStart(..) | Event::MappingStart(..) => {
                nodes += 1;
                if expects_key || nodes > MAX_NODES || stack.len() >= MAX_DEPTH {
                    return None;
                }
                stack.push(if matches!(event, Event::SequenceStart(..)) {
                    Frame::Seq(Vec::new())
                } else {
                    Frame::Map {
                        entries: Vec::new(),
                        key: None,
                    }
                });
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let node = match stack.pop()? {
                    Frame::Seq(items) => Node::Seq(items),
                    // A key with nothing after it at all is not a mapping this reader trusts.
                    Frame::Map { key: Some(_), .. } => return None,
                    Frame::Map { entries, .. } => Node::Map(entries),
                };
                attach(&mut stack, &mut root, node);
            }
        }
    }
    if stack.is_empty() { root } else { None }
}

// ------------------------------------------------------------------------------------------
// Rule S: is the workflow started by the factory's push or pull request?
// ------------------------------------------------------------------------------------------

/// What starts the workflow, as far as the factory is concerned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Started {
    /// By the push, the pull request, or another event of the factory's branch.
    by_the_factory: bool,
    /// By `pull_request_target` to the default branch.
    by_pull_request_target: bool,
}

/// The events of `on`, each with its filters (`Nothing` when it has none). `None` when `on` is
/// missing or has a shape this module does not know.
fn events(root: &Node) -> Option<Vec<(&str, &Node)>> {
    const NO_FILTERS: &Node = &Node::Nothing;
    match root.get("on")? {
        Node::Text(name) => Some(vec![(name.as_str(), NO_FILTERS)]),
        Node::Seq(items) => items
            .iter()
            .map(|item| match item {
                Node::Text(name) => Some((name.as_str(), NO_FILTERS)),
                _ => None,
            })
            .collect(),
        // Filters of a shape this module does not know (the list under `schedule`, or a mistake)
        // are kept: a `push` or a pull request event with such filters counts as unfiltered.
        Node::Map(entries) => Some(
            entries
                .iter()
                .map(|(name, filters)| (name.as_str(), filters))
                .collect(),
        ),
        Node::Nothing => None,
    }
}

/// The patterns of a branch filter: a list of scalars, or one scalar. `None` when the filter has
/// another shape.
fn patterns(filter: &Node) -> Option<Vec<&str>> {
    match filter {
        Node::Text(one) => Some(vec![one.as_str()]),
        Node::Seq(items) => items
            .iter()
            .map(|item| match item {
                Node::Text(pattern) => Some(pattern.as_str()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

fn is_literal(pattern: &str) -> bool {
    pattern
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
}

/// True unless the pattern certainly matches no name that starts with `start` (for the factory's
/// branches) or no name equal to `start` (when `whole` is true, for the default branch). Case is
/// ignored, which can only make more patterns match.
fn could_match(pattern: &str, start: &str, whole: bool) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let start = start.to_ascii_lowercase();
    if is_literal(&pattern) {
        return if whole {
            pattern == start
        } else {
            pattern.starts_with(&start)
        };
    }
    // Cut at the first special character. A `?` makes the character before it optional, so that
    // one is dropped too.
    let mut fixed: String = pattern
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
        .collect();
    if pattern[fixed.len()..].starts_with('?') {
        fixed.pop();
    }
    start.starts_with(&fixed) || (!whole && fixed.starts_with(&start))
}

/// Whether a `push` with these filters runs for a branch whose name starts with `factory/`.
fn push_reaches_the_factory(filters: &Node) -> bool {
    let include = filters.get("branches");
    let ignore = filters.get("branches-ignore");
    match (include, ignore) {
        // Only tags: a push to a branch does not start it. No filter at all: every branch does.
        (None, None) => filters.get("tags").is_none() && filters.get("tags-ignore").is_none(),
        (Some(include), None) => patterns(include).is_none_or(|list| {
            list.iter()
                .any(|pattern| could_match(pattern, FACTORY_PREFIX, false))
        }),
        (None, Some(ignore)) => patterns(ignore).is_none_or(|list| {
            list.iter().any(|pattern| pattern.starts_with('!'))
                || !list
                    .iter()
                    .any(|pattern| IGNORES_THE_FACTORY.contains(pattern))
        }),
        // GitHub refuses a workflow with both. Whatever it then does, this does not rely on it.
        (Some(_), Some(_)) => true,
    }
}

/// Whether a pull request event with these filters runs for a pull request to the default branch.
fn pull_request_reaches(filters: &Node, default_branch: &str) -> bool {
    let include = filters.get("branches");
    let ignore = filters.get("branches-ignore");
    match (include, ignore) {
        (None, None) => true,
        (Some(include), None) => patterns(include).is_none_or(|list| {
            list.iter()
                .any(|pattern| could_match(pattern, default_branch, true))
        }),
        (None, Some(ignore)) => patterns(ignore).is_none_or(|list| {
            list.iter().any(|pattern| pattern.starts_with('!'))
                || !list
                    .iter()
                    .any(|pattern| *pattern == default_branch || *pattern == "**")
        }),
        (Some(_), Some(_)) => true,
    }
}

fn started(events: &[(&str, &Node)], default_branch: &str) -> Started {
    let mut found = Started::default();
    for (name, filters) in events {
        match *name {
            "push" => found.by_the_factory |= push_reaches_the_factory(filters),
            "pull_request" => {
                found.by_the_factory |= pull_request_reaches(filters, default_branch);
            }
            "pull_request_target" => {
                if pull_request_reaches(filters, default_branch) {
                    found.by_the_factory = true;
                    found.by_pull_request_target = true;
                }
            }
            "create" | "pull_request_review" | "pull_request_review_comment" => {
                found.by_the_factory = true;
            }
            _ => {}
        }
    }
    found
}

// ------------------------------------------------------------------------------------------
// Rule R: what a started workflow puts in reach
// ------------------------------------------------------------------------------------------

fn is_name_character(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
}

/// True when the scalar reads the `secrets` context for anything other than `GITHUB_TOKEN`.
fn reads_a_secret(scalar: &str) -> bool {
    const WORD: &str = "secrets";
    const TOKEN: &str = ".github_token";
    let lower = scalar.to_ascii_lowercase();
    let mut from = 0;
    while let Some(offset) = lower[from..].find(WORD) {
        let at = from + offset;
        let after = &lower[at + WORD.len()..];
        from = at + WORD.len();
        if lower[..at]
            .chars()
            .next_back()
            .is_some_and(is_name_character)
        {
            continue;
        }
        let rest = after.trim_start();
        match rest.chars().next() {
            Some('.') => {
                let harmless = rest
                    .strip_prefix(TOKEN)
                    .is_some_and(|tail| !tail.chars().next().is_some_and(is_name_character));
                if !harmless {
                    return true;
                }
            }
            // An index, or the whole context handed to a function or closed in an expression.
            Some('[' | ')' | ',' | '}') => return true,
            _ => {}
        }
    }
    false
}

fn any_scalar_reads_a_secret(node: &Node) -> bool {
    match node {
        Node::Nothing => false,
        Node::Text(text) => reads_a_secret(text),
        Node::Seq(items) => items.iter().any(any_scalar_reads_a_secret),
        Node::Map(entries) => entries
            .iter()
            .any(|(key, value)| reads_a_secret(key) || any_scalar_reads_a_secret(value)),
    }
}

/// What a `permissions` value gives the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grant {
    /// Read or nothing, for every scope.
    ReadOnly,
    /// A write scope, or a value this module does not know.
    Write,
    /// The key is there with no value: taken as not declared.
    NotDeclared,
}

fn grant(permissions: &Node) -> Grant {
    let read_or_none =
        |level: &Node| matches!(level, Node::Text(level) if level == "read" || level == "none");
    match permissions {
        Node::Nothing => Grant::NotDeclared,
        Node::Text(all) if all == "read-all" => Grant::ReadOnly,
        Node::Map(scopes) if scopes.iter().all(|(_, level)| read_or_none(level)) => Grant::ReadOnly,
        _ => Grant::Write,
    }
}

/// True when the label is one of the names GitHub gives its own standard runners.
fn is_hosted_label(label: &str) -> bool {
    let label = label.to_ascii_lowercase();
    ["ubuntu-", "windows-", "macos-"].iter().any(|prefix| {
        label.strip_prefix(prefix).is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        })
    })
}

fn runner_reason(runs_on: &Node) -> Option<WorkflowExposureReason> {
    let labels: Vec<&str> = match runs_on {
        Node::Text(one) => vec![one.as_str()],
        Node::Seq(items) if !items.is_empty() => {
            let mut labels = Vec::new();
            for item in items {
                match item {
                    Node::Text(label) => labels.push(label.as_str()),
                    _ => return Some(WorkflowExposureReason::RunnerUnknown),
                }
            }
            labels
        }
        // A runner group, an empty list, nothing.
        _ => return Some(WorkflowExposureReason::RunnerUnknown),
    };
    if labels
        .iter()
        .any(|label| label.trim().eq_ignore_ascii_case("self-hosted"))
    {
        Some(WorkflowExposureReason::SelfHostedRunner)
    } else if labels.iter().all(|label| is_hosted_label(label)) {
        None
    } else {
        Some(WorkflowExposureReason::RunnerUnknown)
    }
}

fn reasons_of(root: &Node, default_branch: &str) -> BTreeSet<WorkflowExposureReason> {
    use WorkflowExposureReason as Reason;
    let unreadable = || BTreeSet::from([Reason::Unreadable]);
    let (Some(events), Some(Node::Map(jobs))) = (events(root), root.get("jobs")) else {
        return unreadable();
    };
    if jobs.is_empty() {
        return unreadable();
    }
    let started = started(&events, default_branch);
    if !started.by_the_factory {
        return BTreeSet::new();
    }
    let mut reasons = BTreeSet::new();
    if started.by_pull_request_target {
        reasons.insert(Reason::PullRequestTarget);
    }
    if any_scalar_reads_a_secret(root) {
        reasons.insert(Reason::UsesSecrets);
    }
    let top = root.get("permissions").map(grant);
    if top == Some(Grant::Write) {
        reasons.insert(Reason::WritePermissions);
    }
    for (_, job) in jobs {
        if !matches!(job, Node::Map(_)) {
            return unreadable();
        }
        // The permissions of a job replace those of the top level; a job without any has the
        // top level's.
        let in_force = match job.get("permissions").map(grant) {
            Some(Grant::NotDeclared) | None => top.unwrap_or(Grant::NotDeclared),
            Some(own) => own,
        };
        match in_force {
            Grant::Write => {
                reasons.insert(Reason::WritePermissions);
            }
            Grant::NotDeclared => {
                reasons.insert(Reason::PermissionsNotDeclared);
            }
            Grant::ReadOnly => {}
        }
        match (job.get("runs-on"), job.get("uses")) {
            (Some(runs_on), None) => reasons.extend(runner_reason(runs_on)),
            (None, Some(_)) => {
                reasons.insert(Reason::CallsReusableWorkflow);
                if matches!(job.get("secrets"), Some(Node::Text(all)) if all == "inherit") {
                    reasons.insert(Reason::InheritsSecrets);
                }
            }
            // A job needs exactly one of the two.
            _ => return unreadable(),
        }
    }
    reasons
}

#[cfg(test)]
mod tests {
    use super::*;
    use WorkflowExposureReason as Reason;

    const SAFE_JOB: &str =
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n";

    fn reasons(text: &str) -> Vec<Reason> {
        classify(".github/workflows/w.yml", Some(text), "main")
            .map(|exposed| exposed.reasons)
            .unwrap_or_default()
    }

    fn read_only(on: &str) -> String {
        format!("on:\n{on}permissions:\n  contents: read\n{SAFE_JOB}")
    }

    fn with_a_secret(on: &str) -> String {
        format!(
            "{}        env:\n          KEY: ${{{{ secrets.DEPLOY_KEY }}}}\n",
            read_only(on)
        )
    }

    #[test]
    fn the_reader_reads_the_shapes_real_workflows_use() {
        // The plain key `on`, keys with no value, a flow list, a block scalar, a comment.
        let text = "name: ci\n\non:\n  pull_request:\n  push:\n    branches: [main]\n  workflow_dispatch:\n\n# Read only.\npermissions:\n  contents: read\n\njobs:\n  ci:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n      - run: |\n          echo one\n          echo two\n";
        let root = read(text).expect("a workflow");
        assert_eq!(
            root.get("on").and_then(|on| on.get("pull_request")),
            Some(&Node::Nothing)
        );
        assert_eq!(reasons(text), []);
    }

    #[test]
    fn the_workflow_of_this_repository_is_read_and_is_not_exposed() {
        // A real file, not one written for the test: `pull_request` with no filter, `push` to
        // main, a read-only token, a runner of GitHub and no secret. Its comments say "secrets",
        // and comments are not read.
        let text = include_str!("../../../.github/workflows/ci.yml");
        assert!(read(text).is_some(), "the reader refuses the real workflow");
        assert_eq!(reasons(text), []);
    }

    #[test]
    fn the_reader_refuses_what_two_readers_could_read_differently() {
        let base = read_only("  push:\n");
        for (what, text) in [
            ("an anchor and an alias", format!("{base}x: &a 1\ny: *a\n")),
            ("a tag", format!("{base}x: !!str 1\n")),
            ("a duplicate key", format!("{base}permissions: write-all\n")),
            ("a second document", format!("{base}---\nx: 1\n")),
            ("a directive", format!("%YAML 1.1\n---\n{base}")),
            ("a merge key", format!("{base}x:\n  <<: {{a: 1}}\n")),
            ("a list as a key", format!("{base}? [a]\n: 1\n")),
            ("broken text", format!("{base}x: [1, 2\n")),
            ("no text", String::new()),
            ("a list", "- a\n- b\n".to_owned()),
            ("a scalar", "hello".to_owned()),
        ] {
            assert_eq!(reasons(&text), [Reason::Unreadable], "{what}");
        }
        let deep = format!("{base}x: {}1{}\n", "[".repeat(40), "]".repeat(40));
        assert_eq!(reasons(&deep), [Reason::Unreadable]);
        let large = format!("{base}# {}\n", "x".repeat(MAX_BYTES));
        assert_eq!(reasons(&large), [Reason::Unreadable]);
        assert_eq!(
            classify("w.yml", None, "main").map(|exposed| exposed.reasons),
            Some(vec![Reason::Unreadable])
        );
    }

    #[test]
    fn a_workflow_without_triggers_or_jobs_this_module_knows_is_unreadable() {
        for text in [
            "permissions: read-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n",
            "on:\njobs:\n  a:\n    runs-on: ubuntu-latest\n",
            "on: [push, {a: b}]\njobs:\n  a:\n    runs-on: ubuntu-latest\n",
            "on: push\n",
            "on: push\njobs: {}\n",
            "on: push\njobs:\n  a: nothing\n",
            "on: push\npermissions: read-all\njobs:\n  a:\n    steps: []\n",
            "on: push\npermissions: read-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    uses: ./x.yml\n",
        ] {
            assert_eq!(reasons(text), [Reason::Unreadable], "{text}");
        }
    }

    #[test]
    fn a_push_reaches_the_factory_unless_its_filters_leave_the_factory_out() {
        let reached = |on: &str| reasons(&with_a_secret(on)) == [Reason::UsesSecrets];
        // Reached.
        for on in [
            "  push:\n",
            "  push: {}\n",
            "  push: [main]\n",
            "  push:\n    paths: ['src/**']\n",
            "  push:\n    branches: ['**']\n",
            "  push:\n    branches: ['*/*']\n",
            "  push:\n    branches: [main, 'factory/**']\n",
            "  push:\n    branches: [factory/job-1]\n",
            "  push:\n    branches: ['f*']\n",
            "  push:\n    branches: ['factoryx?/**']\n",
            "  push:\n    branches: ['FACTORY/**']\n",
            "  push:\n    branches: ['**', '!factory/**']\n",
            "  push:\n    branches: {a: b}\n",
            "  push:\n    branches-ignore: [main]\n",
            "  push:\n    branches-ignore: ['factory/job-1']\n",
            "  push:\n    branches-ignore: ['factory/**', '!factory/job-*']\n",
            "  push:\n    branches: [main]\n    branches-ignore: ['factory/**']\n",
            "  push:\n    tags: ['v*']\n    branches-ignore: [main]\n",
            "  create:\n",
            "  pull_request_review:\n",
            "  pull_request_review_comment:\n",
        ] {
            assert!(reached(on), "{on}");
        }
        assert!(
            reasons(&with_a_secret("  push:\n").replace("on:\n  push:\n", "on: push\n"))
                == [Reason::UsesSecrets]
        );
        assert!(
            reasons(&with_a_secret("  push:\n").replace("on:\n  push:\n", "on: [push]\n"))
                == [Reason::UsesSecrets]
        );
        // Not reached.
        for on in [
            "  push:\n    branches: [main]\n",
            "  push:\n    branches: main\n",
            "  push:\n    branches: [main, 'release/**', 'v[0-9]+', 'feat?/x']\n",
            "  push:\n    branches: ['feature/*']\n",
            "  push:\n    branches-ignore: ['factory/**']\n",
            "  push:\n    branches-ignore: [docs, 'factory/*']\n",
            "  push:\n    branches-ignore: ['factory/job-*']\n",
            "  push:\n    tags: ['v*']\n",
            "  push:\n    tags-ignore: ['x']\n",
            "  workflow_dispatch:\n",
            "  schedule:\n    - cron: '0 3 * * *'\n",
            "  workflow_call:\n",
        ] {
            assert_eq!(reasons(&with_a_secret(on)), [], "{on}");
        }
    }

    #[test]
    fn a_pull_request_reaches_the_factory_when_its_base_filters_include_the_default_branch() {
        let reached = |on: &str| reasons(&with_a_secret(on)) == [Reason::UsesSecrets];
        for on in [
            "  pull_request:\n",
            "  pull_request:\n    types: [closed]\n",
            "  pull_request:\n    branches: [main]\n",
            "  pull_request:\n    branches: [MAIN]\n",
            "  pull_request:\n    branches: ['m*']\n",
            "  pull_request:\n    branches: ['**']\n",
            "  pull_request:\n    branches: ['release/**', main]\n",
            "  pull_request:\n    branches-ignore: [develop]\n",
            "  pull_request:\n    branches-ignore: [main, '!main']\n",
            "  pull_request:\n    branches-ignore: ['ma*']\n",
        ] {
            assert!(reached(on), "{on}");
        }
        for on in [
            "  pull_request:\n    branches: [develop]\n",
            "  pull_request:\n    branches: ['release/**']\n",
            "  pull_request:\n    branches: [mainline]\n",
            "  pull_request:\n    branches-ignore: [main]\n",
            "  pull_request:\n    branches-ignore: ['**']\n",
        ] {
            assert_eq!(reasons(&with_a_secret(on)), [], "{on}");
        }
        // The default branch is the one the caller names, not the word "main".
        let develop = with_a_secret("  pull_request:\n    branches: [develop]\n");
        assert!(classify("w.yml", Some(&develop), "develop").is_some());
    }

    #[test]
    fn pull_request_target_is_a_reason_of_its_own() {
        assert_eq!(
            reasons(&read_only("  pull_request_target:\n")),
            [Reason::PullRequestTarget]
        );
        assert_eq!(
            reasons(&read_only(
                "  pull_request_target:\n    branches: [release]\n"
            )),
            []
        );
    }

    #[test]
    fn only_a_read_of_the_secrets_context_for_another_name_is_a_secret() {
        for (scalar, expected) in [
            ("${{ secrets.DEPLOY_KEY }}", true),
            ("${{ SECRETS.deploy_key }}", true),
            ("${{ secrets['DEPLOY_KEY'] }}", true),
            ("${{ secrets [ 'X' ] }}", true),
            ("${{ toJSON(secrets) }}", true),
            ("${{ format('{0}', secrets, 1) }}", true),
            ("${{ secrets }}", true),
            ("${{ secrets.GITHUB_TOKEN_2 }}", true),
            ("${{ secrets.GITHUB_TOKEN }} ${{ secrets.OTHER }}", true),
            ("cat secrets.txt", true),
            ("${{ secrets.GITHUB_TOKEN }}", false),
            ("${{ secrets.github_token }}", false),
            ("${{ secrets . GITHUB_TOKEN}}", true),
            ("${{ github.token }}", false),
            ("Scan for secrets", false),
            ("no-secrets.sh", false),
            ("mysecrets.NAME", false),
            ("secrets: inherit", false),
            ("", false),
        ] {
            assert_eq!(reads_a_secret(scalar), expected, "{scalar}");
        }
        // A comment is not read; a key is.
        let commented = format!("{}# ${{{{ secrets.X }}}}\n", read_only("  push:\n"));
        assert_eq!(reasons(&commented), []);
    }

    #[test]
    fn permissions_are_judged_for_every_job() {
        let job = |permissions: &str| {
            format!("  j:\n    runs-on: ubuntu-latest\n{permissions}    steps: []\n")
        };
        let workflow =
            |top: &str, jobs: &[String]| format!("on: push\n{top}jobs:\n{}", jobs.concat());
        for (top, in_job, expected) in [
            ("", "", vec![Reason::PermissionsNotDeclared]),
            ("permissions:\n", "", vec![Reason::PermissionsNotDeclared]),
            ("permissions: {}\n", "", vec![]),
            ("permissions: read-all\n", "", vec![]),
            (
                "permissions:\n  contents: read\n  issues: none\n",
                "",
                vec![],
            ),
            (
                "permissions: write-all\n",
                "",
                vec![Reason::WritePermissions],
            ),
            (
                "permissions:\n  contents: write\n",
                "",
                vec![Reason::WritePermissions],
            ),
            (
                "permissions:\n  id-token: write\n",
                "",
                vec![Reason::WritePermissions],
            ),
            (
                "permissions:\n  contents: admin\n",
                "",
                vec![Reason::WritePermissions],
            ),
            ("permissions: [read]\n", "", vec![Reason::WritePermissions]),
            ("", "    permissions:\n      contents: read\n", vec![]),
            ("", "    permissions: {}\n", vec![]),
            (
                "permissions: read-all\n",
                "    permissions:\n      pull-requests: write\n",
                vec![Reason::WritePermissions],
            ),
            (
                "permissions: write-all\n",
                "    permissions: read-all\n",
                vec![Reason::WritePermissions],
            ),
        ] {
            assert_eq!(
                reasons(&workflow(top, &[job(in_job)])),
                expected,
                "{top}{in_job}"
            );
        }
        // One job that declares and one that does not.
        let two = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions: read-all\n  b:\n    runs-on: ubuntu-latest\n";
        assert_eq!(reasons(two), [Reason::PermissionsNotDeclared]);
    }

    #[test]
    fn a_runner_is_safe_only_when_the_file_names_a_runner_of_github() {
        let workflow = |runs_on: &str| {
            format!("on: push\npermissions: read-all\njobs:\n  j:\n    runs-on: {runs_on}\n")
        };
        for (runs_on, expected) in [
            ("ubuntu-latest", vec![]),
            ("ubuntu-24.04", vec![]),
            ("[macos-14]", vec![]),
            ("windows-2025", vec![]),
            ("self-hosted", vec![Reason::SelfHostedRunner]),
            ("[self-hosted, linux]", vec![Reason::SelfHostedRunner]),
            ("[Self-Hosted]", vec![Reason::SelfHostedRunner]),
            ("${{ matrix.os }}", vec![Reason::RunnerUnknown]),
            (
                "[ubuntu-latest, '${{ inputs.runner }}']",
                vec![Reason::RunnerUnknown],
            ),
            ("gpu-box", vec![Reason::RunnerUnknown]),
            ("ubuntu-", vec![Reason::RunnerUnknown]),
            ("{group: big}", vec![Reason::RunnerUnknown]),
            ("[]", vec![Reason::RunnerUnknown]),
            ("[[ubuntu-latest]]", vec![Reason::RunnerUnknown]),
        ] {
            assert_eq!(reasons(&workflow(runs_on)), expected, "{runs_on}");
        }
        assert_eq!(
            reasons("on: push\npermissions: read-all\njobs:\n  j:\n    runs-on:\n"),
            [Reason::RunnerUnknown]
        );
    }

    #[test]
    fn a_call_of_a_reusable_workflow_is_exposed_and_inherit_is_named() {
        let call = "on: pull_request\npermissions: read-all\njobs:\n  j:\n    uses: ./.github/workflows/build.yml\n";
        assert_eq!(reasons(call), [Reason::CallsReusableWorkflow]);
        assert_eq!(
            reasons(&format!("{call}    secrets: inherit\n")),
            [Reason::InheritsSecrets, Reason::CallsReusableWorkflow]
        );
    }

    #[test]
    fn an_environment_does_not_make_a_job_safe() {
        let text = "on: pull_request\npermissions: read-all\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    environment: production\n    steps:\n      - run: ./deploy.sh\n        env:\n          KEY: ${{ secrets.DEPLOY_KEY }}\n";
        assert_eq!(reasons(text), [Reason::UsesSecrets]);
    }

    #[test]
    fn every_reason_is_listed_and_the_list_is_ordered_by_path() {
        let all = "on:\n  pull_request_target:\njobs:\n  a:\n    runs-on: self-hosted\n    permissions: write-all\n    env:\n      K: ${{ secrets.K }}\n  b:\n    runs-on: ${{ matrix.os }}\n  c:\n    uses: o/r/.github/workflows/w.yml@v1\n    secrets: inherit\n";
        assert_eq!(
            reasons(all),
            [
                Reason::UsesSecrets,
                Reason::WritePermissions,
                Reason::PermissionsNotDeclared,
                Reason::SelfHostedRunner,
                Reason::RunnerUnknown,
                Reason::PullRequestTarget,
                Reason::InheritsSecrets,
                Reason::CallsReusableWorkflow,
            ]
        );
        let files = [
            WorkflowFile {
                path: ".github/workflows/z.yml".to_owned(),
                text: None,
            },
            WorkflowFile {
                path: ".github/workflows/safe.yml".to_owned(),
                text: Some(read_only("  push:\n")),
            },
            WorkflowFile {
                path: ".github/workflows/a.yml".to_owned(),
                text: Some(all.to_owned()),
            },
        ];
        let exposed = exposed_workflows(&files, "main");
        let paths: Vec<&str> = exposed.iter().map(|w| w.path.as_str()).collect();
        assert_eq!(
            paths,
            [".github/workflows/a.yml", ".github/workflows/z.yml"]
        );
    }
}
