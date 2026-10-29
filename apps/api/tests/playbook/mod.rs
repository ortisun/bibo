//! The scripted agent playbook for `fixtures/repos/word-count`.
//!
//! # What this is
//!
//! A test double for the nine agents of the factory. It gives each agent, for the one task of the
//! fixture (add a `--json` option), the answer a competent agent would give. It is **scripted**: no
//! model is called, and every output it makes says so in the one place a person looks (the
//! runtime reports fidelity `fake`, and the specification stage records that in its evidence).
//!
//! The data is in `fixtures/recordings/playbook/word-count/` (see the README there): the agents'
//! answers as JSON, the Spec Kit files, the builder's patch and the documents. This module is the
//! loader and the runtime that hands them out.
//!
//! # Rules the runtime keeps
//!
//! * An answer is handed out **by role**, and by the skill or the task where the role has several
//!   (the specification writer runs two skills, the builder runs one task at a time).
//! * An agent that is asked for something the playbook has no entry for **fails loudly**: the
//!   runtime panics with a message that names the agent and the entry, and the miss is also kept
//!   in [`Playbook::misses`]. It never answers "done" to a question nobody planned for. The same
//!   happens when an entry is asked for more often than the playbook allows: a second call to the
//!   architect means the first answer was refused, and the playbook has no second answer.
//! * What an agent does in the checkout (the specification files, the builder's patch, the
//!   documents) is written into the workspace of the sandbox it runs in, through the fake
//!   workspace provider, before the answer is returned. The host then audits and commits it as it
//!   would a real tree.
//! * A test that breaks the pipeline on purpose does it through [`Playbook::replace`] and
//!   [`Playbook::tweak`], which are visible at the call site.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{
    AgentRunError, AgentRunReport, AgentRunRequest, AgentRuntime, ProbeError, RuntimeCapabilities,
    RuntimeId,
};
use factory_ports::clock::CancelSignal;
use factory_ports::paths::RepoPath;
use factory_ports::sandbox::SandboxSession;
use factory_testkit::agent::{AdversarialScript, FakeAgentRuntime};
use factory_testkit::contracts::workspace::TreeEdit;
use factory_testkit::workspace::FakeWorkspaceProvider;
use serde_json::Value;

/// The directory of the data, below the repository root.
const DATA: &str = "fixtures/recordings/playbook/word-count";

/// The two tasks of the plan, in the order the builder runs them.
pub const TASKS: [&str; 2] = ["write-json-formatter", "read-json-option"];

/// The files each task changes, as `(path in the checkout, file under patch/)`.
const PATCH: [(&str, &[(&str, &str)]); 2] = [
    (TASKS[0], &[("src/lib.rs", "src/lib.rs")]),
    (
        TASKS[1],
        &[
            ("src/main.rs", "src/main.rs"),
            ("tests/json_output.rs", "tests/json_output.rs"),
        ],
    ),
];

/// One answer of the playbook: what the agent returns, and what it does in the checkout.
#[derive(Debug, Clone)]
pub struct Reply {
    /// The name of the entry, for the log.
    pub entry: String,
    /// The final output the agent submits.
    pub output: Value,
    /// The files the agent writes in the checkout of its sandbox.
    pub writes: Vec<(String, Vec<u8>)>,
}

/// One call the playbook answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    /// The agent that asked.
    pub agent: String,
    /// The entry that answered.
    pub entry: String,
    /// The paths the agent wrote in its checkout, as it was served (after any change a test made).
    pub wrote: Vec<String>,
}

type Tweak = Box<dyn Fn(&mut Reply) + Send + Sync>;

#[derive(Default)]
struct State {
    served: Vec<Served>,
    misses: Vec<String>,
    replaced: BTreeMap<String, Reply>,
    tweaks: BTreeMap<String, Tweak>,
    repeatable: std::collections::BTreeSet<String>,
}

/// The playbook for the word-count fixture.
pub struct Playbook {
    root: PathBuf,
    state: Mutex<State>,
}

impl Playbook {
    /// The playbook whose data is under `repository_root`.
    pub fn word_count(repository_root: &Path) -> Arc<Self> {
        let root = repository_root.join(DATA);
        assert!(root.is_dir(), "the playbook data is at {}", root.display());
        Arc::new(Self {
            root,
            state: Mutex::new(State::default()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("the playbook lock is not poisoned")
    }

    /// The calls answered so far, oldest first.
    pub fn served(&self) -> Vec<Served> {
        self.lock().served.clone()
    }

    /// The agents that asked for something the playbook has no entry for.
    pub fn misses(&self) -> Vec<String> {
        self.lock().misses.clone()
    }

    /// How many times the entry has been served.
    pub fn times_served(&self, entry: &str) -> usize {
        self.lock()
            .served
            .iter()
            .filter(|served| served.entry == entry)
            .count()
    }

    /// Replaces the answer for an entry. For a deliberate break; the call site shows it.
    pub fn replace(&self, entry: &str, reply: Reply) {
        self.lock().replaced.insert(entry.to_owned(), reply);
    }

    /// Lets the entries be asked for again. A deliberate break that makes a stage ask its agent a
    /// second time (a retry, a round of rework) says so here; the honest run never does.
    pub fn allow_repeats(&self, entries: &[&str]) {
        self.lock()
            .repeatable
            .extend(entries.iter().map(|entry| (*entry).to_owned()));
    }

    /// Changes the answer for an entry after it is made. For a deliberate break.
    pub fn tweak(&self, entry: &str, change: impl Fn(&mut Reply) + Send + Sync + 'static) {
        self.lock()
            .tweaks
            .insert(entry.to_owned(), Box::new(change));
    }

    // ---- reading the data ------------------------------------------------------------------

    fn text(&self, relative: &str) -> String {
        std::fs::read_to_string(self.root.join(relative))
            .unwrap_or_else(|error| panic!("the playbook file {relative} is readable: {error}"))
    }

    fn json(&self, relative: &str) -> Value {
        serde_json::from_str(&self.text(relative))
            .unwrap_or_else(|error| panic!("the playbook file {relative} is JSON: {error}"))
    }

    /// The text of the constitution the repository already has.
    pub fn constitution(&self) -> String {
        self.text("constitution.md")
    }

    /// The text a file of the builder's patch has once the task is done.
    pub fn patched(&self, patch_file: &str) -> Vec<u8> {
        self.text(&format!("patch/{patch_file}")).into_bytes()
    }

    /// The text of a document the documenter writes.
    pub fn document(&self, name: &str) -> Vec<u8> {
        self.text(&format!("docs/{name}")).into_bytes()
    }

    /// The text a program printed in the verify sandbox, recorded from the real program.
    pub fn recorded(&self, name: &str) -> String {
        self.text(&format!("sandbox/{name}"))
    }

    // ---- answering -------------------------------------------------------------------------

    /// The answer for one call, or a panic that names what was asked.
    ///
    /// `instructions` is the whole prompt the agent received.
    pub fn answer(&self, agent: &str, instructions: &str) -> Reply {
        match self.try_answer(agent, instructions) {
            Ok(reply) => reply,
            Err(message) => {
                self.lock().misses.push(message.clone());
                panic!("the playbook has no entry for this call: {message}");
            }
        }
    }

    fn try_answer(&self, agent: &str, instructions: &str) -> Result<Reply, String> {
        let entry = self.entry_for(agent, instructions)?;
        let times = self.times_served(&entry);
        let replaced = self.lock().replaced.get(&entry).cloned();
        let repeatable = self.lock().repeatable.contains(&entry);
        if times >= 1 && replaced.is_none() && !repeatable {
            return Err(format!(
                "{agent} asked for the entry {entry} for the {} time, and the playbook has one answer for it",
                times + 1
            ));
        }
        let mut reply = match replaced {
            Some(reply) => reply,
            None => self.build(&entry, agent, instructions)?,
        };
        if let Some(change) = self.lock().tweaks.get(&entry) {
            change(&mut reply);
        }
        let wrote = reply.writes.iter().map(|(path, _)| path.clone()).collect();
        self.lock().served.push(Served {
            agent: agent.to_owned(),
            entry,
            wrote,
        });
        Ok(reply)
    }

    /// Which entry a call is for.
    fn entry_for(&self, agent: &str, instructions: &str) -> Result<String, String> {
        match agent {
            "intake-classifier" => Ok("intake-classifier".to_owned()),
            "specification-writer" => match skill_of(instructions) {
                Some(skill @ ("specify" | "checklist")) => {
                    Ok(format!("specification-writer.{skill}"))
                }
                Some(other) => Err(format!(
                    "specification-writer was asked to run the skill {other}, which the playbook does not have"
                )),
                None => Err(
                    "specification-writer was asked for something that is not a Spec Kit skill"
                        .to_owned(),
                ),
            },
            "specification-reviewer"
            | "architect"
            | "planner"
            | "code-reviewer"
            | "documentation-writer"
            | "documentation-reviewer" => Ok(agent.to_owned()),
            "builder" => {
                let task = block(instructions, "task");
                // A rework round gives the builder one task that lists the tasks of the plan for
                // context, so it names all of them. The playbook has no data file for a rework
                // answer; a test that drives a rework round supplies one with `replace`.
                if let Some(round) = task.strip_prefix("Task rework-round-") {
                    let number: String = round.chars().take_while(char::is_ascii_digit).collect();
                    return Ok(format!("builder.rework-round-{number}"));
                }
                let known: Vec<&str> = TASKS
                    .into_iter()
                    .filter(|task_id| task.contains(task_id))
                    .collect();
                match known.as_slice() {
                    [one] => Ok(format!("builder.{one}")),
                    [] => Err(format!(
                        "builder was given a task the playbook does not know (it knows {TASKS:?})"
                    )),
                    several => Err(format!(
                        "builder was given a task that names several known tasks: {several:?}"
                    )),
                }
            }
            other => Err(format!("{other} is not an agent the playbook plays")),
        }
    }

    fn build(&self, entry: &str, _agent: &str, instructions: &str) -> Result<Reply, String> {
        let file = format!("agent-output/{entry}.json");
        let mut output = self.json(&file);
        let mut writes: Vec<(String, Vec<u8>)> = Vec::new();
        match entry {
            "specification-writer.specify" | "specification-writer.checklist" => {
                let feature = feature_directory_of(instructions)
                    .ok_or("the skill instruction names no feature directory")?;
                substitute(&mut output, "{{FEATURE_DIR}}", &feature);
                let name = feature.rsplit('/').next().unwrap_or(&feature).to_owned();
                let fill = |template: String| {
                    template
                        .replace("{{FEATURE_DIR}}", &feature)
                        .replace("{{TITLE}}", "Add a JSON output option")
                        .replace("{{BRANCH}}", &name)
                        .replace("{{INPUT}}", &argument_of(instructions))
                        // The checklists sit one directory below the specification in the
                        // workspace, and next to it in the fixture, where the link must resolve.
                        .replace("](spec.md)", "](../spec.md)")
                };
                if entry.ends_with("specify") {
                    writes.push((
                        format!("{feature}/spec.md"),
                        fill(self.text("specification/spec.md")).into_bytes(),
                    ));
                    writes.push((
                        format!("{feature}/checklists/requirements.md"),
                        fill(self.text("specification/requirements-checklist.md")).into_bytes(),
                    ));
                    writes.push((
                        ".specify/feature.json".to_owned(),
                        fill(self.text("specification/feature.json")).into_bytes(),
                    ));
                } else {
                    writes.push((
                        format!("{feature}/checklists/requirements-quality.md"),
                        fill(self.text("specification/requirements-quality-checklist.md"))
                            .into_bytes(),
                    ));
                }
            }
            "planner" => {
                let metadata: Value =
                    serde_json::from_str(&block(instructions, "plan_metadata"))
                        .map_err(|_| "the planner prompt carries no plan metadata as JSON")?;
                let specification: Value =
                    serde_json::from_str(&block(instructions, "frozen_specification"))
                        .map_err(|_| "the planner prompt carries no specification as JSON")?;
                output["plan"]["metadata"] = metadata;
                expand_scenarios(&mut output["plan"]["tasks"], &specification);
            }
            builder if builder.starts_with("builder.") => {
                let task = &builder["builder.".len()..];
                let files = PATCH
                    .iter()
                    .find(|(id, _)| *id == task)
                    .map(|(_, files)| *files)
                    .ok_or_else(|| format!("no patch for the task {task}"))?;
                for (path, from) in files {
                    writes.push(((*path).to_owned(), self.patched(from)));
                }
            }
            "documentation-writer" => {
                writes.push(("README.md".to_owned(), self.document("README.md")));
                writes.push(("CHANGELOG.md".to_owned(), self.document("CHANGELOG.md")));
            }
            _ => {}
        }
        Ok(Reply {
            entry: entry.to_owned(),
            output,
            writes,
        })
    }
}

/// Replaces `from` by `to` in every string of the document.
fn substitute(value: &mut Value, from: &str, to: &str) {
    match value {
        Value::String(text) if text.contains(from) => *text = text.replace(from, to),
        Value::Array(items) => items.iter_mut().for_each(|item| substitute(item, from, to)),
        Value::Object(map) => map.values_mut().for_each(|item| substitute(item, from, to)),
        _ => {}
    }
}

/// Turns each `@FR-001` in a task's scenario list into the identifiers of the scenarios that cite
/// that requirement, as the frozen specification lists them.
fn expand_scenarios(tasks: &mut Value, specification: &Value) {
    let scenarios_of = |requirement: &str| -> Vec<String> {
        specification["requirements"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|found| found["id"] == requirement)
            .flat_map(|found| {
                found["acceptance_scenario_ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|id| id.as_str().map(str::to_owned))
            })
            .collect()
    };
    for task in tasks.as_array_mut().into_iter().flatten() {
        let listed = task["acceptance_mapping"]["acceptance_scenario_ids"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut expanded: Vec<String> = Vec::new();
        for item in listed {
            let Some(text) = item.as_str() else { continue };
            match text.strip_prefix('@') {
                Some(requirement) => {
                    for id in scenarios_of(requirement) {
                        if !expanded.contains(&id) {
                            expanded.push(id);
                        }
                    }
                }
                None => expanded.push(text.to_owned()),
            }
        }
        task["acceptance_mapping"]["acceptance_scenario_ids"] = Value::from(expanded);
    }
}

/// The text of one data block of a prompt, with the quoting removed.
pub fn block(prompt: &str, name: &str) -> String {
    let open = format!("<<<DATA name={name} ");
    let close = format!("<<<END name={name}>>>");
    let mut inside = false;
    let mut lines: Vec<&str> = Vec::new();
    for line in prompt.lines() {
        if line.starts_with(&open) {
            inside = true;
        } else if line.starts_with(&close) {
            break;
        } else if inside {
            lines.push(
                line.strip_prefix("> ")
                    .unwrap_or(line.trim_start_matches('>')),
            );
        }
    }
    lines.join("\n")
}

/// The Spec Kit skill a prompt invokes: `/speckit-specify ...` and the like.
fn skill_of(instructions: &str) -> Option<&str> {
    let rest = instructions
        .strip_prefix(['/', '$'])?
        .strip_prefix("speckit")?
        .strip_prefix(['-', '.'])?;
    let end = rest
        .find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(rest.len());
    (end > 0).then(|| &rest[..end])
}

/// The text after the invocation: what Spec Kit would call its arguments.
fn argument_of(instructions: &str) -> String {
    instructions
        .split_once(' ')
        .map_or_else(String::new, |(_, rest)| rest.trim().to_owned())
}

/// The feature directory the fixed instruction names ("... in the directory `specs/x`, ...").
fn feature_directory_of(instructions: &str) -> Option<String> {
    let at = instructions.find("the directory ")? + "the directory ".len();
    let name: String = instructions[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_'))
        .collect();
    name.starts_with("specs/").then_some(name)
}

// ---- the runtime ---------------------------------------------------------------------------

/// The agent runtime that plays the playbook. It reports fidelity `fake`.
///
/// It wraps the testkit's scripted runtime, which keeps the capability checks, the transcript and
/// the usage, and adds two things: the answer comes from the playbook by role, and the files the
/// agent would write are written into the workspace the sandbox was made over.
pub struct PlaybookRuntime {
    inner: FakeAgentRuntime,
    playbook: Arc<Playbook>,
    workspaces: Arc<FakeWorkspaceProvider>,
}

impl PlaybookRuntime {
    /// Every prompt the runtime received, as text, oldest first.
    pub fn prompts(&self) -> Vec<String> {
        self.inner
            .recorded_prompts()
            .into_iter()
            .map(|prompt| prompt.instructions)
            .collect()
    }

    /// A runtime over the playbook. `inner` stores transcripts; `workspaces` is the fake provider
    /// that made the workspaces the sandboxes mount.
    pub fn new(
        inner: FakeAgentRuntime,
        playbook: Arc<Playbook>,
        workspaces: Arc<FakeWorkspaceProvider>,
    ) -> Self {
        Self {
            inner,
            playbook,
            workspaces,
        }
    }
}

#[async_trait]
impl AgentRuntime for PlaybookRuntime {
    fn id(&self) -> &RuntimeId {
        self.inner.id()
    }

    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn probe(
        &self,
        session: &mut dyn SandboxSession,
    ) -> Result<RuntimeCapabilities, ProbeError> {
        self.inner.probe(session).await
    }

    async fn run(
        &self,
        session: &mut dyn SandboxSession,
        req: AgentRunRequest,
        cancel: &dyn CancelSignal,
    ) -> AgentRunReport {
        let agent = req.agent.id.as_str().to_owned();
        let reply = self.playbook.answer(&agent, &req.prompt.instructions);
        if !reply.writes.is_empty() {
            let mount = session
                .posture()
                .mounts
                .iter()
                .find(|mount| mount.target == "/workspace")
                .map(|mount| PathBuf::from(&mount.source))
                .unwrap_or_else(|| {
                    panic!("the sandbox of {agent} has no /workspace mount to write the files into")
                });
            for (path, bytes) in &reply.writes {
                let path = RepoPath::new(path)
                    .unwrap_or_else(|_| panic!("the playbook wrote a bad path: {path}"));
                self.workspaces
                    .edit_tree(&mount, TreeEdit::Write(path, bytes.clone()))
                    .unwrap_or_else(|error| panic!("the playbook could not write a file: {error}"));
            }
        }
        self.inner
            .queue(AdversarialScript::returning(reply.output.clone()));
        let report = self.inner.run(session, req, cancel).await;
        if matches!(report.outcome, Err(AgentRunError::OutputMissing)) {
            // The inner runtime had no script left, which cannot happen after the queue above.
            panic!("the scripted runtime lost the answer of {agent}");
        }
        report
    }
}
