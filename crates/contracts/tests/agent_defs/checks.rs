//! The rules every agent manifest and prompt must follow. Each check returns plain-English
//! problems, and an empty list means the definition is fine. The tests run the checks on the real
//! files, and again on deliberately broken copies to show that each break is caught.

use std::collections::BTreeSet;

use factory_contracts::policy::SecurityPolicy;
use factory_contracts::policy::security::{AppliesTo, ProtectionMode};
use globset::GlobBuilder;
use serde_json::Value;

/// The headings every prompt has, in this order. "Untrusted data" comes last but one, so that the
/// fixed instructions are read before any data, and "End of data" closes the prompt.
pub const REQUIRED_HEADINGS: [&str; 9] = [
    "Role and boundaries",
    "How to treat untrusted data",
    "Input contract",
    "Output contract",
    "Evidence required",
    "Stop conditions",
    "When information is missing",
    "Untrusted data",
    "End of data",
];

/// The fixed instruction that puts external text under no authority. It is the same in every
/// prompt, so a change to it is a change to every prompt and to this file.
pub const UNTRUSTED_INSTRUCTION: &str = include_str!("untrusted_instruction.txt");

/// The closing paragraph after the data blocks.
pub const END_OF_DATA: &str = include_str!("end_of_data.txt");

/// The stage kind each agent role works in. The stage decides which skill profile applies.
pub const STAGE_OF_ROLE: [(&str, &str); 10] = [
    ("intake", "INTAKE"),
    ("specification_writer", "SPECIFICATION"),
    ("specification_reviewer", "SPECIFICATION"),
    ("architect", "ARCHITECTURE"),
    ("architecture_critic", "ARCHITECTURE"),
    ("planner", "TASK_PLANNING"),
    ("builder", "IMPLEMENTATION"),
    ("code_reviewer", "REVIEW"),
    ("technical_writer", "DOCUMENTING"),
    ("documentation_reviewer", "DOCUMENTATION_REVIEW"),
];

/// The roles of the operations agents. Such a role has no stage: it is in no `STAGE_OF_ROLE` pair
/// and no pipeline route. Its agent holds only gateway tools and the output channel, reaches only
/// the MCP gateway, and has no skill.
pub const OPERATIONS_ROLES: [&str; 1] = ["troubleshooter"];

/// The one place an operations agent may reach: the fixed relay of its sandbox sidecar to the MCP
/// gateway (ADR 0021, Decision 5). It is the name of that relay, not a host the agent resolves.
pub const GATEWAY_NETWORK: &str = "mcp_gateway";

/// The prefix of the tool ids of the MCP gateway in the security policy's tool table.
pub const GATEWAY_TOOL_PREFIX: &str = "mcp.";

/// True for the role of an operations agent.
pub fn is_operations_role(role: &str) -> bool {
    OPERATIONS_ROLES.contains(&role)
}

/// The stage a role works in, or `None` for an operations role, which has none.
pub fn stage_of_role(role: &str) -> Option<&'static str> {
    STAGE_OF_ROLE
        .iter()
        .find(|(r, _)| *r == role)
        .map(|(_, s)| *s)
}

/// What `policies/security.yaml` does not grant yet. The tool table now lists the
/// `specification_writer` and `specification_reviewer` roles with the tools their manifests
/// declare, so nothing is left. The list stays so that a future gap can be recorded in one place,
/// and `known_policy_gaps_are_still_gaps` fails as soon as the policy closes an entry.
pub const KNOWN_POLICY_GAPS: [(&str, &str); 0] = [];

/// The access each tool has, by the effect it can have on the workspace.
const TOOL_ACCESS: [(&str, &str); 6] = [
    ("fs.read", "read"),
    ("fs.list", "read"),
    ("fs.search", "read"),
    ("report.submit", "read"),
    ("fs.write", "write"),
    ("exec.run", "execute_sandboxed"),
];

/// Words that name an action only a person or the control plane may take.
const FORBIDDEN_TOOL_WORDS: [&str; 8] = [
    "merge", "deploy", "push", "publish", "approval", "policy", "grant", "secret",
];

fn text<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value.pointer(pointer).and_then(Value::as_str).unwrap_or("")
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The tools of a manifest as (name, access, path scopes).
pub fn tools_of(manifest: &Value) -> Vec<(String, String, Vec<String>)> {
    manifest["allowed_tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .map(|t| {
                    (
                        text(t, "/name").to_owned(),
                        text(t, "/access").to_owned(),
                        strings(t.get("path_scope")),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------------------------

/// The `## ` sections of a prompt as (heading, body).
pub fn sections(prompt: &str) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();
    for line in prompt.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            found.push((heading.trim().to_owned(), String::new()));
        } else if let Some((_, body)) = found.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    found
}

/// One row of the input table: name, class, whether it is required.
pub struct InputRow {
    pub name: String,
    pub class: String,
    pub required: bool,
}

/// The rows of the "Input contract" table.
pub fn input_rows(prompt: &str) -> Vec<InputRow> {
    let body = sections(prompt)
        .into_iter()
        .find(|(h, _)| h == "Input contract")
        .map(|(_, b)| b)
        .unwrap_or_default();
    body.lines()
        .filter(|l| l.starts_with('|'))
        .skip(2)
        .map(|line| {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            InputRow {
                name: cells.first().unwrap_or(&"").trim_matches('`').to_owned(),
                class: cells.get(1).unwrap_or(&"").to_string(),
                required: cells.get(2).is_some_and(|c| *c == "yes"),
            }
        })
        .collect()
}

/// The names of the `{{input.name}}` placeholders, in order, and the problems with how they are
/// written. A placeholder is a whole line.
pub fn placeholders(prompt: &str) -> (Vec<String>, Vec<String>) {
    let mut names = Vec::new();
    let mut problems = Vec::new();
    for (number, line) in prompt.lines().enumerate() {
        if !line.contains("{{") && !line.contains("}}") {
            continue;
        }
        match line
            .strip_prefix("{{input.")
            .and_then(|rest| rest.strip_suffix("}}"))
        {
            Some(name) if !name.is_empty() && !name.contains(['{', '}', ' ']) => {
                names.push(name.to_owned());
            }
            _ => problems.push(format!(
                "line {}: a placeholder must be a whole line of the form {{{{input.name}}}}",
                number + 1
            )),
        }
    }
    (names, problems)
}

/// Problems with a prompt, given its manifest and the classes of untrusted content the policy
/// names.
pub fn prompt_problems(manifest: &Value, prompt: &str, classes: &[String]) -> Vec<String> {
    let mut problems = Vec::new();
    let id = text(manifest, "/id");

    let mut lines = prompt.lines().filter(|l| !l.trim().is_empty());
    if !lines.next().is_some_and(|l| l.starts_with("# ")) {
        problems.push("the prompt does not start with a title line".to_owned());
    }
    let version = prompt
        .lines()
        .find_map(|l| l.strip_prefix("Prompt version: "))
        .unwrap_or("");
    if version != text(manifest, "/prompt/template_version") {
        problems.push(format!(
            "the prompt says version `{version}` but the manifest says template_version `{}`",
            text(manifest, "/prompt/template_version")
        ));
    }
    let agent = prompt
        .lines()
        .find_map(|l| l.strip_prefix("Agent: "))
        .unwrap_or("");
    if agent != id {
        problems.push(format!(
            "the prompt names agent `{agent}` but the manifest id is `{id}`"
        ));
    }

    let found = sections(prompt);
    let headings: Vec<&str> = found.iter().map(|(h, _)| h.as_str()).collect();
    for required in REQUIRED_HEADINGS {
        if !headings.contains(&required) {
            problems.push(format!("the required section `{required}` is missing"));
        }
    }
    if headings != REQUIRED_HEADINGS && REQUIRED_HEADINGS.iter().all(|r| headings.contains(r)) {
        problems.push(format!(
            "the sections are out of order or repeated: {headings:?}"
        ));
    }
    for (heading, body) in &found {
        if body.trim().len() < 40 {
            problems.push(format!("the section `{heading}` is empty or a stub"));
        }
    }
    let body_of = |name: &str| {
        found
            .iter()
            .find(|(h, _)| h == name)
            .map(|(_, b)| b.trim().to_owned())
    };
    if body_of("How to treat untrusted data").as_deref() != Some(UNTRUSTED_INSTRUCTION.trim()) {
        problems.push(
            "the section `How to treat untrusted data` is not the fixed instruction".to_owned(),
        );
    }
    if body_of("End of data").is_some_and(|b| !b.starts_with(END_OF_DATA.trim())) {
        problems.push("the section `End of data` is not the fixed closing paragraph".to_owned());
    }

    // The input table.
    let rows = input_rows(prompt);
    if rows.is_empty() {
        problems.push("the input contract lists no input".to_owned());
    }
    let mut seen = BTreeSet::new();
    for row in &rows {
        if !seen.insert(row.name.clone()) {
            problems.push(format!("the input `{}` is listed twice", row.name));
        }
        if !classes.contains(&row.class) {
            problems.push(format!(
                "the input `{}` has class `{}`, which is not an untrusted content class of the policy",
                row.name, row.class
            ));
        }
    }

    // The placeholders: whole lines, inside the data section only, one per input, in table order.
    let (names, shape) = placeholders(prompt);
    problems.extend(shape);
    let table: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
    if names.iter().map(String::as_str).collect::<Vec<_>>() != table {
        problems.push(format!(
            "the placeholders {names:?} do not match the inputs of the table {table:?}"
        ));
    }
    for (heading, body) in &found {
        if heading != "Untrusted data" && (body.contains("{{") || body.contains("}}")) {
            problems.push(format!(
                "the section `{heading}` holds a placeholder, but data may only appear under `Untrusted data`"
            ));
        }
    }
    problems
}

/// The sentence every prompt uses to say how the report is returned. The command line tools give
/// an agent no tool to submit a report with: the adapter takes the last message of the run as the
/// answer, so the prompt has to say exactly that.
pub const FINAL_MESSAGE_RULE: &str =
    "Put no sentence before or after the document and no code fence around it.";

/// The schemas shown inside ` ```json ` fences of a section, in order.
pub fn embedded_schemas(section: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut open: Option<Vec<&str>> = None;
    for line in section.lines() {
        match (&mut open, line) {
            (None, "```json") => open = Some(Vec::new()),
            (Some(lines), "```") => {
                found.push(lines.join("\n"));
                open = None;
            }
            (Some(lines), _) => lines.push(line),
            (None, _) => {}
        }
    }
    found
}

/// The output contract must tell the model how its report really leaves the run, and must show it
/// the schemas the factory checks the report against, byte for byte.
///
/// `schemas` are the texts of the schema files the agent's answer is validated against, in the
/// order the prompt shows them: the output schema of the manifest first.
pub fn output_channel_problems(prompt: &str, schemas: &[String]) -> Vec<String> {
    let mut problems = Vec::new();
    let lowered = prompt.to_lowercase();
    for phrase in [
        "call `report.submit`",
        "`report.submit` call",
        "tool is `report.submit`",
    ] {
        if lowered.contains(phrase) {
            problems.push(format!(
                "the prompt says `{phrase}`, but no runtime gives the agent a tool of that name"
            ));
        }
    }
    let found = sections(prompt);
    let Some((_, contract)) = found.iter().find(|(h, _)| h == "Output contract") else {
        problems.push("there is no output contract to check".to_owned());
        return problems;
    };
    if !contract.contains("final message") {
        problems.push(
            "the output contract does not say that the final message is the report".to_owned(),
        );
    }
    if !contract.contains(FINAL_MESSAGE_RULE) {
        problems.push(
            "the output contract does not carry the fixed rule for the final message".to_owned(),
        );
    }
    let shown = embedded_schemas(contract);
    if shown.len() != schemas.len() {
        problems.push(format!(
            "the output contract shows {} schema(s) but the answer is checked against {}",
            shown.len(),
            schemas.len()
        ));
    }
    for (index, (shown, wanted)) in shown.iter().zip(schemas).enumerate() {
        if shown.trim_end() != wanted.trim_end() {
            problems.push(format!(
                "embedded schema {} differs from its schema file; run python3 -I agents/refresh_hashes.py",
                index + 1
            ));
        }
    }
    for (heading, body) in &found {
        if heading != "Output contract" && !embedded_schemas(body).is_empty() {
            problems.push(format!(
                "the section `{heading}` shows a schema, which belongs in the output contract"
            ));
        }
    }
    problems
}

/// The properties and required names of an input schema must be exactly the inputs of the table.
pub fn input_schema_problems(prompt: &str, schema: &Value) -> Vec<String> {
    let rows = input_rows(prompt);
    let declared: BTreeSet<String> = schema["properties"]
        .as_object()
        .map(|p| p.keys().cloned().collect())
        .unwrap_or_default();
    let named: BTreeSet<String> = rows.iter().map(|r| r.name.clone()).collect();
    let required: BTreeSet<String> = strings(schema.get("required")).into_iter().collect();
    let table_required: BTreeSet<String> = rows
        .iter()
        .filter(|r| r.required)
        .map(|r| r.name.clone())
        .collect();
    let mut problems = Vec::new();
    if declared != named {
        problems.push(format!(
            "the input schema has properties {declared:?} but the prompt table has {named:?}"
        ));
    }
    if required != table_required {
        problems.push(format!(
            "the input schema requires {required:?} but the prompt table requires {table_required:?}"
        ));
    }
    problems
}

// ---------------------------------------------------------------------------------------------
// Reviewer independence
// ---------------------------------------------------------------------------------------------

/// The inputs each reviewer role may receive, and no others. None is the author's own account.
/// `project_rules` is the project's `AGENTS.md` at the job's base commit, or the factory's
/// built-in copy (ADR 0026): text the project's owners approved, not anything the author of the
/// work wrote, so every reviewer may have it.
pub const REVIEWER_INPUTS: [(&str, &[&str]); 4] = [
    (
        "code_reviewer",
        &[
            "frozen_specification",
            "diff",
            "gate_reports",
            "project_rules",
        ],
    ),
    (
        "specification_reviewer",
        // `people_answers` is what people decided, from the factory's own record of their
        // answers. The writer cannot write it, so it is not the author's account.
        &[
            "request",
            "specification",
            "requirements_checklist",
            "people_answers",
            "project_rules",
        ],
    ),
    (
        "architecture_critic",
        // The design it receives is the elements, decisions, risks and open questions; the
        // architect's summary is withheld by the stage (`Design::for_critic`).
        &[
            "frozen_specification",
            "architecture_design",
            "repository_map",
            "project_rules",
        ],
    ),
    (
        "documentation_reviewer",
        &[
            "frozen_specification",
            "documentation_plan",
            "code_diff",
            "documentation_diff",
            "gate_reports",
            "project_rules",
        ],
    ),
];

/// Words in an input name that point at the author's own account of the work.
const SELF_ACCOUNT_WORDS: [&str; 9] = [
    "builder",
    "writer",
    "author",
    "self",
    "summary",
    "justification",
    "rationale",
    "assessment",
    "explanation",
];

/// A reviewer receives only the inputs listed for its role, and none of them is the author's
/// account. It can read but not write, and it has no version control tool, because a commit
/// message can carry the builder's account.
pub fn reviewer_problems(manifest: &Value, prompt: &str) -> Vec<String> {
    let role = text(manifest, "/role");
    let Some((_, allowed)) = REVIEWER_INPUTS.iter().find(|(r, _)| *r == role) else {
        return Vec::new();
    };
    let mut problems = Vec::new();
    let names: Vec<String> = input_rows(prompt).into_iter().map(|r| r.name).collect();
    let (placed, _) = placeholders(prompt);
    for name in names.iter().chain(placed.iter()) {
        if !allowed.contains(&name.as_str()) {
            problems.push(format!(
                "the {role} receives the input `{name}`, which is not on its list {allowed:?}"
            ));
        }
        if let Some(word) = SELF_ACCOUNT_WORDS.iter().find(|w| name.contains(**w)) {
            problems.push(format!(
                "the {role} input `{name}` looks like the author's own account (`{word}`)"
            ));
        }
    }
    for (tool, access, _) in tools_of(manifest) {
        if access != "read" {
            problems.push(format!(
                "the {role} holds the tool `{tool}` with access `{access}`"
            ));
        }
        if tool.starts_with("vcs.") {
            problems.push(format!(
                "the {role} holds `{tool}`, and a commit message can carry the builder's account"
            ));
        }
    }
    problems
}

// ---------------------------------------------------------------------------------------------
// Tools, permissions, placements
// ---------------------------------------------------------------------------------------------

fn globs_match(pattern: &str, path: &str) -> bool {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .is_ok_and(|g| g.compile_matcher().is_match(path))
}

/// Whether `pattern` matches the paths that `other` stands for (its wildcards read as the letter x).
pub fn covers(pattern: &str, other: &str) -> bool {
    globs_match(pattern, &sample(other))
}

/// A path that a glob matches: every wildcard becomes the letter x.
fn sample(pattern: &str) -> String {
    pattern.replace("**", "x").replace('*', "x")
}

/// Whether a write scope can reach a path in a group the policy forbids writing.
fn write_reaches(scope: &str, protected: &str) -> bool {
    globs_match(scope, &sample(protected)) || globs_match(protected, &sample(scope))
}

/// The writes the allowed Spec Kit skills make, from the stage profile of the policy.
pub fn skill_writes(policy: &SecurityPolicy, skill: &str) -> Vec<String> {
    policy
        .agent_stage_profiles
        .profiles
        .iter()
        .filter_map(|p| p.skills.as_ref())
        .flat_map(|s| s.allowed.iter())
        .filter(|a| a.id == skill)
        .flat_map(|a| a.writes.iter().map(|g| g.pattern().to_owned()))
        .collect()
}

/// The access a tool needs, by the effect it can have. Every gateway tool reads.
fn expected_access(name: &str) -> Option<&'static str> {
    if name.starts_with(GATEWAY_TOOL_PREFIX) {
        return Some("read");
    }
    TOOL_ACCESS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, access)| *access)
}

/// Tools against the policy: the tool exists, is on, may run where the agent runs, is held by
/// this role, is not on the never-grantable list, and has the access its effect needs.
///
/// A pipeline agent's tools run in the `agent` sandbox profile and it holds no gateway tool. An
/// operations agent holds gateway tools and the output channel only. A gateway tool runs in the
/// MCP gateway of the control plane, so its policy entry names no sandbox profile, and no role
/// but an operations role holds it.
pub fn tool_problems(manifest: &Value, policy: &SecurityPolicy) -> Vec<String> {
    let role = text(manifest, "/role");
    let operations = is_operations_role(role);
    let mut problems = Vec::new();
    for (name, access, _) in tools_of(manifest) {
        let gateway = name.starts_with(GATEWAY_TOOL_PREFIX);
        if gateway && !operations {
            problems.push(format!(
                "the tool `{name}` is a gateway tool, and only an operations agent may hold one"
            ));
        }
        if operations && !gateway && name != "report.submit" {
            problems.push(format!(
                "the operations role `{role}` holds `{name}`, but it may hold only gateway tools and the output channel"
            ));
        }
        if policy.tools.never_grantable.contains(&name) {
            problems.push(format!("the tool `{name}` is never grantable"));
        }
        if let Some(word) = FORBIDDEN_TOOL_WORDS.iter().find(|w| name.contains(**w)) {
            problems.push(format!(
                "the tool `{name}` names an action that only a person or the control plane may take (`{word}`)"
            ));
        }
        let Some(entry) = policy.tools.entries.iter().find(|e| e.id == name) else {
            problems.push(format!(
                "the tool `{name}` is not in the policy's tool table"
            ));
            continue;
        };
        if entry.enabled == Some(false) {
            problems.push(format!("the tool `{name}` is switched off in the policy"));
        }
        if gateway {
            if !entry.profiles.is_empty() {
                problems.push(format!(
                    "the gateway tool `{name}` names sandbox profiles {:?}, but it runs in the gateway of the control plane",
                    entry.profiles
                ));
            }
            if entry.roles.iter().any(|r| !is_operations_role(r)) {
                problems.push(format!(
                    "the gateway tool `{name}` is given to {:?}, but only operations roles may hold it",
                    entry.roles
                ));
            }
        } else if !entry.profiles.iter().any(|p| p == "agent") {
            problems.push(format!(
                "the tool `{name}` cannot run in the `agent` sandbox profile"
            ));
        }
        let held = entry.roles.iter().any(|r| r == "*" || r == role);
        let gap = KNOWN_POLICY_GAPS.contains(&(role, name.as_str()));
        if !held && !gap {
            problems.push(format!(
                "the policy does not give the tool `{name}` to the role `{role}`"
            ));
        }
        match expected_access(&name) {
            Some(expected) if expected != access => problems.push(format!(
                "the tool `{name}` is declared with access `{access}`, but its effect is `{expected}`"
            )),
            None => problems.push(format!("the tool `{name}` has no known access")),
            _ => {}
        }
    }
    problems
}

/// A write scope must not reach a protected path, except a write that one of the manifest's own
/// Spec Kit skills is allowed to make.
pub fn forbidden_write_problems(manifest: &Value, policy: &SecurityPolicy) -> Vec<String> {
    let skill_exceptions: Vec<String> = manifest["skills"]
        .as_array()
        .map(|skills| {
            skills
                .iter()
                .flat_map(|s| skill_writes(policy, text(s, "/id")))
                .collect()
        })
        .unwrap_or_default();
    let mut scopes: Vec<String> = strings(manifest.pointer("/permissions/filesystem/write"));
    for (_, access, path_scope) in tools_of(manifest) {
        if access == "write" {
            scopes.extend(path_scope);
        }
    }
    let mut problems = Vec::new();
    for scope in scopes {
        if skill_exceptions.contains(&scope) {
            continue;
        }
        for group in &policy.protected_paths.groups {
            let forbids_writing = matches!(group.mode, ProtectionMode::DenyWrite);
            let applies = !matches!(group.applies_to, AppliesTo::FactoryRepo);
            if !forbids_writing || !applies {
                continue;
            }
            for glob in &group.globs {
                if !glob.is_reinclusion() && write_reaches(&scope, glob.pattern()) {
                    problems.push(format!(
                        "the write scope `{scope}` can reach `{}` of the protected group `{}`",
                        glob.pattern(),
                        group.id
                    ));
                }
            }
        }
    }
    problems
}

/// Placements, filesystem access, shell and network must agree with the tools.
pub fn placement_problems(manifest: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let placements = strings(manifest.get("permitted_placements"));
    if placements != ["sandbox"] {
        problems.push(format!(
            "Slice 1 allows only the sandbox placement, but the manifest permits {placements:?}"
        ));
    }
    let tools = tools_of(manifest);
    let writes = tools.iter().any(|(_, a, _)| a == "write");
    let executes = tools.iter().any(|(_, a, _)| a == "execute_sandboxed");
    let fs_write = strings(manifest.pointer("/permissions/filesystem/write"));
    let fs_read = strings(manifest.pointer("/permissions/filesystem/read"));
    let shell = text(manifest, "/permissions/shell");

    if writes && fs_write.is_empty() {
        problems.push("a write tool is declared but filesystem.write is empty".to_owned());
    }
    if !writes && !fs_write.is_empty() {
        problems.push(format!(
            "filesystem.write lists {fs_write:?} but no tool can write"
        ));
    }
    if executes && shell != "sandboxed_typed_wrapper" {
        problems.push(format!(
            "a tool executes commands but the shell is `{shell}`"
        ));
    }
    if !executes && shell != "none" {
        problems.push(format!(
            "no tool executes commands but the shell is `{shell}`"
        ));
    }
    let write_scopes: BTreeSet<String> = tools
        .iter()
        .filter(|(_, a, _)| a == "write")
        .flat_map(|(_, _, s)| s.clone())
        .collect();
    if writes && write_scopes != fs_write.iter().cloned().collect::<BTreeSet<_>>() {
        problems.push(format!(
            "the path scopes of the write tools {write_scopes:?} differ from filesystem.write {fs_write:?}"
        ));
    }
    let read_scopes: BTreeSet<String> = tools
        .iter()
        .filter(|(_, a, _)| a == "read")
        .flat_map(|(_, _, s)| s.clone())
        .collect();
    let allowed_reads: BTreeSet<String> = fs_read.iter().cloned().collect();
    if !read_scopes.is_subset(&allowed_reads) {
        problems.push(format!(
            "the read tools reach {read_scopes:?}, which is more than filesystem.read {fs_read:?}"
        ));
    }
    for field in ["production_access", "secrets"] {
        let value = text(manifest, &format!("/permissions/{field}"));
        if value != "none" {
            problems.push(format!("permissions.{field} is `{value}`, not `none`"));
        }
    }
    problems.extend(network_problems(manifest));
    problems
}

/// A pipeline agent reaches no network. An operations agent reaches exactly one place, the relay
/// to the MCP gateway, and nothing else; it also holds no file access.
fn network_problems(manifest: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let network = text(manifest, "/permissions/network");
    let allowlist = strings(manifest.pointer("/permissions/network_allowlist"));
    if is_operations_role(text(manifest, "/role")) {
        if network != "allowlist" || allowlist != [GATEWAY_NETWORK] {
            problems.push(format!(
                "an operations agent reaches only `{GATEWAY_NETWORK}`, but the manifest says network `{network}` with {allowlist:?}"
            ));
        }
        for field in ["read", "write"] {
            let paths = strings(manifest.pointer(&format!("/permissions/filesystem/{field}")));
            if !paths.is_empty() {
                problems.push(format!(
                    "an operations agent has an empty workspace, but filesystem.{field} lists {paths:?}"
                ));
            }
        }
    } else {
        if network != "none" {
            problems.push(format!("permissions.network is `{network}`, not `none`"));
        }
        if !allowlist.is_empty() {
            problems.push(format!(
                "permissions.network_allowlist lists {allowlist:?}, but a pipeline agent reaches no network"
            ));
        }
    }
    problems
}

/// Skills exist only in the specification stage, and there only the allowed ones.
pub fn skill_problems(manifest: &Value, policy: &SecurityPolicy) -> Vec<String> {
    let role = text(manifest, "/role");
    let skills = manifest["skills"].as_array().cloned().unwrap_or_default();
    // An operations role has no stage, so no stage profile allows it a skill.
    if is_operations_role(role) {
        return skills
            .iter()
            .map(|s| {
                format!(
                    "the skill `{}` is held by the operations role `{role}`, which has no stage and no skill",
                    text(s, "/id")
                )
            })
            .collect();
    }
    let Some(stage) = stage_of_role(role) else {
        return vec![format!(
            "the role `{role}` is neither a pipeline role with a stage nor an operations role"
        )];
    };
    let profile = policy
        .agent_stage_profiles
        .profiles
        .iter()
        .find(|p| p.applies_to_stage_kinds.iter().any(|k| k == stage))
        .or_else(|| {
            policy
                .agent_stage_profiles
                .profiles
                .iter()
                .find(|p| p.id == policy.agent_stage_profiles.default_profile)
        });
    let allowed: Vec<String> = profile
        .and_then(|p| p.skills.as_ref())
        .map(|s| s.allowed.iter().map(|a| a.id.clone()).collect())
        .unwrap_or_default();
    let denied: Vec<String> = profile
        .and_then(|p| p.skills.as_ref())
        .map(|s| s.denied.clone())
        .unwrap_or_default();
    let mut problems = Vec::new();
    for skill in skills {
        let id = text(&skill, "/id");
        if denied.iter().any(|d| d == id) {
            problems.push(format!("the skill `{id}` is denied in the {stage} stage"));
        } else if !allowed.iter().any(|a| a == id) {
            problems.push(format!(
                "the skill `{id}` is not allowed in the {stage} stage, whose profile allows {allowed:?}"
            ));
        }
    }
    problems
}

/// Models and limits: an explicit, cheaper default and a larger escalation model, and a bounded run.
pub fn model_and_limit_problems(manifest: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let models = manifest["recommended_models"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if models.iter().any(|m| text(m, "/model").is_empty()) {
        problems.push("a recommended model has no explicit model name".to_owned());
    }
    let tier_of = |m: &Value| text(m, "/tier").to_owned();
    let claude: Vec<&Value> = models
        .iter()
        .filter(|m| text(m, "/runtime_id") == "claude-code-cli")
        .collect();
    match (
        claude.first(),
        claude.iter().map(|m| tier_of(m)).collect::<Vec<_>>(),
    ) {
        (Some(first), tiers) => {
            if tier_of(first) == "large" {
                problems.push("the default model of claude-code-cli is the large tier".to_owned());
            }
            if !tiers.iter().any(|t| t == "large") {
                problems.push("claude-code-cli has no larger model to escalate to".to_owned());
            }
        }
        (None, _) => problems.push("there is no recommended model for claude-code-cli".to_owned()),
    }
    for (pointer, what) in [
        ("/resource_limits/max_wall_time_seconds", "time"),
        ("/resource_limits/max_tokens", "tokens"),
        ("/resource_limits/max_cost_usd", "cost"),
        ("/resource_limits/max_tool_calls", "tool calls"),
    ] {
        if manifest
            .pointer(pointer)
            .and_then(Value::as_f64)
            .is_none_or(|n| n <= 0.0)
        {
            problems.push(format!("the limit on {what} is missing or not positive"));
        }
    }
    if manifest.pointer("/resource_limits/max_delegation_depth") != Some(&Value::from(0)) {
        problems
            .push("an agent may not start other agents: max_delegation_depth must be 0".to_owned());
    }
    problems
}
