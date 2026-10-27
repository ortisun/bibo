//! The rules that need a scan of the source text: DEP-09 and DEP-10 from the rules file, and the
//! static checks ST-01 to ST-05 and ST-09 from the negative-test catalog.
//!
//! These scans are guard rails, not proofs. They read text, so they miss code that builds a name
//! at run time. The process spawn recorder in the end-to-end tests covers that side (ST-03).
//!
//! The rules file says what each rule means in prose. The parameters here (which crate may spawn
//! which program, where the posture verifier and the ingestion module live) come from that prose
//! and from the catalog. A test checks that every crate named below still exists in the file.

use crate::finding::Finding;
use crate::metadata::Workspace;
use crate::rules::{Role, Rules};
use crate::scan::{self, Source, brace_block, find_word, is_ident, next_ident};
use std::fs;
use std::path::Path;

const WORKFLOW: &str = "workflow";
const SPEC_ADAPTER: &str = "spec_adapter";
const SANDBOX: &str = "sandbox";
const RUNTIME: &str = "runtime";

/// Every crate these scans name. A test checks they are all in the rules file.
pub const NAMED_CRATES: [&str; 4] = [WORKFLOW, SPEC_ADAPTER, SANDBOX, RUNTIME];

/// ST-09 applies to the crates that handle workspace content or agent output.
const WORKSPACE_READERS: [&str; 4] = [SANDBOX, RUNTIME, SPEC_ADAPTER, WORKFLOW];
/// The ingestion module, relative to the sandbox crate. Every read of sandbox output goes here.
const INGESTION_DIR: &str = "src/workspace/";

const SHELLS: [&str; 11] = [
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "ksh",
    "csh",
    "tcsh",
    "cmd",
    "powershell",
    "pwsh",
];
const AGENT_TOOLS: [&str; 2] = ["claude", "codex"];
const SANDBOX_PROGRAMS: [&str; 2] = ["docker", "git"];

const DANGEROUS_STRINGS: [&str; 5] = [
    "--privileged",
    "--cap-add",
    "seccomp=unconfined",
    "apparmor=unconfined",
    "docker.sock",
];
const HOST_NAMESPACE_FLAGS: [&str; 3] = ["--network", "--net", "--pid"];

const FS_READ_CALLS: [&str; 9] = [
    "fs::read(",
    "fs::read_to_string(",
    "fs::read_dir(",
    "fs::metadata(",
    "fs::symlink_metadata(",
    "fs::canonicalize(",
    "fs::read_link(",
    "File::open(",
    "OpenOptions::new(",
];
const FS_READ_METHODS: [&str; 8] = [
    ".read_dir(",
    ".metadata(",
    ".symlink_metadata(",
    ".canonicalize(",
    ".read_link(",
    ".exists()",
    ".is_file()",
    ".is_dir()",
];

struct Scanned {
    /// The name in the rules file, such as `sandbox` or `api`.
    name: String,
    /// The crate directory relative to the workspace root.
    dir: String,
    sources: Vec<Source>,
}

pub fn check(rules: &Rules, ws: &Workspace) -> Result<Vec<Finding>, String> {
    let mut scanned = Vec::new();
    for member in &ws.members {
        let name = match rules.role_of_package(&member.name) {
            // Test support is test code and may break rules that production code must keep.
            Some(Role::Library(c)) if c.layer != "test-support" => c.name.clone(),
            Some(Role::App(a)) => a.name.clone(),
            _ => continue,
        };
        scanned.push(Scanned {
            name,
            dir: ws.relative_dir(member),
            sources: scan::production_sources(&ws.root, &member.dir)?,
        });
    }

    let mut findings = Vec::new();
    for krate in &scanned {
        for source in &krate.sources {
            begin_system_only_in_workflow(krate, source, &mut findings);
            spec_kit_layout_only_in_spec_adapter(krate, source, &mut findings);
            change_host_has_no_merge_method(source, &mut findings);
            process_spawning(krate, source, &mut findings);
            no_equality_on_signatures(source, &mut findings);
            container_flags_only_in_the_posture_verifier(krate, source, &mut findings);
            no_merge_or_deploy_path(source, &mut findings);
            workspace_reads_go_through_ingestion(krate, source, &mut findings);
        }
    }
    tree_checks(&ws.root, &mut findings)?;
    Ok(findings)
}

// ---------------------------------------------------------------------------------------------
// DEP-09

/// `Store::begin_system` is called only from the workflow crate. Defining or implementing it is
/// not a call.
fn begin_system_only_in_workflow(krate: &Scanned, source: &Source, findings: &mut Vec<Finding>) {
    if krate.name == WORKFLOW {
        return;
    }
    for at in find_word(&source.code, "begin_system") {
        if !preceded_by_fn(&source.code, at) {
            findings.push(Finding::new(
                "DEP-09",
                source.location(at),
                format!(
                    "{} calls begin_system; only the workflow crate may open a system transaction",
                    krate.name
                ),
            ));
        }
    }
}

fn preceded_by_fn(code: &str, at: usize) -> bool {
    let before = code[..at].trim_end().as_bytes();
    before.ends_with(b"fn") && (before.len() == 2 || !is_ident(before[before.len() - 3]))
}

/// The Spec Kit file layout (`.specify`, `speckit`) appears only in the spec_adapter crate.
fn spec_kit_layout_only_in_spec_adapter(
    krate: &Scanned,
    source: &Source,
    findings: &mut Vec<Finding>,
) {
    if krate.name == SPEC_ADAPTER {
        return;
    }
    let lowercase = source.with_strings.to_ascii_lowercase();
    for term in [".specify", "speckit"] {
        for (at, _) in lowercase.match_indices(term) {
            findings.push(Finding::new(
                "DEP-09",
                source.location(at),
                format!("{} mentions {term:?}; only the spec_adapter crate may know the Spec Kit layout", krate.name),
            ));
        }
    }
}

/// `ChangeHost` has no method whose name starts with `merge`. The factory never merges.
fn change_host_has_no_merge_method(source: &Source, findings: &mut Vec<Finding>) {
    for at in find_word(&source.code, "trait") {
        let Some((name_at, name)) = next_ident(&source.code, at + "trait".len()) else {
            continue;
        };
        if !name.starts_with("ChangeHost") {
            continue;
        }
        let Some((open, end)) = brace_block(&source.code, name_at + name.len()) else {
            continue;
        };
        let body = &source.code[open..end];
        for fn_at in find_word(body, "fn") {
            if let Some((method_at, method)) = next_ident(body, fn_at + 2)
                && method.starts_with("merge")
            {
                findings.push(Finding::new(
                    "DEP-09",
                    source.location(open + method_at),
                    format!("trait {name} has a method named {method}; the factory never merges"),
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// DEP-10 and ST-03

/// Only the sandbox crate spawns docker or git, only the runtime crate spawns an agent tool, and
/// no crate spawns a shell.
fn process_spawning(krate: &Scanned, source: &Source, findings: &mut Vec<Finding>) {
    for spawn in spawn_calls(source) {
        let location = source.location(spawn.at);
        let Some(program) = spawn.program else {
            if krate.name != SANDBOX && krate.name != RUNTIME {
                findings.push(Finding::new(
                    "DEP-10",
                    location,
                    format!("{} spawns a program that is not a string literal, so the allowed-program rule cannot be checked", krate.name),
                ));
            }
            continue;
        };
        if SHELLS.contains(&program.as_str()) {
            findings.push(Finding::new(
                "ST-03",
                location,
                format!("{} spawns the shell {program}", krate.name),
            ));
        } else if SANDBOX_PROGRAMS.contains(&program.as_str()) {
            if krate.name != SANDBOX {
                findings.push(Finding::new(
                    "DEP-10",
                    location,
                    format!(
                        "{} spawns {program}; only the sandbox crate may spawn docker or git",
                        krate.name
                    ),
                ));
            }
        } else if AGENT_TOOLS.contains(&program.as_str()) {
            if krate.name != RUNTIME {
                findings.push(Finding::new(
                    "DEP-10",
                    location,
                    format!(
                        "{} spawns the agent tool {program}; only the runtime crate may",
                        krate.name
                    ),
                ));
            }
        } else {
            findings.push(Finding::new(
                "DEP-10",
                location,
                format!("{} spawns {program}, which is not an allowed program (docker and git in sandbox, agent tools in runtime)", krate.name),
            ));
        }
    }
}

struct Spawn {
    at: usize,
    /// The program name, lower case, without directory or `.exe`. `None` when the argument is
    /// not a string literal.
    program: Option<String>,
}

/// Calls of `Command::new` that spawn a process. A `Command` from another crate, such as a
/// command line parser, is not a spawn.
fn spawn_calls(source: &Source) -> Vec<Spawn> {
    let text = &source.with_strings;
    let imports_process_command =
        text.contains("process::Command") || process_brace_import_has_command(text);
    let mut spawns = Vec::new();
    for (at, _) in text.match_indices("Command::new") {
        let qualified = text[..at].ends_with("process::");
        let standalone = at == 0 || !is_ident(text.as_bytes()[at - 1]);
        if !(standalone && (qualified || imports_process_command)) {
            continue;
        }
        let rest = text[at + "Command::new".len()..].trim_start();
        let Some(argument) = rest.strip_prefix('(') else {
            continue;
        };
        spawns.push(Spawn {
            at,
            program: string_literal_at_start(argument.trim_start()).map(|p| program_name(&p)),
        });
    }
    spawns
}

/// True for `use std::process::{Child, Command};`.
fn process_brace_import_has_command(text: &str) -> bool {
    text.match_indices("process::{").any(|(at, found)| {
        text[at + found.len()..]
            .split('}')
            .next()
            .is_some_and(|list| !find_word(list, "Command").is_empty())
    })
}

fn string_literal_at_start(text: &str) -> Option<String> {
    let body = text.strip_prefix('"')?;
    let mut value = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(value),
            '\\' => value.extend(chars.next()),
            other => value.push(other),
        }
    }
    None
}

fn program_name(literal: &str) -> String {
    let name = literal
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(literal)
        .to_ascii_lowercase();
    name.strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(name)
}

// ---------------------------------------------------------------------------------------------
// ST-02

/// No `==`, `!=`, `.eq(` or `.ne(` on a value named like a MAC or a signature. Comparing lengths
/// is fine. This reads one line at a time.
fn no_equality_on_signatures(source: &Source, findings: &mut Vec<Finding>) {
    let mut offset = 0;
    for line in source.code.split('\n') {
        let compares = ["==", "!=", ".eq(", ".ne("]
            .iter()
            .any(|op| line.contains(op));
        if compares
            && let Some(name) = identifiers(line).into_iter().find(|(_, name, after)| {
                looks_like_a_mac(name)
                    && !after.starts_with(".len()")
                    && !after.starts_with(".is_empty()")
            })
        {
            findings.push(Finding::new(
                "ST-02",
                source.location(offset + name.0),
                format!(
                    "{} is compared with an equality operator; use a constant-time comparison",
                    name.1
                ),
            ));
        }
        offset += line.len() + 1;
    }
}

/// Each identifier in a line with its offset and the text after it.
fn identifiers(line: &str) -> Vec<(usize, &str, &str)> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if is_ident(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_ident(bytes[i]) {
                i += 1;
            }
            found.push((start, &line[start..i], &line[i..]));
        } else {
            i += 1;
        }
    }
    found
}

fn looks_like_a_mac(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("signature")
        || lower.contains("hmac")
        || lower.split('_').any(|part| part == "mac" || part == "sig")
}

// ---------------------------------------------------------------------------------------------
// ST-04

/// Dangerous container flags appear only in the posture verifier's deny list: a file or
/// directory whose name starts with `posture`, under the sandbox crate's `src`.
fn container_flags_only_in_the_posture_verifier(
    krate: &Scanned,
    source: &Source,
    findings: &mut Vec<Finding>,
) {
    if krate.name == SANDBOX && is_posture_verifier(krate, source) {
        return;
    }
    let text = &source.with_strings;
    let mut report = |at: usize, what: &str| {
        findings.push(Finding::new(
            "ST-04",
            source.location(at),
            format!("{} contains {what:?}; dangerous container flags may appear only in the posture verifier's deny list", krate.name),
        ));
    };
    for needle in DANGEROUS_STRINGS {
        for (at, _) in text.match_indices(needle) {
            report(at, needle);
        }
    }
    for flag in HOST_NAMESPACE_FLAGS {
        for (at, _) in text.match_indices(flag) {
            let after = &text[at + flag.len()..];
            let value = after.trim_start_matches([' ', '\t', '\n', '=', '"', '\'', ',']);
            let is_host =
                value.starts_with("host") && value.as_bytes().get(4).is_none_or(|b| !is_ident(*b));
            if is_host {
                report(at, &format!("{flag} host"));
            }
        }
    }
}

fn is_posture_verifier(krate: &Scanned, source: &Source) -> bool {
    let prefix = format!("{}/src/", krate.dir);
    source
        .relative
        .strip_prefix(&prefix)
        .is_some_and(|inside| inside.split('/').any(|part| part.starts_with("posture")))
}

// ---------------------------------------------------------------------------------------------
// ST-05

/// No function, route or workflow file named merge, deploy or release publish. The factory opens
/// draft pull requests and a human merges, so no such path exists in this release. Reading the
/// merged state of a pull request is fine.
fn no_merge_or_deploy_path(source: &Source, findings: &mut Vec<Finding>) {
    for at in find_word(&source.code, "fn") {
        let Some((name_at, name)) = next_ident(&source.code, at + 2) else {
            continue;
        };
        if is_merge_or_deploy_name(name) {
            findings.push(Finding::new(
                "ST-05",
                source.location(name_at),
                format!("function {name} is a merge or deploy path; the factory has none, and a human approves and merges"),
            ));
        }
    }
    for (at, literal) in string_literals(source) {
        if literal.contains('/') && literal.split('/').any(is_merge_or_deploy_segment) {
            findings.push(Finding::new(
                "ST-05",
                source.location(at),
                format!("route {literal:?} is a merge or deploy path; the factory has none"),
            ));
        }
    }
}

fn is_merge_or_deploy_name(name: &str) -> bool {
    ["merge", "deploy"]
        .iter()
        .any(|verb| name == *verb || name.starts_with(&format!("{verb}_")))
        || name.contains("publish_release")
        || name.contains("release_publish")
}

fn is_merge_or_deploy_segment(segment: &str) -> bool {
    let segment = segment.split('?').next().unwrap_or_default();
    matches!(segment, "merge" | "merges" | "deploy" | "deployments")
}

/// String literals with the offset of their opening quote. The `code` view keeps the quotes and
/// blanks the contents, so quotes pair up in order.
fn string_literals(source: &Source) -> Vec<(usize, String)> {
    let quotes: Vec<usize> = source.code.match_indices('"').map(|(at, _)| at).collect();
    quotes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[open, close]| (*open, source.with_strings[open + 1..*close].to_string()))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// ST-09

/// In the crates that handle workspace content, reading the filesystem is allowed only inside
/// the ingestion module (`workspace/` in the sandbox crate).
fn workspace_reads_go_through_ingestion(
    krate: &Scanned,
    source: &Source,
    findings: &mut Vec<Finding>,
) {
    if !WORKSPACE_READERS.contains(&krate.name.as_str()) {
        return;
    }
    if krate.name == SANDBOX
        && source
            .relative
            .starts_with(&format!("{}/{INGESTION_DIR}", krate.dir))
    {
        return;
    }
    let code = &source.code;
    let calls = FS_READ_CALLS.iter().flat_map(|call| {
        code.match_indices(call)
            .filter(|(at, _)| *at == 0 || !is_ident(code.as_bytes()[at - 1]))
            .map(|(at, _)| (at, *call))
    });
    let methods = FS_READ_METHODS
        .iter()
        .flat_map(|call| code.match_indices(call).map(|(at, _)| (at, *call)));
    for (at, call) in calls.chain(methods) {
        findings.push(Finding::new(
            "ST-09",
            source.location(at),
            format!(
                "{} reads the filesystem with {}; every read of a workspace or output path goes through crates/sandbox/{INGESTION_DIR}",
                krate.name,
                call.trim_end_matches('(').trim_start_matches('.')
            ),
        ));
    }
}

// ---------------------------------------------------------------------------------------------
// Checks over the whole repository tree

fn tree_checks(root: &Path, findings: &mut Vec<Finding>) -> Result<(), String> {
    let mut files = Vec::new();
    walk(root, root, &mut files)?;
    for relative in files {
        let path = root.join(&relative);
        if relative.starts_with(".github/workflows/") {
            let name = relative
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if ["deploy", "merge", "publish"]
                .iter()
                .any(|word| name.contains(word))
            {
                findings.push(Finding::new(
                    "ST-05",
                    &relative,
                    "a workflow file named for deploying, merging or publishing; the factory has no such path",
                ));
            }
        }
        // Text files only. Binary or very large files are not configuration.
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if text.len() <= 1 << 20 {
            // A comment that forbids the wildcard, as policies/security.yaml has, is not a use.
            let code = if relative.ends_with(".rs") {
                scan::mask(&text).with_strings
            } else {
                without_hash_comments(&text)
            };
            safe_directory_wildcard(&relative, &code, findings);
        }
    }
    Ok(())
}

const SKIPPED_DIRECTORIES: [&str; 3] = [".git", "target", "node_modules"];
const PROSE_EXTENSIONS: [&str; 4] = ["md", "txt", "rst", "lock"];

/// Every file under `root` that may hold code or configuration, relative and sorted. Prose, build
/// output and xtask itself (whose tests contain the offending text on purpose) are left out.
fn walk(root: &Path, dir: &Path, files: &mut Vec<String>) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        // A symbolic link is never followed: it could loop, or lead outside the repository.
        let Ok(kind) = fs::symlink_metadata(&path).map(|m| m.file_type()) else {
            continue;
        };
        if kind.is_dir() {
            let is_xtask = dir == root && name == "xtask";
            if !SKIPPED_DIRECTORIES.contains(&name) && !is_xtask {
                walk(root, &path, files)?;
            }
        } else if kind.is_file() {
            let prose = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| PROSE_EXTENSIONS.contains(&e));
            if !prose {
                files.push(
                    path.strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    Ok(())
}

/// Blank everything after a `#` that is outside quotes, line by line. Keeps offsets and newlines.
fn without_hash_comments(text: &str) -> String {
    text.split('\n')
        .map(|line| {
            let mut quote = None;
            for (at, c) in line.char_indices() {
                match (quote, c) {
                    (None, '"' | '\'') => quote = Some(c),
                    (Some(open), c) if c == open => quote = None,
                    (None, '#') => {
                        return format!("{}{}", &line[..at], " ".repeat(line.len() - at));
                    }
                    _ => {}
                }
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// ST-01: `safe.directory` set to `*`, in any spelling: `safe.directory=*`, a quoted argument
/// list, or a `[safe]` section of a git config file.
fn safe_directory_wildcard(relative: &str, text: &str, findings: &mut Vec<Finding>) {
    let line_of = |at: usize| text[..at].matches('\n').count() + 1;
    let mut report = |at: usize| {
        findings.push(Finding::new(
            "ST-01",
            format!("{relative}:{}", line_of(at)),
            "safe.directory is set to a wildcard; the git ownership check must stay on",
        ));
    };
    for (at, found) in text.match_indices("safe.directory") {
        let after = text[at + found.len()..]
            .trim_start_matches([' ', '\t', '"', '\'', '=', ',', ':', '[', ']', '(', ')']);
        if after.starts_with('*') {
            report(at);
        }
    }
    for (at, found) in text.match_indices("[safe]") {
        let section = text[at + found.len()..]
            .split("\n[")
            .next()
            .unwrap_or_default();
        let mut offset = at + found.len();
        for line in section.split('\n') {
            let line_text = line.trim();
            if let Some(rest) = line_text.strip_prefix("directory")
                && rest
                    .trim_start_matches([' ', '\t', '=', '"', '\''])
                    .starts_with('*')
            {
                report(offset);
            }
            offset += line.len() + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real_rules() -> Rules {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/architecture/crate-dependency-rules.json");
        Rules::load(&path).expect("the real rules file loads")
    }

    #[test]
    fn every_crate_these_scans_name_is_in_the_rules_file() {
        let rules = real_rules();
        for name in NAMED_CRATES {
            assert!(
                rules.crate_named(name).is_some(),
                "{name} is not in crate-dependency-rules.json"
            );
        }
    }

    #[test]
    fn the_rules_file_still_says_what_the_scans_enforce() {
        let rules = real_rules();
        let dep_09 = rules.statement("DEP-09").expect("DEP-09");
        for needle in [
            "begin_system",
            "workflow",
            "ChangeHost",
            "merge",
            ".specify",
            "speckit",
            "spec_adapter",
        ] {
            assert!(
                dep_09.contains(needle),
                "DEP-09 no longer mentions {needle}: {dep_09}"
            );
        }
        let dep_10 = rules.statement("DEP-10").expect("DEP-10");
        for needle in ["sandbox", "docker", "git", "runtime", "shell"] {
            assert!(
                dep_10.contains(needle),
                "DEP-10 no longer mentions {needle}: {dep_10}"
            );
        }
    }

    #[test]
    fn the_sandbox_crate_lives_where_the_ingestion_path_assumes() {
        let rules = real_rules();
        assert_eq!(
            rules.crate_named(SANDBOX).map(|c| c.path.as_str()),
            Some("crates/sandbox")
        );
    }

    #[test]
    fn a_wildcard_is_found_in_every_spelling() {
        for text in [
            "git config --global --add safe.directory '*'",
            "git -c safe.directory=* status",
            "[\"config\", \"safe.directory\", \"*\"]",
            "safe.directory: \"*\"",
            "[safe]\n\tdirectory = *\n",
        ] {
            let mut findings = Vec::new();
            safe_directory_wildcard("f", text, &mut findings);
            assert_eq!(findings.len(), 1, "{text}");
        }
    }

    #[test]
    fn a_named_directory_is_not_a_wildcard() {
        let mut findings = Vec::new();
        safe_directory_wildcard(
            "f",
            "git config --add safe.directory /work/repo\n[safe]\n\tdirectory = /work\n",
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn a_hash_comment_is_blanked_but_a_hash_in_quotes_is_kept() {
        let text = "a: 1 # note safe.directory=*\nb: \"x # y\" # tail\n";
        let blanked = without_hash_comments(text);
        assert_eq!(blanked.len(), text.len());
        assert!(!blanked.contains("note") && !blanked.contains("tail"));
        assert!(blanked.contains("\"x # y\""));
    }

    #[cfg(unix)]
    #[test]
    fn the_tree_walk_does_not_follow_symbolic_links() {
        let dir = std::env::temp_dir().join(format!("xtask-walk-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("a")).unwrap();
        fs::write(dir.join("a/file.sh"), "echo hi\n").unwrap();
        std::os::unix::fs::symlink(&dir, dir.join("a/loop")).unwrap();
        std::os::unix::fs::symlink(dir.join("a/file.sh"), dir.join("a/link.sh")).unwrap();

        let mut files = Vec::new();
        walk(&dir, &dir, &mut files).expect("a symbolic link loop must not break the walk");
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(files, ["a/file.sh"]);
    }

    #[test]
    fn program_names_lose_their_directory_and_extension() {
        assert_eq!(program_name("/usr/bin/Git"), "git");
        assert_eq!(program_name("C:\\Windows\\cmd.exe"), "cmd");
    }

    #[test]
    fn a_string_literal_argument_handles_escapes() {
        assert_eq!(
            string_literal_at_start("\"do\\\"cker\")").as_deref(),
            Some("do\"cker")
        );
        assert_eq!(string_literal_at_start("program)"), None);
    }
}
