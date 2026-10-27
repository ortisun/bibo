//! The rules that need a scan of the source: DEP-09 and DEP-10 from the rules file, and the static
//! checks ST-01 to ST-05, ST-09, ST-13 and ST-14 from the negative-test catalog.
//!
//! These scans are guard rails, not proofs. Most read the token stream of `syntax`, a few read
//! masked text, and none expands a macro or follows a path through a re-export in another file,
//! so code that builds a name at run time is not seen. The process spawn recorder in the
//! end-to-end tests covers that side (ST-03).
//!
//! Every parameter (which crate may spawn which program, where the posture verifier and the
//! ingestion module live, the shells, the container flags) is read from the `source_scans`
//! section of the rules file. Nothing is listed in this file.

use crate::finding::Finding;
use crate::metadata::Workspace;
use crate::rules::{Role, Rules};
use crate::scan::{self, Source, brace_block, find_word, is_ident, next_ident};
use crate::source_scans::SourceScans;
use crate::syntax::{Kind, Resolver, ends_with, is_under};
use std::fs;
use std::path::Path;

struct Scanned {
    /// The name in the rules file, such as `sandbox` or `api`.
    name: String,
    /// The crate directory relative to the workspace root.
    dir: String,
    sources: Vec<Source>,
}

pub fn check(rules: &Rules, ws: &Workspace) -> Result<Vec<Finding>, String> {
    let scans = &rules.source_scans;
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
            sources: scan::production_sources(&ws.root, &member.dir, &member.production_targets)?,
        });
    }

    let mut findings = Vec::new();
    for krate in &scanned {
        for source in &krate.sources {
            let resolver = Resolver::new(&source.syntax);
            begin_system_only_in_workflow(scans, krate, source, &mut findings);
            spec_kit_layout_only_in_spec_adapter(scans, krate, source, &mut findings);
            change_host_has_no_merge_method(scans, source, &mut findings);
            process_spawning(scans, krate, source, &resolver, &mut findings);
            no_equality_on_signatures(source, &mut findings);
            container_flags_only_in_the_posture_verifier(scans, krate, source, &mut findings);
            no_merge_or_deploy_path(scans, source, &mut findings);
            workspace_reads_go_through_ingestion(scans, krate, source, &resolver, &mut findings);
            constructors_only_where_allowed(scans, krate, source, &resolver, &mut findings);
            no_metering_in_workflow(scans, krate, source, &mut findings);
        }
    }
    tree_checks(scans, &ws.root, &mut findings)?;
    Ok(findings)
}

// ---------------------------------------------------------------------------------------------
// DEP-09

/// `Store::begin_system` is called only from the workflow crate. Defining or implementing it is
/// not a call.
fn begin_system_only_in_workflow(
    scans: &SourceScans,
    krate: &Scanned,
    source: &Source,
    findings: &mut Vec<Finding>,
) {
    let rule = &scans.dep_09;
    if krate.name == rule.begin_system_crate {
        return;
    }
    for at in find_word(&source.code, &rule.begin_system_function) {
        if !preceded_by_fn(&source.code, at) {
            findings.push(Finding::new(
                "DEP-09",
                source.location(at),
                format!(
                    "{} calls {}; only the {} crate may open a system transaction",
                    krate.name, rule.begin_system_function, rule.begin_system_crate
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
    scans: &SourceScans,
    krate: &Scanned,
    source: &Source,
    findings: &mut Vec<Finding>,
) {
    let rule = &scans.dep_09;
    if krate.name == rule.spec_kit_crate {
        return;
    }
    let lowercase = source.with_strings.to_ascii_lowercase();
    for term in &rule.spec_kit_terms {
        for (at, _) in lowercase.match_indices(term.as_str()) {
            findings.push(Finding::new(
                "DEP-09",
                source.location(at),
                format!(
                    "{} mentions {term:?}; only the {} crate may know the Spec Kit layout",
                    krate.name, rule.spec_kit_crate
                ),
            ));
        }
    }
}

/// `ChangeHost` has no method whose name starts with `merge`, `ready` or `undraft`. The factory
/// never merges and never marks a pull request ready for review.
fn change_host_has_no_merge_method(
    scans: &SourceScans,
    source: &Source,
    findings: &mut Vec<Finding>,
) {
    let rule = &scans.dep_09;
    for at in find_word(&source.code, "trait") {
        let Some((name_at, name)) = next_ident(&source.code, at + "trait".len()) else {
            continue;
        };
        if !name.starts_with(&rule.change_host_trait) {
            continue;
        }
        let Some((open, end)) = brace_block(&source.code, name_at + name.len()) else {
            continue;
        };
        let body = &source.code[open..end];
        for fn_at in find_word(body, "fn") {
            if let Some((method_at, method)) = next_ident(body, fn_at + 2)
                && rule
                    .forbidden_method_prefixes
                    .iter()
                    .any(|prefix| method.starts_with(prefix.as_str()))
            {
                findings.push(Finding::new(
                    "DEP-09",
                    source.location(open + method_at),
                    format!(
                        "trait {name} has a method named {method}; the factory never merges and never marks a pull request ready, so no method starts with {}",
                        rule.forbidden_method_prefixes.join(", ")
                    ),
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// DEP-10 and ST-03

/// Only one file contains a process-spawning path (ST-03). In it, only the crate that owns the
/// program may spawn it, and nobody spawns a shell (DEP-10).
///
/// Names are resolved first: `use std::process::Command as Cmd` and `use std::process::*` are
/// the same as the plain path. A mention counts wherever it is, import or call, so a re-export
/// of the type cannot carry it into another file.
fn process_spawning(
    scans: &SourceScans,
    krate: &Scanned,
    source: &Source,
    resolver: &Resolver,
    findings: &mut Vec<Finding>,
) {
    let rule = &scans.dep_10;
    let in_spawn_file = source.relative == rule.spawn_file;
    let banned = |path: &[String]| rule.spawn_paths.iter().any(|b| is_under(path, b));
    let mut reported = std::collections::BTreeSet::new();
    let mut mention = |at: usize, path: &[String], findings: &mut Vec<Finding>| {
        if in_spawn_file || !reported.insert(at) {
            return;
        }
        findings.push(Finding::new(
            "ST-03",
            source.location(at),
            format!(
                "{} mentions {}; only {} may contain a process-spawning path",
                krate.name,
                path.join("::"),
                rule.spawn_file
            ),
        ));
    };

    for import in source.syntax.imports() {
        let resolved = resolver
            .candidates(&import.path)
            .into_iter()
            .find(|c| banned(c));
        if let Some(path) = resolved {
            mention(import.at, &path, findings);
        }
    }
    for used in source.syntax.path_uses() {
        let Some(path) = resolver
            .candidates(&used.segments)
            .into_iter()
            .find(|c| banned(c))
        else {
            continue;
        };
        mention(used.at, &path, findings);
        if !ends_with(&path, &["Command", "new"]) {
            continue;
        }
        let program = source
            .syntax
            .tokens
            .get(used.next + 1)
            .filter(|t| t.kind == Kind::Str && source.syntax.is_punct(used.next, "("));
        program_rules(
            scans,
            krate,
            source.location(used.at),
            program.map(|t| program_name(&t.text)),
            findings,
        );
    }
}

/// DEP-10 and ST-03 for one `Command::new` call. `program` is `None` when the argument is not a
/// string literal.
fn program_rules(
    scans: &SourceScans,
    krate: &Scanned,
    location: String,
    program: Option<String>,
    findings: &mut Vec<Finding>,
) {
    let rule = &scans.dep_10;
    let own = rule.programs.iter().find(|p| p.krate == krate.name);
    let Some(program) = program else {
        if own.is_none() {
            findings.push(Finding::new(
                "DEP-10",
                location,
                format!("{} spawns a program that is not a string literal, so the allowed-program rule cannot be checked", krate.name),
            ));
        }
        return;
    };
    if rule.shells.contains(&program) {
        findings.push(Finding::new(
            "ST-03",
            location,
            format!("{} spawns the shell {program}", krate.name),
        ));
    } else if own.is_some_and(|o| o.programs.contains(&program)) {
        // The crate owns this program.
    } else if let Some(owner) = rule.programs.iter().find(|p| p.programs.contains(&program)) {
        findings.push(Finding::new(
            "DEP-10",
            location,
            format!(
                "{} spawns {program}; only the {} crate may spawn {}",
                krate.name,
                owner.krate,
                owner.programs.join(" or ")
            ),
        ));
    } else {
        let allowed: Vec<String> = rule
            .programs
            .iter()
            .map(|p| format!("{} in {}", p.programs.join(" and "), p.krate))
            .collect();
        findings.push(Finding::new(
            "DEP-10",
            location,
            format!(
                "{} spawns {program}, which is not an allowed program ({})",
                krate.name,
                allowed.join(", ")
            ),
        ));
    }
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
/// directory whose name starts with the verifier prefix, under the verifier crate's `src`.
fn container_flags_only_in_the_posture_verifier(
    scans: &SourceScans,
    krate: &Scanned,
    source: &Source,
    findings: &mut Vec<Finding>,
) {
    let rule = &scans.st_04;
    if krate.name == rule.verifier_crate
        && is_posture_verifier(rule.verifier_prefix.as_str(), krate, source)
    {
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
    for needle in &rule.dangerous_strings {
        for (at, _) in text.match_indices(needle.as_str()) {
            report(at, needle);
        }
    }
    for flag in &rule.host_namespace_flags {
        for (at, _) in text.match_indices(flag.as_str()) {
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

fn is_posture_verifier(prefix: &str, krate: &Scanned, source: &Source) -> bool {
    let src = format!("{}/src/", krate.dir);
    source
        .relative
        .strip_prefix(&src)
        .is_some_and(|inside| inside.split('/').any(|part| part.starts_with(prefix)))
}

// ---------------------------------------------------------------------------------------------
// ST-05

/// No function, route or workflow file named merge, deploy or release publish. The factory
/// opens draft pull requests and a human merges, so no such path exists in this release.
/// Reading the merged state of a pull request is fine.
fn no_merge_or_deploy_path(scans: &SourceScans, source: &Source, findings: &mut Vec<Finding>) {
    let rule = &scans.st_05;
    for at in find_word(&source.code, "fn") {
        let Some((name_at, name)) = next_ident(&source.code, at + 2) else {
            continue;
        };
        if is_merge_or_deploy_name(rule, name) {
            findings.push(Finding::new(
                "ST-05",
                source.location(name_at),
                format!("function {name} is a merge or deploy path; the factory has none, and a human approves and merges"),
            ));
        }
    }
    for (at, literal) in string_literals(source) {
        if literal.contains('/')
            && literal
                .split('/')
                .any(|segment| is_merge_or_deploy_segment(rule, segment))
        {
            findings.push(Finding::new(
                "ST-05",
                source.location(at),
                format!("route {literal:?} is a merge or deploy path; the factory has none"),
            ));
        }
    }
}

fn is_merge_or_deploy_name(rule: &crate::source_scans::St05, name: &str) -> bool {
    rule.verbs
        .iter()
        .any(|verb| name == verb || name.starts_with(&format!("{verb}_")))
        || rule.fragments.iter().any(|f| name.contains(f.as_str()))
}

fn is_merge_or_deploy_segment(rule: &crate::source_scans::St05, segment: &str) -> bool {
    let segment = segment.split('?').next().unwrap_or_default();
    rule.route_segments.iter().any(|s| s == segment)
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
/// the ingestion module (`workspace/` in the sandbox crate). A call is found through its
/// resolved path, so `use std::fs as f; f::read(..)` and `use std::fs::read; read(..)` count.
fn workspace_reads_go_through_ingestion(
    scans: &SourceScans,
    krate: &Scanned,
    source: &Source,
    resolver: &Resolver,
    findings: &mut Vec<Finding>,
) {
    let rule = &scans.st_09;
    if !rule.crates.contains(&krate.name) {
        return;
    }
    if krate.name == rule.ingestion_crate
        && source
            .relative
            .starts_with(&format!("{}/{}", krate.dir, rule.ingestion_dir))
    {
        return;
    }
    let message = |call: &str| {
        format!(
            "{} reads the filesystem with {}; every read of a workspace or output path goes through crates/{}/{}",
            krate.name,
            call.trim_end_matches('(').trim_start_matches('.'),
            rule.ingestion_crate,
            rule.ingestion_dir
        )
    };
    for used in source.syntax.path_uses() {
        if !source.syntax.is_punct(used.next, "(") {
            continue;
        }
        let candidates = resolver.candidates(&used.segments);
        for call in &rule.calls {
            let wanted: Vec<&str> = call.trim_end_matches('(').split("::").collect();
            if candidates.iter().any(|c| ends_with(c, &wanted)) {
                findings.push(Finding::new(
                    "ST-09",
                    source.location(used.at),
                    message(call),
                ));
            }
        }
    }
    let code = &source.code;
    for call in &rule.methods {
        for (at, _) in code.match_indices(call.as_str()) {
            findings.push(Finding::new("ST-09", source.location(at), message(call)));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// ST-13 and ST-14

/// A constructor that only some crates may call: `TenantScope::new(..)` as a call, or
/// `ResolvedPrincipal { .. }` as a struct literal. The type's own definition and its `impl`
/// blocks are not a use.
fn constructors_only_where_allowed(
    scans: &SourceScans,
    krate: &Scanned,
    source: &Source,
    resolver: &Resolver,
    findings: &mut Vec<Finding>,
) {
    for rule in &scans.st_13 {
        if rule.allowed_crates.contains(&krate.name) {
            continue;
        }
        let wanted: Vec<&str> = rule.name.split("::").collect();
        let is_call = wanted.len() > 1;
        for used in source.syntax.path_uses() {
            let matches = resolver
                .candidates(&used.segments)
                .iter()
                .any(|c| ends_with(c, &wanted));
            let syntax = &source.syntax;
            let constructs = if is_call {
                syntax.is_punct(used.next, "(")
            } else {
                // A struct literal. The name after `struct`, `impl`, `for` and similar words, or
                // after `->`, is a declaration or a return type, not a literal.
                let before = syntax.tokens.iter().rposition(|t| t.start < used.at);
                let declaration = before.is_some_and(|b| {
                    let t = &syntax.tokens[b];
                    (t.kind == Kind::Ident
                        && matches!(
                            t.text.as_str(),
                            "struct"
                                | "impl"
                                | "for"
                                | "enum"
                                | "trait"
                                | "union"
                                | "use"
                                | "type"
                                | "mod"
                                | "dyn"
                        ))
                        || (t.kind == Kind::Punct
                            && t.text == ">"
                            && b > 0
                            && syntax.is_punct(b - 1, "-"))
                });
                syntax.is_punct(used.next, "{") && !declaration
            };
            if matches && constructs {
                findings.push(Finding::new(
                    "ST-13",
                    source.location(used.at),
                    format!(
                        "{} constructs {}; only {} may",
                        krate.name,
                        rule.name,
                        rule.allowed_crates.join(", ")
                    ),
                ));
            }
        }
    }
}

/// The workflow crate does not mention the metering operations. The engine reads usage through
/// the ledger, and only the broker meters.
fn no_metering_in_workflow(
    scans: &SourceScans,
    krate: &Scanned,
    source: &Source,
    findings: &mut Vec<Finding>,
) {
    let rule = &scans.st_14;
    if krate.name != rule.krate {
        return;
    }
    for name in &rule.names {
        for at in find_word(&source.code, name) {
            findings.push(Finding::new(
                "ST-14",
                source.location(at),
                format!(
                    "{} mentions {name}; the engine does not touch metering",
                    krate.name
                ),
            ));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Checks over the whole repository tree

fn tree_checks(
    scans: &SourceScans,
    root: &Path,
    findings: &mut Vec<Finding>,
) -> Result<(), String> {
    let mut files = Vec::new();
    walk(scans, root, root, &mut files)?;
    for relative in files {
        let path = root.join(&relative);
        if relative.starts_with(".github/workflows/") {
            let name = relative
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if scans
                .st_05
                .workflow_file_words
                .iter()
                .any(|word| name.contains(word.as_str()))
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
                scan::without_hash_comments(&text)
            };
            safe_directory_wildcard(&relative, &code, findings);
        }
    }
    Ok(())
}

/// Every file under `root` that may hold code or configuration, relative and sorted. Prose, build
/// output, nested checkouts such as git worktrees, and xtask itself (whose tests contain the
/// offending text on purpose) are left out.
fn walk(
    scans: &SourceScans,
    root: &Path,
    dir: &Path,
    files: &mut Vec<String>,
) -> Result<(), String> {
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
            // A directory with a `.git` entry of its own (a file for a git worktree, a directory
            // for a clone) is another checkout. Its sources are not part of this repository.
            let is_nested_checkout = path.join(".git").symlink_metadata().is_ok();
            let skipped = scans.st_01.skipped_directories.iter().any(|d| d == name);
            if !skipped && !is_xtask && !is_nested_checkout {
                walk(scans, root, &path, files)?;
            }
        } else if kind.is_file() {
            let prose = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| scans.st_01.prose_extensions.iter().any(|p| p == e));
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
    fn the_spawn_file_and_the_ingestion_path_are_inside_the_crates_that_own_them() {
        let rules = real_rules();
        let scans = &rules.source_scans;
        let sandbox = rules.crate_named("sandbox").expect("sandbox");
        assert!(
            scans
                .dep_10
                .spawn_file
                .starts_with(&format!("{}/src/", sandbox.path))
        );
        assert_eq!(scans.st_09.ingestion_crate, "sandbox");
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
        walk(&real_rules().source_scans, &dir, &dir, &mut files)
            .expect("a symbolic link loop must not break the walk");
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(files, ["a/file.sh"]);
    }

    #[test]
    fn program_names_lose_their_directory_and_extension() {
        assert_eq!(program_name("/usr/bin/Git"), "git");
        assert_eq!(program_name("C:\\Windows\\cmd.exe"), "cmd");
    }
}
