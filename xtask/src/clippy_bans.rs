//! DEP-05: the inner crates make no call to the clock, the filesystem, the network or process
//! spawning. Clippy enforces it from each crate's `clippy.toml`. This module holds the ban list,
//! prints it, and checks that each inner crate's file still contains every entry.
//!
//! Clippy silently ignores a path it cannot resolve, so a misspelt entry bans nothing. The
//! tests in `tests/clippy_bans.rs` therefore compile a scratch crate under the rendered file and
//! check that every entry produces a diagnostic.

use crate::finding::Finding;
use crate::metadata::Workspace;
use crate::rules::{Role, Rules};
use crate::syntax;
use std::collections::BTreeSet;
use std::fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BanKind {
    Method,
    Type,
}

pub struct Ban {
    pub kind: BanKind,
    pub path: &'static str,
    pub reason: &'static str,
    /// A statement that uses the banned item, for the scratch crate. Empty when the test cannot
    /// build one (see `UNPROVEN`).
    pub snippet: &'static str,
    /// True when the path starts in a crate that not every inner crate depends on (`tokio`,
    /// `time`, `uuid`), or in a feature that may be off. The rendered entry then carries
    /// `allow-invalid = true`; without it clippy prints a warning for every run in a crate where
    /// the path does not resolve.
    pub optional_path: bool,
}

const CLOCK: &str = "Take the time from the Clock port.";
const FILES: &str = "The inner crates do no file I/O. Reach files through a port.";
const NETWORK: &str =
    "The inner crates open no network connection. Reach the network through a port.";
const PROCESS: &str = "The inner crates start no process. Only the sandbox crate does.";
const ENVIRONMENT: &str =
    "The inner crates do not read or change the process environment. Pass the value in.";
const IDENTIFIERS: &str =
    "The inner crates make no identifier. Take one from the IdGenerator port.";

const fn method(path: &'static str, reason: &'static str, snippet: &'static str) -> Ban {
    Ban {
        kind: BanKind::Method,
        path,
        reason,
        snippet,
        optional_path: false,
    }
}

const fn type_(path: &'static str, reason: &'static str, snippet: &'static str) -> Ban {
    Ban {
        kind: BanKind::Type,
        path,
        reason,
        snippet,
        optional_path: false,
    }
}

/// A method that lives in a crate or behind a feature that some inner crates do not have.
const fn optional_method(path: &'static str, reason: &'static str, snippet: &'static str) -> Ban {
    Ban {
        optional_path: true,
        ..method(path, reason, snippet)
    }
}

const fn optional_type(path: &'static str, reason: &'static str, snippet: &'static str) -> Ban {
    Ban {
        optional_path: true,
        ..type_(path, reason, snippet)
    }
}

/// Bans whose scratch snippet cannot be built, with the reason. The test lists them so the gap
/// is visible: each is spelled from the crate's documentation and source, and a misspelling
/// would ban nothing without a diagnostic.
pub const UNPROVEN: &[(&str, &str)] = &[
    (
        "time::OffsetDateTime::now_local",
        "needs the `local-offset` feature, which needs the `num_threads` crate; it is not in the offline registry cache",
    ),
    (
        "uuid::Uuid::new_v1",
        "needs the `v1` feature, which needs the `atomic` crate; it is not in the offline registry cache",
    ),
    ("uuid::Uuid::now_v1", "same as new_v1"),
    ("uuid::Uuid::new_v6", "same as new_v1"),
    ("uuid::Uuid::now_v6", "same as new_v1"),
];

/// The ban list for `domain`, `ports`, `workflow` and `spec_adapter`. The std paths resolve in
/// every crate. The `tokio`, `time` and `uuid` paths fire only where the crate and the feature
/// exist, and a crate where they do not simply has nothing to ban. The paths of `Path` cover a
/// `PathBuf` receiver too: the method is called through `Deref`, and the test shows it fires.
pub const BANS: &[Ban] = &[
    // The clock.
    method(
        "std::time::SystemTime::now",
        CLOCK,
        "let _ = std::time::SystemTime::now();",
    ),
    method(
        "std::time::Instant::now",
        CLOCK,
        "let _ = std::time::Instant::now();",
    ),
    method(
        "std::thread::sleep",
        CLOCK,
        "std::thread::sleep(std::time::Duration::from_millis(1));",
    ),
    optional_method(
        "time::OffsetDateTime::now_utc",
        CLOCK,
        "let _ = time::OffsetDateTime::now_utc();",
    ),
    optional_method("time::OffsetDateTime::now_local", CLOCK, ""),
    optional_method(
        "tokio::time::sleep",
        CLOCK,
        "let _ = tokio::time::sleep(std::time::Duration::from_millis(1));",
    ),
    optional_method(
        "tokio::time::sleep_until",
        CLOCK,
        "let _ = tokio::time::sleep_until(unimplemented!());",
    ),
    optional_method(
        "tokio::time::timeout",
        CLOCK,
        "let _ = tokio::time::timeout(std::time::Duration::from_millis(1), async {});",
    ),
    optional_method(
        "tokio::time::timeout_at",
        CLOCK,
        "let _ = tokio::time::timeout_at(unimplemented!(), async {});",
    ),
    optional_method(
        "tokio::time::interval",
        CLOCK,
        "let _ = tokio::time::interval(std::time::Duration::from_millis(1));",
    ),
    optional_method(
        "tokio::time::interval_at",
        CLOCK,
        "let _ = tokio::time::interval_at(unimplemented!(), std::time::Duration::from_millis(1));",
    ),
    optional_method(
        "tokio::time::Instant::now",
        CLOCK,
        "let _ = tokio::time::Instant::now();",
    ),
    // Identifiers.
    optional_method(
        "uuid::Uuid::new_v4",
        IDENTIFIERS,
        "let _ = uuid::Uuid::new_v4();",
    ),
    optional_method(
        "uuid::Uuid::now_v7",
        IDENTIFIERS,
        "let _ = uuid::Uuid::now_v7();",
    ),
    optional_method(
        "uuid::Uuid::new_v7",
        IDENTIFIERS,
        "let _ = uuid::Uuid::new_v7(unimplemented!());",
    ),
    optional_method(
        "uuid::Uuid::new_v8",
        IDENTIFIERS,
        "let _ = uuid::Uuid::new_v8([0; 16]);",
    ),
    optional_method("uuid::Uuid::new_v1", IDENTIFIERS, ""),
    optional_method("uuid::Uuid::now_v1", IDENTIFIERS, ""),
    optional_method("uuid::Uuid::new_v6", IDENTIFIERS, ""),
    optional_method("uuid::Uuid::now_v6", IDENTIFIERS, ""),
    // The file system.
    method("std::fs::read", FILES, "let _ = std::fs::read(\"x\");"),
    method(
        "std::fs::read_to_string",
        FILES,
        "let _ = std::fs::read_to_string(\"x\");",
    ),
    method(
        "std::fs::read_dir",
        FILES,
        "let _ = std::fs::read_dir(\"x\");",
    ),
    method(
        "std::fs::read_link",
        FILES,
        "let _ = std::fs::read_link(\"x\");",
    ),
    method(
        "std::fs::metadata",
        FILES,
        "let _ = std::fs::metadata(\"x\");",
    ),
    method(
        "std::fs::symlink_metadata",
        FILES,
        "let _ = std::fs::symlink_metadata(\"x\");",
    ),
    method(
        "std::fs::canonicalize",
        FILES,
        "let _ = std::fs::canonicalize(\"x\");",
    ),
    method("std::fs::exists", FILES, "let _ = std::fs::exists(\"x\");"),
    method(
        "std::fs::write",
        FILES,
        "let _ = std::fs::write(\"x\", \"y\");",
    ),
    method(
        "std::fs::copy",
        FILES,
        "let _ = std::fs::copy(\"x\", \"y\");",
    ),
    method(
        "std::fs::rename",
        FILES,
        "let _ = std::fs::rename(\"x\", \"y\");",
    ),
    method(
        "std::fs::hard_link",
        FILES,
        "let _ = std::fs::hard_link(\"x\", \"y\");",
    ),
    method(
        "std::fs::remove_file",
        FILES,
        "let _ = std::fs::remove_file(\"x\");",
    ),
    method(
        "std::fs::remove_dir",
        FILES,
        "let _ = std::fs::remove_dir(\"x\");",
    ),
    method(
        "std::fs::remove_dir_all",
        FILES,
        "let _ = std::fs::remove_dir_all(\"x\");",
    ),
    method(
        "std::fs::create_dir",
        FILES,
        "let _ = std::fs::create_dir(\"x\");",
    ),
    method(
        "std::fs::create_dir_all",
        FILES,
        "let _ = std::fs::create_dir_all(\"x\");",
    ),
    method(
        "std::path::Path::exists",
        FILES,
        "let _ = std::path::Path::new(\"x\").exists();",
    ),
    method(
        "std::path::Path::try_exists",
        FILES,
        "let _ = std::path::Path::new(\"x\").try_exists();",
    ),
    method(
        "std::path::Path::is_file",
        FILES,
        "let _ = std::path::Path::new(\"x\").is_file();",
    ),
    method(
        "std::path::Path::is_dir",
        FILES,
        "let _ = std::path::Path::new(\"x\").is_dir();",
    ),
    method(
        "std::path::Path::read_dir",
        FILES,
        "let _ = std::path::Path::new(\"x\").read_dir();",
    ),
    method(
        "std::path::Path::metadata",
        FILES,
        "let _ = std::path::Path::new(\"x\").metadata();",
    ),
    method(
        "std::path::Path::symlink_metadata",
        FILES,
        "let _ = std::path::Path::new(\"x\").symlink_metadata();",
    ),
    method(
        "std::path::Path::canonicalize",
        FILES,
        "let _ = std::path::Path::new(\"x\").canonicalize();",
    ),
    method(
        "std::path::Path::read_link",
        FILES,
        "let _ = std::path::Path::new(\"x\").read_link();",
    ),
    optional_method("tokio::fs::read", FILES, "let _ = tokio::fs::read(\"x\");"),
    optional_method(
        "tokio::fs::read_to_string",
        FILES,
        "let _ = tokio::fs::read_to_string(\"x\");",
    ),
    optional_method(
        "tokio::fs::write",
        FILES,
        "let _ = tokio::fs::write(\"x\", \"y\");",
    ),
    optional_method(
        "tokio::fs::read_dir",
        FILES,
        "let _ = tokio::fs::read_dir(\"x\");",
    ),
    optional_method(
        "tokio::fs::metadata",
        FILES,
        "let _ = tokio::fs::metadata(\"x\");",
    ),
    optional_method(
        "tokio::fs::try_exists",
        FILES,
        "let _ = tokio::fs::try_exists(\"x\");",
    ),
    optional_method(
        "tokio::fs::canonicalize",
        FILES,
        "let _ = tokio::fs::canonicalize(\"x\");",
    ),
    optional_method(
        "tokio::fs::remove_file",
        FILES,
        "let _ = tokio::fs::remove_file(\"x\");",
    ),
    optional_method(
        "tokio::fs::create_dir_all",
        FILES,
        "let _ = tokio::fs::create_dir_all(\"x\");",
    ),
    // The environment.
    method(
        "std::env::var",
        ENVIRONMENT,
        "let _ = std::env::var(\"x\");",
    ),
    method(
        "std::env::var_os",
        ENVIRONMENT,
        "let _ = std::env::var_os(\"x\");",
    ),
    method("std::env::vars", ENVIRONMENT, "let _ = std::env::vars();"),
    method(
        "std::env::vars_os",
        ENVIRONMENT,
        "let _ = std::env::vars_os();",
    ),
    method(
        "std::env::set_var",
        ENVIRONMENT,
        "unsafe { std::env::set_var(\"x\", \"y\") };",
    ),
    method(
        "std::env::remove_var",
        ENVIRONMENT,
        "unsafe { std::env::remove_var(\"x\") };",
    ),
    method(
        "std::env::current_dir",
        ENVIRONMENT,
        "let _ = std::env::current_dir();",
    ),
    method(
        "std::env::current_exe",
        ENVIRONMENT,
        "let _ = std::env::current_exe();",
    ),
    method(
        "std::env::temp_dir",
        ENVIRONMENT,
        "let _ = std::env::temp_dir();",
    ),
    // The network.
    method(
        "std::net::ToSocketAddrs::to_socket_addrs",
        NETWORK,
        "let _ = std::net::ToSocketAddrs::to_socket_addrs(\"localhost:80\");",
    ),
    optional_method(
        "tokio::net::lookup_host",
        NETWORK,
        "let _ = tokio::net::lookup_host(\"localhost:80\");",
    ),
    // Processes.
    method(
        "std::process::Command::new",
        PROCESS,
        "let _ = std::process::Command::new(\"x\");",
    ),
    optional_method(
        "tokio::process::Command::new",
        PROCESS,
        "let _ = tokio::process::Command::new(\"x\");",
    ),
    type_(
        "std::fs::File",
        FILES,
        "let _: Option<std::fs::File> = None;",
    ),
    type_(
        "std::fs::OpenOptions",
        FILES,
        "let _: Option<std::fs::OpenOptions> = None;",
    ),
    optional_type(
        "tokio::fs::File",
        FILES,
        "let _: Option<tokio::fs::File> = None;",
    ),
    optional_type(
        "tokio::fs::OpenOptions",
        FILES,
        "let _: Option<tokio::fs::OpenOptions> = None;",
    ),
    type_(
        "std::net::TcpStream",
        NETWORK,
        "let _: Option<std::net::TcpStream> = None;",
    ),
    type_(
        "std::net::TcpListener",
        NETWORK,
        "let _: Option<std::net::TcpListener> = None;",
    ),
    type_(
        "std::net::UdpSocket",
        NETWORK,
        "let _: Option<std::net::UdpSocket> = None;",
    ),
    type_(
        "std::os::unix::net::UnixStream",
        NETWORK,
        "let _: Option<std::os::unix::net::UnixStream> = None;",
    ),
    type_(
        "std::os::unix::net::UnixListener",
        NETWORK,
        "let _: Option<std::os::unix::net::UnixListener> = None;",
    ),
    type_(
        "std::os::unix::net::UnixDatagram",
        NETWORK,
        "let _: Option<std::os::unix::net::UnixDatagram> = None;",
    ),
    optional_type(
        "tokio::net::TcpStream",
        NETWORK,
        "let _: Option<tokio::net::TcpStream> = None;",
    ),
    optional_type(
        "tokio::net::TcpListener",
        NETWORK,
        "let _: Option<tokio::net::TcpListener> = None;",
    ),
    optional_type(
        "tokio::net::UdpSocket",
        NETWORK,
        "let _: Option<tokio::net::UdpSocket> = None;",
    ),
    optional_type(
        "tokio::net::UnixStream",
        NETWORK,
        "let _: Option<tokio::net::UnixStream> = None;",
    ),
    optional_type(
        "tokio::net::UnixListener",
        NETWORK,
        "let _: Option<tokio::net::UnixListener> = None;",
    ),
    optional_type(
        "tokio::net::UnixDatagram",
        NETWORK,
        "let _: Option<tokio::net::UnixDatagram> = None;",
    ),
    type_(
        "std::process::Command",
        PROCESS,
        "let _: Option<std::process::Command> = None;",
    ),
    optional_type(
        "tokio::process::Command",
        PROCESS,
        "let _: Option<tokio::process::Command> = None;",
    ),
];

/// The text of a `clippy.toml` with every ban. Print it with `cargo xtask clippy-toml`.
pub fn render_clippy_toml() -> String {
    let mut out = String::from(
        "# Generated by `cargo xtask clippy-toml`. DEP-05: this crate makes no call to the clock,\n\
         # the filesystem, the network or process spawning. `cargo xtask check-architecture`\n\
         # fails if an entry is missing or misspelt. Add entries for this crate below the\n\
         # generated ones; do not remove any.\n",
    );
    for (key, kind) in [
        ("disallowed-methods", BanKind::Method),
        ("disallowed-types", BanKind::Type),
    ] {
        out.push_str(&format!("\n{key} = [\n"));
        for ban in BANS.iter().filter(|b| b.kind == kind) {
            let optional = if ban.optional_path {
                ", allow-invalid = true"
            } else {
                ""
            };
            out.push_str(&format!(
                "    {{ path = \"{}\", reason = \"{}\"{optional} }},\n",
                ban.path, ban.reason
            ));
        }
        out.push_str("]\n");
    }
    out
}

/// The source of the scratch crate that proves the bans fire: a header line, then one function
/// per ban on its own line, in the order of `BANS`.
pub fn scratch_source() -> String {
    let mut out =
        String::from("#![allow(unused, unreachable_code, clippy::let_underscore_future)]\n");
    for (index, ban) in BANS.iter().enumerate() {
        out.push_str(&format!("pub fn ban_{index}() {{ {} }}\n", ban.snippet));
    }
    out
}

/// DEP-05: each inner crate has a `clippy.toml` that holds every ban. Extra entries are fine.
pub fn check(rules: &Rules, ws: &Workspace) -> Vec<Finding> {
    let mut findings = Vec::new();
    for member in &ws.members {
        let Some(Role::Library(rule)) = rules.role_of_package(&member.name) else {
            continue;
        };
        if !rules.source_scans.dep_05.inner_crates.contains(&rule.name) {
            continue;
        }
        let location = format!("{}/clippy.toml", ws.relative_dir(member));
        let Ok(text) = fs::read_to_string(member.dir.join("clippy.toml")) else {
            findings.push(Finding::new(
                "DEP-05",
                &location,
                format!(
                    "{} has no clippy.toml; create it with `cargo xtask clippy-toml > {location}`",
                    member.name
                ),
            ));
            continue;
        };
        let listed = match listed_bans(&text) {
            Ok(listed) => listed,
            Err(why) => {
                findings.push(Finding::new(
                    "DEP-05",
                    &location,
                    format!("cannot read the ban list: {why}"),
                ));
                continue;
            }
        };
        let missing: Vec<&str> = BANS
            .iter()
            .filter(|ban| !listed.contains(&(ban.kind, ban.path.to_string())))
            .map(|ban| ban.path)
            .collect();
        if !missing.is_empty() {
            findings.push(Finding::new(
                "DEP-05",
                &location,
                format!(
                    "{} does not ban: {}; clippy ignores a path it cannot resolve, so check the spelling (`cargo xtask clippy-toml` prints the full list)",
                    member.name,
                    missing.join(", ")
                ),
            ));
        }
    }
    findings
}

/// DEP-05, silencing: an `allow` or `expect` of one of the ban lints (or of `clippy::all` or
/// `warnings`, which include them) in an inner crate. The attribute can sit in `src`, in
/// `tests`, `benches` or `examples` (clippy runs on them with `--all-targets`), inside
/// `cfg_attr`, or as a lint table in the manifests or the cargo configuration.
pub fn check_silencing(rules: &Rules, ws: &Workspace) -> Result<Vec<Finding>, String> {
    let forbidden = &rules.source_scans.dep_05.forbidden_lint_allows;
    let mut findings = Vec::new();
    let mut manifests = vec![(ws.root.join("Cargo.toml"), "Cargo.toml".to_string())];
    for config in [".cargo/config.toml", ".cargo/config"] {
        let path = ws.root.join(config);
        if let Ok(text) = fs::read_to_string(&path) {
            for lint in forbidden
                .iter()
                .filter(|l| l.starts_with("clippy::disallowed"))
            {
                if text.contains(lint.as_str())
                    || text.contains(lint.trim_start_matches("clippy::"))
                {
                    findings.push(Finding::new(
                        "DEP-05",
                        config,
                        format!("the cargo configuration mentions {lint}, which could turn a ban off for every crate"),
                    ));
                }
            }
        }
    }
    for member in &ws.members {
        let Some(Role::Library(rule)) = rules.role_of_package(&member.name) else {
            continue;
        };
        if !rules.source_scans.dep_05.inner_crates.contains(&rule.name) {
            continue;
        }
        let relative = ws.relative_dir(member);
        manifests.push((
            member.dir.join("Cargo.toml"),
            format!("{relative}/Cargo.toml"),
        ));
        let mut files = Vec::new();
        rust_files_under(&member.dir, &mut files)?;
        for file in files {
            let text = fs::read_to_string(&file)
                .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
            let shown = file
                .strip_prefix(&ws.root)
                .unwrap_or(&file)
                .to_string_lossy()
                .replace('\\', "/");
            for attribute in syntax::lex(&text).lint_attributes() {
                if forbidden.contains(&attribute.lint) {
                    findings.push(Finding::new(
                        "DEP-05",
                        format!("{shown}:{}", line_of(&text, attribute.at)),
                        format!(
                            "{} has {}({}), which silences a DEP-05 ban; remove it and take the value through a port",
                            rule.name, attribute.level, attribute.lint
                        ),
                    ));
                }
            }
        }
    }
    for (path, shown) in manifests {
        if let Ok(text) = fs::read_to_string(&path) {
            for lint in crate::lints::silenced_lints(&text, forbidden) {
                findings.push(Finding::new(
                    "DEP-05",
                    shown.clone(),
                    format!("the manifest sets {lint} to allow, which silences a DEP-05 ban"),
                ));
            }
        }
    }
    Ok(findings)
}

/// Every `.rs` file under `dir`, without following links and without `target`.
fn rust_files_under(
    dir: &std::path::Path,
    files: &mut Vec<std::path::PathBuf>,
) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .path();
        let Ok(kind) = fs::symlink_metadata(&path).map(|m| m.file_type()) else {
            continue;
        };
        if kind.is_dir() {
            if path.file_name().is_some_and(|n| n != "target") {
                rust_files_under(&path, files)?;
            }
        } else if kind.is_file() && path.extension().is_some_and(|e| e == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

/// The paths listed under `disallowed-methods` and `disallowed-types`. This reads the two
/// shapes clippy documents, a plain string or an inline table with a `path` key, and fails on
/// anything else instead of skipping it.
pub fn listed_bans(clippy_toml: &str) -> Result<BTreeSet<(BanKind, String)>, String> {
    let mut found = BTreeSet::new();
    for (key, kind) in [
        ("disallowed-methods", BanKind::Method),
        ("disallowed-types", BanKind::Type),
    ] {
        if let Some(open) = list_start(clippy_toml, key)? {
            for path in list_paths(clippy_toml, open)? {
                found.insert((kind, path));
            }
        }
    }
    Ok(found)
}

/// The offset of the `[` that opens the list for `key`, if the file sets the key.
fn list_start(text: &str, key: &str) -> Result<Option<usize>, String> {
    let mut line_start = 0;
    for line in text.split('\n') {
        let indent = line.len() - line.trim_start().len();
        if let Some(after_key) = line[indent..].strip_prefix(key) {
            let blank = after_key.len() - after_key.trim_start().len();
            if let Some(after_equals) = after_key[blank..].strip_prefix('=') {
                let gap = after_equals.len() - after_equals.trim_start().len();
                let at = line_start + indent + key.len() + blank + 1 + gap;
                return if text.as_bytes().get(at) == Some(&b'[') {
                    Ok(Some(at))
                } else {
                    Err(format!("{key} must be a list"))
                };
            }
        }
        line_start += line.len() + 1;
    }
    Ok(None)
}

fn list_paths(text: &str, open: usize) -> Result<Vec<String>, String> {
    let bytes = text.as_bytes();
    let mut paths = Vec::new();
    let mut i = open + 1;
    loop {
        i = skip_blank(text, i);
        match bytes.get(i) {
            None => return Err("a list is not closed".to_string()),
            Some(b']') => return Ok(paths),
            Some(b'"' | b'\'') => {
                let (value, next) = read_string(text, i)?;
                paths.push(value);
                i = next;
            }
            Some(b'{') => {
                let (path, next) = read_inline_table(text, i)?;
                paths.extend(path);
                i = next;
            }
            Some(_) => {
                return Err(format!(
                    "unexpected text in a list on line {}",
                    line_of(text, i)
                ));
            }
        }
    }
}

/// Reads `{ path = "...", reason = "..." }` and returns the `path`, if any.
fn read_inline_table(text: &str, open: usize) -> Result<(Option<String>, usize), String> {
    let bytes = text.as_bytes();
    let mut path = None;
    let mut i = open + 1;
    loop {
        i = skip_blank(text, i);
        match bytes.get(i) {
            None => return Err("an inline table is not closed".to_string()),
            Some(b'}') => return Ok((path, i + 1)),
            Some(_) => {}
        }
        let key_start = i;
        while bytes
            .get(i)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
        {
            i += 1;
        }
        let key = &text[key_start..i];
        i = skip_blank(text, i);
        if key.is_empty() || bytes.get(i) != Some(&b'=') {
            return Err(format!(
                "unexpected text in an inline table on line {}",
                line_of(text, key_start)
            ));
        }
        i = skip_blank(text, i + 1);
        if matches!(bytes.get(i), Some(b'"' | b'\'')) {
            let (value, next) = read_string(text, i)?;
            if key == "path" {
                path = Some(value);
            }
            i = next;
        } else {
            i = skip_bare_value(text, i)?;
        }
    }
}

/// Skip a value that is not a string (a number, a boolean, a list or a table), and stop at the
/// comma or closing brace that ends it.
fn skip_bare_value(text: &str, from: usize) -> Result<usize, String> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => i = read_string(text, i)?.1 - 1,
            b'[' | b'{' => depth += 1,
            b']' => depth = depth.saturating_sub(1),
            b'}' if depth == 0 => return Ok(i),
            b'}' => depth -= 1,
            b',' if depth == 0 => return Ok(i),
            _ => {}
        }
        i += 1;
    }
    Err("an inline table is not closed".to_string())
}

/// A basic or literal one-line string. Returns its value and the offset after the closing quote.
fn read_string(text: &str, open: usize) -> Result<(String, usize), String> {
    let quote = char::from(text.as_bytes()[open]);
    let triple: String = std::iter::repeat_n(quote, 3).collect();
    if text[open..].starts_with(&triple) {
        return Err("multi-line strings are not supported".to_string());
    }
    let mut value = String::new();
    let mut chars = text[open + 1..].char_indices();
    while let Some((offset, c)) = chars.next() {
        if c == quote {
            return Ok((value, open + 1 + offset + 1));
        }
        if c == '\n' {
            break;
        }
        if c == '\\' && quote == '"' {
            if let Some((_, escaped)) = chars.next() {
                value.push(escaped);
            }
        } else {
            value.push(c);
        }
    }
    Err(format!(
        "a string on line {} is not closed",
        line_of(text, open)
    ))
}

/// Skip whitespace, commas and comments.
fn skip_blank(text: &str, from: usize) -> usize {
    let bytes = text.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'\r' | b'\n' | b',' => i += 1,
            b'#' => {
                i += bytes[i..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .unwrap_or(bytes.len() - i)
            }
            _ => break,
        }
    }
    i
}

fn line_of(text: &str, at: usize) -> usize {
    text[..at].matches('\n').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listed(text: &str) -> Vec<(BanKind, String)> {
        listed_bans(text).expect("parses").into_iter().collect()
    }

    #[test]
    fn it_reads_plain_strings_and_inline_tables() {
        let text = "disallowed-methods = [\n  \"a::b\",\n  { path = \"c::d\", reason = \"why\" },\n]\ndisallowed-types = [{ path = \"e::F\" }]\n";
        assert_eq!(
            listed(text),
            [
                (BanKind::Method, "a::b".into()),
                (BanKind::Method, "c::d".into()),
                (BanKind::Type, "e::F".into())
            ]
        );
    }

    #[test]
    fn a_reason_may_contain_brackets_braces_commas_and_hashes() {
        let text = "disallowed-methods = [\n  { reason = \"see [1], {2}, a # b\", path = \"x::y\" },\n  { path = \"z::w\", reason = 'it is' },\n]\n";
        assert_eq!(
            listed(text),
            [
                (BanKind::Method, "x::y".into()),
                (BanKind::Method, "z::w".into())
            ]
        );
    }

    #[test]
    fn comments_and_unrelated_keys_are_ignored() {
        let text = "# disallowed-methods = [\"not::this\"]\nallow-unwrap-in-tests = true\ndisallowed-types = [\n  # { path = \"nor::this\" },\n  \"yes::This\", # trailing\n]\n";
        assert_eq!(listed(text), [(BanKind::Type, "yes::This".into())]);
    }

    #[test]
    fn an_indented_key_still_counts() {
        assert_eq!(
            listed("  disallowed-methods = [\"a::b\"]\n"),
            [(BanKind::Method, "a::b".into())]
        );
    }

    #[test]
    fn a_file_without_the_keys_lists_nothing() {
        assert!(listed("avoid-breaking-exported-api = false\n").is_empty());
        assert!(listed("").is_empty());
    }

    #[test]
    fn other_values_in_a_table_are_skipped() {
        let text = "disallowed-methods = [{ path = \"a::b\", replacement = \"c::d\", allow-invalid = true, extra = [1, 2], t = { x = 1 } }]\n";
        assert_eq!(listed(text), [(BanKind::Method, "a::b".into())]);
    }

    #[test]
    fn unsupported_shapes_are_errors_not_silence() {
        for text in [
            "disallowed-methods = \"std::fs::read\"\n",
            "disallowed-methods = [\"a::b\"\n",
            "disallowed-methods = [\"a::b\", 42]\n",
            "disallowed-methods = [{ path = \"a::b\" ]\n",
            "disallowed-methods = [\"\"\"a::b\"\"\"]\n",
            "disallowed-methods = [\"a::b]\n",
        ] {
            assert!(listed_bans(text).is_err(), "{text:?} should not parse");
        }
    }

    #[test]
    fn the_four_inner_crates_are_the_ones_the_rules_file_names() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/architecture/crate-dependency-rules.json");
        let rules = Rules::load(&path).expect("rules");
        let statement = rules.statement("DEP-05").expect("DEP-05");
        for name in &rules.source_scans.dep_05.inner_crates {
            assert!(
                statement.contains(name),
                "DEP-05 no longer names {name}: {statement}"
            );
            assert!(rules.crate_named(name).is_some());
        }
    }

    #[test]
    fn every_snippet_fits_on_one_line_and_the_header_comes_first() {
        let source = scratch_source();
        assert!(source.starts_with("#![allow(unused, "));
        assert_eq!(source.lines().count(), BANS.len() + 1);
        assert!(
            BANS.iter()
                .all(|b| !b.snippet.contains('\n') && !b.reason.contains('"'))
        );
    }
}
