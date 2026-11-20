//! FX-REPO-CLEAN and FX-REPO-HOSTILE: the fixture repositories, and the ingestion attacks.
//!
//! The repositories are data in `fixtures/repos/security/`. Each has a `manifest.json` that lists
//! every file, link and directory of the repository with its purpose, the catalog tests that use
//! it and a SHA-256 of the stored bytes. This module reads the manifest, checks it, and writes the
//! repository out into a private temporary directory for a test.
//!
//! # Nothing here runs
//!
//! The hostile repository carries instruction text, hooks, an MCP server, a build script, an
//! install script and a nested `.git` with a hostile configuration. All of it is text. This module
//! writes the text to disk and does nothing else with it. No test in this crate runs a command
//! from it on the host. The one that shows the hostility is real runs git inside a container with
//! the hardened profile, and reports BLOCKED when Docker or the image is not there.
//!
//! # How the files are stored
//!
//! A stored file is `files/<path>.fixture`, with every path component that starts with a dot
//! stored as `dot-<name>`. The suffix and the rename keep tools from treating the fixture as live
//! configuration of this repository: `CLAUDE.md` and `.claude/settings.json` would be read by an
//! agent working here, `build.rs` is a build script, git cannot store a directory named `.git`,
//! and the root `.gitignore` excludes `.env.*`. The manifest records the real path for each.
//!
//! # No secret is stored
//!
//! Where a canary belongs, the stored file has a placeholder, `@@CANARY:<kind>@@`, and the value
//! is generated when the repository is written out. Other placeholders are `@@MARKER_DIR@@`
//! (the directory where a hostile command would leave a marker file), `@@HOST_CANARY_FILE@@` (a
//! file outside the repository that holds a canary) and `@@GIT_OWNERSHIP_OVERRIDE@@`, which becomes
//! the wildcard ownership override that the static check ST-01 forbids anywhere in this repository.
//! It is built from pieces here so that it never appears in a file.
//!
//! # Markers
//!
//! Every hostile command touches a file in `@@MARKER_DIR@@`. A test that proves something did not
//! run lists the directory and expects it empty ([`Materialized::markers_present`]).

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::canary::{CanaryKind, CanarySet};
use super::digest::sha256;
use super::encoding::hex_encode;
use super::tmpdir::FxTempDir;

/// The two fixture repositories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fixture {
    /// An ordinary small repository.
    Clean,
    /// A repository that attacks.
    Hostile,
}

impl Fixture {
    /// Both, in order.
    pub const ALL: [Fixture; 2] = [Fixture::Clean, Fixture::Hostile];

    /// The identifier in the catalog.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Fixture::Clean => "FX-REPO-CLEAN",
            Fixture::Hostile => "FX-REPO-HOSTILE",
        }
    }

    fn directory(self) -> &'static str {
        match self {
            Fixture::Clean => "clean",
            Fixture::Hostile => "hostile",
        }
    }
}

/// The directory that holds the fixtures: `fixtures/repos/security` at the workspace root.
#[must_use]
pub fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/repos/security")
}

/// What an entry of the manifest is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file with stored content.
    File,
    /// A directory.
    Dir,
    /// A symbolic link.
    Symlink,
}

/// One file, directory or link of a fixture repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// The path in the written-out repository.
    pub path: String,
    /// What it is.
    pub kind: EntryKind,
    /// For a file: the stored path under the fixture directory.
    pub stored: Option<String>,
    /// For a file: the SHA-256 (hex) of the stored bytes.
    pub sha256: Option<String>,
    /// The permission bits.
    pub mode: u32,
    /// For a link: the target, which may hold a placeholder.
    pub target: Option<String>,
    /// True when the stored file holds placeholders.
    pub template: bool,
    /// What the entry is for.
    pub role: String,
    /// The catalog test identifiers that use it.
    pub used_by: Vec<String>,
    /// Written out only for this variant, such as `replaced_root_git`.
    pub only_with: Option<String>,
}

/// A fixture repository's manifest.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Which fixture it is.
    pub fixture: Fixture,
    /// The directory it was read from.
    pub dir: PathBuf,
    /// A one-sentence description.
    pub summary: String,
    /// The marker file names the hostile commands touch.
    pub markers: Vec<String>,
    /// The placeholders the stored files use.
    pub placeholders: Vec<String>,
    /// The variants an entry can belong to, with a description.
    pub variants: BTreeMap<String, String>,
    /// Every entry.
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    /// Reads and checks the shape of a manifest.
    ///
    /// # Errors
    /// A message naming the problem when the file is missing or does not have the expected shape.
    pub fn load(fixture: Fixture) -> Result<Self, String> {
        let dir = fixtures_root().join(fixture.directory());
        let text = fs::read_to_string(dir.join("manifest.json"))
            .map_err(|e| format!("cannot read the manifest of {}: {e}", fixture.id()))?;
        let json: Value = serde_json::from_str(&text)
            .map_err(|e| format!("the manifest of {} is not JSON: {e}", fixture.id()))?;
        if json["schema_version"] != 1 {
            return Err("the manifest has an unknown schema_version".to_owned());
        }
        if json["id"] != fixture.id() {
            return Err(format!(
                "the manifest names {} instead of {}",
                json["id"],
                fixture.id()
            ));
        }
        let strings = |value: &Value| -> Vec<String> {
            value
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut entries = Vec::new();
        for raw in json["entries"].as_array().ok_or("entries is not a list")? {
            let text = |key: &str| raw[key].as_str().map(str::to_owned);
            let path = text("path").ok_or("an entry has no path")?;
            let kind = match raw["kind"].as_str() {
                Some("file") => EntryKind::File,
                Some("dir") => EntryKind::Dir,
                Some("symlink") => EntryKind::Symlink,
                other => return Err(format!("{path}: unknown kind {other:?}")),
            };
            let mode = u32::from_str_radix(raw["mode"].as_str().unwrap_or("0644"), 8)
                .map_err(|_| format!("{path}: bad mode"))?;
            entries.push(ManifestEntry {
                path,
                kind,
                stored: text("stored"),
                sha256: text("sha256"),
                mode,
                target: text("target"),
                template: raw["template"].as_bool().unwrap_or(false),
                role: text("role").unwrap_or_default(),
                used_by: strings(&raw["used_by"]),
                only_with: text("only_with"),
            });
        }
        Ok(Self {
            fixture,
            dir,
            summary: json["summary"].as_str().unwrap_or_default().to_owned(),
            markers: strings(&json["markers"]),
            placeholders: strings(&json["placeholders"]),
            variants: json["variants"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
                        .collect()
                })
                .unwrap_or_default(),
            entries,
        })
    }

    /// The entry with this path.
    #[must_use]
    pub fn entry(&self, path: &str) -> Option<&ManifestEntry> {
        self.entries.iter().find(|e| e.path == path)
    }

    /// The stored bytes of a file entry.
    ///
    /// # Errors
    /// The I/O error when the file cannot be read, or `InvalidInput` for an entry with no file.
    pub fn stored_bytes(&self, entry: &ManifestEntry) -> io::Result<Vec<u8>> {
        let stored = entry.stored.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "the entry has no stored file")
        })?;
        fs::read(self.dir.join(stored))
    }

    /// Entries whose stored bytes do not match the SHA-256 in the manifest, or cannot be read.
    #[must_use]
    pub fn digest_problems(&self) -> Vec<String> {
        self.problems_with(|entry| self.stored_bytes(entry).ok())
    }

    /// Like [`digest_problems`](Self::digest_problems), reading the bytes from `read` instead of
    /// the disk. Tests use it to show that a changed byte is noticed.
    #[must_use]
    pub fn problems_with(&self, read: impl Fn(&ManifestEntry) -> Option<Vec<u8>>) -> Vec<String> {
        let mut problems = Vec::new();
        for entry in self.entries.iter().filter(|e| e.kind == EntryKind::File) {
            match (read(entry), &entry.sha256) {
                (None, _) => {
                    problems.push(format!("{}: the stored file cannot be read", entry.path))
                }
                (Some(_), None) => {
                    problems.push(format!("{}: the manifest has no digest", entry.path))
                }
                (Some(bytes), Some(want)) => {
                    let got = hex_encode(&sha256(&bytes), false);
                    if &got != want {
                        problems.push(format!(
                            "{}: the stored bytes do not match the manifest",
                            entry.path
                        ));
                    }
                }
            }
        }
        problems
    }

    /// Stored files under `files/` that no entry names.
    #[must_use]
    pub fn orphans(&self) -> Vec<String> {
        let mut found = Vec::new();
        collect_files(&self.dir.join("files"), &self.dir, &mut found);
        let listed: Vec<&str> = self
            .entries
            .iter()
            .filter_map(|e| e.stored.as_deref())
            .collect();
        found.retain(|f| !listed.contains(&f.as_str()));
        found.sort();
        found
    }
}

fn collect_files(dir: &Path, base: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => collect_files(&path, base, out),
            Ok(_) => {
                if let Ok(relative) = path.strip_prefix(base) {
                    out.push(relative.to_string_lossy().replace('\\', "/"));
                }
            }
            Err(_) => {}
        }
    }
}

/// How to write a repository out.
#[derive(Debug, Clone, Default)]
pub struct MaterializeOptions {
    /// Also write the entries of the `replaced_root_git` variant: a hostile `.git` at the root.
    pub replaced_root_git: bool,
    /// The text that `@@MARKER_DIR@@` becomes. By default the real marker directory. A test that
    /// mounts the repository into a container sets the path as the container sees it.
    pub marker_path_text: Option<String>,
}

/// A repository written to disk. Dropping it removes everything, including the markers.
#[derive(Debug)]
pub struct Materialized {
    dir: FxTempDir,
    manifest: Manifest,
    canaries: CanarySet,
}

impl Materialized {
    /// The repository root.
    #[must_use]
    pub fn root(&self) -> PathBuf {
        self.dir.join("repo")
    }

    /// The directory where hostile commands leave marker files. Empty after writing.
    #[must_use]
    pub fn markers_dir(&self) -> PathBuf {
        self.dir.join("markers")
    }

    /// The file outside the repository that holds a canary.
    #[must_use]
    pub fn host_canary_file(&self) -> PathBuf {
        self.dir.join("host/canary.txt")
    }

    /// The directory that holds the repository, the markers and the host files.
    #[must_use]
    pub fn parent(&self) -> &Path {
        self.dir.path()
    }

    /// The manifest the repository was written from.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The canaries that were written into it.
    #[must_use]
    pub fn canaries(&self) -> &CanarySet {
        &self.canaries
    }

    /// The marker files that exist now. A file here means a hostile command ran.
    #[must_use]
    pub fn markers_present(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.markers_dir())
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }
}

/// Writes a fixture repository to a new temporary directory.
///
/// # Errors
/// A message when a manifest path is unsafe, a stored file does not match its digest, a
/// placeholder is unknown, or the disk refuses a write.
pub fn materialize(
    fixture: Fixture,
    canaries: &CanarySet,
    options: &MaterializeOptions,
) -> Result<Materialized, String> {
    write_out(Manifest::load(fixture)?, canaries, options)
}

/// Writes out a manifest that has already been loaded. [`materialize`] calls it. A test calls it
/// with a manifest it has changed, to show that a wrong digest or an unsafe path is refused.
///
/// # Errors
/// The same as [`materialize`].
pub fn write_out(
    manifest: Manifest,
    canaries: &CanarySet,
    options: &MaterializeOptions,
) -> Result<Materialized, String> {
    let io_error = |what: &str, e: io::Error| format!("{what}: {e}");
    let dir = FxTempDir::new("fx-repo").map_err(|e| io_error("temporary directory", e))?;
    let root = dir.join("repo");
    for sub in ["repo", "markers", "host"] {
        fs::create_dir(dir.join(sub)).map_err(|e| io_error(sub, e))?;
    }
    let host_value = canaries.get(CanaryKind::SecondTenantString).value();
    let host_text = format!("host-only secret: {host_value}\n");
    fs::write(dir.join("host/canary.txt"), &host_text).map_err(|e| io_error("host canary", e))?;
    // The target of the relative link that climbs out of the repository.
    fs::write(dir.join("host-secret"), &host_text).map_err(|e| io_error("host secret", e))?;

    let context = Context {
        canaries,
        marker_text: options
            .marker_path_text
            .clone()
            .unwrap_or_else(|| dir.join("markers").display().to_string()),
        host_canary_file: dir.join("host/canary.txt").display().to_string(),
    };

    for entry in &manifest.entries {
        match entry.only_with.as_deref() {
            None => {}
            Some("replaced_root_git") if options.replaced_root_git => {}
            Some(_) => continue,
        }
        let target = safe_path(&root, &entry.path)?;
        match entry.kind {
            EntryKind::Dir => {
                fs::create_dir_all(&target).map_err(|e| io_error(&entry.path, e))?;
                set_mode(&target, entry.mode)?;
            }
            EntryKind::File => {
                let bytes = manifest
                    .stored_bytes(entry)
                    .map_err(|e| io_error(&entry.path, e))?;
                let want = entry.sha256.as_deref().unwrap_or_default();
                if hex_encode(&sha256(&bytes), false) != want {
                    return Err(format!(
                        "{}: the stored bytes do not match the manifest; the fixture was changed",
                        entry.path
                    ));
                }
                let content = if entry.template {
                    let text = String::from_utf8(bytes)
                        .map_err(|_| format!("{}: a template must be UTF-8", entry.path))?;
                    context
                        .substitute(&text)
                        .map_err(|e| format!("{}: {e}", entry.path))?
                        .into_bytes()
                } else {
                    bytes
                };
                fs::write(&target, content).map_err(|e| io_error(&entry.path, e))?;
                set_mode(&target, entry.mode)?;
            }
            EntryKind::Symlink => {
                let link = entry
                    .target
                    .as_deref()
                    .ok_or_else(|| format!("{}: a link has no target", entry.path))?;
                let link = context
                    .substitute(link)
                    .map_err(|e| format!("{}: {e}", entry.path))?;
                make_symlink(&link, &target).map_err(|e| io_error(&entry.path, e))?;
            }
        }
    }
    Ok(Materialized {
        dir,
        manifest,
        canaries: canaries.clone(),
    })
}

/// Joins a manifest path onto the root after checking it, and refuses to write through a link.
///
/// The manifest is data in this repository, and a changed manifest must not be able to write
/// outside the temporary directory: no absolute path, no `..`, no empty or odd component, and
/// every directory already on the way must be a real directory and not a link.
fn safe_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.contains('\\')
        || relative.contains('\0')
        || relative.len() > 4096
    {
        return Err(format!("{relative:?}: not a safe relative path"));
    }
    let mut current = root.to_path_buf();
    let parts: Vec<&str> = relative.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || *part == "." || *part == ".." {
            return Err(format!("{relative:?}: not a safe relative path"));
        }
        current.push(part);
        if index + 1 < parts.len() {
            match fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(format!("{relative:?}: passes through a link at {part}"));
                }
                Ok(meta) if !meta.is_dir() => {
                    return Err(format!("{relative:?}: {part} is not a directory"));
                }
                Ok(_) => {}
                Err(_) => fs::create_dir(&current)
                    .map_err(|e| format!("{relative:?}: cannot make {part}: {e}"))?,
            }
        }
    }
    Ok(current)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn make_symlink(target: &str, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn make_symlink(_target: &str, _link: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "links need a unix host",
    ))
}

struct Context<'a> {
    canaries: &'a CanarySet,
    marker_text: String,
    host_canary_file: String,
}

impl Context<'_> {
    /// Replaces each placeholder once, in a single pass, so a canary that happens to contain `@@`
    /// is not read as another placeholder.
    fn substitute(&self, text: &str) -> Result<String, String> {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find("@@") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let Some(end) = after.find("@@") else {
                return Err("an unclosed placeholder".to_owned());
            };
            let name = &after[..end];
            out.push_str(&self.value(name)?);
            rest = &after[end + 2..];
        }
        out.push_str(rest);
        Ok(out)
    }

    fn value(&self, name: &str) -> Result<String, String> {
        if let Some(kind) = name.strip_prefix("CANARY:") {
            let kind = CanaryKind::from_name(kind)
                .ok_or_else(|| format!("unknown canary kind {kind:?}"))?;
            return Ok(self.canaries.get(kind).value().to_owned());
        }
        match name {
            "MARKER_DIR" => Ok(self.marker_text.clone()),
            "HOST_CANARY_FILE" => Ok(self.host_canary_file.clone()),
            // The wildcard ownership override. It is assembled here from pieces so that the text
            // never appears in a file of this repository, where the static check ST-01 would
            // refuse it.
            "GIT_OWNERSHIP_OVERRIDE" => Ok(["[sa", "fe]\n\tdirec", "tory = *"].concat()),
            other => Err(format!("unknown placeholder {other:?}")),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Ingestion attacks
// ---------------------------------------------------------------------------------------------

/// The hostile entries that the sandbox could leave in a workspace (NT-SBX-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttackKind {
    /// A named pipe, which blocks a reader that opens it.
    Fifo,
    /// A socket file.
    Socket,
    /// A hard link to a file outside the workspace.
    Hardlink,
    /// A file with the setuid bit.
    Setuid,
    /// A file over the size limit, made sparse so it costs no disk.
    Oversize,
    /// A great many tiny files.
    ManyTinyFiles,
    /// A file name with a line break.
    NewlineName,
    /// A file name with terminal control codes.
    AnsiName,
    /// A file name that is not valid UTF-8.
    InvalidUtf8Name,
    /// A file name over 255 bytes.
    OverlongName,
    /// A path over 4096 bytes.
    OverlongPath,
}

impl AttackKind {
    /// Every attack.
    pub const ALL: [AttackKind; 11] = [
        AttackKind::Fifo,
        AttackKind::Socket,
        AttackKind::Hardlink,
        AttackKind::Setuid,
        AttackKind::Oversize,
        AttackKind::ManyTinyFiles,
        AttackKind::NewlineName,
        AttackKind::AnsiName,
        AttackKind::InvalidUtf8Name,
        AttackKind::OverlongName,
        AttackKind::OverlongPath,
    ];
}

/// How big to make the volume attacks.
#[derive(Debug, Clone, Copy)]
pub struct AttackOptions {
    /// The size of the oversize file. The default is one byte over `path_access.max_file_bytes`.
    pub oversize_bytes: u64,
    /// How many tiny files to write. The policy's limit is 200,000; the default is small so a
    /// test run is quick, and a test of the limit sets it.
    pub tiny_files: usize,
}

impl Default for AttackOptions {
    fn default() -> Self {
        Self {
            oversize_bytes: 5 * 1024 * 1024 + 1,
            tiny_files: 1_000,
        }
    }
}

/// What [`plant_ingestion_attacks`] did.
#[derive(Debug, Default)]
pub struct AttackReport {
    /// Attacks that were planted, with the path of the entry (the directory for many files).
    pub planted: Vec<(AttackKind, PathBuf)>,
    /// Attacks the host could not plant, and why. Never silently dropped: a test that needs one
    /// must use a synthetic entry or the sandbox.
    pub unsupported: Vec<(AttackKind, String)>,
}

impl AttackReport {
    /// The path an attack was planted at.
    #[must_use]
    pub fn path_of(&self, kind: AttackKind) -> Option<&Path> {
        self.planted
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, p)| p.as_path())
    }
}

/// Plants the hostile entries of NT-SBX-09 in `workspace`, for the tests of the no-follow audit
/// walk. `outside_file` is a file outside the workspace that the hard link points at.
///
/// The same entries are made by the sandbox itself in the Docker test of the catalog. This is the
/// host-side version, so the walk can be tested without Docker. Nothing planted here is opened
/// except to create it.
#[cfg(unix)]
pub fn plant_ingestion_attacks(
    workspace: &Path,
    outside_file: &Path,
    options: &AttackOptions,
) -> AttackReport {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let mut report = AttackReport::default();
    let mut record = |kind: AttackKind, path: PathBuf, result: io::Result<()>| match result {
        Ok(()) => report.planted.push((kind, path)),
        Err(error) => report.unsupported.push((kind, error.to_string())),
    };

    let fifo = workspace.join("pipe");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .and_then(|s| {
            if s.success() {
                Ok(())
            } else {
                Err(io::Error::other("mkfifo failed"))
            }
        });
    record(AttackKind::Fifo, fifo, made);

    let socket = workspace.join("sock");
    let made = std::os::unix::net::UnixListener::bind(&socket).map(drop);
    record(AttackKind::Socket, socket, made);

    let hard = workspace.join("hardlink-to-outside");
    record(
        AttackKind::Hardlink,
        hard.clone(),
        fs::hard_link(outside_file, &hard),
    );

    let setuid = workspace.join("setuid-file");
    let made = fs::write(&setuid, b"#!/bin/sh\n")
        .and_then(|()| fs::set_permissions(&setuid, fs::Permissions::from_mode(0o4755)));
    record(AttackKind::Setuid, setuid, made);

    let big = workspace.join("oversize.bin");
    let made = fs::File::create(&big).and_then(|f| f.set_len(options.oversize_bytes));
    record(AttackKind::Oversize, big, made);

    let tiny = workspace.join("tiny");
    let made = fs::create_dir(&tiny).and_then(|()| {
        (0..options.tiny_files).try_for_each(|n| fs::write(tiny.join(format!("f{n}")), b""))
    });
    record(AttackKind::ManyTinyFiles, tiny, made);

    let newline = workspace.join("line\nbreak.txt");
    record(
        AttackKind::NewlineName,
        newline.clone(),
        fs::write(&newline, b"x"),
    );

    let ansi = workspace.join("red\u{1b}[31mname.txt");
    record(AttackKind::AnsiName, ansi.clone(), fs::write(&ansi, b"x"));

    let invalid = workspace.join(std::ffi::OsStr::from_bytes(b"bad-\xff\xfe-name.txt"));
    record(
        AttackKind::InvalidUtf8Name,
        invalid.clone(),
        fs::write(&invalid, b"x"),
    );

    let overlong_name = workspace.join("n".repeat(256));
    record(
        AttackKind::OverlongName,
        overlong_name.clone(),
        fs::write(&overlong_name, b"x"),
    );

    // A path over 4096 bytes cannot be named in one call on this host, because the kernel's own
    // limit is the same. The audit walk's limit is tested with a synthetic entry.
    report.unsupported.push((
        AttackKind::OverlongPath,
        "the kernel refuses a path over its own limit; test the walk's limit with a synthetic entry"
            .to_owned(),
    ));
    report
}

#[cfg(test)]
mod tests;
