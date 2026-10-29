//! The audit walk: a no-follow walk of a tree the sandbox could write, before any byte of it is
//! read and before any diff is computed (`path_access.workspace_audit` of
//! `policies/security.yaml`).
//!
//! # What the walk never does
//!
//! It never opens a symbolic link, a FIFO, a socket or a device: it asks `lstat` what an entry is
//! and reads a link with `readlink`. A link is therefore text, and the text is judged: it may not
//! be absolute, and following it (lexically and through the other links of the tree, never on the
//! disk) may not leave the tree, reach a hidden path or reach a git directory.
//!
//! # What it rejects
//!
//! Every entry that breaks a rule gets a reason ([`AuditReason`]); the walk keeps going so that
//! the report lists them all, and stops early only when a limit makes going on pointless (too many
//! entries, too many bytes).
//!
//! * a `.git` entry anywhere except the empty regular file that is the mount point of the mask at
//!   the root (a directory is a nested repository, a file is a gitlink pointer);
//! * a file or link at a hidden path, or at a path the base commit holds but the checkout does not;
//! * a FIFO, socket, block or character device;
//! * a symbolic link that leaves the tree;
//! * a regular file with more than one hard link (it may be a link to a file outside the job);
//! * a setuid or setgid mode;
//! * a file over the size limit, a tree over the byte or entry limit, a path that is too long or
//!   too deep;
//! * a name with a control character, a backslash, or bytes that are not UTF-8.
//!
//! # Reading a file after the walk
//!
//! [`read_file`] opens a path the walk accepted. `std` has no no-follow open, so it checks the
//! entry with `lstat` before, opens it, and compares the device and inode of the open file with
//! what the walk saw. A path swapped for a link in between fails the comparison. A path swapped
//! for a FIFO would block the open, which is why `ingest` is called only after the container is
//! gone, and why the caller runs the walk on a blocking thread under a timeout.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use factory_ports::paths::{PathMode, PathRules, RepoPath, is_git_directory_alias};
use factory_ports::workspace::{PathViolation, WorkspaceError};

use super::AuditLimits;
use super::basetree::BaseTree;
use super::provider::PathPolicyLayer;

/// Why one entry was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditKind {
    /// A `.git` directory (or a link or other entry named like one), or a repository below the
    /// root.
    NestedGit,
    /// A `.git` file below the root: the pointer file of a submodule or linked worktree.
    GitFile,
    /// A symbolic link whose target leaves the tree, is absolute, loops, or reaches a protected
    /// place.
    EscapingSymlink,
    /// A file or link at a hidden path or at a path the checkout was built without.
    HiddenPath,
    /// A FIFO, socket, block device or character device.
    SpecialFile,
    /// A regular file with a link count over 1.
    HardLink,
    /// A setuid or setgid mode.
    SetuidMode,
    /// A name with a control character, a backslash or bytes that are not UTF-8.
    UnsafeName,
    /// A name over the limit.
    NameTooLong,
    /// A path over the limit.
    PathTooLong,
    /// A path with more components than the limit.
    TooDeep,
    /// A file over the limit.
    FileTooLarge,
    /// All the files together are over the limit.
    TreeTooLarge,
    /// More entries than the limit.
    TooManyEntries,
    /// The root of the checkout is not a directory any more.
    RootReplaced,
}

/// One rejected entry. The path is safe to print: bytes that are not printable are escaped as
/// `%XX`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReason {
    /// What was wrong.
    pub kind: AuditKind,
    /// Where. For a nested repository it is the directory that holds it.
    pub path: RepoPath,
}

/// Every reason a walk rejected a tree for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditReport {
    /// The reasons, in the order found (sorted names, depth first). At most [`MAX_REASONS`].
    pub reasons: Vec<AuditReason>,
}

/// The most reasons a report lists.
pub const MAX_REASONS: usize = 100;

impl AuditReport {
    /// The reasons of one kind.
    #[must_use]
    pub fn of_kind(&self, kind: AuditKind) -> Vec<&AuditReason> {
        self.reasons.iter().filter(|r| r.kind == kind).collect()
    }

    /// The error the `Workspace` port reports for this report. The port's error set is closed, so
    /// a few kinds share a variant: see the module documentation of `workspace`.
    pub(crate) fn into_error(self) -> WorkspaceError {
        let first = |kind: AuditKind| self.reasons.iter().find(|r| r.kind == kind);
        if let Some(r) = first(AuditKind::NestedGit) {
            return WorkspaceError::NestedGit(r.path.clone());
        }
        if let Some(r) = first(AuditKind::GitFile) {
            return WorkspaceError::Gitlink(r.path.clone());
        }
        if let Some(r) = first(AuditKind::EscapingSymlink) {
            return WorkspaceError::EscapingSymlink(r.path.clone());
        }
        if let Some(r) = first(AuditKind::HiddenPath) {
            return WorkspaceError::HiddenPathPresent(r.path.clone());
        }
        let refused: Vec<PathViolation> = self
            .reasons
            .iter()
            .filter(|r| {
                matches!(
                    r.kind,
                    AuditKind::SpecialFile
                        | AuditKind::HardLink
                        | AuditKind::SetuidMode
                        | AuditKind::UnsafeName
                        | AuditKind::RootReplaced
                )
            })
            .map(|r| PathViolation {
                path: r.path.clone(),
                mode: PathMode::DenyWrite,
            })
            .collect();
        if !refused.is_empty() {
            return WorkspaceError::ProtectedPathChanged(refused);
        }
        WorkspaceError::TooLarge
    }
}

/// Why a walk did not produce a manifest.
#[derive(Debug)]
pub(crate) enum AuditFailure {
    /// The tree broke at least one rule.
    Rejected(AuditReport),
    /// The stop flag was set.
    Stopped,
    /// The disk could not be read.
    Unreadable,
}

/// What the walk learned about an accepted entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Entry {
    /// A regular file.
    File {
        /// True when the owner may execute it.
        exec: bool,
        /// Its size when the walk looked.
        size: u64,
        /// Device and inode when the walk looked.
        identity: (u64, u64),
    },
    /// A symbolic link and its target text.
    Symlink {
        /// The target, as written.
        target: String,
    },
}

/// The accepted entries of a tree.
#[derive(Debug, Default)]
pub(crate) struct Manifest {
    /// Files and links by path relative to the root.
    pub entries: BTreeMap<String, Entry>,
    /// The sum of the file sizes.
    pub total_bytes: u64,
}

/// What the walk checks against.
pub(crate) struct WalkContext<'a> {
    pub limits: &'a AuditLimits,
    pub rules: &'a PathRules,
    pub base: &'a BaseTree,
    pub policy: Option<&'a PathPolicyLayer>,
    /// True for a checkout, which holds the empty regular file that the `.git` mask covers.
    pub mask_at_root: bool,
    pub stop: &'a AtomicBool,
}

struct Recorder {
    reasons: Vec<AuditReason>,
}

impl Recorder {
    fn add(&mut self, kind: AuditKind, path: RepoPath) {
        if self.reasons.len() < MAX_REASONS {
            self.reasons.push(AuditReason { kind, path });
        }
    }

    fn add_raw(&mut self, kind: AuditKind, raw: &[u8]) {
        self.add(kind, report_path(raw));
    }
}

/// The path to print for an entry: the path itself when it is a safe path, else the same bytes
/// with every unsafe one escaped as `%XX`, else a fixed stand-in.
pub(crate) fn report_path(raw: &[u8]) -> RepoPath {
    // A name that hides or reorders text is escaped in the report as a control character is, so
    // that the finding that names it cannot hide or reorder the text around it.
    if let Ok(text) = std::str::from_utf8(raw)
        && !text.chars().any(hides_text)
        && !looks_blank_or_alike(text)
        && let Ok(path) = RepoPath::new(text)
    {
        return path;
    }
    let mut escaped = String::with_capacity(raw.len());
    for byte in raw {
        if (0x20..0x7f).contains(byte) && *byte != b'%' && *byte != b'\\' {
            escaped.push(char::from(*byte));
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped.truncate(200);
    RepoPath::new(&escaped).unwrap_or_else(|_| stand_in())
}

fn stand_in() -> RepoPath {
    RepoPath::new("_unsafe_entry_").expect("a fixed safe name")
}

/// The first rule one name breaks: too long, not UTF-8, a control character or a backslash. A name
/// that hides or reorders text is checked separately, after the git directory aliases (see
/// [`hides_text`]), because `.git` followed by a zero width character is a nested git directory
/// first and an unreadable name second.
fn name_problem(raw: &[u8], limits: &AuditLimits) -> Option<AuditKind> {
    if raw.len() > limits.max_name_bytes {
        return Some(AuditKind::NameTooLong);
    }
    let Ok(text) = std::str::from_utf8(raw) else {
        return Some(AuditKind::UnsafeName);
    };
    if text.chars().any(char::is_control) || text.contains('\\') {
        return Some(AuditKind::UnsafeName);
    }
    None
}

/// True for a character that changes how a name reads without showing: the whole Unicode category
/// Cf (format characters: the bidirectional controls U+202A to U+202E and U+2066 to U+2069, the
/// zero width characters U+200B to U+200F and U+2060, the byte order mark U+FEFF, the soft hyphen,
/// the Arabic number signs, the interlinear annotation marks and the others), the line and
/// paragraph separators U+2028 and U+2029 (categories Zl and Zp), the tag block and the variation
/// selector supplement (U+E0000 to U+E0FFF: tag characters can carry a hidden message), and the
/// fillers that render as nothing and are not format characters (the combining grapheme joiner,
/// the Hangul fillers, the Khmer inherent vowels), and the braille pattern blank U+2800, a symbol
/// that prints as an empty cell (finding RR-13).
///
/// The standard library has no category lookup, so the Cf ranges are listed, from Unicode 16.
/// Letters, digits, marks, punctuation, symbols, emoji and the variation selectors U+FE00 to
/// U+FE0F, which emoji and CJK ideographs need, are not here: a name in any script passes. Two
/// legitimate uses are refused with the rest of the category: the zero width non-joiner of Persian
/// and the zero width joiner of emoji sequences and of some Indic scripts. A file that needs
/// either is rejected with a named reason and a person renames it, which is the safe side.
pub(crate) fn hides_text(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// True for a character that prints as empty space: Unicode White_Space (the no-break space, the
/// en and em spaces, the thin space, the narrow no-break space, the ideographic space and the
/// rest) and the braille blank. The control characters among them were refused before.
fn prints_blank(c: char) -> bool {
    c.is_whitespace() || c == '\u{2800}'
}

/// True for a variation selector: the basic block U+FE00 to U+FE0F, which emoji and CJK
/// ideographs need, and the Mongolian ones U+180B to U+180D. (The supplement U+E0100 to U+E01EF is
/// in the tag block that [`hides_text`] refuses.)
fn is_variation_selector(c: char) -> bool {
    matches!(c, '\u{FE00}'..='\u{FE0F}' | '\u{180B}'..='\u{180D}')
}

/// True for a combining mark of the blocks used to stack diacritics on a Latin letter. Marks of
/// other scripts (Hebrew points, Arabic vowels, Thai tone marks, Indic signs) are not counted, so a
/// name in those scripts is never judged by this.
fn is_stacking_mark(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{FE20}'..='\u{FE2F}'
    )
}

/// The most marks of [`is_stacking_mark`] one base character may carry in a name. Vietnamese needs
/// two (a vowel with a circumflex and a dot below); three or more are decoration.
const MAX_STACKED_MARKS: usize = 2;

/// True for a name that prints as empty or as another name, and that has no plain reason to
/// (finding RR-13). It is a second filter, next to [`hides_text`], for the things that are not
/// format characters:
///
/// * a name that begins or ends with a character that prints as a space (`report.md` followed by a
///   no-break space is two files that read the same in a change list), which includes a name made of
///   nothing else;
/// * a variation selector with nothing before it that can take one: at the start, after another
///   selector, or after an ASCII character other than the digit, `#` or `*` of a keycap sequence
///   (`1` followed by U+FE0F and U+20E3). Emoji and CJK ideographs, which are not ASCII, keep theirs;
/// * more than [`MAX_STACKED_MARKS`] combining marks in a row.
///
/// What it leaves alone, and why. A space that is not ASCII in the middle of a name passes: the
/// ideographic space is how Japanese file names are written, and typographic spaces occur in names
/// from word processors. The audit logs those (see [`has_inner_blank`]) and does not refuse them. A
/// name that is not in Unicode normal form NFC (`e` and a combining acute, where one character
/// exists) also passes: macOS writes names that way, and the standard library has no normalization
/// tables to tell the two forms apart, so two names that differ only in that cannot be told here
/// without a new dependency. Marks of scripts other than the Latin diacritics are not counted at
/// all.
pub(crate) fn looks_blank_or_alike(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    if chars.first().copied().is_some_and(prints_blank)
        || chars.last().copied().is_some_and(prints_blank)
    {
        return true;
    }
    let mut marks = 0;
    for (at, &c) in chars.iter().enumerate() {
        if is_variation_selector(c) {
            let base = at.checked_sub(1).map(|before| chars[before]);
            let keycap = c == '\u{FE0F}'
                && chars.get(at + 1) == Some(&'\u{20E3}')
                && base.is_some_and(|b| b.is_ascii_digit() || b == '#' || b == '*');
            let takes_one = base
                .is_some_and(|b| !b.is_ascii() && !is_variation_selector(b) && !prints_blank(b));
            if !keycap && !takes_one {
                return true;
            }
        }
        if is_stacking_mark(c) {
            marks += 1;
            if marks > MAX_STACKED_MARKS {
                return true;
            }
        } else {
            marks = 0;
        }
    }
    false
}

/// True for a name with a space that is not an ASCII space inside it (the no-break, thin and
/// ideographic spaces and the like). It is accepted and logged: such a name prints like one with an
/// ordinary space, and a person reading a change list cannot tell the two apart.
pub(crate) fn has_inner_blank(text: &str) -> bool {
    text.chars().any(|c| prints_blank(c) && c != ' ')
}

struct Pending {
    abs: PathBuf,
    rel: String,
    depth: usize,
}

/// Walks `root` and returns what it holds, or says why not.
pub(crate) fn walk(root: &Path, ctx: &WalkContext<'_>) -> Result<Manifest, AuditFailure> {
    let mut rec = Recorder {
        reasons: Vec::new(),
    };
    let root_meta = fs::symlink_metadata(root).map_err(|_| AuditFailure::Unreadable)?;
    if !root_meta.file_type().is_dir() {
        rec.add_raw(AuditKind::RootReplaced, b"_checkout_root_");
        return Err(AuditFailure::Rejected(AuditReport {
            reasons: rec.reasons,
        }));
    }
    let mut manifest = Manifest::default();
    let mut symlinks: BTreeMap<String, String> = BTreeMap::new();
    let mut visited: usize = 0;
    let mut stack = vec![Pending {
        abs: root.to_path_buf(),
        rel: String::new(),
        depth: 0,
    }];
    while let Some(dir) = stack.pop() {
        let mut names: Vec<OsString> = Vec::new();
        for item in fs::read_dir(&dir.abs).map_err(|_| AuditFailure::Unreadable)? {
            names.push(item.map_err(|_| AuditFailure::Unreadable)?.file_name());
        }
        names.sort();
        // Directories are pushed in reverse so that they are popped in name order.
        let mut subdirs = Vec::new();
        for name in names {
            visited += 1;
            if visited > ctx.limits.max_entries {
                rec.add_raw(AuditKind::TooManyEntries, b"_too_many_entries_");
                return Err(AuditFailure::Rejected(AuditReport {
                    reasons: rec.reasons,
                }));
            }
            if visited.is_multiple_of(256) && ctx.stop.load(Ordering::Relaxed) {
                return Err(AuditFailure::Stopped);
            }
            let abs = dir.abs.join(&name);
            let raw = name.as_bytes();
            let mut full_raw = dir.rel.as_bytes().to_vec();
            if !full_raw.is_empty() {
                full_raw.push(b'/');
            }
            full_raw.extend_from_slice(raw);
            let meta = fs::symlink_metadata(&abs).map_err(|_| AuditFailure::Unreadable)?;
            let file_type = meta.file_type();

            if let Some(kind) = name_problem(raw, ctx.limits) {
                rec.add_raw(kind, &full_raw);
                continue;
            }
            let Some(text) = name.to_str() else {
                rec.add_raw(AuditKind::UnsafeName, &full_raw);
                continue;
            };
            if full_raw.len() > ctx.limits.max_path_bytes {
                rec.add_raw(AuditKind::PathTooLong, &full_raw);
                continue;
            }
            if is_git_directory_alias(text) {
                let is_mask = ctx.mask_at_root
                    && dir.rel.is_empty()
                    && text == ".git"
                    && file_type.is_file()
                    && meta.len() == 0
                    && meta.nlink() == 1;
                if is_mask {
                    continue;
                }
                let holder: &[u8] = if dir.rel.is_empty() {
                    b"_checkout_root_"
                } else {
                    dir.rel.as_bytes()
                };
                let kind = if file_type.is_file() && !dir.rel.is_empty() {
                    AuditKind::GitFile
                } else {
                    AuditKind::NestedGit
                };
                rec.add_raw(kind, holder);
                continue;
            }
            if text.chars().any(hides_text) || looks_blank_or_alike(text) {
                rec.add_raw(AuditKind::UnsafeName, &full_raw);
                continue;
            }
            if has_inner_blank(text) {
                tracing::warn!(
                    entry = %report_path(&full_raw),
                    "a name holds a space that is not an ASCII space; it is accepted, and prints like an ordinary one"
                );
            }
            let rel = String::from_utf8_lossy(&full_raw).into_owned();
            let Ok(path) = RepoPath::new(&rel) else {
                rec.add_raw(AuditKind::UnsafeName, &full_raw);
                continue;
            };
            if file_type.is_dir() {
                if dir.depth + 1 >= ctx.limits.max_depth {
                    rec.add(AuditKind::TooDeep, path);
                    continue;
                }
                subdirs.push(Pending {
                    abs,
                    rel,
                    depth: dir.depth + 1,
                });
                continue;
            }
            // From here on the entry is a file, a link or something special.
            if let Some(gitlink) = ctx.base.gitlink_above(&rel) {
                rec.add_raw(AuditKind::GitFile, gitlink.as_bytes());
                continue;
            }
            let hidden = ctx.base.absent.contains(&rel)
                || (ctx.rules.classify(&path) == Some(PathMode::Hidden)
                    && !ctx.base.visible.contains_key(&rel));
            if hidden {
                rec.add(AuditKind::HiddenPath, path);
                continue;
            }
            if file_type.is_symlink() {
                match fs::read_link(&abs) {
                    Ok(target) => match target.to_str() {
                        Some(text) if text.len() <= ctx.limits.max_path_bytes => {
                            symlinks.insert(rel.clone(), text.to_owned());
                            manifest.entries.insert(
                                rel,
                                Entry::Symlink {
                                    target: text.to_owned(),
                                },
                            );
                        }
                        _ => rec.add(AuditKind::EscapingSymlink, path),
                    },
                    Err(_) => return Err(AuditFailure::Unreadable),
                }
            } else if file_type.is_file() {
                if meta.nlink() > 1 {
                    rec.add(AuditKind::HardLink, path);
                } else if meta.mode() & 0o6000 != 0 {
                    rec.add(AuditKind::SetuidMode, path);
                } else if meta.len() > ctx.limits.max_file_bytes {
                    rec.add(AuditKind::FileTooLarge, path);
                } else {
                    manifest.total_bytes = manifest.total_bytes.saturating_add(meta.len());
                    if manifest.total_bytes > ctx.limits.max_total_bytes {
                        rec.add_raw(AuditKind::TreeTooLarge, b"_tree_too_large_");
                        return Err(AuditFailure::Rejected(AuditReport {
                            reasons: rec.reasons,
                        }));
                    }
                    manifest.entries.insert(
                        rel,
                        Entry::File {
                            exec: meta.mode() & 0o100 != 0,
                            size: meta.len(),
                            identity: (meta.dev(), meta.ino()),
                        },
                    );
                }
            } else {
                // A FIFO, a socket, a block or character device, or a type this code does not
                // know. None of them is opened.
                rec.add(AuditKind::SpecialFile, path);
            }
        }
        while let Some(sub) = subdirs.pop() {
            stack.push(sub);
        }
    }

    // Links are judged last, when every link of the tree is known, so that a chain of links is
    // followed in the table and never on the disk.
    for (link, target) in &symlinks {
        let leaves = symlink_leaves(&symlinks, link, target, ctx.rules)
            || ctx
                .policy
                .is_some_and(|layer| layer.denies_symlink(link, target));
        if leaves {
            rec.add_raw(AuditKind::EscapingSymlink, link.as_bytes());
        }
    }

    if rec.reasons.is_empty() {
        Ok(manifest)
    } else {
        Err(AuditFailure::Rejected(AuditReport {
            reasons: rec.reasons,
        }))
    }
}

/// The most links one resolution follows before it counts as a loop.
const MAX_HOPS: usize = 40;

/// True when the link at `link` with text `target` leaves the tree, or ends at a hidden path or a
/// git directory. The resolution reads the table of links and nothing else: it never touches the
/// disk. Components that are not links are treated as plain names.
pub(crate) fn symlink_leaves(
    table: &BTreeMap<String, String>,
    link: &str,
    target: &str,
    rules: &PathRules,
) -> bool {
    if target.is_empty() || target.starts_with('/') {
        return true;
    }
    let mut stack: Vec<String> = link.split('/').map(str::to_owned).collect();
    stack.pop();
    let mut pending: VecDeque<String> = target.split('/').map(str::to_owned).collect();
    let mut hops = 0usize;
    while let Some(component) = pending.pop_front() {
        match component.as_str() {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() {
                    return true;
                }
            }
            name => {
                if is_git_directory_alias(name) {
                    return true;
                }
                stack.push(name.to_owned());
                if let Some(next) = table.get(&stack.join("/")) {
                    hops += 1;
                    if hops > MAX_HOPS || next.starts_with('/') {
                        return true;
                    }
                    stack.pop();
                    for part in next.split('/').rev() {
                        pending.push_front(part.to_owned());
                    }
                }
            }
        }
    }
    match RepoPath::new(&stack.join("/")) {
        Ok(resolved) => rules.classify(&resolved) == Some(PathMode::Hidden),
        // The tree root itself, or a path that is not a safe path.
        Err(_) => !stack.is_empty(),
    }
}

/// Why a file could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadFailure {
    /// The entry is not the regular file the walk saw.
    Changed,
    /// The file is larger than the limit.
    TooLarge,
    /// The disk failed.
    Io,
}

/// Reads a regular file the walk accepted, at most `limit` bytes.
pub(crate) fn read_file(
    abs: &Path,
    identity: (u64, u64),
    limit: u64,
) -> Result<Vec<u8>, ReadFailure> {
    let before = fs::symlink_metadata(abs).map_err(|_| ReadFailure::Io)?;
    if !before.file_type().is_file() || (before.dev(), before.ino()) != identity {
        return Err(ReadFailure::Changed);
    }
    let file = File::open(abs).map_err(|_| ReadFailure::Io)?;
    let open = file.metadata().map_err(|_| ReadFailure::Io)?;
    if !open.file_type().is_file() || (open.dev(), open.ino()) != identity || open.nlink() != 1 {
        return Err(ReadFailure::Changed);
    }
    read_bounded(file, limit)
}

/// Reads at most `limit` bytes and says `TooLarge` when the source has more. It never pulls more
/// than `limit + 1` bytes from the source, however large the source is.
fn read_bounded(source: impl Read, limit: u64) -> Result<Vec<u8>, ReadFailure> {
    let mut bytes = Vec::new();
    source
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ReadFailure::Io)?;
    if bytes.len() as u64 > limit {
        return Err(ReadFailure::TooLarge);
    }
    Ok(bytes)
}

/// One file of the output directory the audit accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputFile {
    /// The path below the output directory.
    pub path: RepoPath,
    /// Its size in bytes.
    pub size: u64,
    pub(crate) identity: (u64, u64),
}

/// Audits an output directory and lists its files. The same walk as the checkout, with no hidden
/// paths and no mask: a link, a pipe, a hard link or a nested git directory in `out/` is rejected.
///
/// # Errors
/// The [`AuditReport`] when the tree breaks a rule, and `None` in its place when the disk failed.
pub fn audit_output(
    out: &Path,
    limits: &AuditLimits,
    stop: &AtomicBool,
) -> Result<Vec<OutputFile>, Option<AuditReport>> {
    let rules = PathRules::default();
    let base = BaseTree::default();
    let ctx = WalkContext {
        limits,
        rules: &rules,
        base: &base,
        policy: None,
        mask_at_root: false,
        stop,
    };
    match walk(out, &ctx) {
        Ok(manifest) => Ok(manifest
            .entries
            .into_iter()
            .filter_map(|(path, entry)| match (RepoPath::new(&path), entry) {
                (Ok(path), Entry::File { size, identity, .. }) => Some(OutputFile {
                    path,
                    size,
                    identity,
                }),
                _ => None,
            })
            .collect()),
        Err(AuditFailure::Rejected(report)) => Err(Some(report)),
        Err(AuditFailure::Stopped | AuditFailure::Unreadable) => Err(None),
    }
}

/// Reads one file the output audit accepted, at most `limit` bytes.
///
/// # Errors
/// `TooLarge` when it is bigger than `limit`, `Io` when it changed since the audit or the disk
/// failed.
pub fn read_output_file(
    out: &Path,
    file: &OutputFile,
    limit: u64,
) -> Result<Vec<u8>, WorkspaceError> {
    read_file(&out.join(file.path.as_str()), file.identity, limit).map_err(
        |failure| match failure {
            ReadFailure::TooLarge => WorkspaceError::TooLarge,
            ReadFailure::Changed | ReadFailure::Io => {
                WorkspaceError::Io(factory_ports::workspace::IoOperation::Walk)
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_testkit::fx::repos::{AttackKind, AttackOptions, plant_ingestion_attacks};
    use factory_testkit::fx::tmpdir::FxTempDir;
    use std::os::unix::fs::symlink;

    fn limits() -> AuditLimits {
        AuditLimits::default()
    }

    fn run(root: &Path, mask: bool) -> Result<Manifest, AuditFailure> {
        let rules = PathRules::default();
        let base = BaseTree::default();
        let stop = AtomicBool::new(false);
        walk(
            root,
            &WalkContext {
                limits: &limits(),
                rules: &rules,
                base: &base,
                policy: None,
                mask_at_root: mask,
                stop: &stop,
            },
        )
    }

    fn kinds(result: Result<Manifest, AuditFailure>) -> Vec<(AuditKind, String)> {
        match result {
            Err(AuditFailure::Rejected(report)) => report
                .reasons
                .into_iter()
                .map(|r| (r.kind, r.path.as_str().to_owned()))
                .collect(),
            Err(other) => panic!("expected a rejection, got {other:?}"),
            Ok(manifest) => panic!("expected a rejection, got {:?}", manifest.entries),
        }
    }

    #[test]
    fn a_plain_tree_is_listed_and_the_mask_file_is_not() {
        let dir = FxTempDir::new("audit-plain").expect("tmp");
        fs::write(dir.join(".git"), b"").expect("mask");
        fs::create_dir(dir.join("src")).expect("dir");
        fs::write(dir.join("src/lib.rs"), b"fn main() {}\n").expect("file");
        symlink("src/lib.rs", dir.join("link")).expect("link");
        let manifest = run(dir.path(), true).expect("accepted");
        let names: Vec<&str> = manifest.entries.keys().map(String::as_str).collect();
        assert_eq!(names, vec!["link", "src/lib.rs"]);
    }

    #[test]
    fn every_special_entry_the_sandbox_can_plant_is_rejected_with_its_reason() {
        let dir = FxTempDir::new("audit-attacks").expect("tmp");
        let outside = FxTempDir::new("audit-outside").expect("tmp");
        let target = outside.join("secret.txt");
        fs::write(&target, b"host-only").expect("outside file");
        let options = AttackOptions {
            oversize_bytes: limits().max_file_bytes + 1,
            tiny_files: 10,
        };
        let report = plant_ingestion_attacks(dir.path(), &target, &options);
        // A file system may refuse a name that is not UTF-8 or is over 255 bytes (APFS does).
        // `a_name_that_is_not_safe_is_named_as_such` covers those two with synthetic bytes.
        let refused: Vec<AttackKind> = report.unsupported.iter().map(|(k, _)| *k).collect();
        assert!(
            refused.iter().all(|k| matches!(
                k,
                AttackKind::InvalidUtf8Name | AttackKind::OverlongName | AttackKind::OverlongPath
            )),
            "{:?}",
            report.unsupported
        );
        let found = kinds(run(dir.path(), false));
        let has = |kind: AuditKind, path: &str| found.iter().any(|(k, p)| *k == kind && p == path);
        assert!(has(AuditKind::SpecialFile, "pipe"), "{found:?}");
        assert!(has(AuditKind::SpecialFile, "sock"), "{found:?}");
        assert!(has(AuditKind::HardLink, "hardlink-to-outside"), "{found:?}");
        assert!(has(AuditKind::SetuidMode, "setuid-file"), "{found:?}");
        assert!(has(AuditKind::FileTooLarge, "oversize.bin"), "{found:?}");
        assert!(
            found
                .iter()
                .filter(|(k, _)| *k == AuditKind::UnsafeName)
                .count()
                >= 2,
            "newline and ANSI names: {found:?}"
        );
        assert!(
            report
                .planted
                .iter()
                .any(|(kind, _)| *kind == AttackKind::ManyTinyFiles)
        );
    }

    #[test]
    fn a_path_over_the_limit_is_rejected_although_each_name_is_short() {
        // The kernel will not make a path of 4,096 bytes, so the limit is lowered to show the rule.
        let dir = FxTempDir::new("audit-long-path").expect("tmp");
        fs::create_dir_all(dir.join("aaaaaaaa/bbbbbbbb")).expect("dirs");
        fs::write(dir.join("aaaaaaaa/bbbbbbbb/cccccccc.txt"), b"x").expect("file");
        let rules = PathRules::default();
        let base = BaseTree::default();
        let stop = AtomicBool::new(false);
        let short = AuditLimits {
            max_path_bytes: 20,
            ..limits()
        };
        let result = walk(
            dir.path(),
            &WalkContext {
                limits: &short,
                rules: &rules,
                base: &base,
                policy: None,
                mask_at_root: false,
                stop: &stop,
            },
        );
        let found = kinds(result);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, AuditKind::PathTooLong);
    }

    #[test]
    fn a_name_that_is_not_safe_is_named_as_such() {
        let limits = limits();
        assert_eq!(name_problem(b"fine-name.rs", &limits), None);
        assert_eq!(
            name_problem(b"bad-\xff\xfe-name.txt", &limits),
            Some(AuditKind::UnsafeName),
            "bytes that are not UTF-8"
        );
        assert_eq!(
            name_problem(b"line\nbreak.txt", &limits),
            Some(AuditKind::UnsafeName)
        );
        assert_eq!(
            name_problem(b"red\x1b[31mname", &limits),
            Some(AuditKind::UnsafeName)
        );
        assert_eq!(
            name_problem(b"back\\slash", &limits),
            Some(AuditKind::UnsafeName)
        );
        assert_eq!(
            name_problem(&[b'n'; 256], &limits),
            Some(AuditKind::NameTooLong)
        );
        assert_eq!(name_problem(&[b'n'; 255], &limits), None);
    }

    #[test]
    fn a_link_to_a_host_file_is_text_and_the_file_is_never_opened() {
        let dir = FxTempDir::new("audit-link").expect("tmp");
        let outside = FxTempDir::new("audit-host").expect("tmp");
        let secret = outside.join("canary.txt");
        fs::write(&secret, b"host canary").expect("outside file");
        symlink(&secret, dir.join("absolute")).expect("link");
        symlink("../../etc/passwd", dir.join("relative")).expect("link");
        let found = kinds(run(dir.path(), false));
        assert!(found.contains(&(AuditKind::EscapingSymlink, "absolute".to_owned())));
        assert!(found.contains(&(AuditKind::EscapingSymlink, "relative".to_owned())));
    }

    #[test]
    fn a_chain_of_links_that_leaves_the_tree_through_two_steps_is_rejected() {
        // `d/up` points at the root; `y` goes `d/up/..`, which lexically stays at `d` but on a
        // disk is the parent of the root.
        let dir = FxTempDir::new("audit-chain").expect("tmp");
        fs::create_dir(dir.join("d")).expect("dir");
        symlink("..", dir.join("d/up")).expect("link");
        symlink("d/up/..", dir.join("y")).expect("link");
        let found = kinds(run(dir.path(), false));
        assert_eq!(
            found,
            vec![(AuditKind::EscapingSymlink, "y".to_owned())],
            "only the second link leaves"
        );
    }

    #[test]
    fn a_loop_of_links_is_rejected() {
        let dir = FxTempDir::new("audit-loop").expect("tmp");
        symlink("b", dir.join("a")).expect("link");
        symlink("a", dir.join("b")).expect("link");
        let found = kinds(run(dir.path(), false));
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn a_link_that_stays_inside_is_accepted() {
        let dir = FxTempDir::new("audit-inside").expect("tmp");
        fs::create_dir(dir.join("src")).expect("dir");
        fs::write(dir.join("src/lib.rs"), b"x").expect("file");
        symlink("../src/lib.rs", dir.join("src/alias.rs")).expect("link");
        assert!(run(dir.path(), false).is_ok());
    }

    #[test]
    fn nested_git_directories_gitfiles_and_aliases_are_rejected_and_never_entered() {
        let dir = FxTempDir::new("audit-git").expect("tmp");
        fs::create_dir_all(dir.join("vendor/inner/.git/hooks")).expect("nested repository");
        fs::write(dir.join("vendor/inner/.git/config"), b"[core]\n").expect("config");
        fs::create_dir(dir.join("sub")).expect("dir");
        fs::write(dir.join("sub/.git"), b"gitdir: ../elsewhere\n").expect("gitfile");
        fs::create_dir(dir.join("alias")).expect("dir");
        fs::create_dir(dir.join("alias/.GIT")).expect("upper case alias");
        fs::create_dir(dir.join("alias/git~1")).expect("short name");
        let found = kinds(run(dir.path(), false));
        assert!(found.contains(&(AuditKind::NestedGit, "vendor/inner".to_owned())));
        assert!(found.contains(&(AuditKind::GitFile, "sub".to_owned())));
        assert_eq!(
            found
                .iter()
                .filter(|(k, p)| *k == AuditKind::NestedGit && p == "alias")
                .count(),
            2,
            "{found:?}"
        );
    }

    #[test]
    fn a_replaced_root_git_is_rejected_but_the_empty_mask_file_is_not() {
        let dir = FxTempDir::new("audit-root-git").expect("tmp");
        fs::create_dir(dir.join(".git")).expect("replaced");
        let found = kinds(run(dir.path(), true));
        assert_eq!(
            found,
            vec![(AuditKind::NestedGit, "_checkout_root_".to_owned())]
        );
        let again = FxTempDir::new("audit-root-git-file").expect("tmp");
        fs::write(again.join(".git"), b"gitdir: /somewhere\n").expect("a pointer with content");
        assert_eq!(kinds(run(again.path(), true)).len(), 1);
    }

    #[test]
    fn a_file_at_a_hidden_path_is_rejected_unless_the_base_holds_it() {
        use factory_ports::paths::{PathRule, RepoGlob};
        let dir = FxTempDir::new("audit-hidden").expect("tmp");
        fs::create_dir_all(dir.join("tests/holdout")).expect("dirs");
        fs::write(dir.join("tests/holdout/x.rs"), b"x").expect("file");
        let rules = PathRules::new(vec![(
            "h".to_owned(),
            PathRule::Mode {
                glob: RepoGlob::new("tests/holdout/**").expect("glob"),
                mode: PathMode::Hidden,
            },
        )]);
        let stop = AtomicBool::new(false);
        let base = BaseTree::default();
        let lim = limits();
        fn ctx<'a>(
            limits: &'a AuditLimits,
            rules: &'a PathRules,
            base: &'a BaseTree,
            stop: &'a AtomicBool,
        ) -> WalkContext<'a> {
            WalkContext {
                limits,
                rules,
                base,
                policy: None,
                mask_at_root: false,
                stop,
            }
        }
        let found = kinds(walk(dir.path(), &ctx(&lim, &rules, &base, &stop)));
        assert_eq!(
            found,
            vec![(AuditKind::HiddenPath, "tests/holdout/x.rs".to_owned())]
        );
        let mut holding = BaseTree::default();
        holding.visible.insert(
            "tests/holdout/x.rs".to_owned(),
            crate::workspace::basetree::BaseEntry {
                mode: "100644".to_owned(),
                sha: "a".repeat(40),
                size: 1,
            },
        );
        assert!(walk(dir.path(), &ctx(&lim, &rules, &holding, &stop)).is_ok());
    }

    #[test]
    fn too_many_entries_and_too_deep_paths_stop_the_walk() {
        let dir = FxTempDir::new("audit-count").expect("tmp");
        for n in 0..20 {
            fs::write(dir.join(format!("f{n}")), b"").expect("file");
        }
        let rules = PathRules::default();
        let base = BaseTree::default();
        let stop = AtomicBool::new(false);
        let small = AuditLimits {
            max_entries: 10,
            ..limits()
        };
        let result = walk(
            dir.path(),
            &WalkContext {
                limits: &small,
                rules: &rules,
                base: &base,
                policy: None,
                mask_at_root: false,
                stop: &stop,
            },
        );
        assert_eq!(kinds(result)[0].0, AuditKind::TooManyEntries);
        let deep = FxTempDir::new("audit-deep").expect("tmp");
        let mut path = deep.path().to_path_buf();
        for _ in 0..6 {
            path.push("d");
        }
        fs::create_dir_all(&path).expect("dirs");
        let shallow = AuditLimits {
            max_depth: 4,
            ..limits()
        };
        let result = walk(
            deep.path(),
            &WalkContext {
                limits: &shallow,
                rules: &rules,
                base: &base,
                policy: None,
                mask_at_root: false,
                stop: &stop,
            },
        );
        assert_eq!(kinds(result)[0].0, AuditKind::TooDeep);
    }

    #[test]
    fn a_fifo_does_not_hang_the_walk() {
        let dir = FxTempDir::new("audit-fifo").expect("tmp");
        let outside = FxTempDir::new("audit-fifo-out").expect("tmp");
        let target = outside.join("t");
        fs::write(&target, b"x").expect("file");
        plant_ingestion_attacks(
            dir.path(),
            &target,
            &AttackOptions {
                oversize_bytes: 1,
                tiny_files: 1,
            },
        );
        let started = std::time::Instant::now();
        let _ = run(dir.path(), false);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_file_swapped_for_a_link_after_the_walk_is_not_read() {
        let dir = FxTempDir::new("audit-swap").expect("tmp");
        let outside = FxTempDir::new("audit-swap-out").expect("tmp");
        let secret = outside.join("canary.txt");
        fs::write(&secret, b"host canary").expect("outside file");
        let file = dir.join("a.txt");
        fs::write(&file, b"fine").expect("file");
        let manifest = run(dir.path(), false).expect("accepted");
        let Some(Entry::File { identity, .. }) = manifest.entries.get("a.txt") else {
            panic!("a file entry")
        };
        let identity = *identity;
        assert_eq!(read_file(&file, identity, 100), Ok(b"fine".to_vec()));
        fs::remove_file(&file).expect("remove");
        symlink(&secret, &file).expect("swap");
        assert_eq!(read_file(&file, identity, 100), Err(ReadFailure::Changed));
    }

    /// A source with no end that fails the read once it has been asked for far more than any
    /// bound allows, so a read without a bound cannot finish quietly.
    struct Endless {
        served: u64,
    }

    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.served > 64 * 1024 {
                return Err(std::io::Error::other("read past any sensible bound"));
            }
            buf.fill(b'x');
            self.served += buf.len() as u64;
            Ok(buf.len())
        }
    }

    #[test]
    fn a_read_never_pulls_more_than_the_limit_from_a_source_without_an_end() {
        assert_eq!(
            read_bounded(Endless { served: 0 }, 1000),
            Err(ReadFailure::TooLarge)
        );
        assert_eq!(read_bounded(&b"abc"[..], 3), Ok(b"abc".to_vec()));
        assert_eq!(read_bounded(&b"abcd"[..], 3), Err(ReadFailure::TooLarge));
    }

    #[test]
    fn a_read_is_bounded() {
        let dir = FxTempDir::new("audit-bound").expect("tmp");
        let file = dir.join("big");
        fs::write(&file, vec![b'x'; 1000]).expect("file");
        let manifest = run(dir.path(), false).expect("accepted");
        let Some(Entry::File { identity, .. }) = manifest.entries.get("big") else {
            panic!("a file entry")
        };
        assert_eq!(read_file(&file, *identity, 999), Err(ReadFailure::TooLarge));
        assert_eq!(read_file(&file, *identity, 1000).map(|b| b.len()), Ok(1000));
    }

    #[test]
    fn report_paths_escape_what_is_not_printable() {
        assert_eq!(report_path(b"a/b.rs").as_str(), "a/b.rs");
        assert_eq!(report_path(b"x\ny").as_str(), "x%0Ay");
        assert_eq!(report_path(b"bad-\xff-name").as_str(), "bad-%FF-name");
        assert!(!report_path(b"\x1b[31m").as_str().contains('\u{1b}'));
        // A name that hides or reorders text is escaped in the finding that names it.
        let reported = report_path("gpj.\u{202E}rs".as_bytes());
        assert!(
            !reported.as_str().contains('\u{202E}'),
            "{}",
            reported.as_str()
        );
        assert!(
            reported.as_str().contains("%E2%80%AE"),
            "{}",
            reported.as_str()
        );
    }

    #[test]
    fn a_name_that_hides_or_reorders_text_is_unsafe_in_every_script() {
        // One character of each kind: bidirectional controls and isolates, zero width characters,
        // the line and paragraph separators, the byte order mark, a tag character, the Hangul
        // filler, the soft hyphen, the Arabic number sign, a variation selector supplement, a
        // musical format control and the interlinear annotation marks.
        let hidden_characters = [
            '\u{202A}',
            '\u{202B}',
            '\u{202C}',
            '\u{202D}',
            '\u{202E}',
            '\u{2066}',
            '\u{2067}',
            '\u{2068}',
            '\u{2069}',
            '\u{200B}',
            '\u{200C}',
            '\u{200D}',
            '\u{200E}',
            '\u{200F}',
            '\u{2060}',
            '\u{2028}',
            '\u{2029}',
            '\u{FEFF}',
            '\u{E0041}',
            '\u{E0001}',
            '\u{E007F}',
            '\u{E0100}',
            '\u{3164}',
            '\u{115F}',
            '\u{FFA0}',
            '\u{00AD}',
            '\u{034F}',
            '\u{061C}',
            '\u{0600}',
            '\u{180E}',
            '\u{1D173}',
            '\u{FFF9}',
            '\u{FFFB}',
            '\u{13430}',
        ];
        let dir = FxTempDir::new("audit-hidden").expect("tmp");
        for (i, hidden) in hidden_characters.into_iter().enumerate() {
            assert!(hides_text(hidden), "U+{:04X}", hidden as u32);
            // Through the walk of a directory that holds a file with that name.
            let case = dir.join(format!("case-{i}"));
            fs::create_dir(&case).expect("a case directory");
            let name = format!("a{hidden}b.rs");
            fs::write(case.join(&name), b"").expect("a file");
            let found = kinds(run(&case, false));
            assert_eq!(found.len(), 1, "U+{:04X}: {found:?}", hidden as u32);
            assert_eq!(found[0].0, AuditKind::UnsafeName, "U+{:04X}", hidden as u32);
            assert!(
                !found[0].1.contains(hidden),
                "the finding must not carry the character: {:?}",
                found[0].1
            );
        }
    }

    #[test]
    fn a_git_directory_alias_with_a_hidden_character_is_a_nested_git_directory_first() {
        let dir = FxTempDir::new("audit-alias").expect("tmp");
        let nested = dir.join("vendor").join(".git\u{200d}");
        fs::create_dir_all(&nested).expect("a nested directory");
        fs::write(nested.join("config"), "[core]\n").expect("a file");
        let found = kinds(run(dir.path(), false));
        assert!(
            found
                .iter()
                .any(|(kind, path)| *kind == AuditKind::NestedGit && path == "vendor"),
            "{found:?}"
        );
    }

    /// RR-13. Names that print as empty, or as another name, are refused: a space-like character at
    /// either end, a variation selector with no base, a long stack of combining marks, and the
    /// braille blank.
    #[test]
    fn names_that_print_blank_or_as_another_name_are_refused() {
        for name in [
            "report.md\u{00A0}",
            "\u{00A0}nbsp.txt",
            "\u{00A0}",
            "\u{3000}",
            "a.rs\u{3000}",
            "\u{2009}a.rs",
            "a.rs\u{202F}",
            "a.rs ",
            " a.rs",
            "report\u{2800}.md",
            "\u{2800}",
            "a\u{FE0E}b.rs",
            "a\u{FE0F}b.rs",
            "a\u{180B}b.rs",
            "\u{FE0F}a.rs",
            "1\u{FE0F}.png",
            "#\u{FE0F}.png",
            "heart\u{2764}\u{FE0F}\u{FE0F}.png",
            "a\u{0300}\u{0301}\u{0302}b.rs",
            "a\u{20D0}\u{20D1}\u{20D2}.rs",
        ] {
            assert!(
                name.chars().any(hides_text) || looks_blank_or_alike(name),
                "{name:?} passes"
            );
        }
        let dir = FxTempDir::new("audit-blank").expect("tmp");
        for (i, name) in [
            "report.md\u{00A0}",
            "report\u{2800}.md",
            "\u{2800}",
            "a\u{FE0E}b.rs",
            "a\u{180B}b.rs",
            "a\u{0300}\u{0301}\u{0302}b.rs",
        ]
        .into_iter()
        .enumerate()
        {
            let case = dir.join(format!("case-{i}"));
            fs::create_dir(&case).expect("a case directory");
            fs::write(case.join(name), b"").expect("a file");
            let found = kinds(run(&case, false));
            assert_eq!(found.len(), 1, "{name:?}: {found:?}");
            assert_eq!(found[0].0, AuditKind::UnsafeName, "{name:?}");
        }
    }

    /// What RR-13 leaves alone: the ideographic and typographic spaces inside a name (they are
    /// logged), keycap and emoji selectors, two stacked marks, marks of other scripts, and a name
    /// that is not in normal form NFC (it cannot be told apart without normalization tables).
    #[test]
    fn names_with_a_plain_reason_to_look_the_way_they_do_are_not_refused() {
        for name in [
            "\u{65e5}\u{672c}\u{3000}\u{8a9e}.txt",
            "10\u{2009}000\u{00A0}EUR.pdf",
            "1\u{FE0F}\u{20E3}.png",
            "#\u{FE0F}\u{20E3}.png",
            "heart\u{2764}\u{FE0F}.png",
            "\u{1820}\u{180B}.txt",
            "e\u{323}\u{302}.txt",
            "cafe\u{301}.rs",
            "\u{e17}\u{e35}\u{e48}.txt",
            "\u{5e7}\u{5b8}\u{5d1}\u{5bc}\u{5b9}.txt",
            "a b.rs",
        ] {
            assert!(!looks_blank_or_alike(name), "{name:?}");
        }
        for name in ["a\u{3000}b.rs", "a\u{2009}b.rs", "a\u{00A0}b.rs"] {
            assert!(has_inner_blank(name), "{name:?}");
            let dir = FxTempDir::new("audit-inner").expect("tmp");
            fs::write(dir.join(name), b"").expect("a file");
            assert_eq!(
                run(dir.path(), false).map(|m| m.entries.len()).ok(),
                Some(1)
            );
        }
        assert!(!has_inner_blank("a b.rs"));
    }

    #[test]
    fn legitimate_names_in_any_script_are_not_unsafe() {
        let limits = limits();
        for name in [
            "caf\u{e9}.rs",
            "cafe\u{301}.rs",
            "\u{65e5}\u{672c}\u{8a9e}.md",
            "\u{444}\u{430}\u{439}\u{43b}.txt",
            "\u{645}\u{644}\u{641}.txt",
            "\u{5e7}\u{5d5}\u{5d1}\u{5e5}.txt",
            "\u{939}\u{93f}\u{928}\u{94d}\u{926}\u{940}.txt",
            "\u{d55c}\u{ae00}.txt",
            "na\u{ef}ve \u{2014} draft.md",
            "smile\u{1F600}.png",
            "heart\u{2764}\u{FE0F}.png",
            "\u{1820}\u{180B}.txt",
            "a b-c_d.e",
            "\u{30a2}\u{30a4}\u{30a6}\u{30a8}\u{30aa}.rs",
        ] {
            assert_eq!(name_problem(name.as_bytes(), &limits), None, "{name:?}");
            assert!(!name.chars().any(hides_text), "{name:?}");
            assert!(!looks_blank_or_alike(name), "{name:?}");
        }
        // The boundaries of the ranges are exact: the characters next to them pass.
        for edge in [
            '\u{2027}',
            '\u{202F}',
            '\u{2070}',
            '\u{200A}',
            '\u{FEFE}',
            '\u{FF00}',
            '\u{E1000}',
        ] {
            assert!(!hides_text(edge), "U+{:04X}", edge as u32);
        }
        assert!(hides_text('\u{206F}') && hides_text('\u{E0FFF}'));
    }
}
