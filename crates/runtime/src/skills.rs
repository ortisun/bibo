//! The pinned skills that the specification stage may see, and how they reach the tool.
//!
//! Claude Code hides project skills when it runs with `--setting-sources user` (spike section 4.6),
//! and that flag is what keeps a repository's hooks and `env` block from running. The specification
//! stage therefore needs its skills in the user skill root, `$HOME/.claude/skills/<name>`. The
//! sandbox spec has no mount for them (its mounts are the checkout, the output directory, the
//! protected overlays and caches), so the adapter writes them into the fresh home of the run with
//! one `tar` extraction, after it checked every file against the digest the pinned manifest names,
//! and takes the write bit off the tree. The tree is read-only for the tool's user, but it is not
//! a read-only mount: a process of the same user could `chmod` it back. A read-only mount in the
//! sandbox spec is the stronger form and is reported as a gap.
//!
//! This crate does not know which skills there are. The composition root passes a [`SkillBundle`]
//! that the Spec Kit layer built and pinned.

use factory_domain::values::{Sha256Digest, Slug};

/// One file of a pinned skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillFile {
    /// The path inside the skill directory, such as `SKILL.md`.
    pub path: String,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// The digest the pinned manifest names for this file.
    pub sha256: Sha256Digest,
}

/// A pinned skill: a directory name and its files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedSkill {
    name: Slug,
    files: Vec<SkillFile>,
}

/// Why a skill or a bundle cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SkillBundleError {
    /// The directory name is not a slug.
    #[error("a skill name must be a slug")]
    BadName,
    /// A file path is empty, absolute, too long, or has a `.`, `..` or empty component.
    #[error("a skill file path must be relative, short and free of `.` and `..`")]
    BadPath,
    /// A file does not hash to the digest the manifest names.
    #[error("a skill file does not match its pinned digest")]
    DigestMismatch,
    /// The skill has no `SKILL.md`.
    #[error("a skill needs a SKILL.md")]
    MissingSkillFile,
    /// Two skills have the same name, or one skill names a path twice.
    #[error("a skill name or file path appears twice")]
    Duplicate,
    /// A bundle with no skill.
    #[error("a bundle needs at least one skill")]
    Empty,
}

/// The longest path the archive format carries.
const MAX_PATH_BYTES: usize = 100;

/// Where the skills sit under the home directory of the run, with the trailing slash.
const ARCHIVE_ROOT: &str = ".claude/skills/";

impl PinnedSkill {
    /// Checks the name, the paths and every digest.
    ///
    /// # Errors
    /// [`SkillBundleError`].
    pub fn new(name: &str, files: Vec<SkillFile>) -> Result<Self, SkillBundleError> {
        let name = Slug::parse(name).map_err(|_| SkillBundleError::BadName)?;
        let mut seen = std::collections::BTreeSet::new();
        for file in &files {
            let path = file.path.as_str();
            let clean = !path.is_empty()
                && ARCHIVE_ROOT.len() + name.as_str().len() + 1 + path.len() <= MAX_PATH_BYTES
                && !path.starts_with('/')
                && !path.contains('\0')
                && path
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..");
            if !clean {
                return Err(SkillBundleError::BadPath);
            }
            if !seen.insert(path.to_owned()) {
                return Err(SkillBundleError::Duplicate);
            }
            if Sha256Digest::of(&file.bytes) != file.sha256 {
                return Err(SkillBundleError::DigestMismatch);
            }
        }
        if !files.iter().any(|f| f.path == "SKILL.md") {
            return Err(SkillBundleError::MissingSkillFile);
        }
        Ok(Self { name, files })
    }

    /// The directory name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

/// The skills the specification stage may see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillBundle(Vec<PinnedSkill>);

impl SkillBundle {
    /// Wraps the skills.
    ///
    /// # Errors
    /// [`SkillBundleError`] for an empty bundle or a repeated name.
    pub fn new(skills: Vec<PinnedSkill>) -> Result<Self, SkillBundleError> {
        if skills.is_empty() {
            return Err(SkillBundleError::Empty);
        }
        let mut names = std::collections::BTreeSet::new();
        if !skills.iter().all(|s| names.insert(s.name().to_owned())) {
            return Err(SkillBundleError::Duplicate);
        }
        Ok(Self(skills))
    }

    /// The names of the skills, in order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.0.iter().map(PinnedSkill::name).collect()
    }

    /// A ustar archive of `.claude/skills/<name>/<file>` for every file, mode 0444. The reader
    /// extracts it under the home directory of the run.
    #[must_use]
    pub fn to_archive(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for skill in &self.0 {
            for file in &skill.files {
                let path = format!("{ARCHIVE_ROOT}{}/{}", skill.name(), file.path);
                out.extend_from_slice(&header(&path, file.bytes.len(), 0o444));
                out.extend_from_slice(&file.bytes);
                let padding = (512 - file.bytes.len() % 512) % 512;
                out.extend(std::iter::repeat_n(0_u8, padding));
            }
        }
        out.extend(std::iter::repeat_n(0_u8, 1024));
        out
    }
}

/// One 512-byte ustar header for a regular file. Paths longer than 100 bytes are cut by the
/// caller's checks, so a longer one is truncated here rather than written into the prefix field.
fn header(path: &str, size: usize, mode: u32) -> [u8; 512] {
    let mut block = [0_u8; 512];
    let name = path.as_bytes();
    let take = name.len().min(MAX_PATH_BYTES);
    block[..take].copy_from_slice(&name[..take]);
    put(&mut block[100..108], &format!("{mode:07o}"));
    put(&mut block[108..116], "0000000");
    put(&mut block[116..124], "0000000");
    put(&mut block[124..136], &format!("{size:011o}"));
    put(&mut block[136..148], "00000000000");
    block[148..156].copy_from_slice(b"        ");
    block[156] = b'0';
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    let sum: u32 = block.iter().map(|b| u32::from(*b)).sum();
    put(&mut block[148..155], &format!("{sum:06o}"));
    block[154] = 0;
    block[155] = b' ';
    block
}

/// Writes ASCII digits at the start of a field. The rest of the field stays NUL.
fn put(field: &mut [u8], text: &str) {
    let bytes = text.as_bytes();
    let take = bytes.len().min(field.len().saturating_sub(1));
    field[..take].copy_from_slice(&bytes[..take]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, text: &str) -> SkillFile {
        SkillFile {
            path: path.to_owned(),
            bytes: text.as_bytes().to_vec(),
            sha256: Sha256Digest::of(text.as_bytes()),
        }
    }

    #[test]
    fn a_file_that_does_not_match_its_pinned_digest_is_refused() {
        let mut bad = file("SKILL.md", "body");
        bad.sha256 = Sha256Digest::of(b"another body");
        assert_eq!(
            PinnedSkill::new("alpha", vec![bad]),
            Err(SkillBundleError::DigestMismatch)
        );
    }

    #[test]
    fn paths_that_climb_or_are_absolute_are_refused() {
        for path in ["../x", "/etc/x", "a//b", "./a", ""] {
            assert_eq!(
                PinnedSkill::new("alpha", vec![file("SKILL.md", "b"), file(path, "x")]),
                Err(SkillBundleError::BadPath),
                "{path:?}"
            );
        }
    }

    #[test]
    fn a_skill_needs_its_skill_file_and_a_bundle_needs_unique_names() {
        assert_eq!(
            PinnedSkill::new("alpha", vec![file("notes.md", "x")]),
            Err(SkillBundleError::MissingSkillFile)
        );
        let one = PinnedSkill::new("alpha", vec![file("SKILL.md", "a")]).expect("a skill");
        let same = PinnedSkill::new("alpha", vec![file("SKILL.md", "b")]).expect("a skill");
        assert_eq!(
            SkillBundle::new(vec![one, same]),
            Err(SkillBundleError::Duplicate)
        );
        assert_eq!(SkillBundle::new(Vec::new()), Err(SkillBundleError::Empty));
    }

    #[test]
    fn the_archive_has_valid_headers_the_files_and_the_end_blocks() {
        let skill = PinnedSkill::new(
            "alpha",
            vec![file("SKILL.md", "body of the skill"), file("notes/x.md", "n")],
        )
        .expect("a skill");
        let bundle = SkillBundle::new(vec![skill]).expect("a bundle");
        let archive = bundle.to_archive();
        // Two files, each a header block and one data block, then two empty blocks.
        assert_eq!(archive.len(), 512 * (2 * 2 + 2));
        let header = &archive[..512];
        assert_eq!(&header[..28], b".claude/skills/alpha/SKILL.m");
        assert_eq!(&header[257..262], b"ustar");
        // The stored checksum is the sum of the header with the checksum field read as spaces.
        let stored = std::str::from_utf8(&header[148..154])
            .expect("digits")
            .trim_matches('\0')
            .to_owned();
        let mut copy = header.to_vec();
        copy[148..156].copy_from_slice(b"        ");
        let sum: u32 = copy.iter().map(|b| u32::from(*b)).sum();
        assert_eq!(u32::from_str_radix(&stored, 8).expect("octal"), sum);
        assert!(archive[archive.len() - 1024..].iter().all(|b| *b == 0));
        assert_eq!(bundle.names(), vec!["alpha"]);
    }
}
