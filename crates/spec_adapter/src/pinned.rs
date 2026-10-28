//! The files Spec Kit 1.1.2 installs, with the SHA-256 the pinned manifests record for each.
//!
//! The Claude Code and shared hashes are the full values from the manifests that the Spec Kit
//! initialisation wrote with `--integration claude` (recorded under `tests/fixtures/recordings/`).
//! The Codex hashes are the 16-character prefixes the integration guide lists (Appendix A), because
//! the full Codex manifest was not kept; 64 bits are enough to tell a modified skill from the
//! pinned one, and the table says so in its name. When Spec Kit is upgraded, this file is generated
//! again from the new manifests.

/// A file the installer wrote and the SHA-256 it recorded for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedFile {
    /// The path relative to the repository root.
    pub path: &'static str,
    /// The lowercase hex SHA-256, or its first 16 characters for the Codex table.
    pub sha256: &'static str,
}

/// The ten skill files of the Claude Code integration (full hashes).
pub const CLAUDE_SKILLS: [PinnedFile; 10] = [
    PinnedFile {
        path: ".claude/skills/speckit-analyze/SKILL.md",
        sha256: "3237cd827194efaf6bb06ba05ef9bc1a703a223d362f5e34d0558c5a38ae34d0",
    },
    PinnedFile {
        path: ".claude/skills/speckit-checklist/SKILL.md",
        sha256: "5dc436df0c727e9078bf182dd385e5cb1b60ee67ebe644d3f659ec12e3b78abb",
    },
    PinnedFile {
        path: ".claude/skills/speckit-clarify/SKILL.md",
        sha256: "164f49ef87cb2e922585316f5281b455a8e1940b1efd25317d517a567acae472",
    },
    PinnedFile {
        path: ".claude/skills/speckit-constitution/SKILL.md",
        sha256: "60c27f3962e78edf204b2b2e7cba91a616980860b61d6bf2051dc6965d483dda",
    },
    PinnedFile {
        path: ".claude/skills/speckit-converge/SKILL.md",
        sha256: "9f93c1d573592f146670202210128ed24a9d75c92133951b19a2bb0e34eac13b",
    },
    PinnedFile {
        path: ".claude/skills/speckit-implement/SKILL.md",
        sha256: "7186d59488f89dcf23abd17baed118b05c242d4f62f1de3f9f44625a2b1728f0",
    },
    PinnedFile {
        path: ".claude/skills/speckit-plan/SKILL.md",
        sha256: "9e97fc0b4ce895c70a1ea720dc0377618c23e27c83ecf4d87b6e0f6c323790a4",
    },
    PinnedFile {
        path: ".claude/skills/speckit-specify/SKILL.md",
        sha256: "d4d93f2444355136e78bb533988aa2dd560dc4b258f4923f67b1a437e7de38f8",
    },
    PinnedFile {
        path: ".claude/skills/speckit-tasks/SKILL.md",
        sha256: "d148aeda1011260c4465c5f105fa1e045a0b0224ccb3e6e0c1ec32c732cae1ae",
    },
    PinnedFile {
        path: ".claude/skills/speckit-taskstoissues/SKILL.md",
        sha256: "464bbaf464a28ffa371b0452599c18e7cb5799630148d9f945e6a4d7066a1234",
    },
];

/// The twelve shared files under the Spec Kit directory (full hashes).
pub const SHARED_FILES: [PinnedFile; 12] = [
    PinnedFile {
        path: ".specify/.gitignore",
        sha256: "8c908410d177a1ef3d0dee16d7ad55f2ac3333df3104c4d4adee1c9b82f1dbc1",
    },
    PinnedFile {
        path: ".specify/scripts/bash/check-prerequisites.sh",
        sha256: "daa377146db4fb69912f42611a7b91c5d55873b3e3e27ed33bd8d67505826344",
    },
    PinnedFile {
        path: ".specify/scripts/bash/common.sh",
        sha256: "53cb1c23e349db4586c272436ce35c6e2f36a9c0b5351a85e0b216d9887a26b7",
    },
    PinnedFile {
        path: ".specify/scripts/bash/create-new-feature.sh",
        sha256: "972f03ed8ca5ee17b7baad6d56d821d46269d77abc337496beafb0fe85a725f2",
    },
    PinnedFile {
        path: ".specify/scripts/bash/resolve-template.sh",
        sha256: "829e227096abc8bf0889889ec9f792f503ca5d395b7836a8a7eb739ee75214e7",
    },
    PinnedFile {
        path: ".specify/scripts/bash/setup-plan.sh",
        sha256: "d0bd298c026446f3c63167130d65e49e4aa4485de6bef18bcdfd57b19aa0de96",
    },
    PinnedFile {
        path: ".specify/scripts/bash/setup-tasks.sh",
        sha256: "4a33dd1e6c32ddc7d570f4b538572c54069192573eed0ec654d9fb826e31a4fe",
    },
    PinnedFile {
        path: ".specify/templates/checklist-template.md",
        sha256: "856532b3cb66171c662cc16f16b31a5856e4655a8666aad1e545bbfc7f603ca1",
    },
    PinnedFile {
        path: ".specify/templates/constitution-template.md",
        sha256: "ce7549540fa45543cca797a150201d868e64495fdff39dc38246fb17bd4024b3",
    },
    PinnedFile {
        path: ".specify/templates/plan-template.md",
        sha256: "7e637502d41eccf0ca672496636365691fdca62ef37b27ec07fcb412dbfa90d4",
    },
    PinnedFile {
        path: ".specify/templates/spec-template.md",
        sha256: "3945437fc35cd30a5b2bf7beea680337c3516826d3efa5a6b92c4a7eca1ba28e",
    },
    PinnedFile {
        path: ".specify/templates/tasks-template.md",
        sha256: "fc29a233f6f5a27ca31f1aa46b596af6500c627441c6e62b2bc4a1d721525842",
    },
];

/// The ten skill files of the Codex integration (16-character hash prefixes).
pub const CODEX_SKILLS_PREFIX: [PinnedFile; 10] = [
    PinnedFile {
        path: ".agents/skills/speckit-analyze/SKILL.md",
        sha256: "0b3261b13cc33537",
    },
    PinnedFile {
        path: ".agents/skills/speckit-checklist/SKILL.md",
        sha256: "7ac5cba31a27151a",
    },
    PinnedFile {
        path: ".agents/skills/speckit-clarify/SKILL.md",
        sha256: "f6acfbc82c96c0d9",
    },
    PinnedFile {
        path: ".agents/skills/speckit-constitution/SKILL.md",
        sha256: "b2a6a979ef751181",
    },
    PinnedFile {
        path: ".agents/skills/speckit-converge/SKILL.md",
        sha256: "5859c9780ddc012f",
    },
    PinnedFile {
        path: ".agents/skills/speckit-implement/SKILL.md",
        sha256: "848a5c9eff7b99e3",
    },
    PinnedFile {
        path: ".agents/skills/speckit-plan/SKILL.md",
        sha256: "db2406adfa50103f",
    },
    PinnedFile {
        path: ".agents/skills/speckit-specify/SKILL.md",
        sha256: "a505028de7f64898",
    },
    PinnedFile {
        path: ".agents/skills/speckit-tasks/SKILL.md",
        sha256: "1086d7885df1188d",
    },
    PinnedFile {
        path: ".agents/skills/speckit-taskstoissues/SKILL.md",
        sha256: "a349d410c1803852",
    },
];
