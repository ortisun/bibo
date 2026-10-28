//! The `REPOSITORY_INTELLIGENCE` stage: what the repository is made of, and whether it builds.
//!
//! Work package `s1-stage-intake-and-repository`. From the commit that the fetch returned, the stage
//! reads the repository through `JobRepo`, detects its languages, build system and test command,
//! reads CODEOWNERS and the project manifest, finds the protected paths, writes a repository map in
//! which every claim names the file, the commit and the lines it was read from, and writes a short
//! summary with a citation after each fact. Then the baseline build and test run in a fresh
//! `verify` sandbox, and their result is the evidence of the stage.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | `detect` | The table of build systems and languages, and the detection that reads it |
//! | `codeowners` | CODEOWNERS read as data |
//! | `map` | The map, its strict shape check and the summary |
//! | `seams` | The small traits the stage needs and no port offers |
//! | `handler` | `RepoIntelHandler`, the `StageHandler` |
//!
//! `repository-map.v1.schema.json` is the schema of the map and `repository-map.example.json` an
//! example. The tests of `factory-contracts` check the example against the schema with the schema
//! engine, because this crate cannot depend on it.
//!
//! # Rules this stage keeps
//!
//! * Repository text is data. No command, path rule or decision is taken from a README, a
//!   comment or any other file, and a hidden path (a key, an `.env` file, a secret-bearing
//!   configuration) is listed by name and never read.
//! * A missing toolchain, or a repository whose build system is unknown or ambiguous, is `BLOCKED`.
//!   The stage never guesses a build command.
//! * The fact that a sandbox is a fake is written in the baseline report, so a baseline that ran in
//!   a fake never counts as a real one.

pub mod codeowners;
pub mod detect;
pub mod handler;
pub mod map;
pub mod seams;

pub use handler::{
    BASELINE_GATE, MAP_GATE, RepoIntelConfig, RepoIntelDeps, RepoIntelHandler, SECRET_GATE,
};
pub use seams::{
    JobRepository, ManifestProblem, ProjectManifestParser, TargetRepository, VerifySandboxSpecs,
};
