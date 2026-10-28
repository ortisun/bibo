//! The anti-corruption layer for GitHub Spec Kit (ADR 0006). It is the only crate that knows the
//! Spec Kit file layout, the invocation syntax and the markers.
//!
//! The crate implements [`factory_ports::spec::SpecificationProvider`] in the shape of ports
//! v1.1 (ADR 0014): `run` drives one skill in the sandbox and says which files it expects, and the
//! pure `assemble` builds the typed outcome from the bytes of the committed files. The crate reads
//! no file and holds no workspace. Spec Kit is used for the specification stage only, through four
//! operations, and nothing else of it is reachable from here.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | [`invocation`] | The host table, the separator read from the installation, the fixed instruction, the closed skill list |
//! | [`pinned`] | The SHA-256 of every file the pinned Spec Kit installs |
//! | [`integrity`] | The pinned version, the installed-file hashes, the extension check, the rule that `init` never runs on an initialised repository |
//! | [`parse`] | `spec.md` and the checklists read into typed values, strictly |
//! | [`postcond`] | The seven post-conditions and the request-leak check |
//! | [`question`] | The question detector and the answer policy |
//! | [`assemble`] | The typed `SpecificationContract` from the committed files |
//! | [`provider`] | `SpecKitProvider`, the `SpecificationProvider` |
//!
//! # Rules this crate keeps
//!
//! * A skill outside the four cannot be named: the operation is a closed enum and the skill name
//!   is an exhaustive match.
//! * Nothing a person or a model wrote reaches the arguments of a skill. The request travels in a
//!   file, and the fixed instruction is built from a closed template and two validated paths.
//! * What the agent says about its work is not evidence. The checks read the files, the hashes and
//!   the paths the host measured.
//! * Spec Kit's checklist ticks are self-assessed and carry no weight. Every checklist item
//!   becomes an open question until the factory records that someone independent verified it or a
//!   person waived it with a reason.
//! * A structure the parser does not recognise is `SPEC_PARSE_ERROR`. It never guesses.

pub mod assemble;
pub mod integrity;
pub mod invocation;
pub mod parse;
pub mod pinned;
pub mod postcond;
pub mod provider;
pub mod question;

pub use provider::{SpecKitConfig, SpecKitProvider};
