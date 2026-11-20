//! Stage handlers. Each stage is a directory owned by the package that writes it, and its module
//! line is declared here so that the owning package adds code without editing this file. A
//! handler implements `crate::handlers::StageHandler` and nothing else of this crate: it holds no
//! engine type and never writes a status.

pub mod approval;
pub mod architecture;
pub mod delivery;
pub mod documentation_review;
pub mod documenting;
pub mod domain_discovery;
pub mod implementation;
pub mod intake;
pub mod planning;
pub mod project_rules;
pub mod repo_intel;
pub mod review;
pub mod specification;
pub mod validation;
