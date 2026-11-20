//! What the validation stage takes from the stage runs before it.
//!
//! * From the **implementation** run, the deliverable `implementation-result`: a JSON document
//!   the factory wrote after it committed the audited change on the host. It names the base
//!   commit and the head commit. The builder never writes it: the implementation stage makes it
//!   from the commit that `Workspace::commit` returned.
//! * From the **specification** run, the deliverable `specification-contract`: the frozen
//!   specification, for the acceptance evidence gate.
//!
//! Both are read from the artifact store by the hash the contract recorded, so a document that
//! changed after the contract was resolved is not the document that is read.

use factory_domain::contracts::{ArtifactRef, SpecificationContract};
use factory_domain::state::StageRunStatus;
use factory_domain::vocabulary::StageKind;
use factory_ports::paths::CommitSha;

use crate::handlers::UpstreamRun;

/// The name of the implementation stage's deliverable that names the commits.
pub const IMPLEMENTATION_RESULT: &str = "implementation-result";

/// The name of the specification stage's deliverable.
pub const SPECIFICATION_CONTRACT: &str = "specification-contract";

/// The commits to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The protected branch tip the change is relative to.
    pub base: CommitSha,
    /// The commit to verify.
    pub head: CommitSha,
}

/// The newest passed run of `kind` that produced a deliverable called `name`.
#[must_use]
pub fn upstream_output<'a>(
    upstream: &'a [UpstreamRun],
    kind: StageKind,
    name: &str,
) -> Option<(&'a UpstreamRun, &'a ArtifactRef)> {
    upstream
        .iter()
        .rev()
        .filter(|run| run.kind == kind && run.status == StageRunStatus::Passed)
        .find_map(|run| {
            run.outputs
                .iter()
                .find(|output| output.name.as_str() == name)
                .map(|output| (run, &output.artifact))
        })
}

/// Reads the implementation result. `None` for anything that is not two commit identifiers.
#[must_use]
pub fn parse_candidate(bytes: &[u8]) -> Option<Candidate> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let field = |name: &str| value.get(name).and_then(serde_json::Value::as_str);
    Some(Candidate {
        base: CommitSha::parse(field("base_commit")?).ok()?,
        head: CommitSha::parse(field("head_commit")?).ok()?,
    })
}

/// Reads the frozen specification.
#[must_use]
pub fn parse_specification(bytes: &[u8]) -> Option<SpecificationContract> {
    use factory_domain::contracts::Contract;
    SpecificationContract::from_json_str(std::str::from_utf8(bytes).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_commit_identifiers_are_a_candidate_and_nothing_else_is() {
        let good = format!(
            r#"{{"base_commit":"{}","head_commit":"{}"}}"#,
            "a".repeat(40),
            "b".repeat(40)
        );
        let candidate = parse_candidate(good.as_bytes()).expect("a candidate");
        assert_eq!(candidate.base.as_str(), "a".repeat(40));
        assert_eq!(candidate.head.as_str(), "b".repeat(40));
        for bad in [
            "{}",
            r#"{"base_commit":"zz","head_commit":"zz"}"#,
            r#"{"base_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            "not json",
        ] {
            assert_eq!(parse_candidate(bad.as_bytes()), None, "{bad}");
        }
    }
}
