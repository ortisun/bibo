//! The names the engine gives to the links between a stage run and the artifacts it consumed or
//! produced (`StageArtifactOps`).
//!
//! The store keeps one link for each stage run, direction and role, and a second link with the same
//! role and another hash is a constraint error. The engine therefore picks roles that cannot clash,
//! and reads them back with the functions in this module, so the writer and the reader of a role
//! cannot drift apart.
//!
//! | Direction | Role | Meaning |
//! |---|---|---|
//! | input | `human-answer-<k>` | A person's answer. `k` is how many attempts the stage run had when the person answered, which is the number the database keeps as `stage_runs.attempts_before_last_answer` (set at `S13` from the highest attempt number). The window of attempts since the last answer is every attempt numbered above the highest `k`. |
//! | output | `<name>.a<n>` | The deliverable `name` that attempt number `n` produced. A stage run can reach its gate more than once (a person answers a gate and a second attempt succeeds), and a link is never replaced, so each attempt keeps its own. The outputs of the stage run are those of the highest `n`. |
//! | input | `dependency-decision-<k>-<command>` | A person's decision on a dependency (`add_new_direct_dependency`) or on its build code (`approve_build_code`), recorded while the stage run was blocked. `k` is how many attempts the stage run had then, and `<command>` is the id of the command without hyphens, so a command that arrives twice names the same role. The decision counts for a rerun when `k` is the number of attempts the stage run has now: a decision recorded before an earlier block does not clear a later one. |
//!
//! | input | `warning-decision-<command>` | An approver's decision about a translation warning of the approval request. A command that arrives twice names the same role. The approval reads the decisions from the ledger, not from the role. |
//!
//! A role that does not follow these forms was not written by the engine, and the readers skip it.

use factory_domain::ids::CausationId;
use factory_domain::values::Slug;

use super::error::EngineError;

const ANSWER_PREFIX: &str = "human-answer-";
const DECISION_PREFIX: &str = "dependency-decision-";
const WARNING_PREFIX: &str = "warning-decision-";
const ATTEMPT_MARK: &str = ".a";

/// The role of a decision on a dependency recorded after `attempts_before` attempts, by the
/// command `command`.
///
/// # Errors
/// [`EngineError::Invalid`] if the role is not a slug (it always is).
pub(crate) fn decision_role(
    attempts_before: u32,
    command: CausationId,
) -> Result<Slug, EngineError> {
    Ok(Slug::parse(&format!(
        "{DECISION_PREFIX}{attempts_before}-{}",
        command.as_uuid().simple()
    ))?)
}

/// How many attempts the stage run had when the decision under `role` was recorded, or `None` when
/// the role is not a decision role.
pub(crate) fn decision_attempts_before(role: &str) -> Option<u32> {
    let rest = role.strip_prefix(DECISION_PREFIX)?;
    let (digits, command) = rest.split_once('-')?;
    let hex = !command.is_empty() && command.bytes().all(|byte| byte.is_ascii_hexdigit());
    (all_digits(digits) && hex)
        .then(|| digits.parse().ok())
        .flatten()
}

/// The role of a decision about a translation warning, recorded by the command `command`. It does
/// not carry the attempts: the stage run waits for a person and runs no attempt meanwhile, and
/// `UnblockRerun` does not read it.
///
/// # Errors
/// [`EngineError::Invalid`] if the role is not a slug (it always is).
pub(crate) fn warning_role(command: CausationId) -> Result<Slug, EngineError> {
    Ok(Slug::parse(&format!(
        "{WARNING_PREFIX}{}",
        command.as_uuid().simple()
    ))?)
}

/// The role of an answer given after `attempts_before` attempts.
///
/// # Errors
/// [`EngineError::Invalid`] if the role is not a slug (it always is for a `u32`).
pub fn answer_role(attempts_before: u32) -> Result<Slug, EngineError> {
    Ok(Slug::parse(&format!("{ANSWER_PREFIX}{attempts_before}"))?)
}

/// How many attempts the stage run had when the answer under `role` was given, or `None` when the
/// role is not an answer role.
pub fn answer_attempts_before(role: &str) -> Option<u32> {
    let digits = role.strip_prefix(ANSWER_PREFIX)?;
    all_digits(digits).then(|| digits.parse().ok()).flatten()
}

/// The role of the deliverable `name` that attempt number `attempt` produced.
///
/// # Errors
/// [`EngineError::Invalid`] when the name is so long that the role would pass the 64 characters a
/// slug allows.
pub fn output_role(name: &Slug, attempt: u32) -> Result<Slug, EngineError> {
    Ok(Slug::parse(&format!(
        "{}{ATTEMPT_MARK}{attempt}",
        name.as_str()
    ))?)
}

/// The deliverable name and the attempt number of an output role, or `None` when the role is not
/// an output role of the engine.
pub fn parse_output_role(role: &str) -> Option<(Slug, u32)> {
    let (name, digits) = role.rsplit_once(ATTEMPT_MARK)?;
    if !all_digits(digits) {
        return None;
    }
    Some((Slug::parse(name).ok()?, digits.parse().ok()?))
}

fn all_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slug(text: &str) -> Slug {
        Slug::parse(text).expect("a slug")
    }

    #[test]
    fn an_answer_role_carries_the_attempts_before_it_and_reads_back() {
        let role = answer_role(3).expect("a role");
        assert_eq!(role.as_str(), "human-answer-3");
        assert_eq!(answer_attempts_before(role.as_str()), Some(3));
        assert_eq!(answer_attempts_before("human-answer-0"), Some(0));
    }

    #[test]
    fn a_decision_role_carries_the_attempts_before_it_and_the_command_and_reads_back() {
        let command = CausationId::from_uuid(uuid::Uuid::from_u128(
            0x018f_3a00_0000_7000_8000_0000_0000_0a01,
        ));
        let role = decision_role(2, command).expect("a role");
        assert_eq!(
            role.as_str(),
            "dependency-decision-2-018f3a00000070008000000000000a01"
        );
        assert_eq!(decision_attempts_before(role.as_str()), Some(2));
        // The same command names the same role, which is what makes a repeat recognisable.
        assert_eq!(decision_role(2, command).expect("a role"), role);
        // Neither an answer, nor an output, nor a malformed role is a decision.
        for other in [
            "human-answer-2",
            "spec.a1",
            "dependency-decision-",
            "dependency-decision-x-ab",
            "dependency-decision-2",
            "dependency-decision-2-",
            "dependency-decision-2-zz",
        ] {
            assert_eq!(decision_attempts_before(other), None, "{other}");
        }
    }

    #[test]
    fn a_role_that_is_not_an_answer_role_is_not_read_as_one() {
        assert_eq!(answer_attempts_before("spec.a1"), None);
        assert_eq!(answer_attempts_before("human-answer-"), None);
        assert_eq!(answer_attempts_before("human-answer-x"), None);
        assert_eq!(answer_attempts_before("human-answer-1x"), None);
    }

    #[test]
    fn an_output_role_names_the_deliverable_and_the_attempt() {
        let role = output_role(&slug("architecture-decision"), 2).expect("a role");
        assert_eq!(role.as_str(), "architecture-decision.a2");
        assert_eq!(
            parse_output_role(role.as_str()),
            Some((slug("architecture-decision"), 2))
        );
    }

    #[test]
    fn a_dot_in_a_deliverable_name_does_not_confuse_the_attempt_suffix() {
        let name = slug("report.a9.final");
        let role = output_role(&name, 4).expect("a role");
        assert_eq!(parse_output_role(role.as_str()), Some((name, 4)));
    }

    #[test]
    fn a_role_that_is_not_an_output_role_is_skipped() {
        assert_eq!(parse_output_role("spec"), None);
        assert_eq!(parse_output_role("spec.a"), None);
        assert_eq!(parse_output_role("spec.ax"), None);
        assert_eq!(parse_output_role("human-answer-1"), None);
    }

    #[test]
    fn a_name_too_long_for_its_role_is_refused() {
        let name = slug(&"n".repeat(62));
        assert!(matches!(
            output_role(&name, 1),
            Err(EngineError::Invalid(_))
        ));
    }
}
