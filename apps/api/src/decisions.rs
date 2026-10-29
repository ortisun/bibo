//! Decisions of people: approve, reject, request rework, pause, resume, cancel, and the two
//! decisions on a new dependency (`approve-dependency`, `approve-build-code`).
//!
//! The API is the front door for a decision, and the engine is the judge. This module does the
//! part that belongs to the front door and nothing the engine decides:
//!
//! 1. **Who.** The caller is the principal behind the token. The roles come from the protected
//!    allowlist by the numeric GitHub id of that principal, and the action table of
//!    `policies/approval.yaml` names the designation each verb needs (`approve_pr` and
//!    `reject_or_request_rework` need an approver; `pause_or_resume_job` and `cancel_job` an
//!    operator). A login string is never read. A caller without the role gets a 403 with no
//!    reason, and the attempt is audited.
//! 2. **What.** The words are read by the same pure grammar every channel uses
//!    (`factory_composition::commands`), so `merge`, `deploy`, `ready` and `undraft` are unknown
//!    verbs here as they are in a pull request comment.
//! 3. **Record.** The request is written to the audit log in the caller's tenant, with an id
//!    derived from the tenant, the job and the `Idempotency-Key`, so a retry writes nothing new
//!    and the same key with a different decision is a conflict. The subject ends with the time of
//!    the request and a keyed word (`at=` and `mac=`, HMAC-SHA256 over the tenant, the person, the
//!    event id, the time and the other words) that only this service can make. The worker's hook
//!    applies a request only if the word is right (AUT-12). A retry of the same request, which has
//!    a later time and so another word, finds the record it wrote and answers as the first did.
//!
//! **What this module does not do: apply the decision.** Moving the stage run needs the engine
//! (`Engine::decide`, `Engine::control`) and, for a pull request approval, the change host and the
//! binding checks of `ApprovalService::judge` (head, tree, base and evidence as they are now). The
//! engine runs in the worker, which holds the sandbox, the runtime and the GitHub App; the API
//! holds none of them and cannot build one without a fake. So the answer is `202` with
//! `"applied": false`: the decision is recorded, authorized by the allowlist and waiting for the
//! worker. `"applied": false` is true of the moment of the answer and says nothing about what
//! comes after. The worker (`factory_composition::decisions::ClaimWork`, a step before each claim)
//! reads the record, checks the allowlist again by numeric id, applies the decision once and
//! writes the audit record `decision.applied` or `decision.rejected` for the same job, which
//! `GET /v1/jobs/{id}/timeline` shows.
//!
//! # The two verbs of a dependency decision
//!
//! `approve-dependency` and `approve-build-code` name a package (`package`, `version` and, to tell
//! two packages apart, the start of the `checksum`) and say why (`reason`, at least ten
//! characters). The words go through the one reader of those commands
//! (`gates::supply_chain::command::parse_dependency_command`), so the API accepts exactly the
//! package names, versions and checksum prefixes the other channels do. The record has its own
//! audit action, `decision.dependency_requested`, and its own signed subject; the worker's step
//! reads the evidence the blocked stage run stored, finds the awaited package the words select,
//! asks the policy engine for the proof of authority and calls
//! `Engine::record_dependency_decision`. The answer is `202` and `"applied": false`, as for the
//! other verbs.

use axum::http::{HeaderMap, StatusCode};
use factory_composition::commands::{CommandError, ParsedDecision, parse_form};
use factory_composition::decision_signing::{
    DependencySigning, DependencySubject, Signing, SubjectKind, read_dependency_subject,
    read_subject,
};
use factory_composition::decisions::DecisionFields;
use factory_composition::dependency_decisions::{
    DependencyFields, REQUESTED as DEPENDENCY_REQUESTED,
};
use factory_composition::stage_decisions::StageVerb;
use factory_domain::ids::{AuditEventId, CorrelationId, JobId, StageRunId};
use factory_domain::vocabulary::HumanRole;
use factory_ports::store::{
    AuditActor, AuditDecision, ConstraintRule, NewAuditEvent, StoreError, Tx, Witness,
};
use factory_workflow::gates::supply_chain::approval::{
    ApprovalKind, MAX_REASON_CHARS, MIN_REASON_CHARS,
};
use factory_workflow::gates::supply_chain::command::{
    APPROVE_BUILD_CODE, APPROVE_DEPENDENCY, CommandError as DependencyCommandError, ParsedLine,
    parse_dependency_command,
};
use factory_workflow::stages::approval::Verb;
use serde::Deserialize;
use serde_json::json;

use crate::answers::{Answer, ApiError, Reply};
use crate::auth::{Caller, require_repository};
use crate::jobs::{
    audit_action, clean_line, clean_text, commit, decode, idempotency_key, parse_id,
};
use crate::limits::Refusal;
use crate::state::ApiState;
use crate::tokens;

/// The body of `POST /v1/jobs/{job_id}/decisions`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecisionBody {
    pub(crate) verb: String,
    #[serde(default)]
    pub(crate) stage_run_id: Option<String>,
    #[serde(default)]
    pub(crate) head: Option<String>,
    #[serde(default)]
    pub(crate) evidence: Option<String>,
    #[serde(default)]
    pub(crate) target: Option<String>,
    #[serde(default)]
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) package: Option<String>,
    #[serde(default)]
    pub(crate) version: Option<String>,
    #[serde(default)]
    pub(crate) checksum: Option<String>,
    #[serde(default)]
    pub(crate) path: Option<String>,
    #[serde(default)]
    pub(crate) digest: Option<String>,
    #[serde(default)]
    pub(crate) warning: Option<u32>,
}

/// The longest slice of a reason the audit record keeps, in bytes.
const REASON_KEPT: usize = 900;

fn field_of(error: &CommandError) -> &'static str {
    match error {
        CommandError::UnknownVerb(_) | CommandError::NoVerb => "verb",
        CommandError::BadValue(field) | CommandError::Repeated(field) => field,
        CommandError::Reason => "reason",
        CommandError::Missing(..) => "body",
    }
}

/// The designations the policy's action table names for a verb. Empty when the table has no row
/// for it, which the caller treats as a refusal.
fn required_roles(state: &ApiState, verb: Verb) -> Vec<HumanRole> {
    roles_of_action(state, verb.action())
}

/// The designations the policy's action table names for an action.
pub(crate) fn roles_of_action(state: &ApiState, action: &str) -> Vec<HumanRole> {
    state
        .policies
        .approval
        .actions
        .iter()
        .find(|row| row.id == action)
        .and_then(|row| row.approver_roles.as_ref())
        .map(|names| {
            names
                .iter()
                .filter_map(|name| HumanRole::parse(name).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// A UUID derived from the tenant, the caller, the job and the caller's key: the same four always
/// give the same id, so a retried request is the same record, and two people who send the same key
/// for the same job write two records, not one record that the second of them is told is theirs
/// (API-2).
pub(crate) fn derived_id(tenant: &str, principal: &str, job: &str, key: &str) -> uuid::Uuid {
    let digest = factory_domain::values::Sha256Digest::of(
        format!("decision\n{tenant}\n{principal}\n{job}\n{key}").as_bytes(),
    );
    let hash = tokens::digest_bytes(&digest);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

pub(crate) fn kept(reason: &str) -> &str {
    if reason.len() <= REASON_KEPT {
        return reason;
    }
    let mut end = REASON_KEPT;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason[..end]
}

/// `POST /v1/jobs/{job_id}/decisions`.
pub async fn decide(
    state: &ApiState,
    caller: &Caller,
    job_id: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Answer {
    let job_id = parse_id(job_id, JobId::parse).ok_or(ApiError::NotFound)?;
    let key = idempotency_key(headers)?;
    let parsed: DecisionBody = decode(body)?;
    if let Some(kind) = dependency_kind(&parsed.verb) {
        return decide_dependency(state, caller, job_id, &key, &parsed, kind).await;
    }
    if let Some(verb) = StageVerb::parse(&parsed.verb) {
        return crate::stage_decisions::decide(state, caller, job_id, &key, &parsed, verb).await;
    }
    // The words of a package, a file or a warning mean nothing to the other verbs, and are not
    // ignored.
    for (field, present) in [
        ("package", parsed.package.is_some()),
        ("version", parsed.version.is_some()),
        ("checksum", parsed.checksum.is_some()),
        ("path", parsed.path.is_some()),
        ("digest", parsed.digest.is_some()),
        ("warning", parsed.warning.is_some()),
    ] {
        if present {
            return Err(ApiError::BadRequest(field));
        }
    }
    for (field, value) in [
        ("verb", Some(&parsed.verb)),
        ("head", parsed.head.as_ref()),
        ("evidence", parsed.evidence.as_ref()),
        ("target", parsed.target.as_ref()),
        ("stage_run_id", parsed.stage_run_id.as_ref()),
    ] {
        if value.is_some_and(|text| !clean_line(text)) {
            return Err(ApiError::BadRequest(field));
        }
    }
    if parsed.reason.as_ref().is_some_and(|text| !clean_text(text)) {
        return Err(ApiError::BadRequest("reason"));
    }
    let mut fields: Vec<(&str, &str)> = vec![("verb", parsed.verb.as_str())];
    for (name, value) in [
        ("head", &parsed.head),
        ("evidence", &parsed.evidence),
        ("target", &parsed.target),
        ("reason", &parsed.reason),
    ] {
        if let Some(text) = value {
            fields.push((name, text));
        }
    }
    let decision: ParsedDecision =
        parse_form(&fields).map_err(|e| ApiError::BadRequest(field_of(&e)))?;
    let stage_run = parsed
        .stage_run_id
        .as_deref()
        .map(|text| parse_id(text, StageRunId::parse).ok_or(ApiError::BadRequest("stage_run_id")))
        .transpose()?;
    match decision.verb {
        Verb::Approve if decision.head.is_none() => return Err(ApiError::BadRequest("head")),
        Verb::Approve if decision.evidence.is_none() => {
            return Err(ApiError::BadRequest("evidence"));
        }
        Verb::Rework if decision.target.is_none() => return Err(ApiError::BadRequest("target")),
        Verb::Approve | Verb::Reject | Verb::Rework if stage_run.is_none() => {
            return Err(ApiError::BadRequest("stage_run_id"));
        }
        _ => {}
    }
    if state
        .redactor
        .contains_secret(decision.reason.as_bytes())
        .unwrap_or(true)
    {
        return Err(ApiError::BadRequest("reason"));
    }

    let ids = &state.ports.ids;
    let command = derived_id(
        &caller.tenant.as_text(),
        &caller.principal.as_text(),
        &job_id.as_text(),
        key.as_str(),
    );

    // 1. Who. The attempt of someone without the role is audited and refused with no reason, and
    // the answer does not depend on whether the job exists: an unlisted person learns nothing
    // about the tenant's jobs. The record names the job as text and does not reference it.
    let needed = required_roles(state, decision.verb);
    let mut allowed = caller.require_any(&needed).is_ok();

    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let mut found_job = None;
    if allowed {
        let job = tx.get_job(job_id).await?;
        // The designation holds on the repositories the allowlist entry names (API-1). A person
        // narrowed to other repositories is refused as one without the designation: audited, no
        // reason, and the record names no job.
        let repository = tx.get_repository(job.value.repository).await?;
        match require_repository(state, caller, &repository.value.full_name) {
            Ok(()) => {}
            Err(ApiError::Forbidden) => allowed = false,
            Err(other) => return Err(other),
        }
        found_job = Some(job);
    }
    let (job_ref, correlation_id) = if let (true, Some(job)) = (allowed, found_job) {
        if let Some(run) = stage_run {
            let found = tx.get_stage_run(run).await?;
            if found.value.job_id != job.value.id {
                return Err(ApiError::NotFound);
            }
        }
        // The job's own correlation id: the same for every record of the job, and the same on a
        // retry, which is what lets a retried request find the record it wrote.
        (Some(job_id), job.value.correlation_id)
    } else {
        (None, CorrelationId::from_uuid(ids.new_uuid()))
    };
    let audit_id = if allowed {
        AuditEventId::from_uuid(command)
    } else {
        AuditEventId::from_uuid(ids.new_uuid())
    };
    // The one grammar of the subject is shared with the worker, which reads it back to apply the
    // decision.
    let fields = DecisionFields {
        verb: decision.verb,
        job: job_id,
        stage_run,
        head: decision.head.as_ref().map(|h| h.as_str().to_owned()),
        evidence: decision.evidence.as_ref().map(|e| e.as_str().to_owned()),
        target: decision.target.map(|t| t.as_str().to_owned()),
    };
    if !allowed {
        return refuse(state, caller, tx, fields.subject(), correlation_id).await;
    }
    let reason = format!("requested: {}", kept(&decision.reason));
    let accepted = || {
        Reply::new(
            StatusCode::ACCEPTED,
            json!({
                "decision_id": command.hyphenated().to_string(),
                "status": "recorded",
                "applied": false,
            }),
        )
    };
    // A retry of a request that was recorded finds its record. The record carries the time of the
    // first request, so a retry's own subject differs in its last two words and the store would call
    // it another record under the same id.
    if let Some(earlier) = recorded_request(&mut *tx, job_id, audit_id).await? {
        return if earlier.is_the_same_request(caller, &fields, stage_run, &reason) {
            let _ = tx.rollback().await;
            Ok(accepted())
        } else {
            Err(ApiError::Conflict)
        };
    }
    let requested_at = state.ports.clock.now().as_text();
    let subject = state.decision_keys.signed_subject(&Signing {
        tenant: caller.tenant,
        actor: caller.principal,
        event: audit_id,
        requested_at: &requested_at,
        fields: &fields,
    });
    let written = tx
        .record_audit(NewAuditEvent {
            id: audit_id,
            actor: AuditActor::Human(caller.principal),
            action: audit_action("decision.requested")?,
            subject,
            decision: AuditDecision::Record,
            reason,
            policy_hash: state.policy_hash(),
            job: job_ref,
            stage_run,
            correlation_id,
        })
        .await;
    match written {
        Ok(_) => {}
        Err(StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent)) => {
            return Err(ApiError::Conflict);
        }
        Err(other) => return Err(other.into()),
    }
    commit(state, caller.scope(), tx, Witness::Audit(audit_id)).await?;
    Ok(accepted())
}

/// The kind of decision a verb is, when it is one of the two verbs of a dependency decision.
fn dependency_kind(verb: &str) -> Option<ApprovalKind> {
    match verb {
        APPROVE_DEPENDENCY => Some(ApprovalKind::NewDependency),
        APPROVE_BUILD_CODE => Some(ApprovalKind::BuildCode),
        _ => None,
    }
}

fn dependency_field(error: DependencyCommandError) -> &'static str {
    match error {
        DependencyCommandError::NoName | DependencyCommandError::InvalidName => "package",
        DependencyCommandError::NoVersion | DependencyCommandError::InvalidVersion => "version",
        DependencyCommandError::InvalidChecksum => "checksum",
    }
}

/// `POST /v1/jobs/{job_id}/decisions` with the verb `approve-dependency` or `approve-build-code`.
#[allow(clippy::too_many_lines)]
async fn decide_dependency(
    state: &ApiState,
    caller: &Caller,
    job_id: JobId,
    key: &factory_ports::store::IdempotencyKey,
    parsed: &DecisionBody,
    kind: ApprovalKind,
) -> Answer {
    // Words that mean nothing to this verb are refused, not ignored.
    for (field, present) in [
        ("head", parsed.head.is_some()),
        ("evidence", parsed.evidence.is_some()),
        ("target", parsed.target.is_some()),
        ("path", parsed.path.is_some()),
        ("digest", parsed.digest.is_some()),
        ("warning", parsed.warning.is_some()),
    ] {
        if present {
            return Err(ApiError::BadRequest(field));
        }
    }
    for (field, value) in [
        ("package", parsed.package.as_ref()),
        ("version", parsed.version.as_ref()),
        ("checksum", parsed.checksum.as_ref()),
        ("stage_run_id", parsed.stage_run_id.as_ref()),
    ] {
        if value.is_some_and(|text| !clean_line(text)) {
            return Err(ApiError::BadRequest(field));
        }
    }
    // Each of the three is one word. A space would let a word of the package or of the reason
    // slip into the line the reader of the commands is given.
    for (field, value) in [
        ("package", parsed.package.as_ref()),
        ("version", parsed.version.as_ref()),
        ("checksum", parsed.checksum.as_ref()),
    ] {
        if value.is_some_and(|text| text.is_empty() || text.contains(char::is_whitespace)) {
            return Err(ApiError::BadRequest(field));
        }
    }
    let package = parsed
        .package
        .as_deref()
        .ok_or(ApiError::BadRequest("package"))?;
    let version = parsed
        .version
        .as_deref()
        .ok_or(ApiError::BadRequest("version"))?;
    let reason = parsed.reason.as_deref().map_or("", str::trim);
    if reason.chars().count() < MIN_REASON_CHARS || reason.chars().count() > MAX_REASON_CHARS {
        return Err(ApiError::BadRequest("reason"));
    }
    if !clean_text(reason)
        || state
            .redactor
            .contains_secret(reason.as_bytes())
            .unwrap_or(true)
    {
        return Err(ApiError::BadRequest("reason"));
    }
    // The words go through the one reader of the dependency commands: the same names, versions and
    // checksum prefixes every channel accepts, and nothing else.
    let line = match parsed.checksum.as_deref() {
        Some(checksum) => format!("{} {package} {version} {checksum}", verb_of(kind)),
        None => format!("{} {package} {version}", verb_of(kind)),
    };
    let command = match parse_dependency_command(&line) {
        Ok(ParsedLine::Command(command))
            if command.name == package
                && command.version == version
                && command.reason.is_empty()
                && command.checksum_prefix.is_some() == parsed.checksum.is_some() =>
        {
            command
        }
        Ok(_) => {
            return Err(ApiError::BadRequest(if parsed.checksum.is_some() {
                "checksum"
            } else {
                "package"
            }));
        }
        Err(error) => return Err(ApiError::BadRequest(dependency_field(error))),
    };
    let stage_run = parsed
        .stage_run_id
        .as_deref()
        .map(|text| parse_id(text, StageRunId::parse).ok_or(ApiError::BadRequest("stage_run_id")))
        .transpose()?;
    let fields = DependencyFields {
        kind,
        job: job_id,
        stage_run,
        package: command.name,
        version: command.version,
        checksum: command.checksum_prefix,
    };
    if !fields.is_well_formed() {
        return Err(ApiError::BadRequest("package"));
    }

    let ids = &state.ports.ids;
    let command_id = derived_id(
        &caller.tenant.as_text(),
        &caller.principal.as_text(),
        &job_id.as_text(),
        key.as_str(),
    );

    // Who: the designations the action names. The worker asks the policy engine again, with the
    // allowlist as it is then and the designation this package needs.
    let needed = roles_of_action(state, kind.action());
    let mut allowed = caller.require_any(&needed).is_ok();
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let mut found_job = None;
    if allowed {
        let job = tx.get_job(job_id).await?;
        let repository = tx.get_repository(job.value.repository).await?;
        match require_repository(state, caller, &repository.value.full_name) {
            Ok(()) => {}
            Err(ApiError::Forbidden) => allowed = false,
            Err(other) => return Err(other),
        }
        found_job = Some(job);
    }
    let (job_ref, correlation_id) = if let (true, Some(job)) = (allowed, found_job) {
        if let Some(run) = stage_run {
            let found = tx.get_stage_run(run).await?;
            if found.value.job_id != job.value.id {
                return Err(ApiError::NotFound);
            }
        }
        (Some(job_id), job.value.correlation_id)
    } else {
        (None, CorrelationId::from_uuid(ids.new_uuid()))
    };
    let audit_id = if allowed {
        AuditEventId::from_uuid(command_id)
    } else {
        AuditEventId::from_uuid(ids.new_uuid())
    };
    if !allowed {
        return refuse(state, caller, tx, fields.subject(), correlation_id).await;
    }
    let stored_reason = format!("requested: {}", kept(reason));
    let accepted = || {
        Reply::new(
            StatusCode::ACCEPTED,
            json!({
                "decision_id": command_id.hyphenated().to_string(),
                "status": "recorded",
                "applied": false,
            }),
        )
    };
    if let Some(earlier) = recorded_request(&mut *tx, job_id, audit_id).await? {
        return if earlier.is_the_same_dependency_request(caller, &fields, stage_run, &stored_reason)
        {
            let _ = tx.rollback().await;
            Ok(accepted())
        } else {
            Err(ApiError::Conflict)
        };
    }
    let requested_at = state.ports.clock.now().as_text();
    let subject = state
        .decision_keys
        .signed_dependency_subject(&DependencySigning {
            tenant: caller.tenant,
            actor: caller.principal,
            event: audit_id,
            requested_at: &requested_at,
            fields: &fields,
        });
    let written = tx
        .record_audit(NewAuditEvent {
            id: audit_id,
            actor: AuditActor::Human(caller.principal),
            action: audit_action(DEPENDENCY_REQUESTED)?,
            subject,
            decision: AuditDecision::Record,
            reason: stored_reason,
            policy_hash: state.policy_hash(),
            job: job_ref,
            stage_run,
            correlation_id,
        })
        .await;
    match written {
        Ok(_) => {}
        Err(StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent)) => {
            return Err(ApiError::Conflict);
        }
        Err(other) => return Err(other.into()),
    }
    commit(state, caller.scope(), tx, Witness::Audit(audit_id)).await?;
    Ok(accepted())
}

const fn verb_of(kind: ApprovalKind) -> &'static str {
    match kind {
        ApprovalKind::NewDependency => APPROVE_DEPENDENCY,
        ApprovalKind::BuildCode => APPROVE_BUILD_CODE,
    }
}

/// The most pages of a job's audit log read to find an earlier request.
const REPLAY_PAGES: u32 = 20;

/// A `decision.requested` record this service wrote earlier.
pub(crate) struct Earlier(pub(crate) factory_ports::store::AuditRecord);

impl Earlier {
    /// True when the record is the same request: the same person, the same words, the same reason.
    /// Only the time and the keyed word may differ.
    fn is_the_same_request(
        &self,
        caller: &Caller,
        fields: &DecisionFields,
        stage_run: Option<StageRunId>,
        reason: &str,
    ) -> bool {
        let event = &self.0.event;
        let same_fields = matches!(
            read_subject(&event.subject),
            Some(SubjectKind::Signed { fields: stored, .. }) if &stored == fields
        );
        same_fields
            && event.actor == AuditActor::Human(caller.principal)
            && event.stage_run == stage_run
            && event.reason == reason
    }
}

impl Earlier {
    /// True when the record is the same decision on a dependency: the same person, the same
    /// words, the same reason. Only the time and the keyed word may differ.
    fn is_the_same_dependency_request(
        &self,
        caller: &Caller,
        fields: &DependencyFields,
        stage_run: Option<StageRunId>,
        reason: &str,
    ) -> bool {
        let event = &self.0.event;
        let same_fields = matches!(
            read_dependency_subject(&event.subject),
            Some(DependencySubject::Signed { fields: stored, .. }) if &stored == fields
        );
        same_fields
            && event.actor == AuditActor::Human(caller.principal)
            && event.stage_run == stage_run
            && event.reason == reason
    }
}

/// The record of this id, if the job's audit log holds it.
pub(crate) async fn recorded_request(
    tx: &mut dyn Tx,
    job: JobId,
    id: AuditEventId,
) -> Result<Option<Earlier>, ApiError> {
    let mut after = 0;
    for _ in 0..REPLAY_PAGES {
        let page = tx
            .read_audit(factory_ports::store::AuditFilter::Job(job), after, 500)
            .await?;
        let count = page.len();
        for record in page {
            after = record.sequence;
            if record.event.id == id {
                return Ok(Some(Earlier(record)));
            }
        }
        if count < 500 {
            break;
        }
    }
    Ok(None)
}

/// The refusal of someone who does not hold the designation: audited, within what the audit log
/// takes from one person (API-8), and answered `403` with no reason.
///
/// A refused caller used to leave one row with a new id for every request, so any token holder, listed
/// or not, could grow the tenant's hash-chained audit log by thousands of rows an hour, and the
/// chain serialises its writers. A person now has a few rows a minute, then one row that says the
/// rest are counted, and the count is written when the next minute opens.
pub(crate) async fn refuse(
    state: &ApiState,
    caller: &Caller,
    mut tx: Box<dyn Tx>,
    subject: String,
    correlation_id: CorrelationId,
) -> Answer {
    let rows: Vec<(&str, String, &str)> = match state
        .refusals
        .admit(caller.principal, std::time::Instant::now())
    {
        Refusal::Count => {
            let _ = tx.rollback().await;
            return Err(ApiError::Forbidden);
        }
        Refusal::Record { carried } => {
            let mut rows = vec![(
                "decision.denied",
                subject,
                "The caller does not hold the designation this decision needs.",
            )];
            if carried > 0 {
                rows.push((
                        "decision.denied_summary",
                        format!("decision refusals: {carried} not recorded"),
                        "Refusals of this person in the minute before went past what the audit log records one by one; the count is in the subject.",
                    ));
            }
            rows
        }
        Refusal::Suppress => vec![(
            "decision.denied_suppressed",
            "decision refusals".to_owned(),
            "More refusals of this person follow in this minute; they are counted, not recorded one by one.",
        )],
    };
    let mut last = None;
    for (action, subject, reason) in rows {
        let id = AuditEventId::from_uuid(state.ports.ids.new_uuid());
        tx.record_audit(NewAuditEvent {
            id,
            actor: AuditActor::Human(caller.principal),
            action: audit_action(action)?,
            subject,
            decision: AuditDecision::Deny,
            reason: reason.to_owned(),
            policy_hash: state.policy_hash(),
            job: None,
            stage_run: None,
            correlation_id,
        })
        .await?;
        last = Some(id);
    }
    if let Some(id) = last {
        commit(state, caller.scope(), tx, Witness::Audit(id)).await?;
    }
    Err(ApiError::Forbidden)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_tenant_caller_job_and_key_give_the_same_id_and_a_different_one_does_not() {
        let a = derived_id("t1", "p1", "j1", "k1");
        assert_eq!(a, derived_id("t1", "p1", "j1", "k1"));
        assert_ne!(a, derived_id("t1", "p1", "j1", "k2"));
        assert_ne!(a, derived_id("t1", "p1", "j2", "k1"));
        assert_ne!(a, derived_id("t2", "p1", "j1", "k1"));
        assert_ne!(
            a,
            derived_id("t1", "p2", "j1", "k1"),
            "another caller, the same key"
        );
        assert_eq!(a.get_version_num(), 4);
    }

    #[test]
    fn a_long_reason_is_cut_at_a_character_boundary() {
        let long = "é".repeat(600);
        assert!(kept(&long).len() <= REASON_KEPT);
        assert!(long.starts_with(kept(&long)));
        assert_eq!(kept("short"), "short");
    }

    #[test]
    fn the_words_are_the_grammar_of_every_channel() {
        for word in ["merge", "deploy", "ready", "undraft", "APPROVE", ""] {
            assert!(parse_form(&[("verb", word)]).is_err(), "{word:?}");
        }
        assert!(parse_form(&[("verb", "cancel"), ("reason", "no longer needed")]).is_ok());
        assert!(
            parse_form(&[("verb", "cancel")]).is_err(),
            "cancel says why"
        );
    }
}
