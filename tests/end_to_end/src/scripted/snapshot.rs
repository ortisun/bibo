//! Reads the engine's stored records into the parts of the evidence that the engine owns: the
//! stage runs and attempts, the ledger, the audit stream and the timeline.

use std::collections::{BTreeMap, HashMap};

use factory_domain::contracts::Contract;
use factory_domain::ids::JobId;
use factory_ports::store::AuditActor;
use serde_json::Value;

use super::support::World;
use crate::evidence::{AttemptRecord, AuditRecord, JobRecord, StageRunRecord, TimelineEntry};

/// Which status an event type leads to, from the transition tables of the state machine file.
#[derive(Debug, Clone, Default)]
pub struct Transitions {
    to: HashMap<String, String>,
}

impl Transitions {
    /// Reads the `emits` and `to` of every job and stage run transition.
    ///
    /// # Errors
    /// A sentence saying what is wrong with the file.
    pub fn from_state_machine(text: &str) -> Result<Self, String> {
        let document: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
        let mut to = HashMap::new();
        for machine in ["job", "stage_run"] {
            let list = document
                .pointer(&format!("/machines/{machine}/transitions"))
                .and_then(Value::as_array)
                .ok_or_else(|| format!("no transitions for {machine}"))?;
            for transition in list {
                let emits = transition.get("emits").and_then(Value::as_str);
                let target = transition.get("to").and_then(|t| {
                    t.as_str().map(str::to_owned).or_else(|| {
                        t.as_array()
                            .and_then(|a| a.first())
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                });
                if let (Some(emits), Some(target)) = (emits, target) {
                    to.insert(emits.to_owned(), target);
                }
            }
        }
        Ok(Self { to })
    }
}

/// What the engine holds about one job.
pub struct Snapshot {
    /// The job row, without the requester and the issue number (the caller knows them).
    pub job: JobRecord,
    /// The stage runs.
    pub stage_runs: Vec<StageRunRecord>,
    /// The ledger entries as JSON.
    pub ledger: Vec<Value>,
    /// The audit stream.
    pub audit: Vec<AuditRecord>,
    /// The timeline.
    pub timeline: Vec<TimelineEntry>,
    /// The code rework rounds the engine counted.
    pub code_rework_rounds: u8,
}

fn actor(actor: &AuditActor) -> String {
    match actor {
        AuditActor::Human(id) => format!("human:{id}"),
        AuditActor::Service(id) => format!("service:{id}"),
        AuditActor::System(slug) => format!("system:{}", slug.as_str()),
        AuditActor::Anonymous(slug) => format!("anonymous:{}", slug.as_str()),
    }
}

/// Reads the job from the engine's stores.
///
/// # Panics
/// When a stored record cannot be read, which would be a defect of the fakes.
pub async fn take(world: &World, job: JobId, transitions: &Transitions) -> Snapshot {
    let view = world.view(job).await;
    let kinds: HashMap<String, String> = view
        .stage_runs
        .iter()
        .map(|run| (run.id.to_string(), run.kind.as_str().to_owned()))
        .collect();
    let stage_runs = view
        .stage_runs
        .iter()
        .map(|run| StageRunRecord {
            id: run.id.to_string(),
            kind: run.kind.as_str().to_owned(),
            status: run.status.as_str().to_owned(),
            attempts: run
                .attempts
                .iter()
                .map(|attempt| AttemptRecord {
                    id: attempt.id.to_string(),
                    status: attempt.status.as_str().to_owned(),
                })
                .collect(),
            rework_round: 0,
        })
        .collect();

    let ledger: Vec<Value> = world
        .ledger(job)
        .await
        .iter()
        .map(|entry| entry.to_json_value().expect("a ledger entry is JSON"))
        .collect();

    let records = world.audit(job).await;
    let audit: Vec<AuditRecord> = records
        .iter()
        .map(|record| AuditRecord {
            seq: record.sequence,
            action: record.event.action.to_string(),
            actor: actor(&record.event.actor),
            correlation_id: Some(record.event.correlation_id.to_string()),
            detail: record.event.reason.clone(),
            subject: String::new(),
        })
        .collect();

    let events = world.events(job).await;
    let correlation = events
        .first()
        .map(|event| event.correlation_id.to_string())
        .or_else(|| audit.first().and_then(|r| r.correlation_id.clone()))
        .unwrap_or_default();
    let mut last_status: BTreeMap<String, String> = BTreeMap::new();
    let mut timeline = Vec::new();
    for event in &events {
        let subject = event.aggregate.kind.as_str();
        if subject != "job" && subject != "stage_run" {
            continue;
        }
        let Some(to) = transitions.to.get(event.event_type.as_str()) else {
            continue;
        };
        let id = event.aggregate.id.to_string();
        let initial = if subject == "job" {
            "RECEIVED"
        } else {
            "PENDING"
        };
        let from = last_status
            .insert(id.clone(), to.clone())
            .unwrap_or_else(|| initial.to_owned());
        timeline.push(TimelineEntry {
            seq: timeline.len() as u64 + 1,
            subject: subject.to_owned(),
            subject_id: id.clone(),
            kind: kinds.get(&id).cloned(),
            from,
            to: to.clone(),
            reason: event
                .reason_code
                .as_ref()
                .map_or_else(|| event.event_type.as_str().to_owned(), ToString::to_string),
        });
    }

    Snapshot {
        job: JobRecord {
            id: job.to_string(),
            status: view.status.as_str().to_owned(),
            correlation_id: correlation,
            requester: String::new(),
            issue_number: 0,
        },
        stage_runs,
        ledger,
        audit,
        timeline,
        code_rework_rounds: view.code_rework_rounds,
    }
}
