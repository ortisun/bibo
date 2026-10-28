//! `execute` of the architecture stage.
//!
//! In order, and each step ends the stage if it fails:
//!
//! 1. Read the frozen specification and the repository map by the hash the contract pinned, and
//!    refuse a specification that is not approved.
//! 2. Learn what the round before this one said, and what people answered.
//! 3. Assemble the architect's prompt. The specification, the map and the feedback are untrusted
//!    data, each in its own block.
//! 4. Run the architect over its own checkout of the base commit, in a sandbox, with tools that
//!    only read, and check its answer against its schema and then against `Design::read`.
//! 5. Compute the risk tier from the job's facts and from the design, and run the deterministic
//!    checks. For work at or above the critic tier whose design passed them, ask the critic. When
//!    there is no critic to ask, say so in the record.
//! 6. Store the design byte for byte, the record of what the stage measured, and the draft
//!    decision records.
//!
//! The architect's answer is never repaired. A design that fails a check is stored all the same,
//! because the gate needs it to say what is wrong, and the engine sends it back.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::specification_contract::SpecStatus;
use factory_domain::contracts::{Contract, SpecificationContract};
use factory_domain::policy::RepoKind;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{RiskTier, StageKind};
use factory_ports::agent::Usage;
use serde_json::{Value, json};

use super::adr;
use super::checks::{self, Complexity, SpecIds};
use super::critic::{self, Absent, Outcome};
use super::design::{Design, Status};
use super::handler::{ADRS, ArchitectureHandler, DESIGN, RECORD};
use super::risk;
use super::shared::{
    Answer, Call, LoadProblem, Loaded, Tools, feedback_text, human_answers, load, read_input,
    run_agent, seam, store_bytes, store_json,
};
use crate::handlers::{StageContext, StageError, StageOutput};
use crate::prompts::{
    Assembler, AssemblyRequest, ContentClass, IndependentRequest, Input, Limits, Scope, Source,
};
use crate::stages::implementation::input::{REPOSITORY_MAP, SPECIFICATION_CONTRACT, map_commit};

fn tools(handler: &ArchitectureHandler) -> Tools<'_> {
    Tools {
        specs: handler.specs.as_ref(),
        probes: handler.probes.as_ref(),
        schemas: handler.schemas.as_ref(),
    }
}

pub(super) async fn execute(
    handler: &ArchitectureHandler,
    ctx: &mut StageContext<'_>,
) -> Result<StageOutput, StageError> {
    let ports = ctx.ports;
    let identity = ctx.identity;
    let missing = || StageError::Blocked(BlockedCode::DependencyUnavailable);

    // 1. The inputs.
    let (spec_ref, spec_bytes) = read_input(ctx, SPECIFICATION_CONTRACT).await?;
    let (map_ref, map_bytes) = read_input(ctx, REPOSITORY_MAP).await?;
    let spec = std::str::from_utf8(&spec_bytes)
        .ok()
        .and_then(|text| SpecificationContract::from_json_str(text).ok())
        .ok_or_else(missing)?;
    if spec.metadata.status != SpecStatus::Approved {
        return Err(missing());
    }
    let base = map_commit(&map_bytes).ok_or_else(missing)?;

    // 2. The rounds before this one.
    let previous = handler.rounds.previous(&identity).await.map_err(seam)?;
    let answers = human_answers(ctx).await?;
    let feedback = feedback_text(previous.as_ref(), &answers, &[]);

    // 3. The prompt.
    let architect =
        load(ports.registry, &handler.config.agent).map_err(|problem| match problem {
            LoadProblem::Unknown | LoadProblem::Unusable => StageError::Internal,
        })?;
    let now = ports.clock.now();
    let host = |kind: &str, sha: &Sha256Digest| Source::HostArtifact {
        kind: kind.to_owned(),
        id: sha.to_string(),
    };
    let mut inputs = vec![
        Input::untrusted(
            "frozen_specification",
            ContentClass::SpecificationText,
            host("frozen-specification", &spec_ref.sha256),
            identity.tenant,
            spec_bytes.clone(),
        )
        .fetched_at(now),
        Input::untrusted(
            "repository_map",
            ContentClass::ToolOutput,
            host("repository-map", &map_ref.sha256),
            identity.tenant,
            map_bytes.clone(),
        )
        .fetched_at(now),
    ];
    if let Some(text) = &feedback {
        inputs.push(
            Input::untrusted(
                "rework_findings",
                ContentClass::ToolOutput,
                host("design-check-findings", &Sha256Digest::of(text.as_bytes())),
                identity.tenant,
                text.clone().into_bytes(),
            )
            .fetched_at(now),
        );
    }
    let assembled = Assembler::new(&handler.redactor, &handler.policy.paths, Limits::default())
        .assemble(AssemblyRequest::new(
            &architect.manifest,
            &architect.prompt,
            Scope::new(identity.tenant, RepoKind::Target),
            inputs,
        ))
        .map_err(|_| StageError::Internal)?;

    // 4. The architect.
    let answer = run_agent(
        ctx,
        &handler.config.settings,
        tools(handler),
        &Call {
            loaded: &architect,
            assembled: &assembled,
            base: &base,
            stage: StageKind::Architecture,
            risk: RiskTier::Medium,
            report_ready: true,
        },
    )
    .await?;
    let design = Design::read(&answer.validated.value).map_err(|_| StageError::InvalidOutput)?;

    // 5. The risk, the checks and the critic.
    let job = handler.risk.of(&identity).await.map_err(seam)?;
    let assessment = risk::assess(&design, &handler.policy, job.facts, job.agent_claim);
    let protected = risk::protected_paths(&design, &handler.policy);
    let rules = handler.config.rules;
    let spec_ids = SpecIds::from_contract(&spec);
    let mut usage = answer.usage;
    let mut denials = answer.denials.clone();
    let (critic_outcome, critic_answer) = if design.status == Status::NeedsHuman {
        (Outcome::NotRequired, None)
    } else {
        let found = checks::check(&design, &spec_ids, assessment.tier, &protected, &rules);
        let clean = found.traceability.is_empty() && found.completeness.is_empty();
        if assessment.tier < rules.critic_from {
            (Outcome::NotRequired, None)
        } else if !clean {
            (Outcome::SkippedDesignFailed, None)
        } else {
            let asked = ask_critic(
                handler,
                ctx,
                &CriticInputs {
                    design: &design,
                    architect: &architect,
                    architect_answer: &answer,
                    spec_ref: &spec_ref,
                    spec_bytes: &spec_bytes,
                    map_ref: &map_ref,
                    map_bytes: &map_bytes,
                    base: &base,
                    tier: assessment.tier,
                },
            )
            .await?;
            usage = usage.saturating_add(asked.usage);
            denials.extend(asked.denials);
            (asked.outcome, asked.answer)
        }
    };

    // 6. The documents.
    let complexity = checks::complexity(&design, &spec_ids, assessment.tier, &rules);
    let record = json!({
        "kind": RECORD,
        "schema_version": 1,
        "design_sha256": answer.validated.sha256,
        "specification_sha256": spec_ref.sha256,
        "round": previous.as_ref().map_or(0, |round| round.round),
        "architect": {
            "agent": architect.manifest.id.as_str(),
            "version": architect.manifest.version.to_string(),
            "runtime": answer.runtime,
            "runtime_version": answer.runtime_version,
            "model": answer.model,
        },
        "risk": {
            "tier": assessment.tier.as_str(),
            "computed": assessment.computed.as_str(),
            "matched": assessment.matched,
            "unclassified": assessment.unclassified,
            "agent_claim": assessment.agent_claim.map(RiskTier::as_str),
            "critic_from": rules.critic_from.as_str(),
            "human_from": rules.human_from.as_str(),
        },
        "protected_paths": protected,
        "complexity": match &complexity {
            Complexity::Trivial(why) => json!({ "kind": "trivial", "justification": why }),
            Complexity::NonTrivial => json!({ "kind": "non_trivial" }),
        },
        "alternatives": checks::alternatives(&design),
        "critic": critic_outcome.to_json(critic_answer.as_ref()),
        "needs_human": design.status == Status::NeedsHuman,
        "human_question": design.human_question,
        "ignored_instructions": design.ignored_instructions,
        "prompt": {
            "signals": assembled.manifest().signals.iter().map(|signal| signal.name()).collect::<Vec<_>>(),
            "sha256": assembled.sha256(),
        },
        "usage": usage_json(usage),
    });
    let artifacts = vec![
        store_bytes(ctx, DESIGN, answer.raw.clone(), "application/json").await?,
        store_json(ctx, RECORD, &record).await?,
        store_json(ctx, ADRS, &adr::drafts(&design)).await?,
    ];
    Ok(StageOutput {
        artifacts,
        usage,
        permission_denials: denials,
        ..StageOutput::default()
    })
}

fn usage_json(usage: Usage) -> Value {
    json!({
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "cost_micro_usd": usage.cost.0,
        "requests": usage.requests,
    })
}

struct CriticInputs<'a> {
    design: &'a Design,
    architect: &'a Loaded,
    architect_answer: &'a Answer,
    spec_ref: &'a factory_domain::contracts::ArtifactRef,
    spec_bytes: &'a [u8],
    map_ref: &'a factory_domain::contracts::ArtifactRef,
    map_bytes: &'a [u8],
    base: &'a factory_ports::paths::CommitSha,
    tier: RiskTier,
}

struct Asked {
    outcome: Outcome,
    answer: Option<Value>,
    usage: Usage,
    denials: Vec<factory_ports::agent::Denial>,
}

fn absent(reason: Absent) -> Asked {
    Asked {
        outcome: Outcome::Absent(reason),
        answer: None,
        usage: Usage::default(),
        denials: Vec::new(),
    }
}

/// Asks the independent critic to review the design, or records why there is none.
async fn ask_critic(
    handler: &ArchitectureHandler,
    ctx: &mut StageContext<'_>,
    given: &CriticInputs<'_>,
) -> Result<Asked, StageError> {
    let ports = ctx.ports;
    let identity = ctx.identity;
    let loaded = match load(ports.registry, &handler.config.critic) {
        Ok(loaded) => loaded,
        Err(LoadProblem::Unknown) => return Ok(absent(Absent::NoSuchAgent)),
        Err(LoadProblem::Unusable) => return Ok(absent(Absent::Unusable)),
    };
    let manifest = &loaded.manifest;
    // A critic is a different agent from the architect, with a role that the prompt assembler
    // treats as independent, and it returns the schema the other reviewers return.
    let usable = manifest.id != given.architect.manifest.id
        && manifest.role.as_str().ends_with("_critic")
        && manifest.outputs_schema.name.as_str() == critic::OUTPUT_SCHEMA;
    if !usable {
        return Ok(absent(Absent::Unusable));
    }
    let now = ports.clock.now();
    let design_text =
        serde_json::to_vec_pretty(&given.design.for_critic()).map_err(|_| StageError::Internal)?;
    let host = |kind: &str, sha: &Sha256Digest| Source::HostArtifact {
        kind: kind.to_owned(),
        id: sha.to_string(),
    };
    // The type of these inputs is the guard: an agent's account of its own work cannot become one.
    let independent = |input: Input| input.fetched_at(now).into_independent();
    let inputs = vec![
        independent(Input::untrusted(
            critic::INPUT_SPECIFICATION,
            ContentClass::SpecificationText,
            host("frozen-specification", &given.spec_ref.sha256),
            identity.tenant,
            given.spec_bytes.to_vec(),
        )),
        independent(Input::untrusted(
            critic::INPUT_DESIGN,
            ContentClass::ModelOutput,
            host(
                "architecture-design-without-summary",
                &Sha256Digest::of(&design_text),
            ),
            identity.tenant,
            design_text,
        )),
        independent(Input::untrusted(
            critic::INPUT_MAP,
            ContentClass::ToolOutput,
            host("repository-map", &given.map_ref.sha256),
            identity.tenant,
            given.map_bytes.to_vec(),
        )),
    ]
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| StageError::Internal)?;
    // The architect's own answer, with its summary, is withheld by its hash as well.
    let scope = Scope::new(identity.tenant, RepoKind::Target)
        .withholding(given.architect_answer.validated.sha256.clone());
    let assembled =
        match Assembler::new(&handler.redactor, &handler.policy.paths, Limits::default())
            .assemble_independent(IndependentRequest::new(
                manifest,
                &loaded.prompt,
                scope,
                inputs,
            )) {
            Ok(assembled) => assembled,
            // A critic whose prompt does not take these three inputs cannot be used.
            Err(_) => return Ok(absent(Absent::Unusable)),
        };
    let answer = run_agent(
        ctx,
        &handler.config.settings,
        tools(handler),
        &Call {
            loaded: &loaded,
            assembled: &assembled,
            base: given.base,
            stage: StageKind::Architecture,
            risk: given.tier,
            report_ready: false,
        },
    )
    .await?;
    let review =
        critic::Review::read(&answer.validated.value).map_err(|_| StageError::InvalidOutput)?;
    Ok(Asked {
        outcome: Outcome::Ran {
            agent: manifest.id.as_str().to_owned(),
            version: manifest.version.to_string(),
            review: Box::new(review),
        },
        answer: Some(answer.validated.value.clone()),
        usage: answer.usage,
        denials: answer.denials,
    })
}
