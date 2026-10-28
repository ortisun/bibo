//! The assembler.

use std::collections::{BTreeMap, BTreeSet};

use factory_domain::contracts::AgentManifest;
use factory_domain::ids::TenantId;
use factory_domain::policy::RepoKind;
use factory_domain::policy::paths::PathPolicy;
use factory_domain::redaction::Redactor;
use factory_domain::values::Sha256Digest;
use factory_ports::registry::LoadedPrompt;

use super::block::{self, Header};
use super::error::AssemblyError;
use super::input::{Input, Trust, is_identifier};
use super::limits::{Limits, allowances};
use super::manifest::{ContextManifest, InputRecord, Signal, TemplateRecord};
use super::sanitize::{Lookalikes, lookalikes, neutralize};
use super::template::{InputSpec, Line, Template};
use super::verify::{self, Meant, instruction_line};

/// What a prompt is assembled for: the job's tenant, the kind of repository, and texts that must
/// never be in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    tenant: TenantId,
    repo: RepoKind,
    withheld: BTreeSet<Sha256Digest>,
}

impl Scope {
    /// The scope of a job.
    #[must_use]
    pub fn new(tenant: TenantId, repo: RepoKind) -> Self {
        Self {
            tenant,
            repo,
            withheld: BTreeSet::new(),
        }
    }

    /// Adds the hash of a text that must never reach this prompt, such as the builder's report
    /// when the prompt is a reviewer's, or the prompt of another agent. An input whose original
    /// text has this hash fails the assembly.
    #[must_use]
    pub fn withholding(mut self, hash: Sha256Digest) -> Self {
        self.withheld.insert(hash);
        self
    }

    /// The tenant.
    #[must_use]
    pub const fn tenant(&self) -> TenantId {
        self.tenant
    }
}

/// Everything an assembly needs.
#[derive(Debug, Clone)]
pub struct AssemblyRequest<'a> {
    manifest: &'a AgentManifest,
    prompt: &'a LoadedPrompt,
    scope: Scope,
    inputs: Vec<Input>,
}

impl<'a> AssemblyRequest<'a> {
    /// A request for the agent `manifest`, whose prompt is `prompt`, with `inputs`. The order of
    /// the inputs does not matter: the blocks come in the order of the template.
    #[must_use]
    pub fn new(
        manifest: &'a AgentManifest,
        prompt: &'a LoadedPrompt,
        scope: Scope,
        inputs: Vec<Input>,
    ) -> Self {
        Self {
            manifest,
            prompt,
            scope,
            inputs,
        }
    }
}

/// A part of a finished prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// Lines of the template, with the values of its trusted slots.
    Instruction(String),
    /// One block, opening line to closing line.
    Data {
        /// The name of the input.
        name: String,
        /// The block.
        text: String,
    },
}

/// A finished prompt, and the record of what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assembled {
    text: String,
    parts: Vec<Part>,
    sha256: Sha256Digest,
    manifest: ContextManifest,
}

impl Assembled {
    /// The prompt text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The prompt as parts, in order. Joined with `\n` they are the text.
    #[must_use]
    pub fn parts(&self) -> &[Part] {
        &self.parts
    }

    /// The lines of the template outside the blocks, joined with `\n`. For the same template and
    /// trusted values this is the same text whatever the data is.
    #[must_use]
    pub fn instruction_text(&self) -> String {
        self.parts
            .iter()
            .filter_map(|part| match part {
                Part::Instruction(text) => Some(text.as_str()),
                Part::Data { .. } => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The hash of the prompt text.
    #[must_use]
    pub const fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    /// The record of what the prompt holds.
    #[must_use]
    pub const fn manifest(&self) -> &ContextManifest {
        &self.manifest
    }
}

/// Builds prompts. It holds the redactor and the path policy of the job and the limits, and
/// reads no clock, file or environment: the same inputs give the same prompt.
#[derive(Debug, Clone)]
pub struct Assembler<'a> {
    redactor: &'a Redactor,
    paths: &'a PathPolicy,
    limits: Limits,
}

/// An input after its text was made ready.
struct Work<'i> {
    spec: &'i InputSpec,
    given: Option<&'i Input>,
    original_bytes: usize,
    original_sha256: Sha256Digest,
    text: String,
    stripped: usize,
    looks: Lookalikes,
    omitted: usize,
    redacted: u64,
    hash_is_of_redacted_text: bool,
}

impl<'a> Assembler<'a> {
    /// An assembler.
    #[must_use]
    pub fn new(redactor: &'a Redactor, paths: &'a PathPolicy, limits: Limits) -> Self {
        Self {
            redactor,
            paths,
            limits,
        }
    }

    /// Builds the prompt of an agent from its template and the inputs.
    ///
    /// # Errors
    /// An [`AssemblyError`]. No prompt is returned in that case.
    pub fn assemble(&self, request: AssemblyRequest<'_>) -> Result<Assembled, AssemblyError> {
        self.run(
            request.manifest,
            request.prompt,
            &request.scope,
            &request.inputs,
        )
    }

    fn run(
        &self,
        manifest: &AgentManifest,
        prompt: &LoadedPrompt,
        scope: &Scope,
        inputs: &[Input],
    ) -> Result<Assembled, AssemblyError> {
        let _ = (self.paths, scope.repo);
        if prompt.template != manifest.prompt {
            return Err(AssemblyError::PromptNotForManifest);
        }
        let actual = Sha256Digest::of(prompt.text.as_bytes());
        if actual != manifest.prompt.template_sha256 {
            return Err(AssemblyError::PromptHashMismatch {
                expected: manifest.prompt.template_sha256.clone(),
                actual,
            });
        }
        let template = Template::parse(&prompt.text)?;

        let mut by_name: BTreeMap<&str, &Input> = BTreeMap::new();
        for input in inputs {
            if by_name.insert(input.name(), input).is_some() {
                return Err(AssemblyError::DuplicateInput {
                    name: shown(input.name()),
                });
            }
        }
        let slots = template.trusted_slots();
        for name in by_name.keys() {
            let known = template.inputs().iter().any(|i| i.name() == *name)
                || slots.iter().any(|s| s == name);
            if !known {
                return Err(AssemblyError::UnknownInput { name: shown(name) });
            }
        }

        let mut trusted: BTreeMap<String, String> = BTreeMap::new();
        for slot in &slots {
            let given = by_name
                .get(slot.as_str())
                .filter(|i| i.trust == Trust::Trusted)
                .ok_or_else(|| AssemblyError::TrustedSlot { name: slot.clone() })?;
            let value = std::str::from_utf8(&given.bytes)
                .ok()
                .filter(|v| is_identifier(v))
                .ok_or(AssemblyError::TrustedValueRefused)?;
            trusted.insert(slot.clone(), value.to_owned());
        }

        let mut read_total = 0usize;
        for input in inputs {
            if input.bytes.len() > self.limits.max_read_bytes_per_input {
                return Err(AssemblyError::InputTooLarge {
                    name: shown(input.name()),
                    limit: self.limits.max_read_bytes_per_input,
                });
            }
            read_total = read_total.saturating_add(input.bytes.len());
        }
        if read_total > self.limits.max_read_bytes_total {
            return Err(AssemblyError::InputsTooLarge {
                limit: self.limits.max_read_bytes_total,
            });
        }

        let mut work: Vec<Work<'_>> = Vec::with_capacity(template.inputs().len());
        for spec in template.inputs() {
            work.push(self.prepare(spec, by_name.get(spec.name()).copied())?);
        }
        let max_tokens = u64::try_from(manifest.resource_limits.max_tokens.get()).unwrap_or(0);
        let budget = self.limits.prompt_budget_bytes(max_tokens);
        self.fit(&template, &trusted, &mut work, budget)?;

        let mut records: Vec<InputRecord> = Vec::with_capacity(work.len());
        let mut signals: Vec<Signal> = Vec::new();
        let mut headers: Vec<String> = Vec::with_capacity(work.len());
        let mut rendered: Vec<String> = Vec::with_capacity(work.len());
        for w in &work {
            let header = Header {
                name: w.spec.name(),
                class: w.spec.class(),
                original_bytes: w.original_bytes,
                original_sha256: &w.original_sha256,
                stripped: w.stripped,
                redacted: w.redacted,
                omitted: w.omitted,
            };
            let block_text = block::render(&header, &w.text);
            headers.push(header.line());
            if w.stripped > 0 {
                signals.push(Signal::HiddenTextDetected {
                    input: w.spec.name().to_owned(),
                    count: w.stripped,
                });
            }
            let found = w.looks;
            if found.delimiters > 0 {
                signals.push(Signal::DelimiterLookalike {
                    input: w.spec.name().to_owned(),
                    count: found.delimiters,
                });
            }
            if found.placeholders > 0 {
                signals.push(Signal::PlaceholderSyntax {
                    input: w.spec.name().to_owned(),
                    count: found.placeholders,
                });
            }
            if w.redacted > 0 {
                signals.push(Signal::SecretRedacted {
                    input: w.spec.name().to_owned(),
                    count: w.redacted,
                });
            }
            if w.omitted > 0 {
                signals.push(Signal::Truncated {
                    input: w.spec.name().to_owned(),
                    omitted_bytes: w.omitted,
                });
            }
            records.push(InputRecord {
                name: w.spec.name().to_owned(),
                class: w.spec.class(),
                trust: w.given.map_or(Trust::Untrusted, |g| g.trust),
                source: w.given.map(|g| g.source.clone()),
                provided: w.given.is_some(),
                paths: w.given.map(|g| g.paths.clone()).unwrap_or_default(),
                fetched_at: w.given.and_then(|g| g.fetched_at),
                original_bytes: w.original_bytes,
                original_sha256: w.original_sha256.clone(),
                included_bytes: w.text.len(),
                block_bytes: block_text.len(),
                stripped: w.stripped,
                redacted: w.redacted,
                hash_is_of_redacted_text: w.hash_is_of_redacted_text,
                truncated: w.omitted > 0,
                omitted_bytes: w.omitted,
            });
            rendered.push(block_text);
        }

        let mut lines: Vec<String> = Vec::new();
        let mut parts: Vec<Part> = Vec::new();
        let mut run: Vec<String> = Vec::new();
        for line in template.lines() {
            match line {
                Line::Text(pieces) => {
                    let text = instruction_line(pieces, &trusted);
                    lines.push(text.clone());
                    run.push(text);
                }
                Line::Block(index) => {
                    if !run.is_empty() {
                        parts.push(Part::Instruction(run.join("\n")));
                        run.clear();
                    }
                    let text = rendered.get(*index).cloned().unwrap_or_default();
                    lines.push(text.clone());
                    parts.push(Part::Data {
                        name: template
                            .inputs()
                            .get(*index)
                            .map(|i| i.name().to_owned())
                            .unwrap_or_default(),
                        text,
                    });
                }
            }
        }
        if !run.is_empty() {
            parts.push(Part::Instruction(run.join("\n")));
        }
        let text = lines.join("\n");

        let meant: Vec<Meant<'_>> = work
            .iter()
            .zip(&headers)
            .map(|(w, header)| Meant {
                name: w.spec.name(),
                header,
                text: &w.text,
            })
            .collect();
        verify::check(&template, &trusted, &meant, &text).map_err(AssemblyError::Containment)?;

        let sha256 = Sha256Digest::of(text.as_bytes());
        match self.redactor.contains_secret(text.as_bytes()) {
            Ok(false) => {}
            Ok(true) => return Err(AssemblyError::SecretInPrompt),
            Err(_) => {
                return Err(AssemblyError::RedactionFailed {
                    name: "prompt".to_owned(),
                });
            }
        }
        if text.len() > budget {
            return Err(AssemblyError::Containment("the prompt is over its budget"));
        }
        let context = ContextManifest {
            agent_id: manifest.id.to_string(),
            agent_version: manifest.version.to_string(),
            template: TemplateRecord {
                path: manifest.prompt.template_path.to_string(),
                version: manifest.prompt.template_version.to_string(),
                sha256: manifest.prompt.template_sha256.clone(),
            },
            prompt_sha256: sha256.clone(),
            prompt_bytes: text.len(),
            estimated_tokens: self.limits.estimate_tokens(text.len()),
            budget_bytes: budget,
            inputs: records,
            exclusions: Vec::new(),
            signals,
        };
        Ok(Assembled {
            text,
            parts,
            sha256,
            manifest: context,
        })
    }

    /// Cuts the inputs so that the prompt fits `budget` bytes and no block is over its limit. The
    /// room is shared out by `allowances`, and what is cut is recorded in `omitted`.
    fn fit(
        &self,
        template: &Template,
        trusted: &BTreeMap<String, String>,
        work: &mut [Work<'_>],
        budget: usize,
    ) -> Result<(), AssemblyError> {
        let mut fixed = template.lines().len().saturating_sub(1);
        for line in template.lines() {
            if let Line::Text(pieces) = line {
                fixed = fixed.saturating_add(instruction_line(pieces, trusted).len());
            }
        }
        let mut overheads: Vec<usize> = Vec::with_capacity(work.len());
        for w in work.iter() {
            let overhead = block::header_reserve(w.spec.name(), w.spec.class())
                .saturating_add(1)
                .saturating_add(block::closing_line(w.spec.name()).len());
            fixed = fixed.saturating_add(overhead);
            overheads.push(overhead);
        }
        let available = budget
            .checked_sub(fixed)
            .ok_or(AssemblyError::BudgetTooSmall {
                needed: fixed,
                available: budget,
            })?;
        let caps: Vec<usize> = work
            .iter()
            .zip(&overheads)
            .map(|(w, overhead)| {
                block::quoted_len(&w.text)
                    .min(self.limits.max_block_bytes.saturating_sub(*overhead))
            })
            .collect();
        for (w, allowance) in work.iter_mut().zip(allowances(&caps, available)) {
            if block::quoted_len(&w.text) > allowance {
                let kept = block::longest_prefix(&w.text, allowance).to_owned();
                w.omitted = w.text.len().saturating_sub(kept.len());
                w.text = kept;
            }
        }
        Ok(())
    }

    /// Makes the text of one input ready, or notes that it was not given.
    fn prepare<'i>(
        &self,
        spec: &'i InputSpec,
        given: Option<&'i Input>,
    ) -> Result<Work<'i>, AssemblyError> {
        let Some(input) = given else {
            if spec.required() {
                return Err(AssemblyError::MissingRequiredInput {
                    name: spec.name().to_owned(),
                });
            }
            return Ok(Work {
                spec,
                given: None,
                original_bytes: 0,
                original_sha256: Sha256Digest::of(b""),
                text: String::new(),
                stripped: 0,
                looks: Lookalikes::default(),
                omitted: 0,
                redacted: 0,
                hash_is_of_redacted_text: false,
            });
        };
        if input.class != spec.class() {
            return Err(AssemblyError::ClassMismatch {
                name: spec.name().to_owned(),
            });
        }
        let text = std::str::from_utf8(&input.bytes).map_err(|e| AssemblyError::InvalidUtf8 {
            name: spec.name().to_owned(),
            valid_up_to: e.valid_up_to(),
        })?;
        // Redact, then neutralize, then redact again. The first pass sees the text as it was
        // written, with any hidden characters that a secret was split by. The second sees the text
        // as the model will, in case removing a character joined the parts of a secret.
        let failed = || AssemblyError::RedactionFailed {
            name: spec.name().to_owned(),
        };
        let first = self.redactor.redact_str(text).map_err(|_| failed())?;
        let mut redacted = first.report.replacements();
        let neutral = neutralize(&first.output);
        let second = self
            .redactor
            .redact_str(&neutral.text)
            .map_err(|_| failed())?;
        redacted = redacted.saturating_add(second.report.replacements());
        let clean = second.output.into_owned();
        let looks = lookalikes(&clean);
        // A hash of text that held a secret would let anyone who can guess the rest of the text
        // check a guess at the secret. So when something was replaced, the hash is of the text
        // after the replacement, and the record says so.
        let original_sha256 = if redacted > 0 {
            Sha256Digest::of(clean.as_bytes())
        } else {
            Sha256Digest::of(&input.bytes)
        };
        Ok(Work {
            spec,
            given,
            original_bytes: input.bytes.len(),
            original_sha256,
            text: clean,
            stripped: neutral.stripped,
            looks,
            omitted: 0,
            redacted,
            hash_is_of_redacted_text: redacted > 0,
        })
    }
}

/// A name from outside, safe to put in an error message: escaped and cut.
fn shown(name: &str) -> String {
    name.chars().take(64).flat_map(char::escape_debug).collect()
}
