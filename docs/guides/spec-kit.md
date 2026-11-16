# How the factory uses GitHub Spec Kit

- Status: written on 2026-10-29 from the adapter (`crates/spec_adapter`), the specification stage (`crates/workflow/src/stages/specification`), the architecture decision record (ADR) [0006](../adr/0006-spec-kit-boundary.md), the [integration guide](../spec-kit/integration-guide.md) and the files under `.specify/`. Where those sources disagree, this page lists the disagreement as an open question and does not pick a side.
- Form: explanation, with a short how-to for the repository owner.
- Goal: say which parts of Spec Kit the factory uses, which it refuses, how the line is held, and what is still unproven.

## What Spec Kit is, and the one job it has here

Spec Kit is a set of agent skills. A skill is a prompt file that a coding agent reads and follows. The `specify` program installs the files and has no command that writes a specification. A coding agent writes it.

The factory uses Spec Kit for the specification stage and nothing else. The master prompt makes it the only framework for requirements, and it forbids using it as an execution engine, a scheduler, a planner, an implementer or a merge mechanism. The factory's own workflow engine, planner and builder do those jobs.

## What is allowed and what is not

Spec Kit 1.1.2 installs ten skills. The factory uses three of them in Slice 1, treats a fourth as the repository's own business, and refuses the other six.

| Skill | Slice 1 | Why |
|---|---|---|
| `constitution` | A precondition of the repository. The factory checks that it exists and never runs the skill. | The constitution belongs to the repository and is approved apart from any feature request. No agent manifest grants this skill. |
| `specify` | Used | Writes `spec.md` from the request. |
| `clarify` | Used when the ambiguity is material | Asks questions. The stage puts them to a person and stops after `stages.max_clarification_rounds` rounds. The default is 2. |
| `checklist` | Used | Writes a checklist for the reviewer. Its ticks count for nothing. |
| `plan`, `tasks`, `analyze`, `implement`, `converge` | Never | The factory's architecture and planning stages own these jobs. `analyze` also needs a plan and tasks, so it cannot judge a specification alone. |
| `taskstoissues` | Never | It breaks the plain-English title policy and has side effects outside the repository. |

`specify workflow run`, the bundled "Full SDD Cycle", is never called. The adapter never calls the networked commands `self`, `extension`, `preset add` or `bundle` either.

## How the line is held

Four controls hold it, and none depends on the agent behaving.

1. **The type.** The adapter's operation type has four variants: `Constitution`, `Specify`, `Clarify` and `Checklist`. A test asserts that no builder can produce another skill. The list in the contract is closed.
2. **The manifest.** The specification writer agent (`agents/specification-writer/manifest.json`) is granted `speckit.specify`, `speckit.clarify` and `speckit.checklist`. The policy lists the denied skills too, in every spelling of their ids.
3. **The post-conditions.** After every skill the host checks seven things and ignores what the agent says about its own work: a normal exit, `specify integration status --json` still `ok`, changes only under the allowed paths, a valid `.specify/feature.json` that points at a directory with `spec.md`, no template placeholder left, no `plan.md`, `tasks.md`, `research.md`, `data-model.md` or `contracts/`, and checklist files that are present and not self-ticked. A forbidden skill, file or denied call makes the stage run BLOCKED. Nobody is asked to override it.
4. **The wall.** Only the `spec_adapter` crate knows the Spec Kit file layout and the markers. A check fails the build if `.specify` or `speckit` appears in another crate.

## How a request reaches a skill

Issue text is untrusted data. Spec Kit treats the text after a skill name as the user's own instruction, so the factory never puts the request there. The adapter writes the normalized request to a file in the workspace, `inputs/request.md`, and passes a fixed instruction that names the file and says its content is source material. The instruction is built from a closed template and two validated paths.

The stage proves what reached the arguments on the invocation itself, not on what the skill wrote. Each skill run reports the invocation the provider sent, and the gate `stage_profile_check` reads the run's own transcript: it must show that skill invoked exactly once, with the fixed instruction as its arguments (whitespace squashed), and no other Spec Kit invocation. Anything else is `skill_arguments_leak` (condition `skill-arguments-fixed`), and so is a run whose transcript is missing or shows no invocation, because then nothing proves what the skill was given. The `**Input**:` line of `spec.md` is not compared any more. It is model output: on the real run of 2026-11-15 the model read the request file and wrote a faithful summary of it there, which says nothing about the arguments either way.

Claude Code 2.1.325 records a typed command in its stream only when the prompt is sent as a stream-json message with `--input-format=stream-json --replay-user-messages`: the replayed `user` event holds `<command-name>/speckit-specify</command-name>` and `<command-args>…</command-args>`. With the prompt on plain standard input, as the runtime sends it today, the stream holds no event for the prompt, so the check fails closed until the runtime sends the specification prompt that way. A `Skill` tool call by the model is an `assistant` event with `{"skill", "args"}` and counts as an invocation too. Codex has not been checked and fails closed the same way. Trimmed real transcripts are in `crates/workflow/tests/fixtures/transcripts`.

The skill runs inside a sandbox container. The host audits the tree when the sandbox is gone, commits only what the workspace ingestion returned, reads the files back, and hands the exact bytes to the provider. The provider builds a typed `SpecificationContract` that every later stage reads. No later stage reads Spec Kit files.

## What the contract holds

Spec Kit supplies requirements (`FR-nnn`), stories with priorities, scenarios, success criteria (`SC-nnn`), edge cases, key entities, assumptions, clarification decisions and `[NEEDS CLARIFICATION]` markers. It does not supply an identifier, a version, a commit, hashes, risks, constraints or an out-of-scope list. The factory adds those. A structure the parser does not recognize is `SPEC_PARSE_ERROR`. The parser never guesses.

Spec Kit's own ticks in `checklists/requirements.md` are self-assessed by the author. They count as no evidence. Every checklist item becomes an open question until an independent reviewer verified it or a person waived it with a reason. The engine records that decision in the ledger.

## The flow in the stage

1. The stage checks that the repository has a filled constitution. If it has none, the stage asks a person and sets the reason `constitution-required`.
2. `specify`, then `clarify` when needed, then `checklist` run, each in its own sandbox over the commit of the one before.
3. A deterministic gate of the factory's own runs its rules. An independent reviewer returns a verdict.
4. The first attempt that passes every rule keeps its draft and asks a person (`specification-approval-needed`). The next attempt reads the approval the engine recorded for that draft and freezes exactly that draft.
5. A frozen specification is never edited. A revision is a new feature directory, seeded from the old one, linked to it and numbered one higher.

The [walkthrough](../walkthroughs/test-mode-run.md) shows step 4 in a recorded run.

## What a repository owner does

Before the first job, the repository needs these files, committed on the protected branch:

- `.specify/` from `specify init --integration claude`, at the pinned version 1.1.2, with the Codex integration added by `specify integration install codex` so that the project works with either tool. The files `.specify/init-options.json` and `.specify/integration.json` must record that version, and `.specify/extensions.yml` must not exist. `scripts/install.sh --checkout PATH` adds whichever of the two is missing to a project that already has `.specify/`; it never runs `init` and never uses `--force`. The Codex skills live in `.agents/skills`, so the project's `.gitignore` must not ignore `.agents/skills/speckit-*` (the installer reports it if it does).
- `.specify/memory/constitution.md`, filled in. A placeholder fails the check.

The adapter never runs `init` on a repository that already has `.specify/`. ADR 0006 lets the control plane run the pinned `specify init` when `.specify/` is missing and policy authorizes it, and commit the files on the job branch for a person to read. Nobody has confirmed that step for Slice 1, so the repository owner does it by hand.

## What is proven and what is not

| Claim | State |
|---|---|
| The adapter, the parser, the seven post-conditions, the closed operation type and the integrity check exist with tests. | Built. |
| The specification stage runs with the real Spec Kit provider over the real files of this repository's Spec Kit install, in the full test-mode run. | Shown in `apps/api/tests/full_run.rs`. |
| In that run the skills are a script. A playbook runtime writes the files an agent would write: `spec.md`, the checklists and `.specify/feature.json`. | Scripted and labelled. |
| A real agent (Claude Code or Codex) runs a skill in the hardened sandbox, behind the model broker. | Never run. The Spec Kit specialist ran headless Claude Code on a host with command allowlists, for the constitution, `specify`, `clarify` and `checklist`, and Codex for `specify` only. |
| Hostile text in a request cannot launch a forbidden skill. | Tested at the adapter and prompt level. Not tested with a real model. |

## Open questions

These come from places where the sources disagree or say "unverified". Nobody has settled them.

1. **Who writes the constitution?** The master prompt says the specification stage should "establish or consult" a constitution. The [integration guide](../spec-kit/integration-guide.md) says to use the `constitution` skill once for each repository, with a person's approval, and ADR 0006 lists `Constitution` among four operations. The stage and the writer manifest treat it as a precondition and run no constitution skill. The worker README leaves this to the lead and the architect.
2. **Where do the skills run?** ADR 0006 says inside the `agent` sandbox profile, and marks that as unverified. The integration guide verified headless runs on the host. No run inside the sandbox exists.
3. **How does `checklist` run without `plan.md`?** The skill's setup script exits with an error when `plan.md` is missing, and the post-conditions forbid a `plan.md`. ADR 0006 lists three workarounds, all unverified. The recorded playbook shows a checklist output, but a scripted one.
4. **How is a specification revised?** Spec Kit has no in-place revision. ADR 0006 proposes a new feature directory seeded by the host, and calls it a proposal that needs a spike. The spike did not run with a real agent.
5. **Does `specify` honour an explicit feature directory** that the factory sets with `SPECIFY_FEATURE_DIRECTORY`, and do concurrent runs in separate worktrees stay apart? The integration guide lists both as unverified.
6. **The protected-path rule and `.specify/feature.json`.** The security policy protects `.specify/**`, and the specify skill must write `.specify/feature.json`. The composition code lifts the writes the policy lists for the specification stage only (`specification_path_rules`). The security owner has not confirmed that this is the intended way.
7. **The skill ids on other hosts.** `/speckit-specify` is the form on Claude Code and `$speckit-specify` on Codex, with the separator read from `.specify/integration.json`. The master prompt writes `/speckit.specify`. The repository records both the `claude` and the `codex` integration (since 2026-11-03), with `-` as the separator for both, and the worker pins the skills of both.

## Where to read more

- [Integration guide](../spec-kit/integration-guide.md): what the installed version does, with the commands run and the evidence tags.
- [Worked example](../spec-kit/worked-example.md): one specification from request to frozen contract.
- [ADR 0006](../adr/0006-spec-kit-boundary.md): the decision and its consequences.
- `crates/spec_adapter/src/lib.rs`: the map of the adapter and the rules it keeps.
