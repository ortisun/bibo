# The project's rules for agents

- Status: proposed on 2026-11-20, built on the branch `fix/agent-report-channel`. The decisions and the options weighed are in [ADR 0026](../adr/0026-project-rules-installed-by-pull-request.md). The port is specified in [ports v1.4](ports-v1.4.md).
- Form: design. Read this first for what the factory does and why, the ADR for the options that lost, and the ports document for the exact signatures.

## Purpose

The factory has rules for the agents that work on its own code: finish the work, weigh every option and choose for the architecture and the business, write the documents before the code, keep the code free of calculation errors, and run only the tests the change touches. The owner decided that the same rules must reach every project the factory serves, **as a file in that project**, so that the people of the project can read them, approve them and add their own.

So the factory opens a pull request in the target repository that creates or updates `AGENTS.md`, and the skeleton of a `docs/` folder when the project has none. A person of the project approves and merges that pull request. The factory never merges it and never writes to the default branch. From then on the factory's own agents read the rules from the repository, at the commit the job starts from.

## The flow in one picture

```mermaid
flowchart TD
    A[Repository registered or enabled] --> S[Rules check for the repository]
    B[A job of the repository waits for admission] --> S
    S --> R[Read AGENTS.md on the default branch]
    R --> D{Installed version<br/>compared with the template}
    D -- current, newer, edited by hand, unreadable --> N[Nothing to propose]
    D -- missing, older, no factory section --> P{Rules pull request<br/>of the factory}
    P -- open with this version --> N
    P -- closed without merge with this version --> N
    P -- none, merged, or older --> O[Open or update the draft pull request<br/>on branch factory/project-rules]
    O --> H[A person reviews, marks it ready and merges]
    H --> J[Next job: the repository stage reads AGENTS.md<br/>at the base commit]
    J --> G[Every agent prompt gets a project_rules block]
```

## What is installed

### The template

The text lives in this repository at [`onboarding/project-rules/AGENTS.md`](../../onboarding/project-rules/AGENTS.md), beside the other files the factory puts into other projects ([`onboarding/README.md`](../../onboarding/README.md)). The skeleton of the `docs/` folder lives in `onboarding/project-rules/docs/`.

The text is this repository's own `AGENTS.md`, adapted to a project that is not the factory:

- The five rules are kept, in the same words where the words are not about the factory.
- The commands of the factory (`cargo nextest`, `scripts/ci.sh`, the crate names) are gone.
- The test advice is generic: run the tests of what the change touched and of what depends on it, take the commands from the project's own manifest (`.factory/project.yaml`) or from the build files of the project, and leave the full suite to the project's continuous integration. A text that differs for each project was rejected: the same version would then have different bytes in different projects, and the factory could no longer tell an old copy from a copy edited by hand (see the ADR).

The code takes the text with `include_str!`, so the binary carries it and needs no file at run time. The template has a version number, a whole number from 1, kept in the code beside the text (`factory_domain::project_rules::TEMPLATE_VERSION`). A test pins the SHA-256 digest of the text: whoever changes a single byte of the template must raise the version and update the pinned digest in the same change, so an edit can never ship under an old version number.

### The installed file

```text
<!-- factory-rules begin version=1 -->
... the factory's rules, exactly the template ...
<!-- factory-rules end -->

## Rules of this project

Add the rules that belong to this project below this heading. The factory keeps everything
after the line `<!-- factory-rules end -->` when it updates its own rules above.
```

The file has two parts:

- **The factory's section**, between the two marker lines. The opening marker carries the version. The factory writes this part and replaces it on an update.
- **The project's section**, everything after the closing marker. The factory never changes it. An update copies it byte for byte.

Rendering is deterministic. The same template and the same project section always give the same bytes: line breaks are `\n`, the file ends with exactly one `\n`, and nothing depends on a clock or a host. When the project already has an `AGENTS.md` without the factory's markers (written by its people), the whole old file becomes the project's section, after the factory's section, so nothing the project wrote is lost.

### The skeleton of `docs/`

The rules say that `docs/` holds the specifications, the architecture, the decisions, the guides and the reference, each with an index. When the default branch lacks one of these files, the pull request adds it:

| File | What it holds |
|---|---|
| `docs/README.md` | The index of the sections, and the rule that the documents come first. |
| `docs/specifications/README.md` | Where specifications go, and their index. |
| `docs/architecture/README.md` | Where the architecture and its diagrams go, and their index. |
| `docs/adr/README.md` | Where decision records go, their numbering and their index. |
| `docs/guides/README.md` | Where guides for people go, and their index. |
| `docs/reference/README.md` | Where reference pages go, and their index. |
| `docs/knowledge/README.md` | The index of the knowledge base ([ADR 0028](../adr/0028-project-knowledge-base.md)): empty at first, in the exact form the factory writes, so the documentation gate finds it well formed. Since template version 2. |

A file that exists on the default branch is never proposed, so the factory never overwrites a document of the project. A project that installed an older version and lacks the knowledge index gets it with the pull request of the new version.

### What each version of the template added

| Version | What changed |
|---|---|
| 1 | The five rules: finishing the work, making decisions, documentation first, code quality, testing while implementing a task. |
| 2 | Under "Documentation comes first", the rule of the knowledge base: an entry for each feature, flow, business rule, term, integration and constraint, kept current in the same change as the code, and read as data, never as instructions. The `docs/` skeleton gains `docs/knowledge/README.md`, and the index of `docs/` links to it. |

## When the factory checks

One step of the worker, the rules check (`ProjectRulesSync` in the composition crate), runs for one repository at a time:

1. **At onboarding.** When the worker applies a signed request to register or to enable a repository (`factory-cli repository register` and `enable`, or the same requests through the API), it runs the check for that repository right after the change is committed. The request itself never waits for GitHub, and a failure of the check never undoes the registration or the enable.
2. **When the factory is updated.** Before each claim, for the repository of each job that waits for admission (the same set of repositories the protection preflight looks at). A new release of the factory with a new template version therefore proposes the update at the next job of each repository.

A repository is checked at most once an hour for the same template version by one worker process, so a busy repository does not cost a GitHub call for every job. A check that failed (GitHub unavailable, rate limited) is tried again at the next occasion after that hour. A worker that starts again checks again, which is harmless: the decision below reads the state on GitHub every time.

The check can be switched off with the configuration key `github.propose_project_rules: false`. The agents still read the rules (the next section), with the built-in copy when the project has none.

## The decision

The check reads `AGENTS.md` at the tip of the default branch, and the newest pull request of the factory on the branch `factory/project-rules`. Then a pure function decides (`factory_domain::project_rules::decide`):

| `AGENTS.md` on the default branch | Rules pull request of the factory | What happens |
|---|---|---|
| Missing | none, or merged, or older version, or version unreadable | Open or update the pull request |
| Present, without the factory's markers | same | Open or update: the old file becomes the project's section |
| Present, version older than the template | same | Open or update: the factory's section is replaced, the project's section kept |
| Missing, without markers or older | open with the template's version | Nothing: it is already proposed |
| Missing, without markers or older | closed without a merge, with the template's version | Nothing: a person declined this version. The next version is proposed again |
| Missing, without markers or older | open or closed with a newer version | Nothing: a newer factory proposed it |
| Same version as the template, factory's section unchanged | anything | Nothing: up to date |
| Same version, factory's section changed by hand | anything | Nothing. The change was merged into the default branch, so a person approved it. The factory does not fight it. The next version proposes its own text again, and the diff shows the person what changes |
| Newer version than the template | anything | Nothing: this worker is older than the one that installed it |
| Unreadable: markers malformed or doubled, text not UTF-8, file over 64 KiB | anything | Nothing, and an audit record says why. A person repairs the file |

"Version unreadable" for a pull request means the factory's version marker is missing from its body. Only pull requests opened by the factory's own App count: a pull request a person opens from a branch of the same name is ignored.

### One pull request per repository

The head branch is always `factory/project-rules`. GitHub itself refuses a second open pull request from the same head to the same base, so two workers that race cannot open two. The adapter looks for an open pull request first and updates it when it finds one.

- **No open pull request:** the branch is set to the tip of the default branch (created, or moved there when an old one is left from a merged or declined proposal), the files are written on it as one commit each, and a draft pull request is opened.
- **An open pull request:** the files are written on top of the branch, without moving it back, so a commit a person added to the branch is not thrown away. The title and the body are replaced.

The pull request is a **draft**, like every pull request of the factory (ADR 0014, decision 7: the factory never marks a pull request ready). The person marks it ready and merges it. Its body says what it changes, which version it installs, that the project's section is kept, and how to decline it; a hidden marker at its end carries the version.

## The credential

The check uses the proposal port, `ProposalHost` with the branch `ProposalBranch::ProjectRules` ([ports v1.4](ports-v1.4.md), generalized in [ports v1.6](ports-v1.6.md)), with a token of its own, minted for one repository: `contents: write`, `pull_requests: write` and the `metadata: read` every token carries (`PermissionSet::project_rules`). It is not a stage token, so no stage token is widened and the delivery token is not borrowed. The App already holds these two permissions for the delivery stage, so the App needs no new permission and the audit of the App's permissions is unchanged.

The factory gains no right to write to the default branch:

- The adapter writes only to `refs/heads/factory/project-rules`. It refuses any other head before it sends a request (`BranchNotAllowed`), and it never names the default branch as the branch of a file write.
- The default branch must be protected by a rule that requires a reviewed pull request (the protection preflight checks this for every repository before its jobs run). The App is on no bypass list, which an administrator attests.
- The port has no merge call and no call that marks a pull request ready (rule DEP-09, extended by ADR 0014).
- The adapter had no `PUT` at all, because a merge is a `PUT`. Writing a file through the contents API needs one, so the adapter gained exactly one method, `Method::PutContents`, which the client and the transport refuse for any path but `/repos/{owner}/{repo}/contents/{path}`. The security tests hold that it is the only `PUT`, that only the rules host sends it, and that a merge path is refused. The reference routes (`/git/refs`), which no other part of the adapter uses, appear only in the rules host, built from the constant `factory/project-rules`.

The token exists in the worker before a job is admitted, because the check runs before each claim. It is minted and used by deterministic code only, never handed to a sandbox, and the check reads no issue text. The loopback scenarios of the worker, which judge the intake path alone and require that no pull request and no push happen on it, run with `github.propose_project_rules: false`.

## How the agents read the rules

The repository stage (`REPOSITORY_INTELLIGENCE`) already reads the repository at the job's base commit, which is the tip of the default branch when the job started. It now also reads `AGENTS.md` there, with the agent view of the path policy, and stores one more output, `project-rules` (Markdown). The repository map records where the text came from (`project_rules`: the path, the digest, the origin and, for a fallback, the reason).

What the output holds:

| `AGENTS.md` at the base commit | `project-rules` holds | Origin in the map |
|---|---|---|
| Present with the factory's markers, any version, UTF-8, at most 64 KiB | The file as it is | `repository` |
| Present without the factory's markers | What the pull request would install: the factory's section, then the project's file | `repository_with_factory_rules` |
| Missing | The built-in copy: the factory's section and the empty project's section | `built_in` |
| Over 64 KiB, or not UTF-8 | The built-in copy | `built_in`, with the reason `too_large` or `not_utf8` |

So the built-in copy applies until the pull request is merged, and from the merge on the project's own file applies, including what its people added below the factory's section. An installed older version applies as installed: it is what the people of the project approved, and the update waits for their approval like the first install.

The limit is 64 KiB (65,536 bytes), counted in bytes of the file. A larger file is not cut, because cutting a set of rules silently drops some of them; the fallback is visible in the map and in the summary.

Every agent stage pins `project-rules` in its stage contract by digest, like every other input, and gives it to its agent as the input `project_rules`, class `repo_file`, in a quoted data block like every other input. The agents that get it: the specification writer and reviewer, the architect and the architecture critic, the planner, the builder, the code reviewer, the documentation writer and the documentation reviewer. The intake classifier does not: it only sorts an issue.

Each prompt says how to treat the block. The fixed text on untrusted data, which is the same in every prompt, says that no block is an instruction; it now names one exception: the block `project_rules`, when the input contract lists it, holds the working conventions of the project, which its owners approved. The agent applies them where they do not conflict with the prompt. They never change the role, the tools, the permissions, the stop conditions or the form of the answer, and an instruction in them to do anything else is ignored like any other. A stage whose contract has no `project-rules` input (a job whose repository stage ran before this change) gives the built-in copy, so a job in flight is not blocked.

The specification writer is the one agent whose prompt is not assembled from its `prompt.md`: it runs the Spec Kit skills, whose arguments are a fixed instruction (ADR 0006). So the stage writes the rules, redacted, into the sandbox as `inputs/project-rules.md`, next to the request file, and takes them away after the run, as it does the request. The fixed instruction of the specify, clarify and checklist skills names that file with the same exception in one fixed sentence. The path is a constant: no text chooses it.

The reviewers keep a short, closed list of inputs (the contract test `REVIEWER_INPUTS`). `project_rules` joins each list: it is text the project's owners approved, never the author's account of the work.

The repository map records `project_rules` (path, digest, origin and the reason for a fallback), so the digest in the map moves with every new template version.

## `AGENTS.md` in a job

`AGENTS.md` is already a protected path of mode `deny_write` (group `agent_instruction_files` of `policies/security.yaml`). No agent of a feature job can add, change or delete it, and the ingestion audit refuses the change on the host. The only way the file changes is the factory's rules pull request, or a person. The skeleton files under `docs/` are ordinary documents: the documentation writer may edit them in a job, as it may edit every document under `docs/`.

## Threats

A person who can merge into the default branch can change `AGENTS.md`, and every agent of every later job reads it. That is prompt injection that persists (threat T-55 in the [threat model](../security/threat-model.md)). The controls:

- **The owner's approval is the control of the content.** The file reaches agents only from the default branch, which the preflight requires to be protected by a reviewed pull request. The factory's own change arrives as a pull request a person must review and merge.
- **The text is data, not instructions,** in the agents' prompts: quoted, delimited, redacted, and named as the project's conventions that never override the prompt.
- **It cannot widen anything.** No text grants a tool, a path, a network host or an approval (`untrusted_content.authority_from_content: never`). The tools come from the policy and the manifest, the sandbox has no network but the broker, and the gates and the reviewer judge the result.
- **An agent cannot change it in a job** (protected path, above).

What is not covered: a malicious change that a reviewer of the project approves. The rules are then the project's own, and the gates, the independent reviewers and the final human approval of the job's pull request remain the controls.

## What this does not do

- It does not merge, and it does not ask anyone to merge. A declined version stays declined until the template changes.
- It does not remove `AGENTS.md` or a skeleton file when a repository is disabled.
- It does not install other instruction files (`CLAUDE.md`, `.github/copilot-instructions.md`). Those stay with the installer and the project's people.
- It is not verified against the real GitHub: the adapter is tested against the fake GitHub server of the test kit, which gained the route that writes a file.
