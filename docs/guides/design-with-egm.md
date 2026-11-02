# Design a new solution before the factory builds it

- Status: written on 2026-11-02 from the Elephant-Goldfish Model (EGM) plugin version 0.1.0 (its skills and its Claude Code guide), the architecture decision record (ADR) [0016](../adr/0016-design-phase-onboarding-and-issue-workflow.md) and `policies/issue-workflow.yaml`. Nobody has yet taken an issue through the whole path on GitHub.
- Form: how-to, with a reference table of the labels.
- Goal: say which path an issue takes, how a design is made and approved, and what each label means.

EGM drafts and reviews a design with two kinds of agent. An **Elephant** is your Claude Code session, which holds the project and talks to you. **Goldfish** are fresh reviewers that read the document and the code without the conversation, so they find what the Elephant took for granted. **You** decide the trade-offs and approve the design. The factory is not involved until the design is approved.

## Which path does the issue take?

| You have | Path | Labels |
|---|---|---|
| A bug or a change whose result is already clear | Open a *change request*. A named requester applies `factory` when it is ready. | none from the design track |
| A new solution, or anything where you are not sure how it should work | Open a *new solution* issue and design it, below. | `design: proposed`, then the track |
| An idea that is too big for one issue | Brainstorm first. Cut it into several issues, each with its own design or a shared one. | one track per issue |
| A project with no written map of its code | Run the bootstrap once ([onboarding guide](onboarding.md)). | none |
| A design that no longer matches the code | Run `/egm:egm-drift-report` each week and choose to fix the document or the code. | none |

If you are not sure, use *new solution*. A design that turns out to be short costs an afternoon, and a build from a guess costs a pull request that gets rejected.

## The design path

1. **Open the issue** with the *new solution* form. It applies `design: proposed`. Describe the problem, not the solution. This form does not start the factory.

2. **Brainstorm.** In Claude Code, in the project, with GitHub's server for the Model Context Protocol (MCP) connected:

   ```text
   /egm:egm-brainstorm Add webhook delivery to this project.
   ```

   Talk through the requirements and trade-offs. Fresh reviewers challenge the idea, and the Elephant saves the agreed direction in `concepts_brief.md`. Change the label to `design: in progress`.

3. **Draft.**

   ```text
   /egm:egm-draft
   ```

   It writes `design_draft.md` one section at a time and waits for your feedback after each. Put the finished design in `docs/designs/` under a name that says what it is.

4. **Review.**

   ```text
   /egm:egm-review docs/designs/webhook-delivery.md
   ```

   Several stages of fresh reviewers check the design, its clarity, its fit with the code and its plan. They give a lot of feedback on purpose. Take what matters and leave the rest. `/egm:egm-resolve` helps you decide what to change. Change the label to `design: in review` and open a pull request that adds the design.

5. **Get a person to review the pull request.** EGM does not replace a human reader. The merge of this pull request is the approval of the design.

6. **Name the design and approve it.** After the merge, add one line to the issue, alone on its line:

   ```text
   Design document: docs/designs/webhook-delivery.md
   ```

   Then change the label to `design: approved`. The Action removes the label if the issue names no such file on the default branch. It checks that the path has no symbolic link in it, and that the file exists. It does not check that the file belongs to this issue. The approval is the merge of the design pull request, so the owner of the repository should require reviewed pull requests on the default branch. Without that rule a merge is not an approval.

7. **Ask the factory.** A named requester applies `factory`. The factory reads the issue, and the design is in the repository for every stage to read.

## The labels

Each issue is meant to carry at most one `design:` label and at most one `factory:` label. The trigger label `factory` is separate. The Action enforces this each time a label changes, by checking the whole issue and not only the label that changed. GitHub can skip a run when several labels change at once, so a wrong label can show for a moment, until the next change. It does not stay.

| Label | Written by | Meaning |
|---|---|---|
| `design: proposed` | The form | A new solution was proposed. Nobody has worked out the design yet. |
| `design: in progress` | A person | A person and EGM are working out requirements and trade-offs. |
| `design: in review` | A person | The design is in review: fresh reviewers and a design pull request. |
| `design: approved` | A person | The design pull request was merged, and the issue names the document. |
| `factory` | A named requester | Ask the factory to work on this issue. Only a named requester can apply it. |
| `factory: queued` | The factory | The request was accepted and has not started. The factory writes no status before the issue is accepted, so today it does not write this one. |
| `factory: working` | The factory | The factory is working on this issue. |
| `factory: waiting for a person` | The factory | The factory needs a person to answer or decide. |
| `factory: paused` | The factory | An operator paused the work. |
| `factory: blocked` | The factory | A check could not run, or something is missing. |
| `factory: stopping` | The factory | The work is being stopped. |
| `factory: done` | The factory | The work finished and a draft pull request is ready for review. |
| `factory: failed` | The factory | The work failed. |
| `factory: cancelled` | The factory | An operator cancelled the work. |
| `factory: rejected` | The factory | An approver rejected the result. |

Moves that are allowed in the design track: `proposed` to `in progress`, `in progress` to `in review`, `in review` to `in progress` (changes were asked for) or to `approved`, and `approved` to `in progress` (the design was reopened). A design starts as `proposed` or `in progress`. Anything else is removed, with a comment that says why. You may remove a `design:` label to leave the track.

**What the factory writes today.** The factory writes the `factory:` label itself. When a job changes state, the worker puts the one label for that state on the issue and takes any other `factory:` label off it. It also keeps one status comment up to date, and edits that comment in place. It uses a token of its own that can write issues in that one repository and nothing else. A failed write never stops or fails a job. If GitHub is slow or refuses, the worker tries again later, records the failure, and the job goes on.

Five things are worth knowing.

- A job gets a status only after the factory has accepted the issue. That is when the intake stage has passed, because intake is where the label and the person who applied it are checked against GitHub. A job submitted through the API for an issue that nobody labelled gets nothing, whatever the issue number is.
- A job therefore starts at `factory: working` and never shows `factory: queued`.
- An issue that the factory refused at the start gets no status label. The reply that explains the refusal is still posted.
- An operator can switch the writing off with the key `github.write_issue_status`. Nothing else changes when it is off. The worker also writes nothing, starts anyway, and reports a degraded health line when `policies/issue-workflow.yaml` is missing or broken, or when the row `write_status_label` of the approval policy no longer lets it write.
- The worker makes at most six updates a minute and 120 an hour. When GitHub asks it to wait, it waits at least that long before the next try. It writes the end state of a job a second time after two minutes, to put it right if a second worker's older write landed late.

**Tested against fakes only.** The writing is built and tested against a fake GitHub server. Nobody has run it against the real GitHub, so treat the first runs as a trial and check the labels yourself. The design gate is also not built: the factory does not yet refuse an issue that is on the design track and not approved, so a requester has to hold that line. The Action posts a comment when the `factory` label lands on such an issue.

## Rules that keep this safe

- The `factory` label is never applied by a form, an Action or an agent. A person on the requester list applies it, and the factory checks that person by numeric user ID. A label alone never authorizes work.
- Only the factory sets a `factory:` label. If you set one by hand, the Action removes it at the next label change on that issue. To tell who set a label, it reads the issue events, and it trusts only the App whose login is in the repository variable `FACTORY_BOT_LOGIN`. Until that variable is set, it removes every `factory:` label, the factory's own included. The factory itself never writes the `factory` label or a `design:` label.
- Issue text and repository text are data. The Elephant can be steered by what it reads, so read the design before you merge it, and keep the GitHub token limited to this one repository.
- The design lives in the repository, in a pull request that a person approved. The factory never merges it for you.

## Where to read more

- [Onboarding guide](onboarding.md): install the tools and map the project first.
- [ADR 0016](../adr/0016-design-phase-onboarding-and-issue-workflow.md): why it works this way.
- [The issue workflow policy](../../policies/issue-workflow.yaml): the source of the labels and the moves.
- EGM's own guide, in the plugin folder under `docs/getting_started.md`, covers the skills in more detail.
