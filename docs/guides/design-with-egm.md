# Design a new solution before the factory builds it

- Status: written on 2026-11-02 from the Elephant-Goldfish Model (EGM) plugin version 0.1.0 (its skills and its Claude Code guide), the architecture decision record (ADR) [0016](../adr/0016-design-phase-onboarding-and-issue-workflow.md) and `policies/issue-workflow.yaml`. Nobody has yet taken an issue through the whole path on GitHub. The design gate at intake, the check that the text of a job is the text of its issue, and the second check right before the pull request is opened are built and tested against fakes only.
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

   Then ask a person who holds the approver designation for this repository to change the label to `design: approved`. The factory accepts the label only when such a person applied it ([what the factory refuses](#what-the-factory-refuses)). The Action removes the label if the issue names no such file on the default branch. It checks that the path has no symbolic link in it, and that the file exists. It does not check that the file belongs to this issue. The approval is the merge of the design pull request, so the owner of the repository should require reviewed pull requests on the default branch. Without that rule a merge is not an approval.

7. **Ask the factory.** A named requester applies `factory`. The factory reads the issue and its labels from GitHub again. If the issue is on the design track, it goes on only when the design is approved. The design is in the repository for every stage to read. The factory checks the approval a second time, right before it opens the draft pull request, so an approval that an approver takes back while the job runs stops the pull request ([what the factory refuses](#what-the-factory-refuses)).

## The labels

Each issue is meant to carry at most one `design:` label and at most one `factory:` label. The trigger label `factory` is separate. The Action enforces this each time a label changes, by checking the whole issue and not only the label that changed. GitHub can skip a run when several labels change at once, so a wrong label can show for a moment, until the next change. It does not stay.

| Label | Written by | Meaning |
|---|---|---|
| `design: proposed` | The form | A new solution was proposed. Nobody has worked out the design yet. |
| `design: in progress` | A person | A person and EGM are working out requirements and trade-offs. |
| `design: in review` | A person | The design is in review: fresh reviewers and a design pull request. |
| `design: approved` | A person who holds the approver designation | The design pull request was merged, and the issue names the document. The factory accepts this label only from an approver. |
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

Moves that are allowed in the design track: `proposed` to `in progress`, `in progress` to `in review`, `in review` to `in progress` (changes were asked for) or to `approved`, and `approved` to `in progress` (the design was reopened). A design starts as `proposed` or `in progress`. Anything else is removed, with a comment that says why. Removing a `design:` label does **not** take the issue off the track: the factory reads the events of the issue, and an issue that was ever given a `design:` label needs `design: approved` from an approver, like any issue on the track. An issue that was never given a `design:` label is a small change by definition and is not on the track.

**What the factory writes today.** The factory writes the `factory:` label itself. When a job changes state, the worker puts the one label for that state on the issue and takes any other `factory:` label off it. It also keeps one status comment up to date, and edits that comment in place. It uses a token of its own that can write issues in that one repository and nothing else. A failed write never stops or fails a job. If GitHub is slow or refuses, the worker tries again later, records the failure, and the job goes on.

Five things are worth knowing.

- A job gets a status only after the factory has accepted the issue. That is when the intake stage has passed, because intake is where the label and the person who applied it are checked against GitHub. A job submitted through the API for an issue that nobody labelled gets nothing, whatever the issue number is.
- A job therefore starts at `factory: working` and never shows `factory: queued`.
- An issue that the factory refused at the start gets no status label. The reply that explains the refusal is still posted.
- A job that passed the checks of the intake stage and is then blocked because the place where the factory runs its tools is not available (the container image or the container service is missing) gets one fixed comment that says so, from the intake stage itself (LB-02). It holds nothing from the error. It does **not** get the `factory: blocked` label: the label and the status comment are written only after the intake stage has passed, and a stage that is blocked has not. Once an operator repairs the environment and unblocks the job, intake passes and the label follows.
- An operator can switch the writing off with the key `github.write_issue_status`. Nothing else changes when it is off. The worker also writes nothing, starts anyway, and reports a degraded health line when `policies/issue-workflow.yaml` is missing or broken, or when the row `write_status_label` of the approval policy no longer lets it write.
- The worker makes at most six updates a minute and 120 an hour. When GitHub asks it to wait, it waits at least that long before the next try. It writes the end state of a job a second time after two minutes, to put it right if a second worker's older write landed late.

**Tested against fakes only.** The writing is built and tested against a fake GitHub server. Nobody has run it against the real GitHub, so treat the first runs as a trial and check the labels yourself. The design gate is built the same way and has the same limit. It ran against fakes of GitHub and of the allowlist, never against the real GitHub.

## What the factory refuses

When a requester applies `factory`, the intake stage reads the issue and its labels from GitHub again. It does not use the labels that the webhook carried, so a label removed or added after the webhook changes the result. Then it applies these rules.

| The issue has | The factory |
|---|---|
| No label that starts with `design:`, and none was ever applied | Goes on. This is the path for a small, clear change. |
| No design label now, but one was applied earlier and taken off | Refuses. The issue stays on the design track. Ask an approver to apply `design: approved`. |
| `design: approved` as its only design label, applied by a person who holds the approver designation | Goes on. |
| A design label and no `design: approved` | Refuses. The design is not approved yet. |
| `design: approved` together with another design label | Refuses. The state of the design is not clear. Remove the label that is out of date. |
| `design: approved`, applied by someone who does not hold the approver designation | Refuses. Ask an approver to apply the label. |
| Any of the above, but the text of the job is not the title and the body of the issue as they are now | Refuses, whether or not the issue is on the design track. The factory acts only on the words of the issue. |
| The design was approved when the job started, and it is not approved when the factory is about to open the pull request | Stops before it pushes or opens anything. The job shows as blocked. |

Seven details matter.

- **Who counts as an approver.** A person holds the designation by being named on the factory's allowlist, by numeric GitHub user ID. An entry that is narrowed to other repositories does not count here. A GitHub role such as admin or triage grants nothing. The account that applied the label must be a person's account: a bot or an organization is refused, even if its numeric ID is on the list. The key `intake_requirements.design_approved_by` in `policies/issue-workflow.yaml` names the designation. Its value, `approver`, is the engineer's default and is pending confirmation by the architect.
- **What counts as a design label.** Any label that reads as `design:` at the start, in any letter case, with or without the space after the colon. So `design:approved` and `Design: approved` are design labels, and neither one approves anything. So is a label with a zero-width or right-to-left character in front, a full-width colon, or a look-alike letter such as a Cyrillic `е` in the first seven characters. A label that starts with an emoji or an arrow and then `design:` counts too. A label in another language, such as `não-urgente`, does not. The label that approves is spelled exactly `design: approved`, with no hidden or look-alike character.
- **What the requester sees.** One comment on the issue. It says that the design is not approved yet, or that the approval came from someone the factory does not accept approvals from, and it says what to do. The job shows as blocked and no agent reads the issue. Nobody can override the refusal. The way through is the label `design: approved`, applied by an approver. After an approver has applied it, remove the `factory` label and apply it again. The factory posts at most five of these replies on one issue in 24 hours (the keys `design_reply_cap_per_issue` and `design_reply_window_hours` of `policies/issue-workflow.yaml`). After that it posts nothing more on the issue and writes an audit record instead: the block, the label and the record are not affected. It also posts nothing when the issue has more comments in the last day than one page of GitHub's answer holds, because it could not tell whether it had already replied. A comment that cannot be posted because GitHub is down is tried again by the next attempt of the stage. If GitHub stays down through the last attempt, the job is blocked with its audit record and without the comment, and not failed (DG-9).
- **The events are read to the end.** The factory reads who applied the label, and which labels the issue ever had, from the events of the issue. It reads up to 3000 events. If the list is longer or cannot be read, the attempt fails and is tried again. It never guesses from the part it read, and it never passes. An honest approval on an issue with more events than that waits until the thread is shorter or the work goes into a new issue.
- **When the factory cannot judge.** If it cannot read `policies/issue-workflow.yaml`, it refuses every issue, with or without a design label, and says in a comment that it could not check. It does not guess and it has no default. The worker prints `NOT READY: design gate` when it starts, and each refusal is logged and audited. Repair the file and the next attempt works, with no restart.
- **The text must be the issue's text.** The factory acts only on the title and the body of the issue, as GitHub shows them now. A job that a webhook makes takes its text from the issue, so it always matches. A job that you make with `POST /v1/jobs` or `factory-cli submit` carries the words you typed. Those words must be the issue's words: the title, a blank line and the body. The factory ignores only two things: the style of the line ends, and white space around the whole text. Any other difference refuses the job. A note added at the end counts as a difference, and so does one changed word or one different letter case. The comment says where the note belongs. Put notes in the body of the issue, then apply `factory` again. The factory keeps no separate note beside the issue. The check runs for every job, on or off the design track, so the labels that the factory reads belong to the issue the words came from. If somebody edits the issue after the job was made, the next attempt of that job is refused. Apply `factory` again, and the factory reads the new words. The audit record of the design gate ends with `text of the job compared with the live issue: same` or `different`. The refusal has its own reason word, `text_not_the_issue`. It has the same block code as the other refusals, so nobody can override it.
- **The design is checked twice.** Right before it opens the draft pull request, the factory reads the labels and the events of the issue again. It uses the same code as intake. Suppose the issue is on the design track, and `design: approved` is not its one design label, applied by an approver. Then the factory pushes nothing and opens nothing. It writes the reason in the audit record and posts one comment that says no pull request was opened. The job shows as blocked: the status label becomes `factory: blocked`, and the status comment says the work stopped while the pull request was being prepared. Nobody can override this block. To go on, an approver puts `design: approved` back as the one design label. Then an operator unblocks the job, or you apply `factory` again for a new job. Suppose GitHub cannot be read at that moment. The factory does not guess. The attempt fails and nothing is opened. The audit record says the check could not be made, which is a degraded condition, and the engine tries again. If the retries run out, the job fails and its label becomes `factory: failed`. Suppose the rule or the allowlist cannot be read. Then the job is blocked, and a comment says the factory could not check again.

The Action still posts a comment when `factory` lands on an issue whose design is not approved. That comment is now an early warning. The engine is the control, and it holds even if the Action is off, late or skipped.

## Rules that keep this safe

- The `factory` label is never applied by a form, an Action or an agent. A person on the requester list applies it, and the factory checks that person by numeric user ID. A label alone never authorizes work.
- The label `design: approved` is a decision of a person, and the factory checks which person. GitHub lets anyone with triage rights apply it, and the Action only checks that a design document exists. The factory accepts the label only from a person who holds the approver designation.
- Only the factory sets a `factory:` label. If you set one by hand, the Action removes it at the next label change on that issue. To tell who set a label, it reads the issue events, and it trusts only the App whose login is in the repository variable `FACTORY_BOT_LOGIN`. Until that variable is set, it removes every `factory:` label, the factory's own included. The factory itself never writes the `factory` label or a `design:` label.
- Issue text and repository text are data. The Elephant can be steered by what it reads, so read the design before you merge it, and keep the GitHub token limited to this one repository.
- The design lives in the repository, in a pull request that a person approved. The factory never merges it for you.

## Where to read more

- [Onboarding guide](onboarding.md): install the tools and map the project first.
- [ADR 0016](../adr/0016-design-phase-onboarding-and-issue-workflow.md): why it works this way.
- [The issue workflow policy](../../policies/issue-workflow.yaml): the source of the labels and the moves.
- EGM's own guide, in the plugin folder under `docs/getting_started.md`, covers the skills in more detail.
