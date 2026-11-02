# 0018: Mirror the issue labels on a GitHub Projects board, adapt to a board that exists, and keep the engine away from it

- Status: Proposed. The product owner asked for a board on 2026-11-02 and asked that it adapt to projects that already have one. **Pending confirmation by the architect.** The policy, the mapper, the Action step and the installer step are built and tested against fakes. Nothing has run against a real board.
- Date: 2026-11-02
- Deciders: the product owner for the requirement. The engineer wrote the design and the code.
- Related: [ADR 0016](0016-design-phase-onboarding-and-issue-workflow.md), [the board policy](../../policies/project-board.yaml), [the issue workflow policy](../../policies/issue-workflow.yaml), [secrets and credentials](../security/secrets-and-credentials.md), [the board guide](../guides/project-board.md)

## Context and problem statement

[ADR 0016](0016-design-phase-onboarding-and-issue-workflow.md) tracks an issue with labels in two namespaces. Labels work in the issue list and in search, and a person cannot drag them. The product owner wants a GitHub Projects board as well, for the view that planning needs. A project that the factory is installed into may already have a board with its own columns and its own habits.

How does the board stay true to the labels, who writes it, and what does the installer do when a board is already there?

## What was checked

On 2026-11-02. "Verified" means read from the source named. "Unverified" means the source is silent or the behavior was not exercised.

**GitHub documentation** (pages on using the API to manage Projects, on automating Projects with Actions, and on the built-in automations). Verified:
- `GITHUB_TOKEN` "cannot access projects." The page recommends a GitHub App for organization projects, with read and write on organization projects, and a classic personal access token with the `project` and `repo` scopes for user projects.
- A project is read with `organization(login:) { projectV2(number:) }` or `user(login:) { projectV2(number:) }`. A single-select field exposes its options with their ids. `addProjectV2ItemById` returns the existing item when the issue is already on the board, and `updateProjectV2ItemFieldValue` sets the option. An item cannot be added and updated in one call.
- The built-in workflows are: item added sets Todo, closed and merged set Done, auto-add, auto-archive. They are set in the web page. The page lists **no workflow that sets a status from a label.**

**Unverified:** whether a GitHub App can reach a user-owned project (the page recommends a token for user projects and does not say an App cannot); what `updateProjectV2Field` does to the values of existing items when it replaces options (the page does not mention it); the API's rate limits for projects (the page does not mention them); whether a board view can be created through the API; the exact shape of `gh project field-list --format json` (the tests use the shape the command documents, written by hand).

**Tools.** Verified on this machine: `gh` 2.102.0 has `project list`, `field-list`, `field-create --single-select-options`, `link` and `create`. The action `actions/create-github-app-token` v3.3.0 (commit `64ab729a`) takes `client-id`, `private-key` and `permission-organization-projects`, and outputs `token`. Its `app-id` input is deprecated.

**This repository.** The engine's GitHub App holds no Projects permission, and its token for a stage is narrowed ([secrets and credentials](../security/secrets-and-credentials.md)).

**Prior art, read at README level:** *super-board* drives a Projects board as its state machine and repairs the columns it needs; *Fabro* and *Foreman* show progress in a board or in comments. None was read below the documents.

## Considered options

**A. Who writes the board**

1. **The engine, through its GitHub App.** Rejected. It needs a new App permission (organization projects, read and write) on the credential that already writes labels and pull requests. A user-owned board would need a classic token with the `repo` scope, which the factory must never hold. A fault in the engine would then reach every board.
2. **An operator command on demand.** Rejected as the main path: the board would be stale until someone ran it. It stays possible later as a repair tool.
3. **The built-in project workflows.** Rejected. They have no rule from a label to a status, and they are set only in the web page, so an installer cannot set them up.
4. **An Action in the project's own repository, with a credential its owner chooses.** Chosen. It already reacts to label changes. It runs the same code the labels run, in the same job, so the board is computed from the final labels.

**B. What to do with a board that already exists**

1. **Impose the factory's columns.** Rejected. It changes options that people use. The documentation is silent on what happens to items when options are replaced.
2. **Add a second field next to the existing one.** Possible, but it puts two overlapping columns on a board that people already read.
3. **Map the stages onto the options that are there, and change none.** Chosen. Each stage has names it is usually called, and fallbacks: a board with only Todo, In Progress and Done still shows every issue. The mapping is a file that a person reviews in a pull request. The factory creates a field of its own only on a board that it creates itself.

**C. How a stage is worked out**

1. **One column per label.** Rejected: fifteen columns, and two tracks at once.
2. **Nine stages and ordered rules over the labels and the state of the issue.** Chosen. The first rule that fits decides. The factory's state beats the design's, a closed issue is Done unless the factory stopped, and an issue on no track is left alone.

**D. Where the mapping lives**

1. **In the factory's database.** Rejected: the engine would need to know the board.
2. **In the project, as `.github/project-board.json`.** Chosen. It is reviewed with the rest of the install, and a person can edit it.

## Decision outcome

- **The labels are the truth and the board is a view.** A card that a person drags goes back to where the labels say at the next change. The board needs no new state.
- **Nine stages:** Idea, Designing, Design review, Ready, Working, Needs a person, In review, Done and Stopped. `policies/project-board.yaml` is the source. A check fails if a label of the issue workflow has no rule, if a stage has no rule, if a rule names the trigger label, or if a fallback loops. A checked JSON rendering feeds the installer and the Action.
- **The installer** (`scripts/install.sh`, step `project-board`) reads the board's single-select field, maps the stages and writes `.github/project-board.json`. It uses the board linked to the repository when there is exactly one, `--project OWNER/NUMBER` when told, and `--create-project OWNER` only when asked. It never regenerates or overwrites a mapping file that exists: it checks it against the board and reports a board that changed. It reports the credential by the **name** of a secret or variable, and never reads a value.
- **The Action** runs `project_board.py sync` after the label step. It reads the issue with the repository token, works out the stage and moves the card. It adds an issue to the board only when the issue is on a track.
- **The credential** belongs to the owner of the board and goes to the board step only. For an organization it is a GitHub App, and the step asks for a token that lives as long as the job and holds two permissions: organization projects (write) and issues (read). For a personal board it is a personal access token in a secret. With neither, the step warns and does nothing.
- **Additive only.** The code has no call that creates, renames, reorders or deletes an option or a field. A test searches the source for each such mutation.
- **Issue text is data.** Every value goes to GitHub as a GraphQL variable. The stage comes from label names and the issue state.

## Consequences

**Good.**
- The engine, its App and its tokens are untouched. A fault in the factory cannot write a board, and a stolen board credential cannot write code or labels.
- A board with few columns still works. A board with many columns gets one column per stage.
- Everything about the mapping is a reviewed file in the project.

**Costs.**
- **A personal board needs a classic token.** The `project` scope reaches every project of that person. Prefer an organization board with an App. This cost belongs to the owner and the installer says so.
- On a small board several stages share a column, so the column does not tell the design apart from the work. The label still does.
- The board lags the labels by the time of one Action run. A change that the Action itself makes to a label (a revert) does not start another run, so the same run moves the card from the final labels.
- A pull request is not a card. Only the issue is on the board.
- The credential check lists repository secrets by name. An organization-level secret is not visible there, so the installer reports a note and not a failure.
- A board view (columns by field) is made by a person in the web page. It is unverified that the API can do it.
- Real GitHub behavior, rate limits and the shape of `gh project field-list` are unverified.

## What is not built

- A run against a real board, organization or personal.
- A repair command that rebuilds the board from the labels.
- Pull requests as cards, and removing a card when an issue leaves every track.
- The engine does not know the board, on purpose.
