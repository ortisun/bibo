# Show the issue workflow on a GitHub Projects board

- Status: written on 2026-11-02 from `scripts/lib/project_board.py`, `scripts/install.sh`, `policies/project-board.yaml`, the architecture decision record (ADR) [0018](../adr/0018-project-board-mirror-that-adapts.md) and the GitHub documentation on Projects. It was tested against fake `gh` programs only. It has not touched a real board.
- Form: how-to, with a reference table of the stages.
- Goal: put the issues of a project on a board that follows their labels, whether the project already has a board or not.

The labels are the truth. The board is a view of them. If you drag a card, the next label change puts it back where the labels say it belongs.

## What you see

A card has one of nine stages. The stage comes from the labels of the [issue workflow](design-with-egm.md) and from whether the issue is closed. The first row that fits decides.

| Stage | When the issue has | Meaning |
|---|---|---|
| Stopped | `factory: failed`, `factory: cancelled` or `factory: rejected` | The work failed, was cancelled or was rejected. A person decides what next. |
| Done | the issue is closed and has a label of this workflow | The issue is closed. |
| Needs a person | `factory: waiting for a person`, `factory: blocked` or `factory: paused` | The factory waits for a person, or something is blocked. |
| In review | `factory: done` | The factory finished and a draft pull request waits for a person. |
| Working | `factory: queued`, `factory: working` or `factory: stopping` | The factory has the request. |
| Ready | `design: approved` | The design is approved. |
| Design review | `design: in review` | The design is in review. |
| Designing | `design: in progress` | A person and the Elephant-Goldfish Model (EGM) are working out the design. |
| Idea | `design: proposed` | Someone proposed a new solution. |

An issue with none of these labels is on no track, and the board leaves it alone. Closing an issue does not put it on a track: a closed issue with none of these labels stays off the board. The `factory` label by itself does not move a card.

## Who can move a card

A card moves only when the factory's App caused the event, or a person with triage rights or higher on the repository did. The App is the account named in the repository variable `FACTORY_BOT_LOGIN`. While the variable is unset, the board steps of the Action do not run at all. In a public repository anybody can open an issue, close their own, or pick a form that adds a label. None of that is an event the board listens to. The cost is that an issue opened by an outside person with the new-solution form shows on the board only after a person with triage rights touches it. The check calls GitHub for the role of the person, and if the call fails, the card does not move.

## Whose board

The board must belong to the owner of the repository, or to an owner that the repository lists in the variable `FACTORY_BOARD_OWNERS` (a comma-separated list). Without this rule, whoever could change `.github/project-board.json` could point the credential at any project it can reach. The installer tells you to set the variable when the board belongs to somebody else.

## If the project already has a board

The installer adapts to it. It reads the options of the field that holds your columns (`Status` unless you say otherwise) and matches each stage to the option people usually call it, ignoring case, punctuation and emoji. When your board has no option for a stage, the card goes to the closest one that exists.

| Your board has | Idea | Designing | Ready | Working | In review | Done |
|---|---|---|---|---|---|---|
| Backlog, Design, Ready, In progress, In review, Done | Backlog | Design | Ready | In progress | In review | Done |
| Todo, In Progress, Done | Todo | In Progress | Todo | In Progress | In Progress | Done |

It writes the result to `.github/project-board.json` and **changes nothing on the board**. It never creates, renames, reorders or deletes an option of a field that exists. Read the file in the pull request and edit it if you want a stage somewhere else. A stage set to `null` leaves the card where it is.

If you run the installer again, it does not rewrite your file. It checks the file against the board and tells you when an option it names is gone.

## If it has no board

The installer can make one. It creates the project, links it to the repository and adds a **new** field called `Stage` with the nine stages. It does not touch the `Status` field that GitHub puts on a new project. Use `--create-project` with the owner:

```bash no-run reason="it creates a project on GitHub, and the owner and repository are placeholders"
scripts/install.sh --checkout ../my-project --repo my-org/my-project --create-project my-org
```

A board view is made in the web page. Open the project, add a view with the Board layout and group it by the field (`Stage`, or the one you chose). GitHub's documentation does not say whether this can be done through the API, so the installer does not try.

## Choosing a board

| You want | Option |
|---|---|
| The board already linked to the repository | Nothing. The installer uses it when exactly one board is linked. |
| A particular board | `--project OWNER/NUMBER` |
| A field other than `Status` | `--board-field NAME`. It must be a single-select field. |
| A new board | `--create-project OWNER`, where the owner is an organization, a user or `@me`. |
| No board | `--no-board` |

If the repository has no linked board, or has several, the installer says so and does not guess. Add `--check` to see what it would do without changing anything.

## The credential

`GITHUB_TOKEN`, the token that every workflow has, cannot reach a project. The board needs a credential of its own, and you choose it. The installer checks that one is set by looking at the **names** of the repository's secrets and variables. It never reads a value.

| Board owner | Use | Set |
|---|---|---|
| An organization (recommended) | A GitHub App with organization Projects read and write, and Issues read, installed on the organization. The Action turns it into a token that lives for one job. | The variable `FACTORY_BOARD_CLIENT_ID` and the secret `FACTORY_BOARD_APP_PRIVATE_KEY` |
| A person | A personal access token (classic) with the `project` scope. GitHub's own example for a project of a person also asks for `repo`, which can write code. Which scope is needed was not verified here, so give it the smaller scope first. It reaches every project of that person, so prefer an organization board. | The secret `FACTORY_BOARD_TOKEN` |

A repository secret can be read by any workflow that can run in the repository, including one pushed on a branch by a collaborator with write access. Keep the credential in an environment that only the default branch may use, and require code owner review for `.github/project-board.json` and `.github/workflows/`. The installer cannot set that up for you.

Set secrets with `gh secret set NAME --repo OWNER/NAME`, which asks for the value on the terminal. Never put the value in a file or a chat. Without a credential the Action prints a warning and the board does not move.

## Troubleshooting

| You see | Cause | Fix |
|---|---|---|
| `NEEDS project-board` and "no board is linked" | The repository has no linked board. | Use `--project`, `--create-project` or `--no-board`. |
| `NEEDS project-board` and "no longer matches" | An option named in `.github/project-board.json` is gone from the board. | Edit the file, or delete it and run the installer again. |
| `BLOCKED project-board` and `gh auth refresh -s project` | Your `gh` login lacks the `project` scope. | Run `gh auth refresh -s project`. |
| "the board has no option ... Run the installer again" in the Action log | The board changed after the file was written. | The same as the second row. |
| "the project was not found, or the credential cannot see it" | The credential cannot reach the project. | Check that the App is installed where the project lives, or that the token belongs to its owner. |
| A card does not move | There is no credential, or the issue is on no track. | Read the warning in the Action log. |

## What it does not do

- The engine does not know about the board and never writes to it.
- It does not show pull requests as cards. Only the issue is on the board.
- It does not remove a card when an issue leaves every track.

## Where to read more

- [ADR 0018](../adr/0018-project-board-mirror-that-adapts.md): the options, what was checked, and what is unverified.
- [The board policy](../../policies/project-board.yaml): the stages, the names they match and the rules.
- [Onboarding guide](onboarding.md) and [design guide](design-with-egm.md): the rest of the path.
