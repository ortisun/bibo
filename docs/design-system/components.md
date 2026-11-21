# Component catalog

- Status: proposed with [ADR 0031](../adr/0031-control-plane-design-system.md), 2026-11-20.
- Code: [`design-system/css/components.css`](../../design-system/css/components.css). Every class starts with `ds-` so that it cannot collide with a framework's own classes.
- See them: open [`design-system/reference/index.html`](../../design-system/reference/index.html) in a browser, section "Components".

Components read only semantic tokens. Variants are set with modifier classes (`ds-btn--danger`) and states with standard attributes (`disabled`, `aria-busy`, `aria-invalid`, `aria-current`) or `data-tone`, so that the markup a screen writes is also its accessible description.

## Application shell

| Class | What it is | Rules |
|---|---|---|
| `ds-env-banner` | A full-width band above everything, `data-env="production"` or `data-env="test"`. | Always present. Production is solid; test is striped and says "Test". Security pattern 9. |
| `ds-topbar` | The bar with the product name, the tenant, the search, the session and the person. | Sticky. Holds `ds-tenant` and `ds-session`. |
| `ds-tenant` | The tenant's name and short id. | Never hidden, even on a phone. |
| `ds-session` | The session indicator. `data-warn="true"` in the last two minutes before the idle timeout. | Security pattern 10. |
| `ds-nav` | The side navigation. The current item has `aria-current="page"`. | Items show a count of what waits for the person (for example decisions). |
| `ds-page-header` | Page title, a one-line summary and the page's main actions. | One per page. |

## Actions

| Class | What it is | Rules |
|---|---|---|
| `ds-btn` | A button. Modifiers `--primary`, `--ghost`, `--danger`, `--sm`, `--lg`. | One primary per area. `--danger` only for the last step of an irreversible action. |
| `ds-btn[aria-busy="true"]` | Pending: shows a spinner, ignores clicks. | Security pattern 13: set on the first click, cleared on the answer. |
| `ds-btn[disabled]` with `ds-reason` | A disabled action and the sentence that says why. | Security patterns 4 and 8. A disabled control without a reason is a defect. |
| `ds-killswitch` | The "Stop work" area: a danger button, a short consequence and the runbook link. | Security pattern 18. |
| `ds-copy` | A small button that copies a full value. | Copies digests and identifiers, never a secret. |

## Inputs

| Class | What it is | Rules |
|---|---|---|
| `ds-field` | A label, an optional hint, the control and a message. | Every control has a visible `<label>`. Placeholders are not labels. |
| `ds-input`, `ds-textarea`, `ds-select` | The controls. | `aria-invalid="true"` shows the error style; the message says how to fix it. |
| `ds-count` | The live character counter of a reason field. `data-state="short"`, `"ok"` or `"long"`. | Security pattern 5. |
| `ds-check` | A checkbox with its label. | The whole row is the target. |
| `ds-confirm` | A typed confirmation: the sentence to type, the field, the danger button. | Security pattern 6. The button stays disabled until the text matches exactly. |

## Status and evidence

| Class | What it is | Rules |
|---|---|---|
| `ds-state` | A state pill with `data-tone` = `pass`, `active`, `human`, `blocked`, `fail`, `warn` or `neutral`. | Shape, colour and the state's name together (security pattern 15). Use the state machine's word, in sentence case: "Waiting for a person". |
| `ds-pipeline` | The 14 stages of a job as a row of steps, each with `data-tone`. | Wraps on narrow screens. The current stage has `aria-current="step"`. |
| `ds-gates` | The list of gate reports of a stage: gate, outcome, block code, report digest. | Always next to a decision panel (security pattern 2). |
| `ds-digest` | A digest or commit: algorithm label, value cut in the middle, full value in the copy button. | Monospace. Never cut at the end: the two ends are what people compare. |
| `ds-fingerprint` | The fingerprint of a credential. | Security pattern 11. |
| `ds-redacted` | Where the redactor removed a value: `redacted: token`. | Never shows the length of what was removed. |
| `ds-meter` | A budget or quota bar with numbers, built on `<meter>`. | Shows the used amount, the ceiling and the unit in words. |
| `ds-stat` | A figure with its label and its change. | Only on the overview. |
| `ds-time` | A `<time>` element with the absolute UTC time and the relative time. | Security pattern 17. |

## Content

| Class | What it is | Rules |
|---|---|---|
| `ds-untrusted` | The untrusted-content frame: a striped edge, a header naming the source and "Shown as text", a sunken body in monospace. | Security pattern 1. The only container for text from outside the factory. `ds-ctl` marks a made-visible control character inside it. |
| `ds-panel` | A bordered surface with an optional header. | Do not nest panels more than once. |
| `ds-table` inside `ds-table-wrap` | A dense data table with a sticky header, tabular figures and hover rows. | The wrapper scrolls sideways on narrow screens; the page never does. |
| `ds-callout` | A message in the page with `data-tone`. | Says what happened and what to do (security pattern 16). |
| `ds-actor` | A person or a bot: name, designation, and `data-kind="human"` or `"bot"`. | Security pattern 12. A bot always shows the word "bot". |
| `ds-ledger` | A list of ledger entries, each linked to the previous one by its digest. | Security pattern 12. The head entry shows the verification result. |
| `ds-tabs` | Tabs inside a page. | Real `role="tablist"`, arrow keys move between tabs. |
| `ds-empty` | An empty state: what will appear here and how it gets there. | Never only "No data". |

## Decisions

| Class | What it is | Rules |
|---|---|---|
| `ds-decision` | The decision panel: what is decided, the binding (head and evidence), the reason field and the buttons. `data-stale="true"` when the evidence changed. | Security patterns 2, 5 and 13. |
| `ds-sod` | The separation-of-duties notice under a decision. | Security pattern 4. |
| `ds-dialog` on a `<dialog>` | A modal dialog. | Opened with `showModal()`, closes on Escape, returns focus. |
| `ds-stepup` | The step-up dialog: the action in words, the target, the security key prompt, the result. | Security pattern 3. No "remember me". |
| `ds-toast` | A short result message ("Approval recorded, ledger entry 4f1c…"). | Never the only place a result is shown: the timeline shows it too. |
