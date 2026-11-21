# Foundations: tokens, colour, type, space and motion

- Status: proposed with [ADR 0031](../adr/0031-control-plane-design-system.md), 2026-11-20.
- Source of truth: the JSON files in [`design-system/tokens/`](../../design-system/tokens/). This page explains them; when the two disagree, the page is updated first and the tokens follow.

## How tokens work

A **token** is a named design value, such as the colour of body text or the gap between two fields. The system has two layers:

1. **Primitives** (`primitives.tokens.json`) are raw values: the ramp of neutrals, the blue of the accent, the green of a pass. They have no meaning. Components never read them.
2. **Semantic tokens** (`semantic.light.tokens.json`, `semantic.dark.tokens.json`, `scale.tokens.json`) say what a value is for: `color.fg-muted`, `color.state.human.bg`, `space.4`. They point at primitives with references such as `{palette.ink.700}`.

The files use the format of the W3C Design Tokens Community Group: every token is an object with `$value` and `$type`, and an optional `$description`.

`design-system/tools/build_tokens.py` reads the files, resolves every reference, and writes `design-system/dist/tokens.css`: one CSS custom property per semantic token, named `--ds-` plus the token's path joined by hyphens (`color.state.human.bg` becomes `--ds-color-state-human-bg`). Primitives are not written out, so a component cannot reach one by mistake.

The same program checks every pair listed in `contrast-pairs.json` in both themes and fails when one misses its minimum ratio. Run it after any token change:

```bash
python3 -I design-system/tools/build_tokens.py          # write dist/tokens.css
python3 -I design-system/tools/build_tokens.py --check  # fail if dist/tokens.css is stale or a pair fails
```

## Themes

The light palette is on `:root`. The dark palette applies when the operating system prefers dark and the page has no `data-theme="light"`, and always when the page has `data-theme="dark"`. A person's own choice (light, dark or system) is stored in their profile, not in the browser.

Dark is not light inverted. Surfaces get lighter as they rise (page, panel, raised panel, dialog), because shadows read poorly on dark grounds. State tints are darker and more saturated in dark mode so that their text keeps its contrast.

## Colour

### Neutrals

The neutrals are an "ink" ramp with a slight blue bias, so that grey surfaces sit with the blue accent instead of looking unchosen.

| Token | Use |
|---|---|
| `color.bg` | The page behind everything. |
| `color.surface` | Panels, tables, cards. |
| `color.surface-raised` | A panel on a panel: menus, popovers, the decision panel. |
| `color.surface-sunken` | Wells: code blocks, the inside of the untrusted-content frame, input fields. |
| `color.border` | Dividers and panel edges. |
| `color.border-strong` | Input and control edges. Meets 3 to 1 against the surface (WCAG 1.4.11). |
| `color.fg` | Body text and headings. |
| `color.fg-muted` | Secondary text, labels. At least 4.5 to 1. |
| `color.fg-subtle` | Captions and placeholders. At least 4.5 to 1 on the surface. |

### Accent

One accent, a cobalt blue, marks what a person can act on: primary buttons, links in factory-written text, the focus ring, the selected item in the navigation. It is never used for a state.

### States

The states of the [state machines](../architecture/state-machine.md) map to seven semantic groups. Each group has four tokens: `fg` (text and icon on the tint), `bg` (the tint), `border`, and `solid` (a dot, a bar, a stripe).

| Group | Meaning | Job states | Stage run states | Gate outcomes |
|---|---|---|---|---|
| `pass` | Done and proven | `COMPLETED` | `PASSED` | passed |
| `active` | Working now | `ACTIVE` | `RUNNING`, `GATING`, `READY` | running |
| `human` | Waits for a person | `WAITING_FOR_HUMAN` | `WAITING_FOR_HUMAN`, `REWORK_REQUESTED` | waiting for a decision |
| `blocked` | Stopped by the environment or a rule; a person must clear the cause | `BLOCKED`, `PAUSED` | `BLOCKED` | blocked |
| `fail` | Failed or refused | `FAILED`, `REJECTED` | `FAILED` | failed |
| `warn` | Needs attention but does not stop work | none | none | warnings |
| `neutral` | Not started, not needed, or ended by a person | `RECEIVED`, `CANCELLING`, `CANCELLED` | `PENDING`, `SKIPPED`, `SUPERSEDED`, `CANCELLED` | not applicable |

`human` has its own hue, an orchid violet, because "a person must act" is the most important thing the control plane shows, and it must not look like a warning or a failure.

### Environment and quarantine

- `color.env.production` and `color.env.test` paint the environment banner (pattern 9 of [the security patterns](security-patterns.md)).
- `color.untrusted.edge` and `color.untrusted.stripe` draw the striped edge of the untrusted-content frame (pattern 1). No other component may use them.

## Type

No font file is shipped yet (ADR 0031, owner decision 4). The stacks start with Inter and JetBrains Mono, which are used when the person has them installed, and fall back to the operating system's faces.

| Token | Value | Use |
|---|---|---|
| `font.family.sans` | Inter, then system interface faces | All interface text. |
| `font.family.mono` | JetBrains Mono, then system monospace faces | Digests, commits, identifiers, code, log lines, the untrusted-content frame. |
| `font.size.xs` to `font.size.3xl` | 12, 13, 14, 16, 20, 24, 30 pixels | 14 is the body size of the console. |
| `font.weight.*` | 400, 500, 600, 700 | 600 for headings and buttons. |
| `font.tracking.caps` | 0.06em | Uppercase labels only. |

Digits that line up in columns use tabular figures (`font-variant-numeric: tabular-nums`), set by the table and meter components.

## Space, size and shape

- `space.*` is a 4-pixel scale: 0, 2, 4, 6, 8, 12, 16, 20, 24, 32, 40, 48, 64. Components lay out siblings with `gap`.
- `radius.*`: 3, 5, 8, 12 pixels and a pill. Controls use 5, panels 8, dialogs 12. Not every box is rounded: table rows and the navigation have none.
- `size.control.*`: 28, 32 and 40 pixels for small, normal and large controls. Targets are at least 24 by 24 pixels (WCAG 2.5.8).
- `layout.*`: the side navigation is 248 pixels wide, the top bar 56 pixels high, content at most 1320 pixels wide.

## Motion

Motion explains a change; it never decorates. `motion.duration.fast` (120 ms) for hover and press, `base` (180 ms) for panels opening, `slow` (260 ms) for dialogs. One easing curve. With `prefers-reduced-motion: reduce`, every duration becomes 0, and the pulsing dot of a running state stops pulsing.

## Elevation and layers

Three shadows (`shadow.sm`, `shadow.md`, `shadow.lg`) and a fixed layer order: environment banner 40, top bar 30, popover 50, dialog 100, toast 110. A dialog always covers the environment banner, so that a step-up prompt cannot be mistaken for part of the page behind it.

## Accessibility baseline

WCAG 2.2 level AA:

- contrast checked by the generator, in both themes;
- a visible focus ring (`--ds-focus-ring`) on every interactive element, never removed;
- full keyboard operation; dialogs trap focus and return it on close;
- state told by colour, shape and words together;
- targets of at least 24 by 24 pixels;
- `prefers-reduced-motion` and `forced-colors` respected.
