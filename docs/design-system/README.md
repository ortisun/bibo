# Control plane design system

The control plane is the screen where people watch the factory and decide: approve a specification or a pull request, enable a repository, stop work. This design system gives every such screen the same look and, more important, the same protections. It was proposed on 2026-11-20 in [ADR 0031](../adr/0031-control-plane-design-system.md) and is not reviewed yet.

## Read in this order

| Page | What it holds |
|---|---|
| [Security patterns](security-patterns.md) | The 18 rules every screen follows, why, and the threat each answers. Start here. |
| [Foundations](foundations.md) | Tokens, colour, type, space, motion and the accessibility baseline. |
| [Component catalog](components.md) | Every component, its class and its rules. |
| [The control plane](control-plane.md) | The screens, what each answers and who may act on it. |

## Where the code is

| Path | What it is |
|---|---|
| `design-system/tokens/*.tokens.json` | The design tokens, the source of truth. |
| `design-system/tokens/contrast-pairs.json` | The text and background pairs the generator checks, with their minimum ratios. |
| `design-system/tools/build_tokens.py` | Turns the tokens into CSS and checks contrast. Python standard library only. |
| `design-system/dist/tokens.css` | The generated CSS custom properties. Do not edit by hand. |
| `design-system/css/components.css` | The component styles. They read only tokens. |
| `design-system/reference/` | A static reference page: components and four screens with example data, under a strict content security policy. |

## The rules in one paragraph

Text from outside the factory is shown only as text, in a frame that names its source. A decision is bound to the commit and the evidence on screen and disables itself when they change. Approvals ask for a fresh security key or passkey. A person sees why they cannot act before they click. There is no override. The tenant and the environment are always on screen. Secrets never reach the browser. Every decision lands in the visible, verifiable audit trail.

## Changing the system

Documents first, as everywhere in this repository: change the page here, then the tokens or the CSS, then run

```bash
python3 -I design-system/tools/build_tokens.py
```

and commit the regenerated `dist/tokens.css` with the change. `scripts/ci.sh` fails when the generated file is stale or a contrast pair fails.
