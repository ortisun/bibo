# 0031: The control plane gets its own design system, with security patterns as components

- Status: **Proposed on 2026-11-20.** The owner asked for the design system; the engineer wrote this record. Not reviewed by the architect, a security reviewer or an accessibility reviewer yet.
- Date: 2026-11-20
- Deciders: the owner asked for a design system for a control plane "with everything the best security professionals recommend" and a modern look; the engineer chose the shape below.
- Related: [threat model](../security/threat-model.md) control C-41 and threats T-01, T-13, T-14, T-16, T-23, T-31, T-32, T-34; [negative test catalog](../security/negative-test-catalog.md) NT-WEB-01 to NT-WEB-05; [ADR 0008](0008-artifact-store-and-evidence-ledger.md); [ADR 0011](0011-canonical-time-and-numbers.md); [architecture overview](../architecture/overview.md) (`apps/dashboard`, Slice 4); [design system documents](../design-system/README.md).

## Context and problem statement

The factory has no screen. People act through `factory-cli` and through GitHub. The overview plans a dashboard, "React and TypeScript", for Slice 4, and the threat model already lists what it must do: control C-41 asks for inert rendering of untrusted text, a content security policy, protection against cross-site request forgery, per-tenant authorization and step-up authentication for sensitive approvals. Its "built" column says "none (dashboard design, ADR)". This is that record.

A control plane for this factory is a high-value target. One click of an approver merges agent-written code into a protected branch. The screen shows text that an attacker controls: issue bodies, pull request titles, model output, file names, logs. Three things therefore matter more than in an ordinary product:

1. **Untrusted text must look and behave untrusted.** A person must see at a glance which words came from the factory and which came from outside, and outside words must never become markup, links or script.
2. **A decision must be bound to what the person saw.** The command line already binds an approval to `head=` and `evidence=`. A screen must do the same and must notice when the evidence changes under the person.
3. **The safe path must be the easy path.** Roles, separation of duties, reasons and step-up authentication must be visible parts of the interface, not error messages after a click.

Without a design system, each screen would solve these again, and the first screen built in a hurry would solve them badly.

## What was checked

On 2026-11-20, from the repository only:

- The threat model (C-41, T-32, T-34) and the negative tests NT-WEB-01 to NT-WEB-05. **Read in `docs/security/`.**
- The states of the job, stage run and attempt machines, the 14 stage kinds and the assurance levels in `docs/architecture/state-machine.json`. **Read.**
- The decision verbs, designations and refusal codes of the operator command line in `docs/reference/commands.md`. **Read.**
- The documentation policy: all interface labels are in English (section 2.1). **Read.**

External guidance cited in [the security patterns](../design-system/security-patterns.md) (OWASP Application Security Verification Standard and cheat sheets, NIST SP 800-63B and SP 800-53, CISA Secure by Design, W3C Content Security Policy Level 3 and Trusted Types, WCAG 2.2) is cited from the engineer's knowledge. **Unverified on this date: no page was fetched.** A reviewer should check the section numbers before the record is accepted.

Not checked: any front-end framework, component library or build tool. None is chosen by this record.

## Considered options

### Option 1: adopt a general design system (Material, Carbon, a Tailwind kit)

- Good: many components exist; documentation is ready.
- Bad: none of them has the components this factory needs most (an untrusted-content frame, an evidence-bound decision panel, a step-up prompt, a hash-chain ledger row). They would be built on top anyway.
- Bad: each brings a large dependency tree into the most sensitive screen of the factory, against the supply chain rules the factory applies to the projects it changes. Several load fonts or icons from a third-party origin by default, which a strict content security policy forbids.

### Option 2: build React components now, inside a future `apps/dashboard`

- Good: closest to the planned dashboard.
- Bad: chooses the framework, the bundler and their dependencies two slices early, without the record those choices need.
- Bad: `apps/*` are members of the Cargo workspace; a JavaScript package there would break the workspace rule.

### Option 3 (chosen): a framework-neutral design system in `design-system/`, with security patterns as first-class components

- Design tokens in the W3C Design Tokens Community Group format (JSON) are the source of truth. A small Python program with no dependency turns them into CSS custom properties and fails when a text and background pair misses its contrast target.
- Component styles in plain CSS read only the tokens. They work under a policy of `style-src 'self'`: no inline style, no inline script.
- A static reference page shows the components and four control plane screens. It runs under the same strict policy that the dashboard will have.
- The documents in `docs/design-system/` say what each component is for, what threat it answers and what a screen must never do.

## Decision

Option 3. The dashboard, whatever framework its own record chooses, imports `design-system/dist/tokens.css` and `design-system/css/components.css` and follows [the security patterns](../design-system/security-patterns.md). A screen that needs a pattern the system lacks adds it to the system first, documents first, as with every other change in this repository.

The rules that bind every screen are in [security-patterns.md](../design-system/security-patterns.md). The most important:

1. Text from outside the factory is shown only as text, inside the untrusted-content frame that names its source. Nothing from outside becomes HTML, a live link or an image.
2. A decision panel shows the head commit and the evidence digest it is bound to, and it disables itself when either changes.
3. Approving, enabling a repository and approving build code ask for a fresh WebAuthn assertion (step-up). A password alone never approves.
4. An action a person may not take is shown disabled with the reason (the designation it needs, or the separation-of-duties rule), and the server still decides.
5. There is no override button anywhere. A blocked gate shows how to clear the cause, never how to skip it.
6. Every page states the tenant and the environment, and production looks different from test.
7. A secret is never shown, not even masked with its last characters. Only its fingerprint is.
8. The page sends `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'`.

## Consequences

- Good: control C-41 has a written design and a reference that can be tested against NT-WEB-01 and NT-WEB-02 before any dashboard exists.
- Good: the system adds no runtime dependency. The generator uses the Python standard library; the CSS needs no build step.
- Good: the contrast check runs in `scripts/ci.sh`, so a token change that makes text unreadable fails like any other test.
- Bad: every component is written by hand and must be maintained by the factory. Accessible behaviour that a library would bring (focus traps in dialogs, keyboard handling in menus) must be written and tested here.
- Bad: no font is shipped. The system uses the operating system's interface and monospace faces until a self-hosted, licence-approved face is chosen. That keeps the policy strict and the look slightly different between macOS, Windows and Linux.
- Bad: the reference page is a static demonstration. It shows example data, marked as examples, and talks to no API.

## Owner decisions this record needs

1. Accept the design system as the base of the Slice 4 dashboard (yes or no).
2. Confirm the step-up rule: which decisions require a fresh WebAuthn assertion, and how long it stays fresh (the proposal is five minutes, for approve, approve-build-code, approve-project-build-code, approve-dependency and repository enable).
3. Confirm the session limits: 15 minutes idle, 8 hours absolute.
4. Choose whether to self-host a typeface (the proposal is Inter and JetBrains Mono, both under the SIL Open Font Licence, which is not yet on the approved licence list).
