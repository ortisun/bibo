# Security patterns of the control plane

- Status: proposed with [ADR 0031](../adr/0031-control-plane-design-system.md), 2026-11-20. Not reviewed.
- Readers: whoever builds a control plane screen, and whoever reviews one.

The control plane is where a person approves agent-written code, enables a repository and stops work. An attacker who controls one approver's screen controls what the factory merges. This page lists the patterns every screen must follow, why each exists, and the threat it answers. Each pattern has a component in [the component catalog](components.md); a screen uses the component and does not rebuild it.

The interface is not the control. The API checks every rule again. The interface exists so that a person makes the right decision quickly and cannot be tricked into the wrong one.

## Sources

The patterns follow guidance that security engineers apply to administrative consoles. The section numbers are from the engineer's knowledge and were **not verified on 2026-11-20**:

- OWASP Application Security Verification Standard (sessions, access control, output encoding) and the OWASP cheat sheets on Content Security Policy, cross-site request forgery, clickjacking and session management.
- NIST SP 800-63B (authenticator assurance and reauthentication) and NIST SP 800-53 (AC-5 separation of duties, AC-6 least privilege, AC-12 session termination, AU-9 protection of audit information, AU-10 non-repudiation).
- CISA Secure by Design (secure defaults, no security as an option to turn on).
- W3C Content Security Policy Level 3, Trusted Types, and WCAG 2.2 level AA.
- The factory's own threat model and negative tests (T-xx and NT-xx below).

## The patterns at a glance

| Pattern | Answers | Component |
|---|---|---|
| 1. Untrusted text is quarantined and inert | T-01, T-32, T-34 | `ds-untrusted` |
| 2. A decision is bound to the evidence on screen | T-13, T-14, C-38 | `ds-decision`, `ds-digest` |
| 3. Sensitive decisions ask for step-up authentication | T-23, C-38 | `ds-stepup` dialog |
| 4. Separation of duties is visible before the click | T-23, REG-6 | `ds-sod` notice, disabled button with reason |
| 5. Every decision carries a reason | T-31 | `ds-field` with counter |
| 6. Irreversible actions name their target | T-27 | typed confirmation |
| 7. There is no override | T-12, T-27 | none, by design |
| 8. Least privilege is rendered, and enforced elsewhere | T-23, T-28 | disabled button with reason |
| 9. Tenant and environment are always on screen | T-28 | `ds-env-banner`, `ds-tenant` |
| 10. Sessions are short and visible | T-23 | `ds-session` |
| 11. Secrets are never shown | T-16, T-19, T-41 | `ds-fingerprint`, `ds-redacted` |
| 12. The audit trail is visible and verifiable | T-31, T-38 | `ds-ledger` |
| 13. One click is one request | T-22, T-25 | button pending state |
| 14. The page cannot be framed, forged or scripted | T-32, NT-WEB-01, NT-WEB-02 | page headers |
| 15. State is never told by colour alone | accessibility | `ds-state` pill |
| 16. Errors say what to do and reveal nothing | T-16 | `ds-callout` |
| 17. Time is absolute | ADR 0011 | `ds-time` |
| 18. The stop switch is near and guarded | runbook "stop work on a repository" | `ds-killswitch` |

## 1. Untrusted text is quarantined and inert

Issue bodies, pull request titles and bodies, comments, model output, file names, branch names, log lines and dependency metadata come from outside the factory. A screen shows them:

- inside the **untrusted-content frame**, whose label names the source ("From issue ortisun/bibo#42, written by a requester") and says "Shown as text";
- as text only, set with `textContent` or the framework's text binding, never with `innerHTML`, `dangerouslySetInnerHTML`, `v-html` or a Markdown renderer;
- with control characters made visible: bidirectional overrides (U+202A to U+202E, U+2066 to U+2069), zero-width characters and ANSI escape sequences are replaced by a visible marker such as `⟨U+202E⟩`, so that a "Trojan Source" line cannot hide what it does;
- with every URL shown as plain text, never as a live link. A person who wants to follow it copies it;
- with images, SVG and HTML artifacts offered only as downloads from the separate artifact origin, with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` (T-34, NT-WEB-04);
- with long text clipped to a height, and a "Show all" control that expands it, so that a hostile body cannot push the decision buttons off the screen.

The frame's striped edge is the only use of that texture in the system. Nothing the factory itself wrote may use it, and nothing from outside may appear without it.

## 2. A decision is bound to the evidence on screen

The command line binds an approval to `head=` (the commit) and `evidence=` (the ledger digest). The decision panel does the same:

- It shows the head commit and the evidence digest it will send, in the `ds-digest` style, with the full value one click away.
- The request carries both values. The API refuses when they differ from the current ones, as it does today for the command line.
- When the page learns that the head or the evidence changed (a poll or an event), the panel turns into the "Evidence changed" state, disables its buttons and offers "Reload the evidence". It never refreshes the values silently, because the person approved what they read, not what came later.
- The gate list next to the panel shows every gate and its outcome. A decision panel without the gate list is not allowed.

## 3. Sensitive decisions ask for step-up authentication

Approve, approve-build-code, approve-project-build-code, approve-dependency and repository enable ask for a fresh WebAuthn assertion from a phishing-resistant authenticator (a security key or a platform passkey), even inside a valid session. The assertion is fresh for five minutes (proposal, owner decision 2 of ADR 0031). The dialog:

- names the action and its target in words ("Approve pull request #118 of ortisun/bibo at commit 9f2c1e7");
- has no "remember me" option;
- shows a refusal as a refusal and keeps the decision unrecorded.

A password, a one-time code sent by e-mail or SMS, or a push notification that the person only taps is not accepted for step-up.

## 4. Separation of duties is visible before the click

Rules such as "the enabler is not the attestor" (REG-6), "an approver does not approve their own request" and "a bot never approves" are shown before the person acts. The button is disabled, and a `ds-sod` notice under it says which rule applies and who else may act: "You confirmed this map. Another approver must enable the repository." A repository registered as single-maintainer shows that fact on the same notice, because it is a weaker rule and the person should know.

## 5. Every decision carries a reason

The verbs that take a reason (reject, rework, pause, resume, cancel, unblock, the approvals of dependencies and build code) show a reason field with its limits (10 to 500 characters for most verbs) and a live counter. The submit button stays disabled until the reason fits. The reason is stored in the audit ledger with the decision, so the field says so: "Recorded in the audit log with your name."

## 6. Irreversible actions name their target

Cancel a job, disable a repository and revoke a credential cannot be undone from the screen. The confirmation:

- says what happens and what does not ("Running jobs are not stopped. Cancel each one.");
- asks the person to type the target's name (the repository `OWNER/NAME`, the job's short id), not "yes";
- uses the danger button only for the final step.

A generic "Are you sure?" dialog is not allowed: people learn to click through it.

## 7. There is no override

The factory has no override for a failed gate, a missing design approval or a refused dependency. The interface must not invent one. A blocked stage shows the cause, the evidence and the legal ways forward (unblock when the cause is gone, rework, reject, cancel), each with its own rules. No "Force", "Skip" or "Approve anyway" control exists in the system.

## 8. Least privilege is rendered, and enforced elsewhere

The interface reads the person's designations (requester, operator, approver, security approver, organisation administrator) and their tenant. An action the person may not take is shown disabled, with the designation it needs ("Needs the security approver designation"). It is not hidden, so that people learn who can act. The API decides again on every request; a screen that skipped this rendering would be wrong but not unsafe.

## 9. Tenant and environment are always on screen

The top bar shows the tenant name and the environment. Production has a solid banner in the `--env-production` colour above the top bar; local and test have a quieter banner with the word "Test". The page title starts with the environment in test ("TEST · Approvals"). A person with two tabs open on two environments can tell them apart in the tab strip and on the page.

## 10. Sessions are short and visible

- Idle timeout 15 minutes, absolute lifetime 8 hours (proposal, owner decision 3 of ADR 0031).
- Two minutes before the idle timeout, the `ds-session` indicator in the top bar shows the remaining time and a "Stay signed in" button. The page never extends a session without a person's action.
- The access page lists the person's active sessions with their device and last use, and can end any of them.
- The session cookie is `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Strict`, with no `Domain`.
- Signing out ends the session on the server, and a session used after sign-out is refused (NT-WEB-05).

## 11. Secrets are never shown

Tokens, keys and webhook secrets never reach the browser. The credentials page shows a **fingerprint** (the first 12 hexadecimal characters of the SHA-256 of the value, in the `ds-fingerprint` style), who created it, when it expires and when it was last used. Masking with the last four characters is not used: it confirms a guess and trains people to read secrets on screens. Where the redactor removed a value from a log or an artifact, the screen shows the `ds-redacted` marker with the kind of value ("redacted: token"), never the original length.

## 12. The audit trail is visible and verifiable

Every decision a person makes appears in the job's timeline with their name, their designation, the reason and the ledger entry's digest. The ledger page shows each entry's link to the previous one and the result of the last chain verification (`docs/database/tools/verify_audit_chain.py`), with its time. When verification fails or is older than one day, the overview shows a critical callout. An actor is always marked human or bot, never only by a name.

## 13. One click is one request

A decision button goes into a pending state on the first click and stays disabled until the answer arrives. The request carries an idempotency key made once per opened panel, so a retry or a double click repeats nothing, as `--key` does on the command line.

## 14. The page cannot be framed, forged or scripted

Every page of the control plane is served with:

```text
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
Strict-Transport-Security: max-age=63072000; includeSubDomains
Cache-Control: no-store
```

Consequences for the design system:

- No inline `<script>`, no inline event handler, no `style` attribute in markup. Dynamic sizes (a meter's fill) are set with `<meter>`, `<progress>` or the CSS object model, which the policy allows.
- No font, icon or script from a third-party origin. Icons are inline SVG in the page's own files or CSS shapes.
- Every state-changing request is a `POST` with a CSRF token and a checked `Origin` header; nothing changes state on `GET` (NT-WEB-02).
- Artifacts are served from a separate origin (pattern 1).

## 15. State is never told by colour alone

Each job, stage run and gate state has a colour, an icon shape and its name in words. The `ds-state` pill carries all three. Contrast meets WCAG 2.2 AA (4.5 to 1 for text, 3 to 1 for icons and borders); the token generator fails the build when a pair misses it.

## 16. Errors say what to do and reveal nothing

An error shows the API's refusal code in a code span and a sentence that says what to do: "`project_map_changed`: the map commit is not the one confirmed now. Read the new map and confirm it." It never shows a stack trace, a SQL error, a file path of the server or an internal host name.

## 17. Time is absolute

Times are shown in UTC, in the shortest ISO 8601 form (ADR 0011), with the relative time beside them ("2026-11-20 14:03:11Z, 6 minutes ago"). The relative form alone is not enough for an audit question.

## 18. The stop switch is near and guarded

"Stop work on this repository" (the runbook of the same name) sits on the repository page and in the overview's incident area. It is a danger action under pattern 6, it takes a reason, and it does not ask for step-up: stopping work must be faster than starting it.

## What a reviewer checks on a new screen

1. Search the code for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `eval` and `new Function`. Each hit is a finding.
2. Open the screen with the NT-WEB-01 corpus as content. No dialog opens, no request leaves for another origin, the console shows no policy violation from the page's own code.
3. Every outside value is inside an `ds-untrusted` frame.
4. Every decision button is bound to a digest and has a pending state.
5. Every disabled control says why.
6. The page passes the contrast check and works with the keyboard alone.
