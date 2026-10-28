# Recorded Spec Kit outputs

The files under `recordings/` are copies of real output of the installed Spec Kit 1.1.2 with Claude Code 2.1.311, recorded on 2026-10-27 and described in `docs/spec-kit/worked-example.md`. They are golden input for the parser. They are labelled recordings: nobody edits them to make a test pass. When Spec Kit is upgraded, the files are recorded again and the parser tests are run again.

- `specs/001-end-to-end-mvp/spec.md`: the specification the specify and clarify skills wrote, with the reviewer's hand edits described in the worked example.
- `specs/001-end-to-end-mvp/checklists/requirements.md`: the built-in checklist, every item ticked by the skill that wrote the specification (a self-assessment).
- `specs/001-end-to-end-mvp/checklists/requirements-quality.md`: the checklist skill's output, 36 items, none ticked.
- `.specify/integration.json`, `.specify/init-options.json`, `.specify/integrations/*.manifest.json`: what the Spec Kit initialisation wrote.
- `.specify/memory/constitution.md`: the filled constitution.
- `.specify/spec-template.md`: the template the specify skill fills in (copied from `.specify/templates/`).

The recorded specification does not cite its requirement ids in its scenarios, because Spec Kit gives no link between a requirement and a scenario. The tests say what that means for the contract.
