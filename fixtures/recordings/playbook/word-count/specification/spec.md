# Feature Specification: {{TITLE}}

**Feature Branch**: `{{BRANCH}}`

**Created**: 2026-10-28

**Status**: Draft

**Input**: User description: "{{INPUT}}"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Programs read the counts as JSON (Priority: P1)

A person who writes scripts runs the tool with the `--json` option and gets the three counts as one JSON object, so another program can read them without parsing columns of text.

**Why this priority**: This is the whole request. Without it, programs must guess where each column starts.

**Independent Test**: Run the tool on a small file with the option and parse the output with any JSON reader. The three counts are the ones the plain output shows.

**Acceptance Scenarios**:

1. **Given** a file with 3 lines, 7 words and 34 characters, **When** the tool runs with the `--json` option, **Then** it prints one JSON object with the keys lines, words and characters, in that order, followed by a line break (FR-001, FR-004).
2. **Given** an empty input, **When** the tool runs with the `--json` option, **Then** it prints the same object with all three counts at 0 (FR-001).

---

### User Story 2 - Existing users see no change (Priority: P1)

A person who already uses the tool runs it without the new option and sees exactly what they saw before.

**Why this priority**: Scripts and habits depend on the plain output. A change there would break people who did not ask for anything.

**Independent Test**: Run the tool on a stored sample without the option and compare the output with the stored plain-text sample, byte for byte.

**Acceptance Scenarios**:

1. **Given** the stored sample file, **When** the tool runs without the `--json` option, **Then** the output is byte for byte the output of the previous release (FR-002).

---

### User Story 3 - Errors look the same with or without the option (Priority: P2)

A person whose file cannot be read gets the same clear error and the same exit status, whether or not they asked for JSON.

**Why this priority**: A script that checks the exit status must not need two code paths.

**Independent Test**: Run the tool on a file that does not exist, with and without the option, and compare the exit status and the message.

**Acceptance Scenarios**:

1. **Given** a file that does not exist, **When** the tool runs with the `--json` option, **Then** nothing is printed on standard output, a message is written on standard error and the exit status is 1 (FR-003).

---

### Edge Cases

- Out of scope: other output formats, a file name inside the JSON object, and any change to the plain-text output.
- What happens when the option is given with a single dash to read standard input? The tool counts standard input and prints the same object.
- What happens when the option is given twice? The tool behaves as if it were given once.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: When the `--json` option is given, the tool MUST print the counts of lines, words and characters as one JSON object with the keys lines, words and characters, in that order.
- **FR-002**: When the `--json` option is not given, the tool MUST print exactly what it printed before this change, byte for byte.
- **FR-003**: When the input cannot be read, the tool MUST print nothing on standard output, write a message on standard error and exit with status 1, whether or not the `--json` option is given.
- **FR-004**: The JSON object MUST be followed by a single line break and MUST hold no other text.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In 100% of the sample inputs of the test suite, the counts in the JSON object equal the counts in the plain-text line.
- **SC-002**: The stored plain-text samples produce no difference at all after this change.

## Assumptions

- The counts are the ones the tool already computes, so the JSON object and the plain line never disagree.
- Risk: a script may read the keys in a different order than the tool prints them, so the order is part of the contract (likelihood low, impact low)
- Constraint (technical): the tool keeps its policy of having no dependencies, so the JSON text is written by the tool itself.
