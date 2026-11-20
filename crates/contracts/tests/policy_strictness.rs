//! Policy loading is strict (NT-POL-03), policy is read only from the protected source
//! (NT-POL-01), and the policy files obey the static check ST-06.
//!
//! Each negative case takes the real policy file, changes it in one way, writes it into a
//! temporary checkout and loads it. The unchanged text loads in the same helper, so a failure is
//! about the change and not about the setup.

mod support;

use std::fs;
use std::path::{Path, PathBuf};

use factory_contracts::policy::{
    APPROVAL_FILE, PolicyError, PolicyErrorKind, PolicyHash, PolicyLoader, ProtectedPolicySource,
    SECURITY_FILE,
};
use factory_contracts::yaml::{self, AmbiguousScalar, Content, Node, YamlErrorKind, YamlLimits};
use support::{TempDir, read_text, repo_root, to_block_yaml};

fn real(file: &str) -> String {
    read_text(&repo_root().join(file))
}

/// A checkout holding the given policy texts, and a source over it.
struct Checkout {
    dir: TempDir,
    source: ProtectedPolicySource,
}

fn checkout(security: &str, approval: &str) -> Checkout {
    let dir = TempDir::new("policy");
    dir.write(SECURITY_FILE, security);
    dir.write(APPROVAL_FILE, approval);
    let source = ProtectedPolicySource::protected_default_branch(dir.path(), &[])
        .expect("the checkout exists");
    Checkout { dir, source }
}

fn load_security_text(text: &str) -> Result<(), PolicyError> {
    let c = checkout(text, &real(APPROVAL_FILE));
    PolicyLoader::load_security(&c.source).map(|_| ())
}

fn load_approval_text(text: &str) -> Result<(), PolicyError> {
    let c = checkout(&real(SECURITY_FILE), text);
    PolicyLoader::load_approval(&c.source).map(|_| ())
}

/// Replaces the first occurrence of `from`, and fails loudly if the policy no longer has it, so a
/// change to the real file asks for this test to be updated instead of passing for the wrong reason.
fn replace_once(text: &str, from: &str, to: &str) -> String {
    assert!(
        text.contains(from),
        "the policy file no longer contains `{from}`; update this negative test to the new text"
    );
    text.replacen(from, to, 1)
}

fn line_of(text: &str, needle: &str) -> usize {
    text.lines()
        .position(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("no line contains `{needle}`"))
        + 1
}

fn refused(result: Result<(), PolicyError>, why: &str) -> PolicyError {
    match result {
        Ok(()) => panic!("the policy should be refused: {why}"),
        Err(error) => error,
    }
}

// ---- Positive controls ----------------------------------------------------------------------

#[test]
fn negative_nt_pol_03_control_the_unchanged_files_load_from_a_temporary_checkout() {
    load_security_text(&real(SECURITY_FILE)).unwrap_or_else(|e| panic!("{e}"));
    load_approval_text(&real(APPROVAL_FILE)).unwrap_or_else(|e| panic!("{e}"));
}

// ---- NT-POL-03: schema strictness -----------------------------------------------------------

#[test]
fn negative_nt_pol_03_the_consequence_of_exposed_workflows_is_one_of_two_words_and_required() {
    // Threat T-48. The key under `credentials.repository_requirements` takes `cap_at_l0` or
    // `record_only`; any other word, and a policy without the key, is refused.
    let text = real(SECURITY_FILE);
    let key = "    exposed_workflows: cap_at_l0\n";
    let other = replace_once(&text, key, "    exposed_workflows: record_only\n");
    load_security_text(&other).unwrap_or_else(|e| panic!("{e}"));
    for word in ["ignore", "allow", "true", "\"\""] {
        let changed = replace_once(&text, key, &format!("    exposed_workflows: {word}\n"));
        let error = refused(load_security_text(&changed), word);
        assert_eq!(error.kind, PolicyErrorKind::Type, "{word}: {error}");
        assert_eq!(
            error.key.as_deref(),
            Some("credentials.repository_requirements.exposed_workflows"),
            "{word}: {error}"
        );
    }
    let missing = replace_once(&text, key, "");
    let error = refused(load_security_text(&missing), "the key is missing");
    assert_eq!(error.kind, PolicyErrorKind::Type, "{error}");
    assert!(error.message.contains("exposed_workflows"), "{error}");
}

#[test]
fn negative_nt_pol_03_an_unknown_key_is_refused_at_any_depth_and_named() {
    let text = real(SECURITY_FILE);
    // Top level.
    let top = format!("{text}\nunexpected_section:\n  a: 1\n");
    let error = refused(load_security_text(&top), "an unknown top-level key");
    assert_eq!(error.kind, PolicyErrorKind::Type);
    assert!(error.message.contains("unexpected_section"), "{error}");
    assert_eq!(error.line, Some(top.lines().count() - 1), "{error}");
    // Nested, inside `sandbox`.
    let nested = replace_once(
        &text,
        "\n  fail_closed: true",
        "\n  fail_closed: true\n  colour: red",
    );
    let error = refused(load_security_text(&nested), "an unknown nested key");
    assert_eq!(error.kind, PolicyErrorKind::Type);
    assert_eq!(error.key.as_deref(), Some("sandbox.colour"), "{error}");
    assert_eq!(error.line, Some(line_of(&nested, "colour: red")));
    // In a list of structs.
    let in_list = replace_once(
        &text,
        "- id: ci_workflows\n",
        "- id: ci_workflows\n      sneaky: true\n",
    );
    let error = refused(
        load_security_text(&in_list),
        "an unknown key in a list entry",
    );
    assert_eq!(error.kind, PolicyErrorKind::Type);
    assert!(
        error
            .key
            .as_deref()
            .is_some_and(|k| k.starts_with("protected_paths.groups[")),
        "{error}"
    );
    // The approval policy too.
    let approval = format!("{}\nunexpected_section: {{a: 1}}\n", real(APPROVAL_FILE));
    let error = refused(
        load_approval_text(&approval),
        "an unknown key in the approval policy",
    );
    assert_eq!(error.kind, PolicyErrorKind::Type);
    assert!(error.message.contains("unexpected_section"), "{error}");
}

#[test]
fn negative_nt_pol_03_a_wrong_schema_version_is_refused_before_anything_else() {
    for (from, to, why) in [
        ("schema_version: 1", "schema_version: 2", "a newer version"),
        ("schema_version: 1", "schema_version: 0", "version zero"),
        ("schema_version: 1", "schema_version: \"1\"", "a string"),
        ("schema_version: 1", "schema_version: 1.0", "a float"),
        ("schema_version: 1", "schema_version: [1]", "a list"),
    ] {
        let text = replace_once(&real(SECURITY_FILE), from, to);
        let error = refused(load_security_text(&text), why);
        assert_eq!(error.kind, PolicyErrorKind::SchemaVersion, "{why}: {error}");
        assert_eq!(
            error.line,
            Some(line_of(&text, "schema_version:")),
            "{why}: {error}"
        );
        assert_eq!(error.key.as_deref(), Some("schema_version"));
    }
    // A wrong version is reported even when other things are wrong too.
    let text = format!(
        "{}\nunexpected_section: 1\n",
        replace_once(
            &real(SECURITY_FILE),
            "schema_version: 1",
            "schema_version: 2"
        )
    );
    assert_eq!(
        refused(load_security_text(&text), "version first").kind,
        PolicyErrorKind::SchemaVersion
    );
    // Missing.
    let missing = real(SECURITY_FILE)
        .lines()
        .filter(|l| !l.starts_with("schema_version:"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        refused(load_security_text(&missing), "no version").kind,
        PolicyErrorKind::SchemaVersion
    );
    // The approval policy has the same rule.
    let approval = replace_once(
        &real(APPROVAL_FILE),
        "schema_version: 1",
        "schema_version: 7",
    );
    assert_eq!(
        refused(load_approval_text(&approval), "approval version").kind,
        PolicyErrorKind::SchemaVersion
    );
}

#[test]
fn negative_nt_pol_03_a_duplicate_key_is_refused_with_its_line() {
    let text = real(SECURITY_FILE);
    let top = format!("{text}\naudit:\n  append_only: true\n");
    let error = refused(load_security_text(&top), "a duplicate top-level key");
    assert_eq!(
        error.kind,
        PolicyErrorKind::Yaml(YamlErrorKind::DuplicateKey)
    );
    assert_eq!(error.line, Some(top.lines().count() - 1), "{error}");
    assert!(error.message.contains("`audit`"), "{error}");
    // Nested.
    let nested = replace_once(
        &text,
        "\n  fail_closed: true",
        "\n  fail_closed: true\n  fail_closed: false",
    );
    let error = refused(load_security_text(&nested), "a duplicate nested key");
    assert_eq!(
        error.kind,
        PolicyErrorKind::Yaml(YamlErrorKind::DuplicateKey)
    );
    assert!(error.message.contains("fail_closed"), "{error}");
    let approval = format!("{}\nroles: []\n", real(APPROVAL_FILE));
    assert_eq!(
        refused(
            load_approval_text(&approval),
            "a duplicate key in the approval policy"
        )
        .kind,
        PolicyErrorKind::Yaml(YamlErrorKind::DuplicateKey)
    );
}

#[test]
fn negative_nt_pol_03_an_anchor_an_alias_and_a_merge_key_are_refused() {
    let text = real(SECURITY_FILE);
    let anchor = replace_once(
        &text,
        "\n  fail_closed: true",
        "\n  fail_closed: &flag true",
    );
    let error = refused(load_security_text(&anchor), "an anchor");
    assert_eq!(error.kind, PolicyErrorKind::Yaml(YamlErrorKind::Anchor));
    assert_eq!(error.line, Some(line_of(&anchor, "&flag")));

    let alias = format!("{anchor}\ncopy: *flag\n");
    let error = refused(load_security_text(&alias), "an alias");
    assert!(
        matches!(
            error.kind,
            PolicyErrorKind::Yaml(YamlErrorKind::Anchor | YamlErrorKind::Alias)
        ),
        "{error}"
    );

    let merge = replace_once(
        &text,
        "\nsandbox:\n",
        "\nsandbox:\n  <<: {fail_closed: false}\n",
    );
    let error = refused(load_security_text(&merge), "a merge key");
    assert_eq!(error.kind, PolicyErrorKind::Yaml(YamlErrorKind::MergeKey));
    assert_eq!(error.line, Some(line_of(&merge, "<<:")));

    // A tag, a second document and an ambiguous boolean, which the same contract forbids.
    let tag = replace_once(
        &text,
        "\n  fail_closed: true",
        "\n  fail_closed: !!bool true",
    );
    assert_eq!(
        refused(load_security_text(&tag), "a tag").kind,
        PolicyErrorKind::Yaml(YamlErrorKind::Tag)
    );
    let two_documents = format!("{text}\n---\nschema_version: 1\n");
    assert_eq!(
        refused(load_security_text(&two_documents), "two documents").kind,
        PolicyErrorKind::Yaml(YamlErrorKind::MultipleDocuments)
    );
    let ambiguous = replace_once(&text, "\n  fail_closed: true", "\n  fail_closed: yes");
    assert_eq!(
        refused(load_security_text(&ambiguous), "yes as a boolean").kind,
        PolicyErrorKind::Yaml(YamlErrorKind::Ambiguous(AmbiguousScalar::LegacyBoolean))
    );
    let approval = replace_once(
        &real(APPROVAL_FILE),
        "default_level: L1",
        "default_level: &level L1",
    );
    assert_eq!(
        refused(
            load_approval_text(&approval),
            "an anchor in the approval policy"
        )
        .kind,
        PolicyErrorKind::Yaml(YamlErrorKind::Anchor)
    );
}

#[test]
fn negative_nt_pol_03_a_wrong_type_is_refused_with_the_key_path_and_line() {
    let text = real(SECURITY_FILE);
    for (from, to, key) in [
        (
            "max_file_bytes: 5242880",
            "max_file_bytes: \"5242880\"",
            "path_access.max_file_bytes",
        ),
        (
            "\n  fail_closed: true",
            "\n  fail_closed: \"true\"",
            "sandbox.fail_closed",
        ),
        (
            "max_calls_per_task: 3000",
            "max_calls_per_task: lots",
            "tools.entries[0].limits.max_calls_per_task",
        ),
        (
            "timeout_s: 10",
            "timeout_s: [10]",
            "tools.entries[0].limits.timeout_s",
        ),
        (
            "max_usd: 8,",
            "max_usd: cheap,",
            "budgets.hard_ceilings.per_task.max_usd",
        ),
    ] {
        let changed = replace_once(&text, from, to);
        let error = refused(load_security_text(&changed), key);
        assert_eq!(error.kind, PolicyErrorKind::Type, "{key}: {error}");
        assert_eq!(error.key.as_deref(), Some(key), "{error}");
        assert!(error.line.is_some(), "{error}");
    }
    // A value outside a closed set.
    let closed = replace_once(&text, "status: designed", "status: finished");
    let error = refused(load_security_text(&closed), "a value outside a closed set");
    assert_eq!(error.kind, PolicyErrorKind::Type);
    assert_eq!(error.key.as_deref(), Some("policy.status"));
    // A threat identifier that is not shaped like one.
    let threat = replace_once(
        &text,
        "threats: [T-15, T-04, T-12]",
        "threats: [T-15, T-4, T-12]",
    );
    let error = refused(load_security_text(&threat), "a malformed threat id");
    assert_eq!(error.kind, PolicyErrorKind::Type);
}

#[test]
fn negative_nt_pol_03_an_invalid_regex_is_refused_with_its_key_and_line() {
    let text = real(SECURITY_FILE);
    for (bad, why) in [
        ("'(?<=a)b'", "look-behind"),
        ("'('", "an unclosed group"),
        ("'a{2,1}'", "an inverted repeat"),
        ("'(a)\\1'", "a back-reference"),
    ] {
        let changed = replace_once(
            &text,
            "regex: 'ghp_[A-Za-z0-9]{36}\\b'",
            &format!("regex: {bad}"),
        );
        let error = refused(load_security_text(&changed), why);
        assert_eq!(error.kind, PolicyErrorKind::InvalidRegex, "{why}: {error}");
        assert_eq!(
            error.key.as_deref(),
            Some("secrets.patterns[0].regex"),
            "{why}: {error}"
        );
        assert_eq!(
            error.line,
            Some(line_of(&changed, &format!("regex: {bad}"))),
            "{why}: {error}"
        );
    }
    // A regex in a command class argument list.
    let changed = replace_once(
        &text,
        "argv_regex: ['(?i)\\|\\s*(sh|bash|zsh|python[0-9.]*|perl|ruby|node)\\b']",
        "argv_regex: ['(?i)(unclosed']",
    );
    let error = refused(load_security_text(&changed), "a bad argv_regex");
    assert_eq!(error.kind, PolicyErrorKind::InvalidRegex);
    assert!(
        error
            .key
            .as_deref()
            .is_some_and(|k| k.contains("argv_regex")),
        "{error}"
    );
}

#[test]
fn negative_nt_pol_03_an_invalid_glob_is_refused_with_its_key_and_line() {
    let text = real(SECURITY_FILE);
    for bad in ["\"[abc\"", "\"{a,b\"", "\"a/[z-a]\""] {
        let changed = replace_once(&text, "\".github/**\"", bad);
        let error = refused(load_security_text(&changed), bad);
        assert_eq!(error.kind, PolicyErrorKind::InvalidGlob, "{bad}: {error}");
        assert!(
            error
                .key
                .as_deref()
                .is_some_and(|k| k.starts_with("protected_paths.groups[")),
            "{error}"
        );
        assert_eq!(error.line, Some(line_of(&changed, bad)), "{error}");
    }
    // An empty glob.
    let empty = replace_once(&text, "\".github/**\"", "\"\"");
    assert_eq!(
        refused(load_security_text(&empty), "empty glob").kind,
        PolicyErrorKind::InvalidGlob
    );
    // A glob in the write allow list.
    let allow = replace_once(&text, "write_allow: [\"**\"]", "write_allow: [\"[**\"]");
    assert_eq!(
        refused(load_security_text(&allow), "bad write_allow").kind,
        PolicyErrorKind::InvalidGlob
    );
}

#[test]
fn negative_nt_pol_03_a_missing_default_action_is_refused_and_so_is_any_other_value() {
    let text = real(SECURITY_FILE);
    let missing = replace_once(
        &text,
        "  default_action: deny",
        "  # default_action removed",
    );
    let error = refused(load_security_text(&missing), "no default action");
    assert_eq!(error.kind, PolicyErrorKind::Type);
    assert!(error.message.contains("default_action"), "{error}");
    assert!(
        error
            .key
            .as_deref()
            .is_some_and(|k| k.starts_with("policy")),
        "{error}"
    );
    let allow = replace_once(&text, "  default_action: deny", "  default_action: allow");
    let error = refused(load_security_text(&allow), "default allow");
    assert_eq!(error.kind, PolicyErrorKind::Type);
    assert_eq!(error.key.as_deref(), Some("policy.default_action"));
    // The approval policy: a human decides by default.
    let approval = replace_once(
        &real(APPROVAL_FILE),
        "  default_action: require_human",
        "  # default_action removed",
    );
    let error = refused(
        load_approval_text(&approval),
        "no default action in the approval policy",
    );
    assert_eq!(error.kind, PolicyErrorKind::Type);
    let approval = replace_once(
        &real(APPROVAL_FILE),
        "  default_action: require_human",
        "  default_action: allow",
    );
    assert_eq!(
        refused(load_approval_text(&approval), "approval default allow").kind,
        PolicyErrorKind::Type
    );
}

#[test]
fn negative_nt_pol_03_identifiers_must_be_unique_and_references_must_resolve() {
    let text = real(SECURITY_FILE);
    let dup = replace_once(
        &text,
        "- id: shell_interpreters",
        "- id: remote_fetch_and_execute",
    );
    let error = refused(load_security_text(&dup), "duplicate class id");
    assert_eq!(error.kind, PolicyErrorKind::DuplicateId);
    assert!(
        error
            .key
            .as_deref()
            .is_some_and(|k| k.starts_with("forbidden_command_classes[")),
        "{error}"
    );

    let dangling = replace_once(
        &text,
        "checks: [new_dependency, lint_relaxation,",
        "checks: [no_such_check, lint_relaxation,",
    );
    let error = refused(load_security_text(&dangling), "dangling check");
    assert_eq!(error.kind, PolicyErrorKind::UnknownReference);
    assert!(error.message.contains("no_such_check"), "{error}");

    let unknown_profile = replace_once(
        &text,
        "default_profile: no_skills",
        "default_profile: nothing",
    );
    assert_eq!(
        refused(
            load_security_text(&unknown_profile),
            "unknown stage profile"
        )
        .kind,
        PolicyErrorKind::UnknownReference
    );

    let late = replace_once(
        &text,
        "review_by: \"2027-01-31\", terminates_tls",
        "review_by: \"31/01/2027\", terminates_tls",
    );
    assert_eq!(
        refused(load_security_text(&late), "malformed date").kind,
        PolicyErrorKind::Constraint
    );

    let approval = replace_once(
        &real(APPROVAL_FILE),
        "min_level: L0, requires: none,             when: \"label `factory`",
        "min_level: L9, requires: none,             when: \"label `factory`",
    );
    assert_eq!(
        refused(load_approval_text(&approval), "unknown level").kind,
        PolicyErrorKind::UnknownReference
    );
    let both = replace_once(
        &real(APPROVAL_FILE),
        "id: approve_pr,                     min_level: L1, requires: human,",
        "id: approve_pr,                     min_level: L1, requires: human, requires_by_level: {L1: human},",
    );
    assert_eq!(
        refused(load_approval_text(&both), "both requires forms").kind,
        PolicyErrorKind::Constraint
    );
}

#[test]
fn negative_nt_pol_03_the_wrong_file_is_refused_by_its_id() {
    // The approval policy under the security policy's name.
    let c = checkout(&real(APPROVAL_FILE), &real(APPROVAL_FILE));
    let error = PolicyLoader::load_security(&c.source).expect_err("wrong file");
    assert!(
        matches!(
            error.kind,
            PolicyErrorKind::Type | PolicyErrorKind::WrongPolicy
        ),
        "{error}"
    );
    let renamed = replace_once(&real(SECURITY_FILE), "  id: security", "  id: approval");
    assert_eq!(
        refused(load_security_text(&renamed), "wrong id").kind,
        PolicyErrorKind::WrongPolicy
    );
}

#[test]
fn negative_nt_pol_03_a_file_over_the_size_limit_is_refused() {
    let big = format!(
        "{}\n# {}\n",
        real(SECURITY_FILE),
        "x".repeat(YamlLimits::POLICY.max_bytes())
    );
    let error = refused(load_security_text(&big), "an oversized file");
    assert_eq!(error.kind, PolicyErrorKind::TooLarge);
}

// ---- LB-04: the bound after which a blocked job gives up its read token ---------------------

#[test]
fn lb_04_the_bound_on_a_blocked_jobs_token_is_required_and_has_to_make_sense() {
    let text = real(SECURITY_FILE);
    let line = "      revoke_when_blocked_after_s: 900";
    assert!(text.contains(line), "the real policy states the bound");
    // Absent: the loader refuses the file, so the worker cannot start without the bound.
    let without = replace_once(&text, &format!("{line}\n"), "");
    let error = refused(load_security_text(&without), "the bound is missing");
    assert!(
        error.message.contains("revoke_when_blocked_after_s"),
        "{error}"
    );
    // Zero, too small to be a wait at all, and larger than a day: each is a problem named by key.
    for (value, why) in [
        ("0", "zero"),
        ("59", "under a minute"),
        ("86401", "over a day"),
    ] {
        let changed = replace_once(
            &text,
            line,
            &format!("      revoke_when_blocked_after_s: {value}"),
        );
        let error = refused(load_security_text(&changed), why);
        assert_eq!(
            error.key.as_deref(),
            Some("credentials.github_app.installation_token.revoke_when_blocked_after_s"),
            "{why}: {error}"
        );
    }
    // The control: one minute and one day are the limits and they load.
    for value in ["60", "86400"] {
        let changed = replace_once(
            &text,
            line,
            &format!("      revoke_when_blocked_after_s: {value}"),
        );
        load_security_text(&changed).unwrap_or_else(|e| panic!("{value}: {e}"));
    }
}

#[test]
fn the_app_may_read_administration_and_never_hold_it_at_a_higher_level() {
    // The owner's decision of 2026-11-12: `administration: read` is required, so that the
    // preflight can read classic branch protection. Its level is also its ceiling, so the App
    // may not hold `administration: write`; `organization_administration` stays forbidden.
    let text = real(SECURITY_FILE);
    let line = "      administration: read";
    assert!(text.contains(line), "the real policy requires the read");
    assert!(text.contains("      - organization_administration\n"));
    assert!(
        !text.contains("      - administration\n"),
        "a permission is not both required and forbidden"
    );
    // Listed in both places: refused, by the key of the required entry.
    let both = replace_once(
        &text,
        "      - workflows ",
        "      - administration\n      - workflows ",
    );
    let error = refused(load_security_text(&both), "required and forbidden");
    assert_eq!(
        error.key.as_deref(),
        Some("credentials.github_app.permissions_required.administration"),
        "{error}"
    );
    assert!(
        error.message.contains("both required and forbidden"),
        "{error}"
    );
    // A level GitHub does not grant: refused, by key.
    let admin = replace_once(&text, line, "      administration: admin");
    let error = refused(load_security_text(&admin), "an unknown level");
    assert_eq!(
        error.key.as_deref(),
        Some("credentials.github_app.permissions_required.administration"),
        "{error}"
    );
    // The control: the real file loads.
    load_security_text(&text).expect("the real policy loads");
}

// ---- NT-POL-01: policy comes only from the protected source ---------------------------------

#[test]
fn negative_nt_pol_01_a_checkout_inside_a_job_workspace_is_refused() {
    let workspace = TempDir::new("workspace");
    workspace.write("policies/security.yaml", real(SECURITY_FILE));
    workspace.write("policies/approval.yaml", real(APPROVAL_FILE));
    // The workspace itself, and a directory below it.
    let error =
        ProtectedPolicySource::protected_default_branch(workspace.path(), &[workspace.path()])
            .expect_err("the workspace is untrusted");
    assert_eq!(error.kind, PolicyErrorKind::UntrustedLocation);
    workspace.write("repo/policies/security.yaml", real(SECURITY_FILE));
    let nested = workspace.path().join("repo");
    let error = ProtectedPolicySource::protected_default_branch(&nested, &[workspace.path()])
        .expect_err("below the workspace is untrusted");
    assert_eq!(error.kind, PolicyErrorKind::UntrustedLocation);
    // The same directory is fine when it is not listed as untrusted: the control is the list.
    ProtectedPolicySource::protected_default_branch(&nested, &[])
        .expect("not untrusted when not listed");
    // An untrusted root that does not exist excludes nothing.
    ProtectedPolicySource::protected_default_branch(&nested, &[Path::new("/no/such/workspace")])
        .expect("a missing untrusted root excludes nothing");
    // A path that climbs out and back in is resolved first.
    let sneaky: PathBuf = workspace.path().join("repo/../repo");
    let error = ProtectedPolicySource::protected_default_branch(&sneaky, &[workspace.path()])
        .expect_err("dot-dot is resolved before the check");
    assert_eq!(error.kind, PolicyErrorKind::UntrustedLocation);
}

#[cfg(unix)]
#[test]
fn negative_nt_pol_01_a_link_into_an_untrusted_place_is_resolved_and_refused() {
    let workspace = TempDir::new("workspace");
    workspace.write("repo/policies/security.yaml", real(SECURITY_FILE));
    let trusted = TempDir::new("trusted");
    let link = trusted.path().join("config");
    std::os::unix::fs::symlink(workspace.path().join("repo"), &link).expect("symlink");
    let error = ProtectedPolicySource::protected_default_branch(&link, &[workspace.path()])
        .expect_err("a link into the workspace is the workspace");
    assert_eq!(error.kind, PolicyErrorKind::UntrustedLocation);
}

#[cfg(unix)]
#[test]
fn negative_nt_pol_01_a_policy_file_that_is_a_symbolic_link_is_refused() {
    let elsewhere = TempDir::new("elsewhere");
    let target = elsewhere.write("evil.yaml", real(SECURITY_FILE));
    let dir = TempDir::new("policy-link");
    dir.write(APPROVAL_FILE, real(APPROVAL_FILE));
    fs::create_dir_all(dir.path().join("policies")).expect("mkdir");
    std::os::unix::fs::symlink(&target, dir.path().join(SECURITY_FILE)).expect("symlink");
    let source = ProtectedPolicySource::protected_default_branch(dir.path(), &[]).expect("source");
    let error = PolicyLoader::load_security(&source).expect_err("a link");
    assert_eq!(error.kind, PolicyErrorKind::Unavailable);
    assert!(error.message.contains("symbolic link"), "{error}");
}

#[test]
fn negative_nt_pol_01_a_missing_policy_is_an_error_and_there_is_no_default() {
    let dir = TempDir::new("no-policy");
    let source = ProtectedPolicySource::protected_default_branch(dir.path(), &[]).expect("source");
    for error in [
        PolicyLoader::load_security(&source)
            .map(|_| ())
            .expect_err("no security policy"),
        PolicyLoader::load_approval(&source)
            .map(|_| ())
            .expect_err("no approval policy"),
    ] {
        assert_eq!(error.kind, PolicyErrorKind::Unavailable);
        assert!(error.message.contains("cannot run jobs"), "{error}");
    }
    let missing_root =
        ProtectedPolicySource::protected_default_branch(&dir.path().join("absent"), &[])
            .expect_err("no checkout");
    assert_eq!(missing_root.kind, PolicyErrorKind::Unavailable);
}

#[test]
fn negative_nt_pol_01_only_the_two_fixed_file_names_are_read() {
    // A hostile near-copy sits next to the real file, as a builder's pull request might add. It
    // is never read, so the hash is the hash of the real file.
    let good = checkout(&real(SECURITY_FILE), &real(APPROVAL_FILE));
    let expected = PolicyLoader::load_security(&good.source)
        .expect("loads")
        .hash;
    let hostile = replace_once(
        &real(SECURITY_FILE),
        "max_file_bytes: 5242880",
        "max_file_bytes: 99999999999",
    );
    for name in [
        "policies/security.override.yaml",
        "policies/security.yml",
        "policies/security.yaml.new",
        "policies/local/security.yaml",
        ".factory/policies/security.yaml",
        "security.yaml",
    ] {
        good.dir.write(name, &hostile);
    }
    let again = PolicyLoader::load_security(&good.source).expect("still loads");
    assert_eq!(again.hash, expected);
}

#[test]
fn negative_nt_pol_01_a_file_that_wants_a_signed_release_is_refused_from_the_branch_source() {
    let text = replace_once(
        &real(SECURITY_FILE),
        "config_source: protected_default_branch",
        "config_source: signed_release",
    );
    let error = refused(
        load_security_text(&text),
        "a file that names another source",
    );
    assert_eq!(error.kind, PolicyErrorKind::WrongSource);
    assert_eq!(error.key.as_deref(), Some("policy.config_source"));
    assert_eq!(
        error.line,
        Some(line_of(&text, "config_source: signed_release"))
    );
}

#[test]
fn negative_nt_pol_01_the_loader_never_reads_the_environment() {
    // The loader has no environment fallback, because no code in this crate reads the
    // environment. A static scan of the crate's source is the proof, as ST-06 and the other static
    // checks are: setting a variable in a test would be an `unsafe` call, which this workspace
    // forbids.
    let src = repo_root().join("crates/contracts/src");
    let mut checked = 0usize;
    let files = rust_files(&src);
    for needed in ["policy/mod.rs", "loader.rs", "yaml/mod.rs", "registry.rs"] {
        assert!(
            files.iter().any(|f| f.ends_with(needed)),
            "the scan did not reach {needed}"
        );
    }
    for path in files {
        let text = read_text(&path);
        // Comments may name what is forbidden; only code counts.
        let text: String = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "std::env",
            "env::var",
            "env::args",
            "env::current_dir",
            "option_env!",
            "env!(",
        ] {
            assert!(
                !text.contains(forbidden),
                "{} uses `{forbidden}`; the policy loader must not read the environment",
                path.display()
            );
        }
        checked += 1;
    }
    assert!(checked >= 10, "only {checked} source files were scanned");
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current)
            .expect("read_dir")
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

// ---- The policy hash ------------------------------------------------------------------------

#[test]
fn the_policy_hash_ignores_layout_and_changes_with_content() {
    let original = real(SECURITY_FILE);
    let base = checkout(&original, &real(APPROVAL_FILE));
    let expected = PolicyLoader::load_security(&base.source).expect("loads");

    // Rewritten as JSON (which is YAML flow style): different layout, same document.
    let typed = serde_json::to_value(&expected.document).expect("to json");
    let as_json = checkout(
        &serde_json::to_string(&typed).expect("json text"),
        &real(APPROVAL_FILE),
    );
    let from_json = PolicyLoader::load_security(&as_json.source).expect("the JSON form loads");
    assert_eq!(from_json.hash, expected.hash, "JSON layout");
    assert_ne!(
        from_json.file_sha256, expected.file_sha256,
        "the bytes differ, the document does not"
    );

    // Rewritten as block YAML with every key quoted and keys sorted, and with comments gone.
    let as_block = checkout(&to_block_yaml(&typed), &real(APPROVAL_FILE));
    let from_block = PolicyLoader::load_security(&as_block.source).expect("the block form loads");
    assert_eq!(from_block.hash, expected.hash, "block layout");

    // Comments and blank lines do not matter either.
    let spaced = checkout(
        &format!("# a new comment\n\n{original}\n\n# another\n"),
        &real(APPROVAL_FILE),
    );
    assert_eq!(
        PolicyLoader::load_security(&spaced.source)
            .expect("loads")
            .hash,
        expected.hash
    );

    // One changed value changes the hash.
    let changed = checkout(
        &replace_once(
            &original,
            "max_file_bytes: 5242880",
            "max_file_bytes: 5242881",
        ),
        &real(APPROVAL_FILE),
    );
    assert_ne!(
        PolicyLoader::load_security(&changed.source)
            .expect("loads")
            .hash,
        expected.hash
    );

    // The same document hashed by a second route: canonical JSON of the typed value.
    assert_eq!(PolicyHash::of(&typed).expect("hash"), expected.hash);
}

// ---- ST-06 ----------------------------------------------------------------------------------

/// Every value under a key named `threats`, anywhere in the document.
fn collect_threats(node: &Node, found: &mut Vec<String>) {
    match &node.content {
        Content::Map(entries) => {
            for entry in entries {
                if entry.key == "threats"
                    && let Content::Seq(items) = &entry.value.content
                {
                    for item in items {
                        if let Content::Str(id) = &item.content {
                            found.push(id.clone());
                        }
                    }
                }
                collect_threats(&entry.value, found);
            }
        }
        Content::Seq(items) => items.iter().for_each(|i| collect_threats(i, found)),
        _ => {}
    }
}

/// The identifiers in the threat model's table (`| T-01 | ... |`).
fn known_threats() -> Vec<String> {
    let text = read_text(&repo_root().join("docs/security/threat-model.md"));
    let mut ids: Vec<String> = text
        .lines()
        .filter_map(|line| {
            let cell = line.strip_prefix("| T-")?.split('|').next()?.trim();
            (cell.len() == 2 && cell.bytes().all(|b| b.is_ascii_digit()))
                .then(|| format!("T-{cell}"))
        })
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[test]
fn st_06_policy_files_pass_the_parser_have_unique_keys_and_cite_only_known_threats() {
    let known = known_threats();
    assert!(
        known.len() >= 35,
        "the threat model lists {} threats",
        known.len()
    );
    for file in [SECURITY_FILE, APPROVAL_FILE] {
        let text = real(file);
        // Passes the parser: one document, no anchors, aliases, tags or merge keys, and unique keys.
        let document =
            yaml::read(&text, YamlLimits::POLICY).unwrap_or_else(|e| panic!("{file}: {e}"));
        // Every threat identifier exists in the threat model.
        let mut cited = Vec::new();
        collect_threats(document.root(), &mut cited);
        assert!(
            cited.len() >= 20,
            "{file} cites only {} threats",
            cited.len()
        );
        let unknown: Vec<&String> = cited.iter().filter(|id| !known.contains(id)).collect();
        assert!(
            unknown.is_empty(),
            "{file} cites threats the threat model does not list: {unknown:?}"
        );
    }
    // And the typed documents agree: loading succeeded for both.
    let source =
        ProtectedPolicySource::protected_default_branch(&repo_root(), &[]).expect("source");
    PolicyLoader::load_security(&source).expect("security loads");
    PolicyLoader::load_approval(&source).expect("approval loads");
}

#[test]
fn st_06_the_check_would_notice_an_unknown_threat_a_duplicate_key_or_an_anchor() {
    let known = known_threats();
    let mut cited = Vec::new();
    let text = format!("{}\nextra:\n  threats: [T-99]\n", real(SECURITY_FILE));
    // Reading succeeds only if the text is otherwise clean, so use a document that is.
    let document = yaml::read(&text, YamlLimits::POLICY).expect("clean YAML");
    collect_threats(document.root(), &mut cited);
    assert!(cited.iter().any(|id| id == "T-99") && !known.contains(&"T-99".to_owned()));
    // The parser half of the check.
    for (suffix, kind) in [
        ("\naudit: {}\n", YamlErrorKind::DuplicateKey),
        ("\nx: &a 1\n", YamlErrorKind::Anchor),
        ("\n<<: {a: 1}\n", YamlErrorKind::MergeKey),
    ] {
        let error = yaml::read(
            &format!("{}{suffix}", real(SECURITY_FILE)),
            YamlLimits::POLICY,
        )
        .expect_err(suffix);
        assert_eq!(error.kind, kind, "{suffix}");
    }
}

/// The text without the last occurrence of `line`: the original entry, once a copy was put earlier.
fn without_last(text: &str, line: &str) -> String {
    let at = text.rfind(line).expect("the line is in the text");
    let mut out = text.to_owned();
    out.replace_range(at..at + line.len(), "");
    out
}

/// ADR 0021, Decision 5: the MCP gateway is reachable from the troubleshooter profile alone. The
/// egress widening was approved by the owner for that profile only, so the check refuses the
/// entry, the network and the egress profile anywhere else.
#[test]
fn the_mcp_gateway_is_reachable_from_the_troubleshooter_profile_only() {
    let text = real(SECURITY_FILE);
    let gateway = text
        .lines()
        .find(|l| l.contains("id: mcp_gateway,"))
        .expect("the real policy lists the MCP gateway")
        .to_owned();
    let broker = "        - { id: model_broker, host: model-broker.sandbox.internal,";
    assert!(text.contains(broker), "the agent profile lists the broker");
    // The gateway entry moved into the agent profile.
    let in_agent = replace_once(&text, broker, &format!("{gateway}\n{broker}"));
    let in_agent = without_last(&in_agent, &format!("{gateway}\n"));
    let error = refused(load_security_text(&in_agent), "mcp_gateway in agent");
    assert_eq!(error.kind, PolicyErrorKind::Constraint, "{error}");
    assert!(
        error
            .key
            .as_deref()
            .is_some_and(|k| k.starts_with("egress.profiles.agent.allow")),
        "{error}"
    );
    // The fetch profile is refused the same way.
    let fetch = "        - { id: crates_index,";
    let in_fetch = replace_once(&text, fetch, &format!("{gateway}\n{fetch}"));
    let in_fetch = without_last(&in_fetch, &format!("{gateway}\n"));
    let error = refused(load_security_text(&in_fetch), "mcp_gateway in fetch_deps");
    assert_eq!(error.kind, PolicyErrorKind::Constraint, "{error}");
    // The agent sandbox profile cannot borrow the troubleshooter's egress profile or network.
    let agent_egress = "      network: model_broker_only\n      egress_profile: agent\n";
    let borrowed = replace_once(
        &text,
        agent_egress,
        "      network: model_broker_only\n      egress_profile: troubleshooter\n",
    );
    let error = refused(
        load_security_text(&borrowed),
        "agent with troubleshooter egress",
    );
    assert_eq!(
        error.key.as_deref(),
        Some("sandbox.profiles.agent.egress_profile"),
        "{error}"
    );
    let widened = replace_once(
        &text,
        agent_egress,
        "      network: model_broker_and_mcp_gateway\n      egress_profile: agent\n",
    );
    let error = refused(
        load_security_text(&widened),
        "agent with the gateway network",
    );
    assert_eq!(
        error.key.as_deref(),
        Some("sandbox.profiles.agent.network"),
        "{error}"
    );
    // The control: the real file loads with the gateway in the troubleshooter profile.
    load_security_text(&text).expect("the real policy loads");
}
