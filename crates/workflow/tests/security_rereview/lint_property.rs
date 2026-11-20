//! Property tests of the host-side lint rule (RR-11 to RR-13, `lint_relaxation`).
//!
//! The generators write the same attribute or the same lint table in many spellings: white space,
//! newlines and comments between every two tokens of an attribute, the attribute after code or in
//! a macro body, a `cfg_attr` around it, and a lint table as a header, a spaced header, a dotted key
//! at the top of the file, an inline table, quoted keys or a table with a `level`. Two properties
//! are asserted over all of them:
//!
//! * a generated relaxation (a new suppression, a lint dropped from a `deny` list, a `forbid`
//!   written as `deny`, a `deny` written as `warn`, a `deny` removed, a lint new at `allow`, a level
//!   lowered, an entry removed) is always found;
//! * a generated tightening (a level raised, a `deny` or `forbid` added, a suppression removed, a
//!   list that grows) and a change of spelling alone are never found, whatever decoys the file holds
//!   in comments and string literals.

use factory_ports::workspace::ChangeKind;
use factory_workflow::gates::scope::FileChange;
use factory_workflow::gates::scope::lint::relaxed;
use proptest::prelude::*;

fn modified(path: &str, before: &str, after: &str) -> FileChange {
    FileChange {
        path: path.to_owned(),
        kind: ChangeKind::Modified,
        before: Some(before.as_bytes().to_vec()),
        after: Some(after.as_bytes().to_vec()),
        readable: true,
    }
}

fn found(path: &str, before: &str, after: &str) -> bool {
    !relaxed(&[modified(path, before, after)]).is_empty()
}

// ------------------------------------------------------------------------------------------
// Rust attributes
// ------------------------------------------------------------------------------------------

const LINTS: [&str; 8] = [
    "dead_code",
    "unused",
    "warnings",
    "clippy::all",
    "clippy::unwrap_used",
    "unsafe_code",
    "missing_docs",
    "clippy::too_many_lines",
];

/// What may stand between two tokens: nothing, blanks, newlines, comments.
fn blank() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "",
        " ",
        "  ",
        "\t",
        "\n",
        "\r\n",
        " \n ",
        "\n\n",
        "/* c */",
        "// line\n",
        "/* multi\nline */",
        " /* a /* nested */ b */ ",
    ])
    .prop_map(str::to_owned)
}

/// Twelve draws of blank space, used one by one.
#[derive(Debug, Clone)]
struct Spacing(Vec<String>);

impl Spacing {
    fn at(&self, index: usize) -> &str {
        &self.0[index % self.0.len()]
    }
}

fn spacing() -> impl Strategy<Value = Spacing> {
    prop::collection::vec(blank(), 12).prop_map(Spacing)
}

/// One attribute, `#[name(lint, lint)]` or `#![..]`, with the spacing drawn, in a `cfg_attr` or not.
fn attribute(
    space: &Spacing,
    inner: bool,
    name: &str,
    lints: &[&str],
    conditional: bool,
) -> String {
    let separator = format!("{},{}", space.at(5), space.at(6));
    let mut body = format!(
        "{name}{}({}{}{})",
        space.at(3),
        space.at(4),
        lints.join(&separator),
        space.at(7)
    );
    if conditional {
        body = format!(
            "cfg_attr{}({}test{},{}{})",
            space.at(8),
            space.at(9),
            space.at(10),
            space.at(11),
            body
        );
    }
    format!(
        "#{}{}{}[{}{}{}]",
        space.at(0),
        if inner { "!" } else { "" },
        space.at(1),
        space.at(2),
        body,
        space.at(3)
    )
}

/// The attribute in one of four places: on its own line, after code on the line, in a macro body,
/// after a statement in a function.
fn in_context(context: u8, attribute: &str) -> String {
    match context % 4 {
        0 => format!("{attribute}\nfn f() {{}}\n"),
        1 => format!("fn a() {{}} {attribute} fn b() {{}}\n"),
        2 => format!("macro_rules! m {{ () => {{ {attribute} fn hidden() {{}} }}; }}\nm!();\n"),
        _ => format!("fn f() {{ let a = 1; {attribute} let b = 2; }}\n"),
    }
}

/// Text that holds attributes which are not attributes: a comment, a block comment, strings, a raw
/// string, a doc comment. The same in both versions of a file, and sometimes the tightening adds
/// more of it.
const DECOYS: &str = "// #![allow(warnings)]\nconst A: &str = \"#![allow(dead_code)]\";\n/* #[allow(unused)] */\nconst B: &str = r#\"#[allow(unused)] \"quoted\" \"#;\n/// #![allow(warnings)]\nfn decoy() {}\n";

fn lints(minimum: usize) -> impl Strategy<Value = Vec<&'static str>> {
    prop::sample::subsequence(LINTS.to_vec(), minimum..=4)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    /// A new suppression is found in every spelling and place.
    #[test]
    fn a_new_suppression_is_always_found(
        space in spacing(),
        inner in any::<bool>(),
        name in prop::sample::select(vec!["allow", "expect"]),
        names in lints(1),
        conditional in any::<bool>(),
        context in 0u8..4,
        decoys in any::<bool>(),
    ) {
        let base = if decoys { DECOYS } else { "" };
        let attribute = attribute(&space, inner, name, &names, conditional);
        let after = format!("{base}{}", in_context(context, &attribute));
        prop_assert!(found("src/lib.rs", base, &after), "{after:?}");
    }

    /// A lint dropped from a list, a level written one step lower, and a removed attribute are
    /// found, whatever the spacing of either version.
    #[test]
    fn a_lowered_level_is_always_found(
        before_space in spacing(),
        after_space in spacing(),
        inner in any::<bool>(),
        names in lints(2),
        step in 0u8..6,
        context in 0u8..4,
    ) {
        let (from, to, keep): (&str, Option<&str>, usize) = match step % 6 {
            0 => ("deny", Some("deny"), names.len() - 1),
            1 => ("forbid", Some("forbid"), names.len() - 1),
            2 => ("forbid", Some("deny"), names.len()),
            3 => ("deny", Some("warn"), names.len()),
            4 => ("forbid", Some("warn"), names.len()),
            _ => ("deny", None, 0),
        };
        let before = in_context(context, &attribute(&before_space, inner, from, &names, false));
        let after = match to {
            Some(level) => in_context(context, &attribute(&after_space, inner, level, &names[..keep], false)),
            None => "fn f() {}\n".to_owned(),
        };
        prop_assert!(found("src/lib.rs", &before, &after), "{before:?} -> {after:?}");
    }

    /// A level raised, a stronger attribute added, a suppression removed, a list that grows: never
    /// found. Decoys that gain `allow` attributes in comments and strings change nothing either.
    #[test]
    fn a_tightening_is_never_found(
        before_space in spacing(),
        after_space in spacing(),
        inner in any::<bool>(),
        names in lints(1),
        step in 0u8..7,
        context in 0u8..4,
    ) {
        let (before_level, after_level): (Option<&str>, Option<&str>) = match step % 7 {
            0 => (Some("warn"), Some("deny")),
            1 => (Some("deny"), Some("forbid")),
            2 => (Some("warn"), Some("forbid")),
            3 => (None, Some("deny")),
            4 => (None, Some("forbid")),
            5 => (Some("allow"), None),
            _ => (Some("expect"), Some("deny")),
        };
        let render = |level: Option<&str>, space: &Spacing, extra: &str| {
            let body = level.map_or_else(
                || "fn f() {}\n".to_owned(),
                |level| in_context(context, &attribute(space, inner, level, &names, false)),
            );
            format!("{DECOYS}{extra}{body}")
        };
        let before = render(before_level, &before_space, "");
        let after = render(after_level, &after_space, "// #![allow(more)]\nconst C: &str = \"#[expect(x)]\";\n");
        prop_assert!(!found("src/lib.rs", &before, &after), "{before:?} -> {after:?}");
    }

    /// A list that gains a lint is a tightening; the same list written again in other spacing is
    /// no change at all.
    #[test]
    fn a_longer_list_and_a_respelled_one_are_never_found(
        before_space in spacing(),
        after_space in spacing(),
        inner in any::<bool>(),
        names in lints(2),
        level in prop::sample::select(vec!["warn", "deny", "forbid"]),
        context in 0u8..4,
    ) {
        let before = in_context(context, &attribute(&before_space, inner, level, &names[..names.len() - 1], false));
        let longer = in_context(context, &attribute(&after_space, inner, level, &names, false));
        prop_assert!(!found("src/lib.rs", &before, &longer), "{before:?} -> {longer:?}");
        let same = in_context(context, &attribute(&before_space, inner, level, &names, false));
        let respelled = in_context(context, &attribute(&after_space, inner, level, &names, false));
        prop_assert!(!found("src/lib.rs", &same, &respelled), "{same:?} -> {respelled:?}");
    }
}

// ------------------------------------------------------------------------------------------
// Lint tables
// ------------------------------------------------------------------------------------------

/// A lint of a table: its tool, its name and its level.
type Entry = (&'static str, &'static str, &'static str);

const TOOLS: [(&str, [&str; 3]); 2] = [
    ("rust", ["dead_code", "unused", "unsafe_code"]),
    ("clippy", ["all", "unwrap_used", "too_many_lines"]),
];

const LEVELS: [&str; 4] = ["allow", "warn", "deny", "forbid"];

fn rank(level: &str) -> usize {
    LEVELS.iter().position(|known| *known == level).unwrap_or(0)
}

/// The lints a table sets: for each of the six lints, a level or none.
fn table() -> impl Strategy<Value = Vec<Option<usize>>> {
    prop::collection::vec(prop::option::of(0usize..4), 6)
}

fn entries(levels: &[Option<usize>]) -> Vec<Entry> {
    let mut found = Vec::new();
    for (tool_index, (tool, names)) in TOOLS.iter().enumerate() {
        for (name_index, name) in names.iter().enumerate() {
            if let Some(level) = levels[tool_index * 3 + name_index] {
                found.push((*tool, *name, LEVELS[level]));
            }
        }
    }
    found
}

/// The entries of one tool.
fn of<'a>(entries: &'a [Entry], tool: &'a str) -> impl Iterator<Item = &'a Entry> + 'a {
    entries.iter().filter(move |entry| entry.0 == tool)
}

/// Seven ways to write the same lint levels in a manifest. All parse the same in cargo.
fn manifest(entries: &[Entry], syntax: u8) -> String {
    let mut text = String::new();
    let tools: Vec<&str> = TOOLS
        .iter()
        .map(|(tool, _)| *tool)
        .filter(|tool| entries.iter().any(|entry| entry.0 == *tool))
        .collect();

    match syntax % 7 {
        0 => {
            for tool in &tools {
                text.push_str(&format!("[lints.{tool}]\n"));
                for (_, name, level) in of(entries, tool) {
                    text.push_str(&format!("{name} = \"{level}\"\n"));
                }
            }
        }
        1 => {
            for tool in &tools {
                text.push_str(&format!("[ lints . {tool} ]\n"));
                for (_, name, level) in of(entries, tool) {
                    text.push_str(&format!(" {name}  =  '{level}'\n"));
                }
            }
        }
        2 => {
            for (tool, name, level) in entries {
                text.push_str(&format!("lints.{tool}.{name} = \"{level}\"\n"));
            }
        }
        3 => {
            for (tool, name, level) in entries {
                text.push_str(&format!("lints . {tool} . {name} = '{level}'\n"));
            }
        }
        4 => {
            if !tools.is_empty() {
                text.push_str("[lints]\n");
            }
            for tool in &tools {
                let items: Vec<String> = of(entries, tool)
                    .map(|(_, name, level)| format!("{name} = \"{level}\""))
                    .collect();
                text.push_str(&format!("{tool} = {{ {} }}\n", items.join(", ")));
            }
        }
        5 => {
            for tool in &tools {
                text.push_str(&format!("[\"lints\".\"{tool}\"]\n"));
                for (_, name, level) in of(entries, tool) {
                    text.push_str(&format!("\"{name}\" = \"{level}\"\n"));
                }
            }
        }
        _ => {
            for tool in &tools {
                text.push_str(&format!("[lints.{tool}]\n"));
                for (_, name, level) in of(entries, tool) {
                    text.push_str(&format!(
                        "{name} = {{ level = \"{level}\", priority = 0 }}\n"
                    ));
                }
            }
        }
    }
    // The dotted keys of the top of the file must come before any header.
    format!("{text}\n[package]\nname = \"x\"\nversion = \"0.1.0\"\n")
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    /// A lint new at `allow`, a level lowered and a `deny` or `forbid` removed are found, in any
    /// spelling of the table before and after.
    #[test]
    fn a_relaxed_table_is_always_found(
        before_levels in table(),
        index in 0usize..6,
        change in 0u8..3,
        before_syntax in 0u8..7,
        after_syntax in 0u8..7,
    ) {
        let mut before_levels = before_levels;
        let mut after_levels = before_levels.clone();
        match change % 3 {
            // New at allow.
            0 => {
                before_levels[index] = None;
                after_levels[index] = Some(0);
            }
            // Lowered by one or more steps.
            1 => {
                before_levels[index] = Some(rank("warn") + (index % 2));
                after_levels[index] = Some(rank("allow") + (index % 2));
            }
            // A deny or a forbid removed.
            _ => {
                before_levels[index] = Some(2 + (index % 2));
                after_levels[index] = None;
            }
        }
        let before = manifest(&entries(&before_levels), before_syntax);
        let after = manifest(&entries(&after_levels), after_syntax);
        prop_assert!(found("Cargo.toml", &before, &after), "{before:?} -> {after:?}");
    }

    /// A level raised, an entry added above `allow`, an `allow` removed, and the same table written
    /// in another spelling are never found.
    #[test]
    fn a_tightened_or_respelled_table_is_never_found(
        before_levels in table(),
        index in 0usize..6,
        change in 0u8..4,
        before_syntax in 0u8..7,
        after_syntax in 0u8..7,
    ) {
        let mut before_levels = before_levels;
        let mut after_levels = before_levels.clone();
        match change % 4 {
            // Raised.
            0 => {
                before_levels[index] = Some(1);
                after_levels[index] = Some(2 + (index % 2));
            }
            // New at deny or forbid.
            1 => {
                before_levels[index] = None;
                after_levels[index] = Some(2 + (index % 2));
            }
            // An allow removed.
            2 => {
                before_levels[index] = Some(0);
                after_levels[index] = None;
            }
            // Nothing changes but the spelling.
            _ => {}
        }
        let before = manifest(&entries(&before_levels), before_syntax);
        let after = manifest(&entries(&after_levels), after_syntax);
        prop_assert!(!found("Cargo.toml", &before, &after), "{before:?} -> {after:?}");
    }
}
