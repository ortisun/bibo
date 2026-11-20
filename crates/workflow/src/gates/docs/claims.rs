//! What the documents say about the program: the commands, flags and variables they name, and the
//! examples they show.
//!
//! The gate does not trust a name because a page writes it. It compares every flag, command and
//! environment variable a page names with two things the factory observed: the output of the
//! program's own `--help`, captured in the verify sandbox, and the names the source code at the
//! documented commit contains. A name found in neither is **invented**.
//!
//! An example is a command line in a console block (`$ program args`) with the output that
//! follows it. The gate runs the command against the built program and compares the output.

use std::collections::BTreeSet;

use super::markdown::scan;

/// What a page names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimKind {
    /// A flag such as `--json` or `-v`.
    Flag,
    /// A word that follows the program name, such as `count`.
    Command,
    /// An environment variable.
    EnvVar,
}

/// One name a page uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The page.
    pub file: String,
    /// The line.
    pub line: usize,
    /// What kind of name it is.
    pub kind: ClaimKind,
    /// The name.
    pub name: String,
}

/// One command a page shows, with the output it says the command prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Example {
    /// The page.
    pub file: String,
    /// The line of the command.
    pub line: usize,
    /// The arguments after the program name.
    pub args: Vec<String>,
    /// The command as written, for the report.
    pub written: String,
    /// The output the page shows, when it shows some.
    pub expected: Option<String>,
    /// False when the command needs a shell (a pipe, a redirect, a chain, a substitution), which
    /// the gate does not run.
    pub runnable: bool,
}

const CONSOLE: [&str; 6] = ["console", "sh", "bash", "shell", "shell-session", "text"];
const SHELL_SYNTAX: [&str; 9] = ["|", ">", "<", ">>", "&&", "||", ";", "&", "2>&1"];

/// Splits a command line into words, honouring single and double quotes. No expansion is made.
#[must_use]
pub fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => current.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started || !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (None, c) => current.push(c),
        }
    }
    if started || !current.is_empty() {
        out.push(current);
    }
    out
}

fn needs_a_shell(line: &str, words: &[String]) -> bool {
    line.contains("$(")
        || line.contains('`')
        || words
            .iter()
            .any(|word| SHELL_SYNTAX.contains(&word.as_str()))
}

fn flag_of(word: &str) -> Option<String> {
    let name = word.split('=').next().unwrap_or(word);
    let long = name.strip_prefix("--").is_some_and(|rest| {
        rest.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && rest
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    });
    let short = name.len() == 2
        && name.starts_with('-')
        && name.chars().nth(1).is_some_and(|c| c.is_ascii_alphabetic());
    (long || short).then(|| name.to_owned())
}

fn env_like(text: &str) -> bool {
    text.len() >= 3
        && text.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && text
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Every flag, command and variable the pages name about `program`.
#[must_use]
pub fn claims(pages: &[(&str, &str)], program: &str) -> Vec<Claim> {
    let mut found = Vec::new();
    for (path, text) in pages {
        let page = scan(text);
        let mut push = |line: usize, kind: ClaimKind, name: String| {
            found.push(Claim {
                file: (*path).to_owned(),
                line,
                kind,
                name,
            });
        };
        for block in page
            .blocks
            .iter()
            .filter(|b| CONSOLE.contains(&b.lang.as_str()))
        {
            for (offset, line) in block.body.lines().enumerate() {
                let Some(command) = line.trim_start().strip_prefix("$ ") else {
                    continue;
                };
                let tokens = words(command);
                if tokens.first().map(String::as_str) != Some(program) {
                    continue;
                }
                for word in &tokens[1..] {
                    if let Some(flag) = flag_of(word) {
                        push(block.line + 1 + offset, ClaimKind::Flag, flag);
                    }
                }
            }
        }
        for span in &page.spans {
            let tokens = words(&span.text);
            let Some(first) = tokens.first() else {
                continue;
            };
            if first == program {
                for (index, word) in tokens.iter().enumerate().skip(1) {
                    if let Some(flag) = flag_of(word) {
                        push(span.line, ClaimKind::Flag, flag);
                    } else if index == 1
                        && word.chars().all(|c| c.is_ascii_lowercase() || c == '-')
                        && !word.is_empty()
                    {
                        push(span.line, ClaimKind::Command, word.clone());
                    }
                }
            } else if tokens.len() == 1 && flag_of(first).is_some() && first.as_str() != "--" {
                push(
                    span.line,
                    ClaimKind::Flag,
                    flag_of(first).unwrap_or_default(),
                );
            } else if tokens.len() == 1 && env_like(first) {
                let context = span.context.to_lowercase();
                if context.contains("environment variable")
                    || context.contains("env var")
                    || context.contains("variable")
                {
                    push(span.line, ClaimKind::EnvVar, first.clone());
                }
            }
        }
    }
    found
}

/// The commands the pages show for `program`.
#[must_use]
pub fn examples(pages: &[(&str, &str)], program: &str) -> Vec<Example> {
    let mut found = Vec::new();
    for (path, text) in pages {
        let page = scan(text);
        for block in page
            .blocks
            .iter()
            .filter(|b| CONSOLE.contains(&b.lang.as_str()))
        {
            let lines: Vec<&str> = block.body.lines().collect();
            let mut at = 0;
            while at < lines.len() {
                let Some(command) = lines[at].trim_start().strip_prefix("$ ") else {
                    at += 1;
                    continue;
                };
                let start = at;
                at += 1;
                let mut output: Vec<&str> = Vec::new();
                while at < lines.len() && !lines[at].trim_start().starts_with("$ ") {
                    output.push(lines[at]);
                    at += 1;
                }
                let tokens = words(command);
                if tokens.first().map(String::as_str) != Some(program) {
                    continue;
                }
                let expected = output.join("\n");
                found.push(Example {
                    file: (*path).to_owned(),
                    line: block.line + 1 + start,
                    args: tokens[1..].to_vec(),
                    written: command.trim().to_owned(),
                    expected: (!expected.trim().is_empty()).then_some(expected),
                    runnable: !needs_a_shell(command, &tokens),
                });
            }
        }
    }
    found
}

/// The flags a program's own help text lists: every word that starts with `--` or is a single
/// letter after one dash, at the start of a word.
#[must_use]
pub fn flags_of_help(help: &str) -> BTreeSet<String> {
    let mut flags = BTreeSet::new();
    for word in help.split(|c: char| {
        c.is_whitespace() || c == ',' || c == '[' || c == ']' || c == '<' || c == '>' || c == '|'
    }) {
        if let Some(flag) = flag_of(word.trim_end_matches(['.', ':', ';'])) {
            flags.insert(flag);
        }
    }
    flags
}

/// Whether a word appears in the help text as a word of its own.
#[must_use]
pub fn help_mentions(help: &str, word: &str) -> bool {
    help.split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_'))
        .any(|w| w == word)
}

/// The names a page uses that neither the help text nor the source has.
#[must_use]
pub fn invented(claims: &[Claim], help: Option<&str>, source_env: &BTreeSet<String>) -> Vec<Claim> {
    let listed = help.map(flags_of_help).unwrap_or_default();
    claims
        .iter()
        .filter(|claim| match claim.kind {
            ClaimKind::Flag => claim.name != "--help" && !listed.contains(&claim.name),
            ClaimKind::Command => !help.is_some_and(|text| help_mentions(text, &claim.name)),
            ClaimKind::EnvVar => {
                !source_env.contains(&claim.name)
                    && !help.is_some_and(|text| help_mentions(text, &claim.name))
            }
        })
        .cloned()
        .collect()
}

/// The names the source code reads from the environment: every upper-case string literal on a
/// line that mentions `env`.
#[must_use]
pub fn env_names_in_source(text: &str) -> BTreeSet<String> {
    text.lines().flat_map(super::plan::env_in).collect()
}

/// Output as the gate compares it: trailing blanks of each line and of the whole output removed.
#[must_use]
pub fn normalized(output: &str) -> String {
    output
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = "# wc-rs\n\nUse `--json` to print JSON, or `wc-rs --count` for counts. Set the environment variable `WC_WIDTH`.\n\n```console\n$ wc-rs --json file.txt\n{\"lines\":1}\n$ cargo build --release\n```\n";

    #[test]
    fn claims_come_from_console_lines_and_inline_code() {
        let found = claims(&[("README.md", PAGE)], "wc-rs");
        let names: Vec<(ClaimKind, &str)> =
            found.iter().map(|c| (c.kind, c.name.as_str())).collect();
        assert!(names.contains(&(ClaimKind::Flag, "--json")));
        assert!(names.contains(&(ClaimKind::Flag, "--count")));
        assert!(names.contains(&(ClaimKind::EnvVar, "WC_WIDTH")));
        // `cargo build --release` is another program's command line.
        assert!(!names.contains(&(ClaimKind::Flag, "--release")));
    }

    #[test]
    fn a_name_the_help_and_the_source_lack_is_invented() {
        let found = claims(&[("README.md", PAGE)], "wc-rs");
        let help = "Usage: wc-rs [OPTIONS] FILE\n\nOptions:\n  --json   Print JSON\n  -h, --help\n";
        let missing = invented(&found, Some(help), &BTreeSet::new());
        let names: Vec<&str> = missing.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"--count"));
        assert!(names.contains(&"WC_WIDTH"));
        assert!(!names.contains(&"--json"));
        let env: BTreeSet<String> = ["WC_WIDTH".to_owned()].into();
        assert!(
            !invented(&found, Some(help), &env)
                .iter()
                .any(|c| c.name == "WC_WIDTH")
        );
    }

    #[test]
    fn examples_carry_their_output_and_say_when_they_need_a_shell() {
        let page = "```console\n$ wc-rs --json a.txt\n{\"lines\":1}\n$ wc-rs a.txt | sort\n```\n";
        let found = examples(&[("README.md", page)], "wc-rs");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].args, ["--json", "a.txt"]);
        assert_eq!(found[0].expected.as_deref(), Some("{\"lines\":1}"));
        assert!(found[0].runnable);
        assert!(!found[1].runnable);
    }

    #[test]
    fn quoted_arguments_stay_whole() {
        assert_eq!(
            words("wc-rs 'a b.txt' \"c d\""),
            ["wc-rs", "a b.txt", "c d"]
        );
    }

    #[test]
    fn output_is_compared_without_trailing_blanks() {
        assert_eq!(normalized("a  \nb\n\n"), normalized("a\nb"));
        assert_ne!(normalized("a\nb"), normalized("a\nc"));
    }
}
