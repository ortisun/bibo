//! What the documents say about the program: the commands, flags and variables they name, and the
//! examples they show.
//!
//! The gate does not trust a name because a page writes it. It compares every flag, command and
//! environment variable a page names with two things the factory observed: the output of the
//! program's own `--help`, captured in the verify sandbox, and the names the source code at the
//! documented commit contains. A name found in neither is **invented**.
//!
//! An example is a command of the program that a block shows, with the output the page shows for
//! it (documentation policy 9.10). Two forms are read: the prompt form, a `$ program args` line
//! followed by its output in the same block, and the script form, a `sh`, `bash`, `shell` or
//! `zsh` block of bare command lines followed by a `text` or `output` block. A command may be fed
//! by one `printf` or `echo` through a pipe; the factory works out those bytes and the program
//! reads them on standard input. The gate runs the program without a shell, so every other
//! command that names the program is kept as an example with a [`Refusal`], which the check
//! reports. An example the gate did not run is never passed.

use std::collections::BTreeSet;

use super::markdown::{Block, Scan, scan};

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

/// Why the gate does not run an example that names the program. The check reports it, so an
/// example that did not run is never passed (documentation policy 9.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The command needs a shell: a pipe into another program, a redirect, a chain, a
    /// substitution, a glob, a variable, a continued line, or a `printf` or `echo` the gate does
    /// not read.
    NeedsAShell,
    /// The command is one of several commands of the program in a script block that an output
    /// block follows, so the gate cannot tell which command printed that output.
    OutputNotPaired,
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
    /// The bytes the program reads on standard input, worked out from the `printf` or `echo`
    /// the page pipes into it. `None` when nothing is piped in.
    pub stdin: Option<Vec<u8>>,
    /// The command as written, for the report.
    pub written: String,
    /// The output the page shows, when it shows some.
    pub expected: Option<String>,
    /// Why the gate does not run it. `None` for an example the gate runs.
    pub refusal: Option<Refusal>,
}

impl Example {
    /// True when the gate runs the example.
    #[must_use]
    pub fn runnable(&self) -> bool {
        self.refusal.is_none()
    }
}

/// The languages of a block whose `$ ` lines are commands (the prompt form).
const PROMPT_FORM: [&str; 7] = [
    "console",
    "shell-session",
    "sh",
    "bash",
    "shell",
    "zsh",
    "text",
];
/// The languages of a block whose lines are commands when it has no `$ ` line (the script form).
const SCRIPT_FORM: [&str; 4] = ["sh", "bash", "shell", "zsh"];
/// The languages of a block that shows the output of the script block before it.
const OUTPUT_FORM: [&str; 4] = ["text", "output", "plaintext", "txt"];
/// The marker of a command line in the prompt form.
const PROMPT: &str = "$ ";

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

/// A command line read the way a POSIX shell reads its words, with nothing expanded: the
/// commands of its pipeline, each a list of words, and whether anything in it needs a shell.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommandLine {
    /// The commands the pipe characters separate, in order. A line with no pipe has one.
    pub pipeline: Vec<Vec<String>>,
    /// True when the line holds something only a shell can do: a redirect, a chain, a background
    /// `&`, a substitution, a variable, a glob, a `~`, an unclosed quote or a continued line.
    pub needs_a_shell: bool,
}

/// Ends the word being read, if one was started, and adds it to the command.
fn end_word(word: &mut String, started: &mut bool, command: &mut Vec<String>) {
    if *started || !word.is_empty() {
        command.push(std::mem::take(word));
        *started = false;
    }
}

/// Reads one command line. Single quotes keep every character. Double quotes keep every
/// character but `$` and the backquote, which need a shell; inside them a backslash before `$`,
/// a backquote, `"` or `\` escapes it, and any other backslash is kept. Outside quotes a
/// backslash escapes the next character, and a `#` at the start of a word begins a comment.
#[must_use]
pub fn read_command(line: &str) -> CommandLine {
    let mut read = CommandLine::default();
    let mut command: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                started = true;
                let mut closed = false;
                for inner in chars.by_ref() {
                    if inner == '\'' {
                        closed = true;
                        break;
                    }
                    word.push(inner);
                }
                read.needs_a_shell |= !closed;
            }
            '"' => {
                started = true;
                let mut closed = false;
                while let Some(inner) = chars.next() {
                    match inner {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => match chars.peek().copied() {
                            Some(next @ ('$' | '`' | '"' | '\\')) => {
                                word.push(next);
                                chars.next();
                            }
                            Some(_) => word.push('\\'),
                            None => read.needs_a_shell = true,
                        },
                        '$' | '`' => {
                            read.needs_a_shell = true;
                            word.push(inner);
                        }
                        other => word.push(other),
                    }
                }
                read.needs_a_shell |= !closed;
            }
            '\\' => match chars.next() {
                Some(next) => {
                    started = true;
                    word.push(next);
                }
                // A backslash at the end continues the command on the next line.
                None => read.needs_a_shell = true,
            },
            '#' if word.is_empty() && !started => break,
            '|' => {
                if chars.peek() == Some(&'|') {
                    read.needs_a_shell = true;
                    chars.next();
                }
                end_word(&mut word, &mut started, &mut command);
                read.pipeline.push(std::mem::take(&mut command));
            }
            '>' | '<' | ';' | '&' | '$' | '`' | '(' | ')' | '*' | '?' | '[' => {
                read.needs_a_shell = true;
                word.push(c);
            }
            '~' if word.is_empty() && !started => {
                read.needs_a_shell = true;
                word.push(c);
            }
            c if c.is_whitespace() => end_word(&mut word, &mut started, &mut command),
            c => word.push(c),
        }
    }
    end_word(&mut word, &mut started, &mut command);
    read.pipeline.push(command);
    // An empty command next to a pipe is a syntax error of the shell.
    if read.pipeline.len() > 1 && read.pipeline.iter().any(Vec::is_empty) {
        read.needs_a_shell = true;
    }
    read
}

/// A word that sets a variable for the command after it, such as `LANG=C`.
fn assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The command of a pipeline that names `program`: its index, whether variables are set before
/// it, and its words from the program name on. `None` when no command of the pipeline names it.
fn naming<'a>(read: &'a CommandLine, program: &str) -> Option<(usize, bool, &'a [String])> {
    read.pipeline.iter().enumerate().find_map(|(index, words)| {
        let assigned = words.iter().take_while(|word| assignment(word)).count();
        let rest = words.get(assigned..)?;
        (rest.first().map(String::as_str) == Some(program)).then_some((index, assigned > 0, rest))
    })
}

/// The bytes `printf FORMAT` prints, for one format argument whose only escapes are `\n`, `\t`,
/// `\r`, `\\` and `%%`. `None` for any other escape or conversion, or for any other number of
/// arguments, because shells do not agree on them (documentation policy 9.10).
fn printf_bytes(arguments: &[String]) -> Option<Vec<u8>> {
    let [format] = arguments else {
        return None;
    };
    let mut out = String::with_capacity(format.len());
    let mut chars = format.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(match chars.next()? {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '\\' => '\\',
                _ => return None,
            }),
            '%' => match chars.next()? {
                '%' => out.push('%'),
                _ => return None,
            },
            other => out.push(other),
        }
    }
    Some(out.into_bytes())
}

/// The bytes `echo WORDS` or `echo -n WORDS` prints: the words joined by one space, and a newline
/// unless `-n` comes first. `None` for any other option or for a word with a backslash, because
/// shells do not agree on them (documentation policy 9.10).
fn echo_bytes(arguments: &[String]) -> Option<Vec<u8>> {
    let (newline, words) = match arguments.first().map(String::as_str) {
        Some("-n") => (false, &arguments[1..]),
        _ => (true, arguments),
    };
    if words
        .iter()
        .any(|word| word.contains('\\') || (word.starts_with('-') && word.len() > 1))
    {
        return None;
    }
    let mut out = words.join(" ");
    if newline {
        out.push('\n');
    }
    Some(out.into_bytes())
}

/// What the gate makes of a command line that names `program`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Understood {
    /// The arguments after the program name.
    pub args: Vec<String>,
    /// The bytes piped into the program, when a `printf` or `echo` the gate reads feeds it.
    pub stdin: Option<Vec<u8>>,
    /// True when the gate cannot run it without a shell.
    pub needs_a_shell: bool,
}

/// Reads a command line that may name `program`: the program alone, or fed by one `printf` or
/// `echo` through a pipe. `None` when no command of the line names the program; every other
/// line that names it needs a shell (documentation policy 9.10).
#[must_use]
pub fn understand(command: &str, program: &str) -> Option<Understood> {
    let read = read_command(command);
    let (index, assigned, words) = naming(&read, program)?;
    let args = words[1..].to_vec();
    let refused = |args: Vec<String>| Understood {
        args,
        stdin: None,
        needs_a_shell: true,
    };
    let stdin = match (read.pipeline.len(), index) {
        (1, _) => None,
        // `printf ... | program` or `echo ... | program`: the factory works out the input.
        (2, 1) => {
            let source = &read.pipeline[0];
            let bytes = match source.first().map(String::as_str) {
                Some("printf") => printf_bytes(&source[1..]),
                Some("echo") => echo_bytes(&source[1..]),
                _ => None,
            };
            match bytes {
                Some(bytes) => Some(bytes),
                None => return Some(refused(args)),
            }
        }
        _ => return Some(refused(args)),
    };
    Some(Understood {
        args,
        stdin,
        needs_a_shell: read.needs_a_shell || assigned,
    })
}

/// One command of the program that a block shows, with where it is and how it was written.
struct Shown {
    line: usize,
    written: String,
    understood: Understood,
}

fn shown(line: usize, command: &str, program: &str) -> Option<Shown> {
    Some(Shown {
        line,
        written: command.trim().to_owned(),
        understood: understand(command, program)?,
    })
}

/// True when a block holds a line in the prompt form.
fn has_prompt_lines(block: &Block) -> bool {
    block
        .body
        .lines()
        .any(|line| line.trim_start().starts_with(PROMPT))
}

/// The commands of the program a block shows in the prompt form, each with the lines after it up
/// to the next command line.
fn prompt_form(block: &Block, program: &str) -> Vec<(Shown, String)> {
    let lines: Vec<&str> = block.body.lines().collect();
    let mut found = Vec::new();
    let mut at = 0;
    while at < lines.len() {
        let Some(command) = lines[at].trim_start().strip_prefix(PROMPT) else {
            at += 1;
            continue;
        };
        let start = at;
        at += 1;
        let mut output: Vec<&str> = Vec::new();
        while at < lines.len() && !lines[at].trim_start().starts_with(PROMPT) {
            output.push(lines[at]);
            at += 1;
        }
        if let Some(command) = shown(block.line + 1 + start, command, program) {
            found.push((command, output.join("\n")));
        }
    }
    found
}

/// The commands of the program a block shows in the script form: every line that names it, with
/// empty lines and comment lines left out.
fn script_form(block: &Block, program: &str) -> Vec<Shown> {
    block
        .body
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let line = line.trim_start();
            !line.is_empty() && !line.starts_with('#')
        })
        .filter_map(|(offset, line)| shown(block.line + 1 + offset, line, program))
        .collect()
}

/// Every command of the program a page shows, in either form, with the output the page shows
/// for it and why the gate refuses it, if it does. A script block is paired with the output block
/// right after it when no heading stands between them (documentation policy 9.10).
fn shown_on(page: &Scan, program: &str) -> Vec<(Shown, Option<String>, Option<Refusal>)> {
    let mut found = Vec::new();
    for (index, block) in page.blocks.iter().enumerate() {
        let lang = block.lang.as_str();
        if has_prompt_lines(block) {
            if PROMPT_FORM.contains(&lang) {
                for (command, output) in prompt_form(block, program) {
                    let expected = (!output.trim().is_empty()).then_some(output);
                    found.push((command, expected, None));
                }
            }
            continue;
        }
        if !SCRIPT_FORM.contains(&lang) {
            continue;
        }
        let commands = script_form(block, program);
        let output = page.blocks.get(index + 1).filter(|next| {
            OUTPUT_FORM.contains(&next.lang.as_str())
                && !has_prompt_lines(next)
                && !page
                    .headings
                    .iter()
                    .any(|heading| heading.line > block.line && heading.line < next.line)
        });
        let several = commands.len() > 1;
        for command in commands {
            match output {
                Some(_) if several => found.push((command, None, Some(Refusal::OutputNotPaired))),
                Some(next) => {
                    let expected = (!next.body.trim().is_empty()).then(|| next.body.clone());
                    found.push((command, expected, None));
                }
                None => found.push((command, None, None)),
            }
        }
    }
    found
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
        // The commands of the program the blocks show, in the same forms the examples are read
        // in, so a flag of an example is checked whether or not the example can be run.
        for (command, _, _) in shown_on(&page, program) {
            for word in &command.understood.args {
                if let Some(flag) = flag_of(word) {
                    push(command.line, ClaimKind::Flag, flag);
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
        for (command, expected, refusal) in shown_on(&page, program) {
            let refusal = refusal.or(command
                .understood
                .needs_a_shell
                .then_some(Refusal::NeedsAShell));
            found.push(Example {
                file: (*path).to_owned(),
                line: command.line,
                args: command.understood.args,
                stdin: command.understood.stdin,
                written: command.written,
                expected,
                refusal,
            });
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
pub fn invented(
    claims: &[Claim],
    help: Option<&str>,
    source_env: &BTreeSet<String>,
    source_flags: &BTreeSet<String>,
) -> Vec<Claim> {
    let listed = help.map(flags_of_help).unwrap_or_default();
    claims
        .iter()
        .filter(|claim| match claim.kind {
            // The help lists the flag, or the program's source holds it as a literal: a project
            // may keep its help text unchanged (documentation policy 9.8).
            ClaimKind::Flag => {
                claim.name != "--help"
                    && !listed.contains(&claim.name)
                    && !source_flags.contains(&claim.name)
            }
            ClaimKind::Command => !help.is_some_and(|text| help_mentions(text, &claim.name)),
            ClaimKind::EnvVar => {
                !source_env.contains(&claim.name)
                    && !help.is_some_and(|text| help_mentions(text, &claim.name))
            }
        })
        .cloned()
        .collect()
}

/// The long flags the source code holds as quoted literals, such as `"--json"`: a double quote,
/// two dashes, then letters, digits and inner dashes up to the closing quote.
#[must_use]
pub fn flags_in_source(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for piece in text.split('"').skip(1).step_by(2) {
        let Some(name) = piece.strip_prefix("--") else {
            continue;
        };
        let well_formed = name
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !name.ends_with('-');
        if well_formed {
            found.insert(piece.to_owned());
        }
    }
    found
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
        let missing = invented(&found, Some(help), &BTreeSet::new(), &BTreeSet::new());
        let names: Vec<&str> = missing.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"--count"));
        assert!(names.contains(&"WC_WIDTH"));
        assert!(!names.contains(&"--json"));
        let env: BTreeSet<String> = ["WC_WIDTH".to_owned()].into();
        assert!(
            !invented(&found, Some(help), &env, &BTreeSet::new())
                .iter()
                .any(|c| c.name == "WC_WIDTH")
        );
    }

    #[test]
    fn a_flag_the_source_holds_is_the_programs_even_when_the_help_does_not_list_it() {
        // The thirty-fifth real run: the owner kept the help text unchanged, the README
        // documented `--json`, and the flag was called invented.
        let found = claims(&[("README.md", PAGE)], "wc-rs");
        let help = "Usage: wc-rs FILE\n\nOptions:\n  -h, --help\n";
        let source = flags_in_source("match arg.as_str() { \"--json\" => json = true, _ => {} }");
        let missing = invented(&found, Some(help), &BTreeSet::new(), &source);
        let names: Vec<&str> = missing.iter().map(|c| c.name.as_str()).collect();
        assert!(!names.contains(&"--json"), "{names:?}");
        assert!(names.contains(&"--count"), "{names:?}");
    }

    #[test]
    fn only_well_formed_long_flags_are_read_from_the_source() {
        let found = flags_in_source(
            "\"--json\" \"--max-count\" \"-x\" \"--\" \"--bad-\" \"--a b\" \"text --json\" \"--9lives\"",
        );
        let expected: BTreeSet<String> = ["--json", "--max-count", "--9lives"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(found, expected);
        assert!(flags_in_source("").is_empty());
        assert!(flags_in_source("no quotes --json here").is_empty());
    }

    #[test]
    fn examples_carry_their_output_and_say_when_they_need_a_shell() {
        let page = "```console\n$ wc-rs --json a.txt\n{\"lines\":1}\n$ wc-rs a.txt | sort\n```\n";
        let found = examples(&[("README.md", page)], "wc-rs");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].args, ["--json", "a.txt"]);
        assert_eq!(found[0].expected.as_deref(), Some("{\"lines\":1}"));
        assert!(found[0].runnable());
        assert_eq!(found[1].refusal, Some(Refusal::NeedsAShell));
    }

    /// The thirty-sixth and thirty-seventh real runs: the README of the fixture shows its
    /// examples as bare commands in a `sh` block, with the output in a `text` block after it, and
    /// feeds standard input with `printf`. The gate found none of them.
    const FIXTURE_STYLE: &str = "# Word count\n\n## Usage\n\n```sh\nword-count notes.txt\n```\n\nIt prints:\n\n```text\n1 3 14\n```\n\nRead standard input:\n\n```sh\nprintf 'one two three\\n' | word-count --json\n```\n\n```text\n{\"lines\":1,\"words\":3}\n```\n";

    #[test]
    fn the_script_form_is_paired_with_the_output_block_after_it() {
        let found = examples(&[("README.md", FIXTURE_STYLE)], "word-count");
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].line, 6);
        assert_eq!(found[0].args, ["notes.txt"]);
        assert_eq!(found[0].stdin, None);
        assert_eq!(found[0].expected.as_deref(), Some("1 3 14"));
        assert!(found[0].runnable());
        assert_eq!(found[1].line, 18);
        assert_eq!(found[1].args, ["--json"]);
        assert_eq!(found[1].stdin.as_deref(), Some(&b"one two three\n"[..]));
        assert_eq!(
            found[1].expected.as_deref(),
            Some("{\"lines\":1,\"words\":3}")
        );
        assert_eq!(
            found[1].written,
            "printf 'one two three\\n' | word-count --json"
        );
        assert!(found[1].runnable());
    }

    #[test]
    fn a_flag_of_a_script_form_example_is_a_claim() {
        let found = claims(&[("README.md", FIXTURE_STYLE)], "word-count");
        assert!(
            found.iter().any(|claim| claim.kind == ClaimKind::Flag
                && claim.name == "--json"
                && claim.line == 18),
            "{found:?}"
        );
    }

    #[test]
    fn a_script_block_with_no_output_block_after_it_runs_without_a_comparison() {
        let page = "```bash\n# Build first.\ncargo build\nword-count --json notes.txt\n```\n\nSome prose.\n";
        let found = examples(&[("README.md", page)], "word-count");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].args, ["--json", "notes.txt"]);
        assert_eq!(found[0].expected, None);
        assert!(found[0].runnable());
    }

    #[test]
    fn an_output_block_after_a_heading_belongs_to_no_example() {
        let page = "```sh\nword-count notes.txt\n```\n\n## Output\n\n```text\n1 3 14\n```\n";
        let found = examples(&[("README.md", page)], "word-count");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].expected, None);
    }

    #[test]
    fn two_commands_of_the_program_before_one_output_block_are_refused() {
        let page =
            "```sh\nword-count a.txt\nword-count --json a.txt\n```\n\n```output\n1 1 1\n```\n";
        let found = examples(&[("README.md", page)], "word-count");
        assert_eq!(found.len(), 2);
        for example in &found {
            assert_eq!(
                example.refusal,
                Some(Refusal::OutputNotPaired),
                "{example:?}"
            );
        }
    }

    #[test]
    fn a_console_block_without_prompt_lines_is_output_not_commands() {
        let page = "```console\nword-count notes.txt\n```\n";
        assert!(examples(&[("README.md", page)], "word-count").is_empty());
    }

    #[test]
    fn a_text_block_with_prompt_lines_is_a_session_not_an_output_block() {
        let page = "```sh\nword-count a.txt\n```\n\n```text\n$ word-count --json a.txt\n{}\n```\n";
        let found = examples(&[("README.md", page)], "word-count");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].expected, None);
        assert_eq!(found[1].expected.as_deref(), Some("{}"));
    }

    #[test]
    fn every_form_that_needs_a_shell_is_kept_and_refused_never_dropped() {
        for command in [
            "word-count a.txt | sort",
            "cat a.txt | word-count",
            "word-count a.txt > out.txt",
            "word-count < a.txt",
            "word-count a.txt && echo done",
            "word-count a.txt || true",
            "word-count a.txt; echo done",
            "word-count a.txt &",
            "word-count $(ls)",
            "word-count `ls`",
            "word-count $FILE",
            "word-count \"$FILE\"",
            "word-count *.txt",
            "word-count ~/a.txt",
            "word-count a.txt \\",
            "word-count 'unclosed",
            "LANG=C word-count a.txt",
            "printf '%s\\n' one | word-count",
            "printf 'a\\x41' | word-count",
            "printf 'a' 'b' | word-count",
            "echo -e 'a\\tb' | word-count",
            "echo 'a\\tb' | word-count",
            "printf 'a' | word-count | sort",
            "printf 'a' | word-count > out",
            "printf 'a' | | word-count",
        ] {
            let page = format!("```sh\n{command}\n```\n");
            let found = examples(&[("README.md", &page)], "word-count");
            assert_eq!(found.len(), 1, "{command}: {found:?}");
            assert_eq!(found[0].refusal, Some(Refusal::NeedsAShell), "{command}");
        }
    }

    #[test]
    fn printf_and_echo_give_the_bytes_a_posix_shell_gives() {
        let cases: [(&str, &[u8]); 8] = [
            ("printf 'one two three\\n'", b"one two three\n"),
            ("printf 'a\\tb\\r\\n'", b"a\tb\r\n"),
            ("printf '100%%\\\\'", b"100%\\"),
            ("printf ''", b""),
            ("printf \"x\\n\"", b"x\n"),
            ("echo one two", b"one two\n"),
            ("echo -n 'one  two'", b"one  two"),
            ("echo", b"\n"),
        ];
        for (source, bytes) in cases {
            let line = format!("{source} | word-count --json");
            let understood = understand(&line, "word-count").expect("it names the program");
            assert!(!understood.needs_a_shell, "{line}");
            assert_eq!(understood.stdin.as_deref(), Some(bytes), "{line}");
            assert_eq!(understood.args, ["--json"]);
        }
    }

    #[test]
    fn quotes_and_escapes_are_read_as_a_posix_shell_reads_them() {
        let read = read_command(r#"word-count 'a b' "c \"d\" \e" f\ g '' # a comment"#);
        assert!(!read.needs_a_shell, "{read:?}");
        assert_eq!(
            read.pipeline,
            [vec![
                "word-count".to_owned(),
                "a b".to_owned(),
                "c \"d\" \\e".to_owned(),
                "f g".to_owned(),
                String::new(),
            ]]
        );
        // A `#` inside a word is not a comment.
        assert_eq!(
            read_command("word-count a#b").pipeline,
            [vec!["word-count".to_owned(), "a#b".to_owned()]]
        );
    }

    #[test]
    fn a_line_that_does_not_name_the_program_is_no_example() {
        for command in [
            "cargo build --release",
            "echo word-count",
            "./word-count a.txt",
            "",
        ] {
            assert_eq!(understand(command, "word-count"), None, "{command}");
        }
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
