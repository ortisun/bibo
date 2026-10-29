//! The words of a decision on a dependency (`approve-dependency`, `approve-build-code`).

use factory_workflow::gates::supply_chain::command::{
    CommandError, DependencyCommand, ParsedLine, parse_dependency_command,
};

fn command(text: &str) -> Option<DependencyCommand> {
    match parse_dependency_command(text) {
        Ok(ParsedLine::Command(command)) => Some(command),
        _ => None,
    }
}

/// Control: the shapes that are not a command, and the checksum rules.
#[test]
fn held_quotes_fences_second_lines_and_odd_words_are_not_commands() {
    for text in [
        "> /factory approve-dependency some-crate 0.1.0 a reason that is long enough",
        "```\n/factory approve-dependency some-crate 0.1.0 a reason that is long enough\n```",
        "Looks fine.\n/factory approve-dependency some-crate 0.1.0 a reason that is long enough",
        "<!-- /factory approve-dependency some-crate 0.1.0 a reason that is long enough -->",
        "/factory Approve-Dependency some-crate 0.1.0 a reason that is long enough",
        "/factory approve-dependencies some-crate 0.1.0 a reason that is long enough",
        "\u{200b}/factory approve-dependency some-crate 0.1.0 a reason that is long enough",
    ] {
        assert_eq!(
            parse_dependency_command(text),
            Ok(ParsedLine::NotOurs),
            "{text:?} was read as a command"
        );
    }
    // A checksum prefix shorter than twelve digits is not a checksum word: it starts the reason, and
    // so a short prefix cannot select among many packages.
    let parsed =
        command("approve-dependency some-crate 0.1.0 6f1d reason follows here").expect("a command");
    assert_eq!(parsed.checksum_prefix, None);
    assert!(parsed.reason.starts_with("6f1d"));
    // Upper-case hex that is long enough to be a checksum is refused, not read as the reason.
    assert_eq!(
        parse_dependency_command("approve-dependency some-crate 0.1.0 6F1D2C9AB0E3 reason here"),
        Err(CommandError::InvalidChecksum)
    );
    // A name with a path, a space trick or a lookalike letter is not a cargo name.
    for name in [
        "../evil",
        "a/b",
        "caf\u{e9}",
        "a\u{200b}b",
        "serde%2f",
        "-x",
        "ser de",
    ] {
        let text = format!("approve-dependency {name} 0.1.0 reason follows here");
        assert!(
            !matches!(parse_dependency_command(&text), Ok(ParsedLine::Command(_))),
            "{name:?} was read as a package name"
        );
    }
}

/// RR-17. The first line is trimmed before the prefix is looked at, so an indented line is a command.
/// In a comment on a pull request, four spaces make a code block, which is how a person quotes an
/// example of the command to a colleague; the other reader of comment commands
/// (`factory_composition::commands::parse_comment`) refuses a line with anything in front of the
/// prefix, and its tests say so. The same comment from an approver is a decision on a dependency here.
#[test]
#[ignore = "confirmed defect RR-17: an indented line is read as a decision on a dependency; cargo test -p factory-workflow --test security_rereview --locked -- --ignored rr_17 --exact"]
fn rr_17_a_line_with_something_in_front_of_the_prefix_is_not_a_command() {
    let mut read = Vec::new();
    for (name, text) in [
        (
            "four spaces (a code block)",
            "    /factory approve-dependency some-crate 0.1.0 a reason that is long enough",
        ),
        (
            "a tab",
            "\t/factory approve-dependency some-crate 0.1.0 a reason that is long enough",
        ),
        (
            "a list marker is not stripped but a space is",
            " /factory approve-dependency some-crate 0.1.0 a reason that is long enough",
        ),
    ] {
        if command(text).is_some() {
            read.push(name);
        }
    }
    assert!(read.is_empty(), "read as a command: {read:?}");
}
