//! The `--json` option: the counts as one JSON object, and no change for everyone else.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// A small text file in the directory cargo gives to the tests of this package.
fn sample(name: &str, text: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("json-output-{name}.txt"));
    std::fs::write(&path, text).expect("the sample file is written");
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_word-count"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("the binary starts")
}

fn run_with_input(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_word-count"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary starts");
    child
        .stdin
        .take()
        .expect("standard input is piped")
        .write_all(input.as_bytes())
        .expect("the input is written");
    child.wait_with_output().expect("the binary finishes")
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).expect("the output is UTF-8")
}

#[test]
fn fr_001_json_prints_the_three_counts_in_order() {
    let path = sample("three-counts", "one two three\nfour five\nsix seven\n");
    let output = run(&["--json", path.to_str().expect("a UTF-8 path")]);
    assert!(output.status.success());
    assert_eq!(
        text(output.stdout),
        "{\"lines\":3,\"words\":7,\"characters\":34}\n"
    );
}

#[test]
fn fr_001_json_for_an_empty_file_prints_zero_counts() {
    let path = sample("empty", "");
    let output = run(&[path.to_str().expect("a UTF-8 path"), "--json"]);
    assert!(output.status.success());
    assert_eq!(
        text(output.stdout),
        "{\"lines\":0,\"words\":0,\"characters\":0}\n"
    );
}

#[test]
fn fr_002_without_the_option_the_plain_line_is_unchanged() {
    let path = sample("plain", "one two three\nfour five\nsix seven\n");
    let name = path.to_str().expect("a UTF-8 path");
    let output = run(&[name]);
    assert!(output.status.success());
    assert_eq!(
        text(output.stdout),
        format!("      3       7      34 {name}\n")
    );
}

#[test]
fn fr_003_a_missing_file_fails_the_same_way_with_and_without_the_option() {
    let missing = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("json-output-no-such-file.txt");
    let name = missing.to_str().expect("a UTF-8 path");
    for args in [vec![name], vec!["--json", name]] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(text(output.stderr).contains("cannot read"), "{args:?}");
    }
}

#[test]
fn json_reads_standard_input_when_the_name_is_a_dash() {
    let output = run_with_input(&["--json", "-"], "a b\n");
    assert!(output.status.success());
    assert_eq!(
        text(output.stdout),
        "{\"lines\":1,\"words\":2,\"characters\":4}\n"
    );
}

#[test]
fn fr_004_one_line_break_follows_the_object_and_nothing_else() {
    let output = run_with_input(&["--json"], "one two\n");
    assert!(output.status.success());
    let printed = text(output.stdout);
    assert!(printed.starts_with('{'));
    assert!(printed.ends_with("}\n"));
    assert_eq!(printed.matches('\n').count(), 1);
}

#[test]
fn a_repeated_option_behaves_as_one() {
    let output = run_with_input(&["--json", "--json"], "a b\n");
    assert!(output.status.success());
    assert_eq!(
        text(output.stdout),
        "{\"lines\":1,\"words\":2,\"characters\":4}\n"
    );
}
