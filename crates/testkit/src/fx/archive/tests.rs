use std::io::Write;
use std::process::{Command, Stdio};

use super::*;

/// Runs a system tool over standard input and returns its output.
fn pipe(program: &str, args: &[&str], input: &[u8]) -> (bool, Vec<u8>, String) {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| {
            panic!("BLOCKED: {program} is needed to check the archive writer: {e}")
        });
    let mut stdin = child.stdin.take().unwrap();
    let data = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    (
        output.status.success(),
        output.stdout,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn crc32_matches_the_standard_check_value() {
    // The check value of CRC-32/ISO-HDLC, the variant gzip uses.
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

#[test]
fn gzip_output_is_accepted_by_the_system_gzip_and_round_trips() {
    for data in [
        Vec::new(),
        b"hello".to_vec(),
        vec![b'x'; 65_535],
        vec![b'y'; 65_536],
        (0..200_000u32)
            .map(|n| (n % 251) as u8)
            .collect::<Vec<u8>>(),
    ] {
        let packed = gzip(&data);
        let (ok, unpacked, error) = pipe("gzip", &["-dc"], &packed);
        assert!(ok, "gzip refused {} bytes: {error}", data.len());
        assert_eq!(unpacked, data);
    }
    assert_eq!(gzip(b"same"), gzip(b"same"), "the output is reproducible");
}

#[test]
fn a_tar_of_ordinary_files_is_listed_and_read_by_the_system_tar() {
    let archive = tar_gz(&[
        Entry::directory("pkg/"),
        Entry::file("pkg/Cargo.toml", b"[package]\nname = \"x\"\n"),
        Entry::file("pkg/src/lib.rs", b"pub fn f() {}\n").with_mode(0o600),
    ]);
    let (ok, listing, error) = pipe("tar", &["-tzf", "-"], &archive);
    assert!(ok, "{error}");
    let names: Vec<&str> = std::str::from_utf8(&listing).unwrap().lines().collect();
    assert_eq!(names, ["pkg/", "pkg/Cargo.toml", "pkg/src/lib.rs"]);

    let (ok, content, _) = pipe("tar", &["-xzOf", "-", "pkg/src/lib.rs"], &archive);
    assert!(ok);
    assert_eq!(content, b"pub fn f() {}\n");
}

#[test]
fn a_path_over_100_bytes_is_written_with_a_long_name_record() {
    let long = format!("pkg/{}/file.txt", "d".repeat(150));
    let archive = tar(&[Entry::file(&long, b"data")]);
    let (ok, listing, error) = pipe("tar", &["-tf", "-"], &archive);
    assert!(ok, "{error}");
    assert_eq!(String::from_utf8(listing).unwrap().trim(), long);
}

#[test]
fn hostile_entries_are_written_as_asked_and_listed_with_their_kinds() {
    let archive = tar(&[
        Entry::file("../escape.txt", b"x"),
        Entry::file("/absolute.txt", b"x"),
        Entry::symlink("link-out", "/etc/passwd"),
        Entry::symlink("link-up", "../../outside"),
        Entry::hardlink("hard", "/etc/hosts"),
        Entry {
            path: "dev-char".to_owned(),
            kind: Kind::CharDevice,
            mode: 0o666,
        },
        Entry {
            path: "dev-block".to_owned(),
            kind: Kind::BlockDevice,
            mode: 0o666,
        },
        Entry {
            path: "pipe".to_owned(),
            kind: Kind::Fifo,
            mode: 0o644,
        },
        Entry::file("setuid", b"x").with_mode(0o4755),
    ]);
    // `-v` shows the kind in the first column and the link target after an arrow.
    let (ok, listing, error) = pipe("tar", &["-tvf", "-"], &archive);
    assert!(ok, "{error}");
    let listing = String::from_utf8(listing).unwrap();
    let line_for = |name: &str| {
        listing
            .lines()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| panic!("no line for {name}: {listing}"))
    };
    assert!(line_for("../escape.txt").starts_with('-'));
    assert!(line_for("/absolute.txt").starts_with('-'));
    assert!(line_for("link-out").starts_with('l') && line_for("link-out").contains("/etc/passwd"));
    assert!(line_for("link-up").contains("../../outside"));
    assert!(line_for("hard").starts_with('h') || line_for("hard").contains("link to"));
    assert!(line_for("dev-char").starts_with('c'));
    assert!(line_for("dev-block").starts_with('b'));
    assert!(line_for("pipe").starts_with('p'));
    assert!(
        line_for("setuid").contains('s'),
        "the setuid bit is set: {}",
        line_for("setuid")
    );
}

#[test]
fn nothing_in_this_module_extracts_so_a_hostile_archive_is_only_listed() {
    // The writer has no reader. This test keeps that true by checking the public surface by
    // name: only writers are exported.
    let source = include_str!("../archive.rs");
    for forbidden in [
        "pub fn untar",
        "pub fn extract",
        "pub fn gunzip",
        "pub fn read_tar",
    ] {
        assert!(!source.contains(forbidden), "{forbidden} must not exist");
    }
}
