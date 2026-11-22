//! The name of the shared migrated template (`support::server::template_name`).
//!
//! Every test process on one server clones the same template, so the name must change whenever
//! the migrations change, and never for anything else. These tests need no database.

mod support;

use support::server::template_name;

fn set(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(version, sql)| ((*version).to_owned(), (*sql).to_owned()))
        .collect()
}

#[test]
fn the_same_migrations_give_the_same_name() {
    let one = set(&[
        ("20261027000100", "CREATE ROLE a;"),
        ("20261027000200", "SELECT 1;"),
    ]);
    assert_eq!(template_name(&one), template_name(&one.clone()));
}

#[test]
fn a_changed_file_a_new_file_and_a_new_version_each_give_a_new_name() {
    let base = set(&[("20261027000100", "CREATE ROLE a;")]);
    let changed = set(&[("20261027000100", "CREATE ROLE b;")]);
    let added = set(&[
        ("20261027000100", "CREATE ROLE a;"),
        ("20261027000200", "SELECT 1;"),
    ]);
    let renumbered = set(&[("20261027000101", "CREATE ROLE a;")]);
    let names = [
        template_name(&base),
        template_name(&changed),
        template_name(&added),
        template_name(&renumbered),
    ];
    for (i, left) in names.iter().enumerate() {
        for right in &names[i + 1..] {
            assert_ne!(left, right);
        }
    }
}

#[test]
fn moving_text_from_one_file_to_the_next_gives_a_new_name() {
    // Each version and file is framed by its length, so the boundary between two files counts.
    let first = set(&[("1", "ab"), ("2", "c")]);
    let second = set(&[("1", "a"), ("2", "bc")]);
    assert_ne!(template_name(&first), template_name(&second));
}

#[test]
fn the_name_is_the_prefix_and_sixteen_lowercase_hexadecimal_characters() {
    let name = template_name(&set(&[("20261027000100", "SELECT 1;")]));
    let digest = name.strip_prefix("factory_tpl_").expect("the prefix");
    assert_eq!(digest.len(), 16);
    assert!(
        digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
}

#[test]
fn the_building_name_with_the_longest_run_fits_in_a_postgresql_identifier() {
    // A run is the process id (at most 8 hexadecimal digits) and 40 bits of nanoseconds (at most
    // 10). PostgreSQL keeps the first 63 bytes of an identifier, so a longer name would collide.
    let name = template_name(&set(&[("20261027000100", "SELECT 1;")]));
    let longest_run = format!("{:x}{:x}", u32::MAX, 0xff_ffff_ffff_u64);
    let building = format!("{name}_building_{longest_run}");
    assert_eq!(building.len(), 56);
    assert!(building.len() <= 63);
}
