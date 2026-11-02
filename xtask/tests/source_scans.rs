//! The lists the source scans use come from the `source_scans` section of
//! `docs/architecture/crate-dependency-rules.json`, and nowhere else. A reviewer changes a list in
//! that one file; the scans read it at run time.

mod common;

use common::{Fixture, real_rules};
use serde_json::json;
use std::fs;
use std::path::Path;
use xtask::scan::Source;

mod source_scans_come_from_the_rules_file {
    use super::*;

    /// Constants that hold the grammar of the `tracing` macros. They are a property of the
    /// `tracing` crate, not a parameter of this repository.
    const GRAMMAR: [&str; 3] = ["SPAN_MACROS", "EVENT_MACROS", "METRIC_PREFIXES"];

    /// The names the lists had before they moved into the rules file.
    const FORMER_CONSTANTS: [&str; 13] = [
        "SHELLS",
        "AGENT_TOOLS",
        "SANDBOX_PROGRAMS",
        "DANGEROUS_STRINGS",
        "HOST_NAMESPACE_FLAGS",
        "FS_READ_CALLS",
        "FS_READ_METHODS",
        "INGESTION_DIR",
        "WORKSPACE_READERS",
        "NAMED_CRATES",
        "INNER_CRATES",
        "SKIPPED_DIRECTORIES",
        "PROSE_EXTENSIONS",
    ];

    fn sources_of_xtask() -> Vec<(String, String)> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        for entry in fs::read_dir(&dir).expect("read xtask/src") {
            let path = entry.expect("entry").path();
            if path.extension().is_some_and(|e| e == "rs") {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                found.push((name, fs::read_to_string(&path).expect("read a source")));
            }
        }
        assert!(found.len() >= 10, "found only {} source files", found.len());
        found
    }

    #[test]
    fn no_former_constant_is_left_in_the_xtask_sources() {
        for (name, text) in sources_of_xtask() {
            let production = Source::from_text(&name, &text).code;
            for constant in FORMER_CONSTANTS {
                assert!(
                    !production.contains(constant),
                    "{name} still mentions {constant}; the list belongs in source_scans"
                );
            }
        }
    }

    #[test]
    fn no_list_of_strings_is_declared_as_a_constant() {
        for (name, text) in sources_of_xtask() {
            let production = Source::from_text(&name, &text).code;
            for (number, line) in production.lines().enumerate() {
                let line = line.trim_start();
                let Some(rest) = line
                    .strip_prefix("const ")
                    .or_else(|| line.strip_prefix("pub const "))
                else {
                    continue;
                };
                let declared = rest.split(':').next().unwrap_or_default().trim();
                let is_list = rest.contains(": [&str;") || rest.contains(": &[&str]");
                assert!(
                    !is_list || GRAMMAR.contains(&declared),
                    "{name}:{} declares the list {declared}; put it in source_scans, or add it to GRAMMAR here if it is the grammar of another crate",
                    number + 1
                );
            }
        }
    }

    #[test]
    fn the_real_rules_file_has_every_section_and_reads_the_values_the_scans_need() {
        let rules = real_rules();
        let scans = &rules.source_scans;
        assert!(scans.dep_10.shells.contains(&"sh".to_string()));
        assert_eq!(scans.dep_10.spawn_file, "crates/sandbox/src/process.rs");
        assert!(
            scans
                .st_04
                .dangerous_strings
                .contains(&"docker.sock".to_string())
        );
        assert_eq!(
            scans.dep_05.inner_crates,
            ["domain", "ports", "workflow", "spec_adapter"]
        );
        assert!(
            scans
                .dep_09
                .forbidden_method_prefixes
                .contains(&"undraft".to_string())
        );
        assert_eq!(scans.st_14.names, ["MeteringOps"]);
    }

    #[test]
    fn a_named_crate_that_does_not_exist_fails_the_check() {
        for (section, key) in [
            ("st_09", "crates"),
            ("st_07", "skip_crates"),
            ("dep_05", "inner_crates"),
        ] {
            let mut fx = Fixture::baseline("scans-missing-crate");
            let list = fx.rules_mut()["source_scans"][section][key]
                .as_array_mut()
                .expect("a list");
            list.push(json!("no_such_crate"));
            fx.run().assert_error("no_such_crate");
        }
    }

    #[test]
    fn a_crate_named_in_a_single_value_field_must_exist_too() {
        let mut fx = Fixture::baseline("scans-missing-single");
        fx.rules_mut()["source_scans"]["dep_09"]["begin_system_crate"] = json!("no_such_crate");
        fx.run().assert_error("no_such_crate");
        let mut fx = Fixture::baseline("scans-missing-rule-crate");
        fx.rules_mut()["source_scans"]["st_13"][0]["allowed_crates"] = json!(["no_such_crate"]);
        fx.run().assert_error("no_such_crate");
    }

    #[test]
    fn a_section_that_is_missing_is_an_error_that_names_it() {
        for section in [
            "dep_04", "dep_05", "dep_09", "dep_10", "st_01", "st_04", "st_05", "st_07", "st_09",
            "st_13", "st_14",
        ] {
            let mut fx = Fixture::baseline("scans-missing-section");
            fx.rules_mut()["source_scans"]
                .as_object_mut()
                .expect("an object")
                .remove(section);
            fx.run().assert_error(section);
        }
    }

    #[test]
    fn a_rules_file_without_the_section_at_all_is_refused() {
        let mut fx = Fixture::baseline("scans-no-section");
        fx.rules_mut()
            .as_object_mut()
            .unwrap()
            .remove("source_scans");
        fx.run().assert_error("source_scans");
    }

    // The scans use the lists. Each test changes one list and shows the scan follow it.

    #[test]
    fn a_shell_added_to_the_list_is_found() {
        let code = "use std::process::Command;\npub fn g() { let _ = Command::new(\"nu\"); }\n";
        let mut fx = Fixture::baseline("scans-shell");
        fx.source("sandbox", "src/process.rs", code);
        fx.run().assert_violation_mentions("DEP-10", "nu");
        fx.rules_mut()["source_scans"]["dep_10"]["shells"]
            .as_array_mut()
            .unwrap()
            .push(json!("nu"));
        fx.run()
            .assert_violation_mentions("ST-03", "spawns the shell nu");
    }

    #[test]
    fn the_spawn_file_is_the_one_the_rules_name() {
        let code = "use std::process::Command;\npub fn g() { let _ = Command::new(\"git\"); }\n";
        let mut fx = Fixture::baseline("scans-spawn-file");
        fx.source("sandbox", "src/exec.rs", code);
        fx.run().assert_violation("ST-03");
        fx.rules_mut()["source_scans"]["dep_10"]["spawn_file"] =
            json!("crates/sandbox/src/exec.rs");
        fx.run().assert_passes();
    }

    #[test]
    fn a_program_added_to_a_crate_is_allowed_there() {
        let code = "use std::process::Command;\npub fn g() { let _ = Command::new(\"podman\"); }\n";
        let mut fx = Fixture::baseline("scans-program");
        fx.source("sandbox", "src/process.rs", code);
        fx.run().assert_violation_mentions("DEP-10", "podman");
        fx.rules_mut()["source_scans"]["dep_10"]["programs"][0]["programs"]
            .as_array_mut()
            .unwrap()
            .push(json!("podman"));
        fx.run().assert_passes();
    }

    #[test]
    fn a_container_flag_added_to_the_list_is_found() {
        let code = "pub const FLAG: &str = \"--device=/dev/mem\";\n";
        let mut fx = Fixture::baseline("scans-flag");
        fx.source("sandbox", "src/container/args.rs", code);
        fx.run().assert_passes();
        fx.rules_mut()["source_scans"]["st_04"]["dangerous_strings"]
            .as_array_mut()
            .unwrap()
            .push(json!("--device=/dev/mem"));
        fx.run().assert_violation("ST-04");
    }

    #[test]
    fn the_ingestion_directory_and_its_crate_come_from_the_file() {
        let read = "pub fn r() { let _ = std::fs::read_to_string(\"x\"); }\n";
        let mut fx = Fixture::baseline("scans-ingestion");
        fx.source("sandbox", "src/intake/mod.rs", read);
        fx.run().assert_violation("ST-09");
        fx.rules_mut()["source_scans"]["st_09"]["ingestion_dir"] = json!("src/intake/");
        fx.run().assert_passes();
    }

    #[test]
    fn the_crates_that_may_call_a_constructor_come_from_the_file() {
        let code = "pub fn f() { let _ = SystemScope::engine(); }\n";
        let mut fx = Fixture::baseline("scans-constructor");
        fx.source("storage", "src/lib.rs", code);
        fx.run().assert_violation("ST-13");
        fx.rules_mut()["source_scans"]["st_13"][1]["allowed_crates"]
            .as_array_mut()
            .unwrap()
            .push(json!("storage"));
        fx.run().assert_passes();
    }

    #[test]
    fn a_function_that_must_not_be_reachable_is_found_by_any_mention_and_the_control_is_the_old_rule()
     {
        // Finding STS-5. A pointer to the function has no `(` after the path.
        let code = "pub fn f(n: Vec<&str>) { let _: Vec<_> = n.into_iter().map(StatusLabel::forged_for_negative_tests).collect(); }\n";
        let mut fx = Fixture::baseline("scans-any-use");
        fx.source("composition", "src/lib.rs", code);
        fx.run().assert_violation("ST-13");
        // The control: with `any_use` off, as the rule was, the pointer gets past the scan.
        let rules = fx.rules_mut()["source_scans"]["st_13"]
            .as_array_mut()
            .expect("a list");
        let entry = rules
            .iter_mut()
            .find(|rule| rule["name"] == "StatusLabel::forged_for_negative_tests")
            .expect("the rule for the forging function");
        assert_eq!(entry["any_use"], json!(true));
        entry["any_use"] = json!(false);
        fx.run().assert_passes();
    }

    #[test]
    fn the_crate_that_may_not_mention_a_name_comes_from_the_file() {
        let code = "pub struct MeteringOps;\n";
        let mut fx = Fixture::baseline("scans-st14");
        fx.source("runtime", "src/lib.rs", code);
        fx.run().assert_passes();
        fx.rules_mut()["source_scans"]["st_14"]["crate"] = json!("runtime");
        fx.run().assert_violation("ST-14");
    }

    #[test]
    fn the_inner_crates_come_from_the_file() {
        let mut fx = Fixture::baseline("scans-inner");
        fx.without_clippy_toml("domain");
        fx.run().assert_violation("DEP-05");
        fx.rules_mut()["source_scans"]["dep_05"]["inner_crates"] =
            json!(["ports", "workflow", "spec_adapter"]);
        fx.run().assert_passes();
    }
}
