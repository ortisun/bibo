//! The bypasses that the independent architecture review found (finding F-12, ADR 0014 decision
//! 11, `docs/architecture/ports-v1.1.md` section 12). Each test is a baseline workspace plus the
//! one change the reviewer made in a scratch copy of the repository. Before the fix, every
//! failing fixture here passed the check.

mod common;

use common::{Fixture, Run};

mod review_bypasses {
    use super::*;

    fn run_with_source(member: &str, relative: &str, code: &str) -> Run {
        let mut fx = Fixture::baseline("bypass");
        fx.source(member, relative, code);
        fx.run()
    }

    /// A spawn of `sh` written the way a reviewer would hide it.
    const SH: &str = "Command::new(\"sh\")";

    mod spawn_through_names_the_old_scan_did_not_resolve {
        use super::*;

        fn assert_hidden_spawn_is_found(code: &str) {
            run_with_source("runtime", "src/lib.rs", code).assert_violation("ST-03");
        }

        #[test]
        fn a_use_as_alias_of_command() {
            assert_hidden_spawn_is_found(&format!(
                "use std::process::Command as Cmd;\npub fn f() {{ let _ = Cmd::new(\"sh\"); }}\n{SH}\n"
            ));
        }

        #[test]
        fn the_alias_call_itself_is_judged_as_a_shell_spawn() {
            run_with_source(
                "runtime",
                "src/lib.rs",
                "use std::process::Command as Cmd;\npub fn f() { let _ = Cmd::new(\"sh\"); }\n",
            )
            .assert_violation_mentions("ST-03", "spawns the shell sh");
        }

        #[test]
        fn a_use_group_with_an_alias_inside() {
            assert_hidden_spawn_is_found(
                "use std::{fs, process::{Command as C, Stdio}};\npub fn f() { let _ = C::new(\"bash\"); }\n",
            );
        }

        #[test]
        fn a_glob_import_of_the_process_module() {
            assert_hidden_spawn_is_found(
                "use std::process::*;\npub fn f() { let _ = Command::new(\"sh\"); }\n",
            );
        }

        #[test]
        fn a_glob_import_of_std_followed_by_the_module_path() {
            assert_hidden_spawn_is_found(
                "use std::*;\npub fn f() { let _ = process::Command::new(\"sh\"); }\n",
            );
        }

        #[test]
        fn the_module_imported_under_another_name() {
            assert_hidden_spawn_is_found(
                "use std::process as p;\npub fn f() { let _ = p::Command::new(\"sh\"); }\n",
            );
        }

        #[test]
        fn the_standard_library_imported_under_another_name() {
            assert_hidden_spawn_is_found(
                "extern crate std as s;\npub fn f() { let _ = s::process::Command::new(\"sh\"); }\n",
            );
        }

        #[test]
        fn a_type_alias() {
            assert_hidden_spawn_is_found(
                "type C = std::process::Command;\npub fn f() { let _ = C::new(\"sh\"); }\n",
            );
        }

        #[test]
        fn a_path_that_starts_with_two_colons() {
            assert_hidden_spawn_is_found(
                "pub fn f() { let _ = ::std::process::Command::new(\"sh\"); }\n",
            );
        }

        #[test]
        fn the_tokio_command_under_an_alias() {
            assert_hidden_spawn_is_found(
                "use tokio::process::Command as T;\npub async fn f() { let _ = T::new(\"sh\"); }\n",
            );
        }

        #[test]
        fn the_unix_command_extension_trait() {
            run_with_source(
                "github",
                "src/lib.rs",
                "use std::os::unix::process::CommandExt;\n",
            )
            .assert_violation_mentions("ST-03", "std::os::unix::process");
        }

        #[test]
        fn a_spawn_inside_a_macro_definition() {
            assert_hidden_spawn_is_found(
                "macro_rules! run { () => { std::process::Command::new(\"sh\") }; }\n",
            );
        }

        #[test]
        fn a_reexport_of_the_command_type() {
            run_with_source(
                "github",
                "src/lib.rs",
                "pub use std::process::Command as Spawn;\n",
            )
            .assert_violation_mentions("ST-03", "std::process::Command");
        }

        #[test]
        fn a_process_module_import_alone_is_not_a_spawn() {
            // `std::process::exit` and `ExitCode` are not in the list of spawning paths.
            run_with_source(
                "api",
                "src/main.rs",
                "use std::process::ExitCode;\nfn main() -> ExitCode { std::process::exit(0) }\n",
            )
            .assert_passes();
        }

        #[test]
        fn a_command_type_from_another_crate_is_still_not_a_spawn() {
            run_with_source(
                "api",
                "src/main.rs",
                "use clap::Command as Cli;\nfn main() { let _ = Cli::new(\"factory\"); }\n",
            )
            .assert_passes();
        }
    }

    mod only_one_file_holds_a_spawn {
        use super::*;

        #[test]
        fn another_file_in_the_sandbox_crate_fails() {
            run_with_source(
                "sandbox",
                "src/git.rs",
                "use std::process::Command;\npub fn g() { let _ = Command::new(\"git\"); }\n",
            )
            .assert_violation_mentions("ST-03", "crates/sandbox/src/process.rs");
        }

        #[test]
        fn the_spawn_file_in_a_crate_that_is_not_sandbox_fails() {
            run_with_source(
                "runtime",
                "src/process.rs",
                "use std::process::Command;\npub fn g() { let _ = Command::new(\"claude\"); }\n",
            )
            .assert_violation("ST-03");
        }

        #[test]
        fn the_spawn_file_keeps_the_program_rules() {
            run_with_source(
                "sandbox",
                "src/process.rs",
                "use std::process::Command;\npub fn g() { let _ = Command::new(\"curl\"); }\n",
            )
            .assert_violation_mentions("DEP-10", "curl");
        }
    }

    mod a_file_is_test_code_only_when_cfg_test_says_so {
        use super::*;

        const SPAWN_FILE: &str =
            "pub fn m() {\n    let _ = std::process::Command::new(\"sh\").status();\n}\n";

        fn run_with_module(lib: &str, file: &str, body: &str) -> Run {
            let mut fx = Fixture::baseline("module");
            fx.source("github", "src/lib.rs", lib);
            fx.source("github", file, body);
            fx.run()
        }

        #[test]
        fn a_module_file_named_like_a_test_file_but_declared_without_cfg_test() {
            run_with_module("mod webhook_tests;\n", "src/webhook_tests.rs", SPAWN_FILE)
                .assert_violation_mentions("ST-03", "crates/github/src/webhook_tests.rs:2");
        }

        #[test]
        fn a_file_called_tests_rs() {
            run_with_module("mod tests;\n", "src/tests.rs", SPAWN_FILE).assert_violation("ST-03");
        }

        #[test]
        fn a_module_directory_called_tests() {
            run_with_module("mod tests;\n", "src/tests/mod.rs", SPAWN_FILE)
                .assert_violation("ST-03");
        }

        #[test]
        fn a_file_called_something_test_rs() {
            run_with_module("mod parse_test;\n", "src/parse_test.rs", SPAWN_FILE)
                .assert_violation("ST-03");
        }

        #[test]
        fn a_file_that_no_module_declares_is_scanned_too() {
            run_with_module("", "src/orphan_tests.rs", SPAWN_FILE).assert_violation("ST-03");
        }

        #[test]
        fn a_child_of_a_plain_module_called_tests() {
            let mut fx = Fixture::baseline("nested");
            fx.source("github", "src/lib.rs", "mod hooks;\n");
            fx.source("github", "src/hooks.rs", "mod tests;\n");
            fx.source("github", "src/hooks/tests.rs", SPAWN_FILE);
            fx.run().assert_violation("ST-03");
        }

        #[test]
        fn a_path_attribute_pointing_outside_src() {
            let mut fx = Fixture::baseline("path");
            fx.source(
                "github",
                "src/lib.rs",
                "#[path = \"../extra/hook.rs\"]\nmod hook;\n",
            );
            fx.source("github", "extra/hook.rs", SPAWN_FILE);
            fx.run().assert_violation("ST-03");
        }

        #[test]
        fn an_include_of_a_file_outside_src() {
            let mut fx = Fixture::baseline("include");
            fx.source("github", "src/lib.rs", "include!(\"../generated.rs\");\n");
            fx.source("github", "generated.rs", SPAWN_FILE);
            fx.run().assert_violation("ST-03");
        }

        #[test]
        fn a_module_declared_under_cfg_test_is_exempt() {
            run_with_module(
                "#[cfg(test)]\nmod webhook_tests;\n",
                "src/webhook_tests.rs",
                SPAWN_FILE,
            )
            .assert_passes();
        }

        #[test]
        fn a_file_that_starts_with_an_inner_cfg_test_is_exempt() {
            run_with_module(
                "mod fixtures;\n",
                "src/fixtures.rs",
                &format!("#![cfg(test)]\n{SPAWN_FILE}"),
            )
            .assert_passes();
        }

        #[test]
        fn a_module_under_not_test_is_production() {
            run_with_module(
                "#[cfg(not(test))]\nmod hooks;\n",
                "src/hooks.rs",
                SPAWN_FILE,
            )
            .assert_violation("ST-03");
        }

        #[test]
        fn a_module_under_any_of_test_or_a_feature_is_production() {
            run_with_module(
                "#[cfg(any(test, feature = \"extras\"))]\nmod hooks;\n",
                "src/hooks.rs",
                SPAWN_FILE,
            )
            .assert_violation("ST-03");
        }

        #[test]
        fn a_module_under_all_of_test_and_a_feature_is_test_code() {
            run_with_module(
                "#[cfg(all(test, feature = \"extras\"))]\nmod hooks;\n",
                "src/hooks.rs",
                SPAWN_FILE,
            )
            .assert_passes();
        }

        #[test]
        fn the_integration_test_directory_at_the_crate_root_is_not_production() {
            let mut fx = Fixture::baseline("integration");
            fx.source("github", "tests/hook.rs", SPAWN_FILE);
            fx.run().assert_passes();
        }
    }

    mod a_cfg_test_attribute_covers_its_own_element_and_no_more {
        use super::*;

        const PRODUCTION_SPAWN: &str =
            "pub fn production() {\n    let _ = std::process::Command::new(\"sh\").status();\n}\n";

        fn after(prefix: &str) -> Run {
            run_with_source(
                "spec_adapter",
                "src/lib.rs",
                &format!("{prefix}{PRODUCTION_SPAWN}"),
            )
        }

        #[test]
        fn on_a_struct_field() {
            after("pub struct S {\n    #[cfg(test)]\n    pub a: u8,\n    pub b: u8,\n}\n")
                .assert_violation("ST-03");
        }

        #[test]
        fn on_an_enum_variant() {
            after("pub enum E {\n    #[cfg(test)]\n    A(u8),\n    B,\n}\n")
                .assert_violation("ST-03");
        }

        #[test]
        fn on_a_function_parameter() {
            after("pub fn f(#[cfg(test)] a: u8, b: u8) -> u8 { b }\n").assert_violation("ST-03");
        }

        #[test]
        fn on_a_match_arm() {
            after("pub fn f(x: u8) -> u8 { match x {\n    #[cfg(test)]\n    1 => 2,\n    _ => 3,\n} }\n")
                .assert_violation("ST-03");
        }

        #[test]
        fn on_a_statement() {
            after("pub fn f() {\n    #[cfg(test)]\n    let _x = 1;\n    let _y = 2;\n}\n")
                .assert_violation("ST-03");
        }

        #[test]
        fn on_a_use_declaration_with_a_group() {
            after("#[cfg(test)]\nuse std::{fs, io};\n").assert_violation("ST-03");
        }

        #[test]
        fn on_a_const_with_a_struct_literal() {
            after("#[cfg(test)]\nconst C: Point = Point { x: 1 };\n").assert_violation("ST-03");
        }

        #[test]
        fn the_spawn_inside_the_cfg_test_element_is_exempt() {
            run_with_source(
                "spec_adapter",
                "src/lib.rs",
                "pub struct S {\n    pub b: u8,\n}\n#[cfg(test)]\nfn helper() {\n    let _ = std::process::Command::new(\"sh\").status();\n}\n",
            )
            .assert_passes();
        }

        #[test]
        fn a_cfg_test_module_with_nested_braces_is_exempt() {
            run_with_source(
                "spec_adapter",
                "src/lib.rs",
                "#[cfg(test)]\nmod tests {\n    fn t() { if true { let _ = std::process::Command::new(\"sh\"); } }\n}\n",
            )
            .assert_passes();
        }
    }
}
