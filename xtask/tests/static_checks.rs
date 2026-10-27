//! One passing and one failing fixture for each rule that needs a scan of the source text:
//! DEP-09, DEP-10 and the static checks ST-01 to ST-05 and ST-09 from the negative-test catalog.
//! Every failing fixture is a baseline workspace plus one offending file.

mod common;

// Every test sits under this module so that `cargo nextest run -p xtask static_checks` selects it.
mod static_checks {
    use super::common::{Fixture, Run};

    /// Run the check on a baseline workspace that has one extra source file.
    fn run_with_source(member: &str, relative: &str, code: &str) -> Run {
        let mut fx = Fixture::baseline("scan");
        fx.source(member, relative, code);
        fx.run()
    }

    /// Run the check on a baseline workspace that has one extra file anywhere.
    fn run_with_file(relative: &str, content: &str) -> Run {
        let mut fx = Fixture::baseline("file");
        fx.file(relative, content);
        fx.run()
    }

    mod dep_09_layout_boundaries {
        use super::*;

        const CALL: &str = "pub async fn start(store: &dyn Store, scope: SystemScope) {\n    let _tx = store.begin_system(scope).await;\n}\n";

        #[test]
        fn begin_system_called_outside_workflow_fails() {
            run_with_source("storage", "src/lib.rs", CALL)
                .assert_violation_mentions("DEP-09", "crates/storage/src/lib.rs:2");
        }

        #[test]
        fn begin_system_called_from_a_binary_fails() {
            run_with_source("api", "src/main.rs", CALL).assert_violation("DEP-09");
        }

        #[test]
        fn begin_system_called_inside_workflow_passes() {
            run_with_source("workflow", "src/engine.rs", CALL).assert_passes();
        }

        #[test]
        fn implementing_begin_system_is_not_calling_it() {
            let implementation = "impl Store for Pg {\n    async fn begin_system(&self, scope: SystemScope) -> Tx { todo() }\n}\n";
            run_with_source("storage", "src/lib.rs", implementation).assert_passes();
        }

        #[test]
        fn a_begin_system_call_in_test_code_passes() {
            let code = format!("#[cfg(test)]\nmod tests {{\n{CALL}}}\n");
            run_with_source("storage", "src/lib.rs", &code).assert_passes();
        }

        #[test]
        fn a_begin_system_call_in_a_comment_passes() {
            run_with_source(
                "storage",
                "src/lib.rs",
                "// store.begin_system(scope) belongs to workflow\n",
            )
            .assert_passes();
        }

        #[test]
        fn a_change_host_with_a_merge_method_fails() {
            let code = "pub trait ChangeHost {\n    fn open_draft_pull_request(&self);\n    fn merge_pull_request(&self);\n}\n";
            run_with_source("ports", "src/change_host.rs", code)
                .assert_violation_mentions("DEP-09", "merge_pull_request");
        }

        #[test]
        fn a_change_host_without_a_merge_method_passes() {
            let code = "pub trait ChangeHost {\n    fn open_draft_pull_request(&self);\n    fn read_checks(&self);\n}\n";
            run_with_source("ports", "src/change_host.rs", code).assert_passes();
        }

        #[test]
        fn a_merge_method_on_another_trait_is_not_a_change_host_method() {
            let code = "pub trait ArtifactStore {\n    fn merge_manifests(&self);\n}\n";
            run_with_source("ports", "src/store.rs", code).assert_no_violation("DEP-09");
        }

        #[test]
        fn the_spec_kit_directory_outside_spec_adapter_fails() {
            let code = "const DIR: &str = \".specify/memory\";\n";
            run_with_source("workflow", "src/stages.rs", code)
                .assert_violation_mentions("DEP-09", "crates/workflow/src/stages.rs:1");
        }

        #[test]
        fn the_word_speckit_outside_spec_adapter_fails_in_any_case() {
            run_with_source(
                "sandbox",
                "src/lib.rs",
                "const SKILL: &str = \"SpecKit-specify\";\n",
            )
            .assert_violation("DEP-09");
        }

        #[test]
        fn the_spec_kit_layout_inside_spec_adapter_passes() {
            let code = "const DIR: &str = \".specify/memory\";\nconst SKILL: &str = \"speckit-specify\";\n";
            run_with_source("spec_adapter", "src/lib.rs", code).assert_passes();
        }

        #[test]
        fn the_spec_kit_name_in_a_comment_outside_spec_adapter_passes() {
            run_with_source(
                "workflow",
                "src/lib.rs",
                "// The speckit layout is hidden behind SpecificationProvider.\n",
            )
            .assert_passes();
        }
    }

    mod dep_10_process_spawning {
        use super::*;

        fn spawn(program: &str) -> String {
            format!(
                "use std::process::Command;\npub fn run() {{\n    let _ = Command::new({program});\n}}\n"
            )
        }

        #[test]
        fn docker_spawned_outside_sandbox_fails() {
            run_with_source("workflow", "src/lib.rs", &spawn("\"docker\""))
                .assert_violation_mentions("DEP-10", "docker");
        }

        #[test]
        fn git_spawned_outside_sandbox_fails() {
            run_with_source("storage", "src/lib.rs", &spawn("\"git\"")).assert_violation("DEP-10");
        }

        #[test]
        fn docker_and_git_spawned_by_sandbox_pass() {
            let mut fx = Fixture::baseline("dep10-sandbox");
            fx.source("sandbox", "src/docker.rs", &spawn("\"docker\""));
            fx.source("sandbox", "src/git.rs", &spawn("\"/usr/bin/git\""));
            fx.run().assert_passes();
        }

        #[test]
        fn an_agent_tool_spawned_by_runtime_passes() {
            run_with_source("runtime", "src/claude.rs", &spawn("\"claude\"")).assert_passes();
        }

        #[test]
        fn an_agent_tool_spawned_outside_runtime_fails() {
            run_with_source("sandbox", "src/lib.rs", &spawn("\"codex\""))
                .assert_violation("DEP-10");
        }

        #[test]
        fn docker_spawned_by_runtime_fails() {
            run_with_source("runtime", "src/lib.rs", &spawn("\"docker\""))
                .assert_violation("DEP-10");
        }

        #[test]
        fn any_other_program_fails_even_in_sandbox() {
            run_with_source("sandbox", "src/lib.rs", &spawn("\"curl\""))
                .assert_violation_mentions("DEP-10", "curl");
        }

        #[test]
        fn a_program_that_is_not_a_literal_fails_outside_sandbox_and_runtime() {
            run_with_source("workflow", "src/lib.rs", &spawn("program"))
                .assert_violation_mentions("DEP-10", "literal");
        }

        #[test]
        fn a_program_that_is_not_a_literal_passes_in_sandbox() {
            run_with_source("sandbox", "src/lib.rs", &spawn("program")).assert_passes();
        }

        #[test]
        fn a_fully_qualified_spawn_is_found_without_an_import() {
            let code = "pub fn run() {\n    let _ = std::process::Command::new(\"docker\");\n}\n";
            run_with_source("github", "src/lib.rs", code).assert_violation("DEP-10");
        }

        #[test]
        fn a_tokio_spawn_is_found() {
            let code = "use tokio::process::Command;\npub async fn run() {\n    let _ = Command::new(\"docker\");\n}\n";
            let mut fx = Fixture::baseline("dep10-tokio");
            fx.source("workflow", "src/lib.rs", code);
            fx.run().assert_violation("DEP-10");
        }

        #[test]
        fn a_command_type_that_is_not_a_process_is_ignored() {
            let code =
                "use clap::Command;\npub fn cli() -> Command {\n    Command::new(\"factory\")\n}\n";
            run_with_source("api", "src/main.rs", code).assert_passes();
        }

        #[test]
        fn a_spawn_in_test_code_passes() {
            let code = format!("#[cfg(test)]\nmod tests {{\n{}}}\n", spawn("\"curl\""));
            run_with_source("workflow", "src/lib.rs", &code).assert_passes();
        }

        #[test]
        fn a_spawn_in_a_comment_passes() {
            run_with_source(
                "workflow",
                "src/lib.rs",
                "// Command::new(\"docker\") is sandbox only\n",
            )
            .assert_passes();
        }
    }

    mod st_03_no_shell {
        use super::*;

        fn spawn(program: &str) -> String {
            format!(
                "use std::process::Command;\npub fn run() {{\n    let _ = Command::new(\"{program}\");\n}}\n"
            )
        }

        #[test]
        fn a_shell_spawned_in_github_fails() {
            run_with_source("github", "src/lib.rs", &spawn("sh"))
                .assert_violation_mentions("ST-03", "sh");
        }

        #[test]
        fn a_shell_spawned_in_sandbox_fails_even_though_sandbox_may_spawn() {
            run_with_source("sandbox", "src/lib.rs", &spawn("/bin/bash")).assert_violation("ST-03");
        }

        #[test]
        fn the_report_points_a_static_check_to_the_catalog() {
            let run = run_with_source("github", "src/lib.rs", &spawn("sh"));
            run.assert_violation("ST-03");
            assert!(
                run.stderr.contains("negative-test-catalog.md"),
                "{}",
                run.stderr
            );
            assert!(
                !run.stderr
                    .contains("does not match crate-dependency-rules.json"),
                "{}",
                run.stderr
            );
        }

        #[test]
        fn every_listed_shell_fails() {
            for shell in [
                "sh",
                "bash",
                "zsh",
                "dash",
                "cmd",
                "cmd.exe",
                "powershell",
                "pwsh",
            ] {
                run_with_source("runtime", "src/lib.rs", &spawn(shell)).assert_violation("ST-03");
            }
        }

        #[test]
        fn a_program_that_only_starts_with_sh_passes_this_rule() {
            run_with_source("sandbox", "src/lib.rs", &spawn("shred")).assert_no_violation("ST-03");
        }

        #[test]
        fn docker_run_without_a_shell_passes() {
            run_with_source("sandbox", "src/lib.rs", &spawn("docker")).assert_passes();
        }
    }

    mod st_01_no_safe_directory_wildcard {
        use super::*;

        #[test]
        fn a_nested_checkout_is_not_part_of_this_repository() {
            // A git worktree or a nested clone has a `.git` entry of its own. Its files belong to
            // another checkout, so this repository's scan must not report them.
            let mut fx = Fixture::baseline("nested-checkout");
            fx.file(
                "worktrees/other/.git",
                "gitdir: /elsewhere/.git/worktrees/other\n",
            )
            .file(
                "worktrees/other/scripts/setup.sh",
                "git config --global --add safe.directory '*'\n",
            );
            fx.run().assert_no_violation("ST-01");
        }

        #[test]
        fn the_same_file_without_a_git_entry_of_its_own_still_fails() {
            // Control for the test above: only the `.git` marker grants the exemption.
            run_with_file(
                "worktrees/other/scripts/setup.sh",
                "git config --global --add safe.directory '*'\n",
            )
            .assert_violation("ST-01");
        }

        #[test]
        fn a_shell_script_that_sets_the_wildcard_fails() {
            run_with_file(
                "scripts/setup.sh",
                "git config --global --add safe.directory '*'\n",
            )
            .assert_violation_mentions("ST-01", "scripts/setup.sh:1");
        }

        #[test]
        fn the_equals_form_fails() {
            run_with_file("scripts/setup.sh", "git -c safe.directory=* status\n")
                .assert_violation("ST-01");
        }

        #[test]
        fn a_rust_argument_list_fails() {
            let code =
                "pub fn args() -> [&'static str; 3] { [\"config\", \"safe.directory\", \"*\"] }\n";
            run_with_source("sandbox", "src/lib.rs", code).assert_violation("ST-01");
        }

        #[test]
        fn a_gitconfig_section_fails() {
            run_with_file("docker/gitconfig", "[safe]\n\tdirectory = *\n")
                .assert_violation("ST-01");
        }

        #[test]
        fn a_yaml_value_fails() {
            run_with_file("deploy/config.yaml", "git:\n  safe.directory: \"*\"\n")
                .assert_violation("ST-01");
        }

        #[test]
        fn a_specific_directory_passes() {
            run_with_file(
                "scripts/setup.sh",
                "git config --global --add safe.directory /work/repo\n",
            )
            .assert_passes();
        }

        #[test]
        fn prose_in_a_markdown_file_passes() {
            run_with_file(
                "docs/notes.md",
                "The loader must never set `safe.directory=*`.\n",
            )
            .assert_passes();
        }

        #[test]
        fn a_comment_in_a_policy_file_that_forbids_the_wildcard_passes() {
            // policies/security.yaml says exactly this in a comment.
            let yaml = "git:\n  safe_directory_wildcard: forbidden   # never set safe.directory=* to silence errors\n";
            run_with_file("policies/example.yaml", yaml).assert_passes();
        }

        #[test]
        fn a_commented_out_shell_line_passes() {
            run_with_file(
                "scripts/setup.sh",
                "# git config --global --add safe.directory '*'\n",
            )
            .assert_passes();
        }

        #[test]
        fn a_hash_inside_a_quoted_string_does_not_hide_the_wildcard() {
            let script = "echo \"step #1\"; git config --global --add safe.directory '*'\n";
            run_with_file("scripts/setup.sh", script).assert_violation("ST-01");
        }

        #[test]
        fn a_wildcard_after_a_semicolon_is_not_a_comment() {
            run_with_file(
                "scripts/setup.sh",
                "cd /work; git config safe.directory '*'\n",
            )
            .assert_violation("ST-01");
        }

        #[test]
        fn a_comment_in_rust_source_passes() {
            let code = "// never pass safe.directory=* to git\npub fn ok() {}\n";
            run_with_source("sandbox", "src/lib.rs", code).assert_passes();
        }

        #[test]
        fn a_rust_attribute_before_the_wildcard_does_not_hide_it() {
            let code = "#[allow(dead_code)] const A: &str = \"safe.directory=*\";\n";
            run_with_source("sandbox", "src/lib.rs", code).assert_violation("ST-01");
        }

        #[test]
        fn a_build_output_directory_is_not_scanned() {
            run_with_file("target/debug/build.log", "safe.directory=*\n").assert_passes();
        }
    }

    mod st_02_no_equality_on_signatures {
        use super::*;

        #[test]
        fn comparing_a_signature_with_equals_fails() {
            let code = "pub fn verify(signature: &[u8], expected: &[u8]) -> bool {\n    signature == expected\n}\n";
            run_with_source("github", "src/webhook.rs", code)
                .assert_violation_mentions("ST-02", "crates/github/src/webhook.rs:2");
        }

        #[test]
        fn comparing_a_mac_with_not_equals_fails() {
            let code = "pub fn bad(computed_mac: &[u8], header_mac: &[u8]) -> bool {\n    computed_mac != header_mac\n}\n";
            run_with_source("github", "src/webhook.rs", code).assert_violation("ST-02");
        }

        #[test]
        fn calling_eq_on_a_signature_fails() {
            let code = "pub fn bad(sig: &[u8], other: &[u8]) -> bool {\n    sig.eq(other)\n}\n";
            run_with_source("api", "src/main.rs", code).assert_violation("ST-02");
        }

        #[test]
        fn an_hmac_comparison_fails() {
            let code = "pub fn bad(hmac_hex: &str, given: &str) -> bool { hmac_hex == given }\n";
            run_with_source("github", "src/lib.rs", code).assert_violation("ST-02");
        }

        #[test]
        fn a_constant_time_comparison_passes() {
            let code = "pub fn good(signature: &[u8], expected: &[u8]) -> bool {\n    constant_time_eq(signature, expected)\n}\n";
            run_with_source("github", "src/webhook.rs", code).assert_passes();
        }

        #[test]
        fn a_length_check_on_a_signature_passes() {
            let code = "pub fn length_ok(signature: &[u8]) -> bool {\n    signature.len() == 32 && !signature.is_empty()\n}\n";
            run_with_source("github", "src/webhook.rs", code).assert_passes();
        }

        #[test]
        fn words_that_only_contain_mac_pass() {
            let code = "pub fn same(machine: u8, macro_id: u8) -> bool { machine == macro_id }\n";
            run_with_source("workflow", "src/lib.rs", code).assert_passes();
        }

        #[test]
        fn a_comparison_in_test_code_passes() {
            let code = "#[cfg(test)]\nmod tests {\n    fn t(signature: u8) { assert!(signature == 1); }\n}\n";
            run_with_source("github", "src/lib.rs", code).assert_passes();
        }

        #[test]
        fn a_comparison_inside_a_string_passes() {
            let code = "pub const HELP: &str = \"never write signature == expected\";\n";
            run_with_source("github", "src/lib.rs", code).assert_passes();
        }
    }

    mod st_04_container_flags_only_in_the_posture_verifier {
        use super::*;

        const PRIVILEGED: &str = "pub const FLAG: &str = \"--privileged\";\n";

        #[test]
        fn a_dangerous_flag_in_the_container_builder_fails() {
            run_with_source("sandbox", "src/container/args.rs", PRIVILEGED)
                .assert_violation_mentions("ST-04", "crates/sandbox/src/container/args.rs:1");
        }

        #[test]
        fn a_dangerous_flag_in_another_crate_fails() {
            run_with_source("workflow", "src/lib.rs", PRIVILEGED).assert_violation("ST-04");
        }

        #[test]
        fn the_posture_verifier_file_may_list_it() {
            run_with_source("sandbox", "src/container/posture.rs", PRIVILEGED).assert_passes();
        }

        #[test]
        fn a_file_inside_a_posture_directory_may_list_it() {
            run_with_source("sandbox", "src/container/posture/deny_list.rs", PRIVILEGED)
                .assert_passes();
        }

        #[test]
        fn a_posture_file_in_another_crate_does_not_count() {
            run_with_source("workflow", "src/posture.rs", PRIVILEGED).assert_violation("ST-04");
        }

        #[test]
        fn every_listed_string_fails() {
            for text in [
                "--cap-add",
                "seccomp=unconfined",
                "apparmor=unconfined",
                "--network host",
                "--network=host",
                "--pid host",
                "--pid=host",
                "/var/run/docker.sock",
            ] {
                let code = format!("pub const FLAG: &str = \"{text}\";\n");
                run_with_source("sandbox", "src/container/args.rs", &code)
                    .assert_violation("ST-04");
            }
        }

        #[test]
        fn a_host_network_passed_as_two_arguments_fails() {
            let code = "pub fn args() -> [&'static str; 2] { [\"--network\", \"host\"] }\n";
            run_with_source("sandbox", "src/container/args.rs", code).assert_violation("ST-04");
        }

        #[test]
        fn a_network_none_passes() {
            let code = "pub fn args() -> [&'static str; 2] { [\"--network\", \"none\"] }\n";
            run_with_source("sandbox", "src/container/args.rs", code).assert_passes();
        }

        #[test]
        fn a_network_name_that_only_starts_with_host_passes() {
            let code = "pub const FLAG: &str = \"--network hostile-net\";\n";
            run_with_source("sandbox", "src/container/args.rs", code).assert_passes();
        }

        #[test]
        fn a_flag_in_test_code_passes() {
            let code = format!("#[cfg(test)]\nmod tests {{\n{PRIVILEGED}}}\n");
            run_with_source("sandbox", "src/container/args.rs", &code).assert_passes();
        }

        #[test]
        fn a_flag_in_a_comment_passes() {
            run_with_source(
                "sandbox",
                "src/container/args.rs",
                "// never pass --privileged\n",
            )
            .assert_passes();
        }
    }

    mod st_05_no_merge_or_deploy_path {
        use super::*;

        #[test]
        fn a_merge_function_fails() {
            let code = "pub async fn merge_pull_request(number: u64) {}\n";
            run_with_source("github", "src/lib.rs", code)
                .assert_violation_mentions("ST-05", "merge_pull_request");
        }

        #[test]
        fn a_function_named_merge_fails() {
            run_with_source("workflow", "src/lib.rs", "fn merge() {}\n").assert_violation("ST-05");
        }

        #[test]
        fn a_deploy_function_fails() {
            run_with_source(
                "workflow",
                "src/lib.rs",
                "pub fn deploy_to_production() {}\n",
            )
            .assert_violation("ST-05");
        }

        #[test]
        fn a_release_publish_function_fails() {
            run_with_source(
                "github",
                "src/lib.rs",
                "pub fn publish_release(tag: &str) {}\n",
            )
            .assert_violation("ST-05");
        }

        #[test]
        fn a_merge_route_fails() {
            let code = "pub fn url(n: u64) -> String { format!(\"/repos/o/r/pulls/{n}/merge\") }\n";
            run_with_source("github", "src/lib.rs", code)
                .assert_violation_mentions("ST-05", "/merge");
        }

        #[test]
        fn a_deploy_route_fails() {
            run_with_source(
                "api",
                "src/main.rs",
                "const ROUTE: &str = \"/api/deploy\";\n",
            )
            .assert_violation("ST-05");
        }

        #[test]
        fn a_workflow_file_named_deploy_fails() {
            run_with_file(".github/workflows/deploy.yml", "name: deploy\n")
                .assert_violation_mentions("ST-05", "deploy.yml");
        }

        #[test]
        fn reading_the_merged_state_passes() {
            let code = "pub fn merged(pr: &Pr) -> bool { pr.merged }\npub fn is_mergeable(pr: &Pr) -> bool { pr.mergeable }\n";
            run_with_source("github", "src/lib.rs", code).assert_passes();
        }

        #[test]
        fn opening_a_draft_pull_request_passes() {
            run_with_source(
                "github",
                "src/lib.rs",
                "pub fn open_draft_pull_request() {}\n",
            )
            .assert_passes();
        }

        #[test]
        fn an_ordinary_workflow_file_passes() {
            run_with_file(".github/workflows/ci.yml", "name: ci\n").assert_passes();
        }

        #[test]
        fn a_merge_function_in_test_code_passes() {
            run_with_source(
                "github",
                "src/lib.rs",
                "#[cfg(test)]\nmod tests {\n    fn merge_fixture() {}\n}\n",
            )
            .assert_passes();
        }
    }

    mod st_09_workspace_reads_go_through_ingestion {
        use super::*;

        const READ: &str = "pub fn read(path: &std::path::Path) -> String {\n    std::fs::read_to_string(path).unwrap_or_default()\n}\n";

        #[test]
        fn a_read_in_sandbox_outside_the_ingestion_module_fails() {
            run_with_source("sandbox", "src/container/logs.rs", READ)
                .assert_violation_mentions("ST-09", "crates/sandbox/src/container/logs.rs:2");
        }

        #[test]
        fn a_read_inside_the_ingestion_module_passes() {
            run_with_source("sandbox", "src/workspace/ingest.rs", READ).assert_passes();
        }

        #[test]
        fn a_read_in_a_crate_that_handles_workspace_content_fails() {
            for member in ["workflow", "runtime", "spec_adapter"] {
                run_with_source(member, "src/lib.rs", READ).assert_violation("ST-09");
            }
        }

        #[test]
        fn opening_a_file_fails() {
            let code = "pub fn open() { let _ = std::fs::File::open(\"x\"); }\n";
            run_with_source("workflow", "src/lib.rs", code).assert_violation("ST-09");
        }

        #[test]
        fn an_async_read_fails() {
            let code = "pub async fn read() { let _ = tokio::fs::read(\"x\").await; }\n";
            run_with_source("runtime", "src/lib.rs", code).assert_violation("ST-09");
        }

        #[test]
        fn listing_a_directory_fails() {
            run_with_source(
                "sandbox",
                "src/lib.rs",
                "pub fn list() { let _ = std::fs::read_dir(\".\"); }\n",
            )
            .assert_violation("ST-09");
        }

        #[test]
        fn checking_that_a_path_exists_fails() {
            run_with_source(
                "sandbox",
                "src/lib.rs",
                "pub fn there(p: &std::path::Path) -> bool { p.exists() }\n",
            )
            .assert_violation("ST-09");
        }

        #[test]
        fn a_write_is_not_a_read() {
            let code = "pub fn write() { let _ = std::fs::write(\"x\", \"y\"); }\n";
            run_with_source("sandbox", "src/lib.rs", code).assert_no_violation("ST-09");
        }

        #[test]
        fn crates_that_read_configuration_or_their_own_blobs_are_outside_the_rule() {
            for member in ["storage", "github"] {
                run_with_source(member, "src/lib.rs", READ).assert_no_violation("ST-09");
            }
        }

        #[test]
        fn a_read_in_test_code_passes() {
            let code = format!("#[cfg(test)]\nmod tests {{\n{READ}}}\n");
            run_with_source("sandbox", "src/lib.rs", &code).assert_passes();
        }

        #[test]
        fn a_read_in_a_comment_passes() {
            run_with_source(
                "sandbox",
                "src/lib.rs",
                "// std::fs::read_to_string(path) is for ingestion only\n",
            )
            .assert_passes();
        }
    }
}
