//! One passing and one failing fixture for each dependency rule that `cargo metadata` or the
//! manifests can prove: DEP-01 to DEP-04, DEP-06 and DEP-08. Each failing fixture changes one thing in the baseline and
//! expects the check to exit non-zero with that rule's id.

mod common;

// Every test sits under this module so that `cargo nextest run -p xtask dependency_rules` selects it.
mod dependency_rules {
    use super::common::Fixture;

    #[test]
    fn baseline_workspace_passes_every_rule() {
        Fixture::baseline("baseline").run().assert_passes();
    }

    mod dep_01_only_listed_workspace_edges {
        use super::*;

        #[test]
        fn a_library_depending_on_an_unlisted_crate_fails() {
            let mut fx = Fixture::baseline("dep01-normal");
            fx.depend("storage", "sandbox");
            fx.run()
                .assert_violation_mentions("DEP-01", "factory-storage");
        }

        #[test]
        fn a_dev_dependency_outside_the_dev_list_fails() {
            // The rules list runtime as a normal dependency of nobody. Only testkit may appear in a
            // dev-dependency list.
            let mut fx = Fixture::baseline("dep01-dev");
            fx.dev_depend("storage", "runtime");
            fx.run()
                .assert_violation_mentions("DEP-01", "factory-runtime");
        }

        #[test]
        fn a_dev_dependency_may_name_anything_the_crate_may_use() {
            // Listing a crate under depends_on allows it as a dev-dependency too, because the tests
            // of a crate may use anything the crate itself may use.
            let mut fx = Fixture::baseline("dep01-dev-allowed");
            fx.dev_depend("workflow", "domain");
            fx.run().assert_no_violation("DEP-01");
        }

        #[test]
        fn a_build_dependency_outside_the_list_fails() {
            let mut fx = Fixture::baseline("dep01-build");
            fx.build_depend("sandbox", "runtime");
            fx.run()
                .assert_violation_mentions("DEP-01", "factory-runtime");
        }

        #[test]
        fn a_dev_dependency_on_a_listed_dev_crate_passes() {
            // The baseline already has workflow -> testkit as a dev-dependency.
            Fixture::baseline("dep01-ok")
                .run()
                .assert_no_violation("DEP-01");
        }

        #[test]
        fn a_binary_may_depend_on_any_library() {
            let mut fx = Fixture::baseline("dep01-app");
            fx.depend("api", "spec_adapter");
            fx.depend("api", "observability");
            fx.run().assert_passes();
        }
    }

    mod dep_02_dependencies_point_inward {
        use super::*;

        #[test]
        fn a_peer_in_the_same_ring_fails_even_when_the_rules_list_it() {
            let mut fx = Fixture::baseline("dep02-peer");
            fx.depend("sandbox", "runtime");
            fx.allow_in_rules("sandbox", "runtime");
            let run = fx.run();
            run.assert_violation_mentions("DEP-02", "factory-sandbox");
            run.assert_no_violation("DEP-01");
        }

        #[test]
        fn an_inner_crate_depending_on_a_higher_ring_fails() {
            let mut fx = Fixture::baseline("dep02-outward");
            fx.depend("domain", "observability");
            fx.allow_in_rules("domain", "observability");
            let run = fx.run();
            run.assert_violation_mentions("DEP-02", "factory-domain");
            run.assert_no_violation("DEP-01");
        }

        #[test]
        fn ports_may_depend_on_domain() {
            // The baseline has this edge; the only allowed upward-looking pair in the rules.
            Fixture::baseline("dep02-ports")
                .run()
                .assert_no_violation("DEP-02");
        }

        #[test]
        fn a_dependency_cycle_through_a_dev_dependency_fails() {
            // Cargo accepts a cycle that runs through a dev-dependency, so the check must find it.
            let mut fx = Fixture::baseline("dep02-cycle");
            fx.dev_depend("domain", "testkit");
            fx.allow_dev_in_rules("domain", "testkit");
            fx.run().assert_violation_mentions("DEP-02", "cycle");
        }
    }

    mod dep_03_testkit_is_dev_only {
        use super::*;

        #[test]
        fn a_normal_dependency_on_testkit_fails() {
            let mut fx = Fixture::baseline("dep03-normal");
            fx.depend("workflow", "testkit");
            fx.allow_in_rules("workflow", "testkit");
            let run = fx.run();
            run.assert_violation_mentions("DEP-03", "factory-workflow");
            run.assert_no_violation("DEP-01");
        }

        #[test]
        fn a_build_dependency_on_testkit_fails() {
            let mut fx = Fixture::baseline("dep03-build");
            fx.build_depend("storage", "testkit");
            fx.allow_in_rules("storage", "testkit");
            fx.run().assert_violation("DEP-03");
        }

        #[test]
        fn a_dev_dependency_on_testkit_passes() {
            Fixture::baseline("dep03-dev")
                .run()
                .assert_no_violation("DEP-03");
        }
    }

    mod dep_04_external_crates_and_features {
        use super::*;

        #[test]
        fn an_external_crate_outside_the_list_fails() {
            let mut fx = Fixture::baseline("dep04-name");
            fx.external("domain", "reqwest", &[]);
            fx.run().assert_violation_mentions("DEP-04", "reqwest");
        }

        #[test]
        fn a_feature_outside_the_list_fails() {
            let mut fx = Fixture::baseline("dep04-feature");
            fx.external("workflow", "tokio", &["sync", "fs"]);
            fx.run().assert_violation_mentions("DEP-04", "fs");
        }

        #[test]
        fn a_feature_that_switches_on_a_forbidden_one_fails() {
            // `full` implies `fs` and `net` in the stub, as it does in the real crate.
            let mut fx = Fixture::baseline("dep04-implied");
            fx.external("workflow", "tokio", &["full"]);
            fx.run().assert_violation_mentions("DEP-04", "tokio");
        }

        #[test]
        fn listed_features_pass() {
            let mut fx = Fixture::baseline("dep04-ok");
            fx.external("workflow", "tokio", &["sync", "time"]);
            fx.run().assert_passes();
        }

        #[test]
        fn a_name_with_a_dash_or_underscore_matches_either_spelling() {
            let mut fx = Fixture::baseline("dep04-spelling");
            fx.external_stub("serde-json-like", &[]);
            fx.external("domain", "serde-json-like", &[]);
            fx.allow_external_in_rules("domain", "serde_json_like");
            fx.run().assert_passes();
        }

        #[test]
        fn test_support_is_outside_the_rule() {
            let mut fx = Fixture::baseline("dep04-testkit");
            fx.external("testkit", "reqwest", &[]);
            fx.run().assert_no_violation("DEP-04");
        }

        #[test]
        fn dev_dependencies_are_outside_the_rule() {
            let mut fx = Fixture::baseline("dep04-dev");
            fx.dev_external("domain", "reqwest", &[]);
            fx.run().assert_no_violation("DEP-04");
        }

        #[test]
        fn a_free_text_entry_allows_nothing_by_name() {
            let mut fx = Fixture::baseline("dep04-placeholder");
            fx.allow_external_in_rules("domain", "a maintained crate chosen later");
            fx.external("domain", "reqwest", &[]);
            fx.run().assert_violation_mentions("DEP-04", "reqwest");
        }
    }

    /// Adapters were exempt from DEP-04 until review finding F-12, so their `external_allow` lists
    /// were read and never enforced.
    mod dep_04_adapters {
        use super::*;

        #[test]
        fn an_adapter_with_a_crate_that_is_not_listed_fails() {
            let mut fx = Fixture::baseline("dep04-adapter-name");
            fx.external("sandbox", "reqwest", &[]);
            fx.run().assert_violation_mentions(
                "DEP-04",
                "factory-sandbox depends on the external crate reqwest",
            );
        }

        #[test]
        fn an_adapter_that_enables_a_tokio_feature_that_is_not_listed_fails() {
            let mut fx = Fixture::baseline("dep04-adapter-feature");
            fx.allow_external_in_rules("runtime", "tokio[sync,rt]");
            fx.external("runtime", "tokio", &["sync", "fs"]);
            fx.run().assert_violation_mentions("DEP-04", "fs");
        }

        #[test]
        fn an_adapter_that_uses_only_the_listed_features_passes() {
            let mut fx = Fixture::baseline("dep04-adapter-ok");
            fx.allow_external_in_rules("runtime", "tokio[sync,rt]");
            fx.external("runtime", "tokio", &["sync", "rt"]);
            fx.run().assert_passes();
        }

        #[test]
        fn an_entry_without_brackets_allows_every_feature_of_that_crate() {
            let mut fx = Fixture::baseline("dep04-adapter-any");
            fx.allow_external_in_rules("storage", "tokio");
            fx.external("storage", "tokio", &["net"]);
            fx.run().assert_passes();
        }

        #[test]
        fn a_tokio_feature_that_no_limit_lists_reaches_workflow_through_an_adapter() {
            // storage may enable any tokio feature by its own entry. Cargo unifies the feature
            // into the tokio that workflow uses, and the limit on the resolved set catches it.
            let mut fx = Fixture::baseline("dep04-adapter-unified");
            fx.allow_external_in_rules("storage", "tokio");
            fx.external("storage", "tokio", &["fs"]);
            let run = fx.run();
            run.assert_violation_mentions("DEP-05", "factory-workflow resolves tokio");
            run.assert_no_violation("DEP-04");
        }

        #[test]
        fn a_dev_dependency_of_an_adapter_is_outside_the_rule() {
            let mut fx = Fixture::baseline("dep04-adapter-dev");
            fx.dev_external("sandbox", "reqwest", &[]);
            fx.run().assert_no_violation("DEP-04");
        }

        #[test]
        fn every_adapter_is_checked() {
            for adapter in ["storage", "sandbox", "runtime", "github", "observability"] {
                let mut fx = Fixture::baseline("dep04-each-adapter");
                fx.external(adapter, "reqwest", &[]);
                fx.run().assert_violation_mentions("DEP-04", adapter);
            }
        }
    }

    /// The domain crate gets no clock and no identifier generator: `time` without `std` and `uuid`
    /// with `std` only (ADR 0002 and 0011). The first two tests read the domain's own manifest,
    /// the others read what Cargo resolves for the whole workspace.
    mod dep_04_domain_features {
        use super::*;

        fn domain_with_time_and_uuid(label: &str) -> Fixture {
            let mut fx = Fixture::baseline(label);
            fx.external_stub(
                "time",
                &[("alloc", &[]), ("std", &["alloc"]), ("macros", &[])],
            );
            fx.external_stub("uuid", &[("std", &[]), ("v4", &["std"]), ("v7", &["std"])]);
            fx.allow_external_in_rules("domain", "time[]");
            fx.allow_external_in_rules("domain", "uuid[std]");
            fx.external("domain", "time", &[]);
            fx.external("domain", "uuid", &["std"]);
            fx
        }

        #[test]
        fn time_without_features_and_uuid_with_std_pass() {
            domain_with_time_and_uuid("dep04-domain-ok")
                .run()
                .assert_passes();
        }

        #[test]
        fn the_domain_crate_enabling_any_feature_of_time_fails() {
            let mut fx = domain_with_time_and_uuid("dep04-domain-time");
            fx.external("domain", "time", &["std"]);
            fx.run().assert_violation_mentions("DEP-04", "std");
        }

        #[test]
        fn the_domain_crate_enabling_a_uuid_feature_other_than_std_fails() {
            let mut fx = domain_with_time_and_uuid("dep04-domain-uuid");
            fx.external("domain", "uuid", &["std", "v4"]);
            fx.run().assert_violation_mentions("DEP-04", "v4");
        }

        #[test]
        fn another_crate_enabling_time_std_gives_the_domain_a_clock() {
            // The review's mutation: time/std switched on in the (empty) storage crate. The
            // domain manifest still says time without features, and it passes DEP-04.
            let mut fx = domain_with_time_and_uuid("dep04-domain-unified-time");
            fx.allow_external_in_rules("storage", "time");
            fx.external("storage", "time", &["std"]);
            let run = fx.run();
            run.assert_violation_mentions("DEP-05", "factory-domain resolves time");
            run.assert_violation_mentions("DEP-05", "Enabled by factory-storage");
            run.assert_no_violation("DEP-04");
        }

        #[test]
        fn another_crate_enabling_a_uuid_generator_gives_the_domain_one() {
            let mut fx = domain_with_time_and_uuid("dep04-domain-unified-uuid");
            fx.allow_external_in_rules("workflow", "uuid");
            fx.external("workflow", "uuid", &["v7"]);
            fx.run()
                .assert_violation_mentions("DEP-05", "factory-domain resolves uuid");
        }

        #[test]
        fn a_dev_dependency_that_enables_it_counts_too() {
            // `cargo clippy --all-targets` builds the tests, so their features are unified.
            let mut fx = domain_with_time_and_uuid("dep04-domain-unified-dev");
            fx.dev_external("storage", "time", &["std"]);
            fx.run().assert_violation_mentions("DEP-05", "time");
        }

        #[test]
        fn another_crate_using_time_without_features_changes_nothing() {
            let mut fx = domain_with_time_and_uuid("dep04-domain-unified-ok");
            fx.allow_external_in_rules("storage", "time");
            fx.external("storage", "time", &[]);
            fx.run().assert_passes();
        }

        #[test]
        fn the_check_names_the_limit_in_the_rules_file() {
            let mut fx = domain_with_time_and_uuid("dep04-domain-message");
            fx.allow_external_in_rules("storage", "time");
            fx.external("storage", "time", &["std"]);
            fx.run()
                .assert_violation_mentions("DEP-05", "source_scans.dep_05.resolved_features");
        }
    }

    mod dep_08_only_binaries_wire_adapters {
        use super::*;

        #[test]
        fn a_library_depending_on_two_adapters_fails() {
            let mut fx = Fixture::baseline("dep08-two");
            fx.depend("workflow", "storage");
            fx.depend("workflow", "sandbox");
            fx.allow_in_rules("workflow", "storage");
            fx.allow_in_rules("workflow", "sandbox");
            let run = fx.run();
            run.assert_violation_mentions("DEP-08", "factory-workflow");
            run.assert_no_violation("DEP-01");
        }

        #[test]
        fn a_binary_depending_on_several_adapters_passes() {
            // The baseline binary depends on storage, sandbox, runtime and github.
            Fixture::baseline("dep08-app")
                .run()
                .assert_no_violation("DEP-08");
        }
    }

    mod layout_the_workspace_matches_the_rules_file {
        use super::*;

        #[test]
        fn a_member_the_rules_do_not_list_fails() {
            let mut fx = Fixture::baseline("layout-unlisted");
            fx.unlisted_crate("rogue");
            fx.run()
                .assert_violation_mentions("LAYOUT", "factory-rogue");
        }

        #[test]
        fn a_crate_outside_its_directory_fails() {
            let mut fx = Fixture::baseline("layout-moved");
            fx.relocate("storage", "crates/elsewhere");
            fx.run()
                .assert_violation_mentions("LAYOUT", "factory-storage");
        }

        #[test]
        fn a_listed_crate_that_does_not_exist_fails_by_default() {
            let mut fx = Fixture::baseline("layout-required");
            fx.remove_dependency("api", "github");
            fx.omit_from_workspace("github");
            fx.run_default()
                .assert_violation_mentions("LAYOUT", "factory-github");
        }

        #[test]
        fn a_listed_binary_that_does_not_exist_fails_by_default() {
            let mut fx = Fixture::baseline("layout-required-app");
            fx.omit_from_workspace("api");
            fx.run_default()
                .assert_violation_mentions("LAYOUT", "factory-api");
        }

        #[test]
        fn a_missing_crate_passes_when_missing_crates_are_allowed() {
            let mut fx = Fixture::baseline("layout-allowed");
            fx.remove_dependency("api", "github");
            fx.omit_from_workspace("github");
            // `run` passes --allow-missing-crates.
            fx.run().assert_passes();
        }

        #[test]
        fn a_workspace_with_every_listed_crate_passes_by_default() {
            Fixture::baseline("layout-complete")
                .run_default()
                .assert_passes();
        }
    }

    mod dep_06_every_crate_inherits_the_workspace_lints {
        use super::*;

        #[test]
        fn a_crate_without_a_lints_table_fails() {
            let mut fx = Fixture::baseline("dep06-none");
            fx.lints_block("storage", None);
            fx.run()
                .assert_violation_mentions("DEP-06", "crates/storage/Cargo.toml");
        }

        #[test]
        fn a_binary_without_a_lints_table_fails() {
            let mut fx = Fixture::baseline("dep06-app");
            fx.lints_block("api", None);
            fx.run()
                .assert_violation_mentions("DEP-06", "apps/api/Cargo.toml");
        }

        #[test]
        fn a_crate_with_its_own_lints_instead_of_the_workspace_ones_fails() {
            let mut fx = Fixture::baseline("dep06-own");
            fx.lints_block("domain", Some("\n[lints.rust]\nunsafe_code = \"warn\"\n"));
            fx.run()
                .assert_violation_mentions("DEP-06", "factory-domain");
        }

        #[test]
        fn a_commented_out_lints_table_fails() {
            let mut fx = Fixture::baseline("dep06-comment");
            fx.lints_block("sandbox", Some("\n# [lints]\n# workspace = true\n"));
            fx.run().assert_violation("DEP-06");
        }

        #[test]
        fn every_crate_that_inherits_passes() {
            Fixture::baseline("dep06-ok")
                .run()
                .assert_no_violation("DEP-06");
        }

        #[test]
        fn a_root_manifest_that_does_not_mention_unsafe_code_fails() {
            // Cargo itself refuses members that inherit from a root without any lints table,
            // so the root keeps one lint and leaves out `unsafe_code`.
            let mut fx = Fixture::baseline("dep06-root-missing");
            fx.root_lints_block(Some(
                "\n[workspace.lints.rust]\nrust_2018_idioms = \"warn\"\n",
            ));
            fx.run().assert_violation_mentions("DEP-06", "unsafe_code");
        }

        #[test]
        fn a_root_manifest_that_only_warns_about_unsafe_code_fails() {
            let mut fx = Fixture::baseline("dep06-root-warn");
            fx.root_lints_block(Some("\n[workspace.lints.rust]\nunsafe_code = \"warn\"\n"));
            fx.run().assert_violation_mentions("DEP-06", "Cargo.toml");
        }

        #[test]
        fn a_root_manifest_with_a_forbid_table_entry_passes() {
            let mut fx = Fixture::baseline("dep06-root-table");
            fx.root_lints_block(Some(
                "\n[workspace.lints.rust]\nunsafe_code = { level = \"forbid\", priority = 0 }\n",
            ));
            fx.run().assert_no_violation("DEP-06");
        }
    }

    mod running_the_check {
        use super::*;

        #[test]
        fn a_missing_rules_file_is_an_error_not_a_pass() {
            let fx = Fixture::baseline("run-no-rules");
            let run = fx.run_with(&["--rules", "/definitely/not/here.json"]);
            run.assert_error("rules");
        }

        #[test]
        fn a_rules_file_that_is_not_json_is_an_error() {
            let mut fx = Fixture::baseline("run-bad-rules");
            fx.rules_mut()["crates"] = serde_json::json!("not a list");
            fx.run().assert_error("crates");
        }

        #[test]
        fn a_missing_manifest_is_an_error() {
            let fx = Fixture::baseline("run-no-manifest");
            let run = fx.run_with(&["--manifest-path", "/definitely/not/here/Cargo.toml"]);
            assert_eq!(run.code, Some(2), "stderr: {}", run.stderr);
        }
    }
}
