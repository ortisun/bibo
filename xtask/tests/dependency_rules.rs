//! One passing and one failing fixture for each dependency rule that `cargo metadata` can prove:
//! DEP-01 to DEP-04 and DEP-08. Each failing fixture changes one thing in the baseline and
//! expects the check to exit non-zero with that rule's id.

mod common;

use common::Fixture;

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
    fn adapters_and_test_support_are_outside_the_rule() {
        // DEP-04 covers rings 0 and 1 and the application crates. An adapter chooses its own.
        let mut fx = Fixture::baseline("dep04-adapter");
        fx.external("storage", "reqwest", &[]);
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
    fn a_listed_crate_that_does_not_exist_yet_passes_by_default() {
        let mut fx = Fixture::baseline("layout-missing");
        fx.remove_dependency("api", "github");
        fx.omit_from_workspace("github");
        fx.run().assert_passes();
    }

    #[test]
    fn a_listed_crate_that_does_not_exist_fails_when_every_crate_is_required() {
        let mut fx = Fixture::baseline("layout-required");
        fx.remove_dependency("api", "github");
        fx.omit_from_workspace("github");
        fx.run_with(&["--require-all-crates"])
            .assert_violation_mentions("LAYOUT", "github");
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
