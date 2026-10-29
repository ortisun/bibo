# P0 coverage matrix

Status: GENERATED from [`p0-coverage.json`](p0-coverage.json) by `docs/security/tools/check_p0_coverage.py`. Do not edit the matrix by hand.
Form: reference.
Owner: the `s1-security-review-and-tests` work package. An independent review of the matrix and of its checker has not happened yet.

## What this page is for

The [negative test catalog](negative-test-catalog.md) lists every test that must pass before Slice 1 is accepted (priority P0). Principle 2 of the catalog says that every test must be able to fail: there has to be a variant of it with its control switched off, and the test has to fail on that variant. This page maps each P0 test to four things, so that a reader can see what is real and what is not:

1. the owner of the test (a work package in [`work-packages.json`](../architecture/work-packages.json) and a crate);
2. the tests in the repository that implement it, by function name;
3. the control-off variant: a mutation that removes the control from the production source, or a break test that does the same through a seam;
4. the status.

## How to read the status

| Status | Meaning |
|---|---|
| implemented, control-off proven | At least one test of the row runs without Docker or a live provider, and the row names a control-off variant that exists and is said to make a test of the row fail. A mutation shows when it was last run in this review. |
| implemented, control-off missing | The test exists and runs, and nothing in the repository removes its control to show it fails. This is a gap in the evidence, not in the control. |
| BLOCKED | Every test of the row needs Docker or a live provider that this machine does not have. The tests exist; they did not run here, and a test that did not run has not passed. |
| missing | The repository holds no test with the catalog name. |

The checker proves what a file can prove: the row exists, every named test is defined in the named file, every named mutation is defined in its script, every named break test exists, and a status never claims more than the evidence under it. It does not run a build. A mutation script rebuilds the crate for each break, so the scripts are run by hand and their results are recorded in `mutation_runs` of the data file, which is how "run in this review" below is known.

## The check

```console
python3 -I docs/security/tools/check_p0_coverage.py --check
python3 -I docs/security/tools/check_p0_coverage.py --write
```

The first command fails when a P0 test of the catalog has no row, when a row points to a test that is not in the source, when a row claims a control-off variant that does not exist, when the owner matrix of the audit event types disagrees with the policy file or with the sources, and when this page is out of date. It also runs `--self-test`, which breaks a copy of the data in ten ways (a row removed, a test that does not exist, a file that does not exist, a mutation that no script defines, a status of proven with no variant, a variant for a test of another row, a block with no reason, an audit event type dropped, an owner that is not a work package, an emitter that the sources do not hold) and needs the validation to catch each one. The CI step is `scripts/ci/steps.d/49-p0-coverage.step`. The command reads files, is cheap and needs no Docker.

## How a control-off variant is run

A variant is a change to the sources that removes one control. The script `tests/security/mutations.py` holds the variants of the cross-cutting tests and can run those of the sandbox, egress and runtime packages too:

```console
python3 -I tests/security/mutations.py --record
python3 -I tests/security/mutations.py --record --script crates/sandbox/tests/mutations.py
```

Each run applies the change, runs `cargo nextest`, writes down which tests failed, and puts the sources back. `--record` copies the result into `mutation_runs` of the data file, and a row lists a variant only when a recorded run made a test of that row fail. The GitHub package has its own script, `crates/github/tests/mutations/run_mutations.py`, whose filters name the tests it runs. The runs are not part of CI, because each one rebuilds a crate.

## Matrix

<!-- GENERATED:begin matrix -->
| Status | Count |
|---|---|
| implemented, control-off proven | 38 |
| implemented, control-off missing | 50 |
| BLOCKED | 0 |
| missing | 0 |
| P0 tests of the catalog | 88 |

### The matrix

| Test | Title | Owner (work package, crate) | Tests in the repository | Control-off variant | Status |
|---|---|---|---|---|---|
| NT-AUD-01 | Append-only audit | s1-storage-postgres, storage | `negative_nt_aud_01` | none | implemented, control-off missing |
| NT-AUD-03 | Coverage | s1-security-review-and-tests, workflow (partial) | `negative_nt_aud_03_every_required_event_type_appears_with_actor_policy_hash_and_correla…`<br>`negative_nt_aud_03_the_matrix_lists_an_owner_for_every_type_the_policy_requires`<br>`negative_nt_aud_03_the_types_the_scenario_scripts_are_the_types_the_engine_does_not_wri…`<br>and 3 more | mutation `the-budget-threshold-is-never-recorded`, caught 2026-10-29<br>mutation `the-api-writes-the-old-webhook-name`, caught 2026-10-29<br>mutation `the-engine-does-not-write-command-executed`, caught 2026-10-29 | implemented, control-off proven |
| NT-AUTHZ-01 | Unauthorized label | s1-stage-intake-and-repository, workflow | `negative_nt_authz_01_only_the_numeric_id_on_the_allowlist_grants_a_designation`<br>`negative_nt_authz_01_the_actor_is_the_numeric_id_and_a_lookalike_login_is_a_different_p…`<br>`negative_nt_authz_01_a_label_that_came_with_issue_creation_names_its_author`<br>and 5 more | mutation `identify a person by the login and not by the numeric id`, caught 2026-10-29<br>mutation `a-bot-may-hold-a-designation`, caught 2026-10-29<br>mutation `an-expired-allowlist-entry-still-grants`, caught 2026-10-29 | implemented, control-off proven |
| NT-AUTHZ-02 | Command by an unauthorized user | s1-stage-delivery-and-approval, workflow | `negative_nt_authz_02_a_command_comment_arrives_with_its_authors_numeric_id`<br>`negative_nt_authz_02_an_unauthorized_command_is_audited_and_gets_no_reply`<br>`negative_nt_authz_02_a_sender_who_may_not_decide_is_refused_without_a_reply` | none | implemented, control-off missing |
| NT-AUTHZ-05 | Issue edited after authorization | s1-stage-intake-and-repository, workflow | `negative_nt_authz_05_an_edit_after_the_snapshot_waits_for_the_requester_and_no_agent_re…`<br>`negative_nt_authz_05_the_stage_refuses_an_edited_request_nobody_confirmed` | mutation `data-lines-are-not-quoted`, caught 2026-10-29 | implemented, control-off proven |
| NT-AUTHZ-06 | Token narrowing across repositories | s1-github-adapter, github | `negative_nt_authz_06_a_token_is_minted_for_one_repository_and_nothing_else_is_reachable`<br>`negative_nt_authz_06_a_token_that_is_wider_than_the_request_is_revoked_and_refused` | mutation `use an over-broad token without looking`, caught 2026-10-29 | implemented, control-off proven |
| NT-AUTHZ-07 | Stage-scoped permissions | s1-github-adapter, github | `negative_nt_authz_07_every_stage_gets_exactly_its_permissions_and_only_delivery_writes_…`<br>`negative_nt_authz_07_a_read_only_token_cannot_comment_or_open_a_pull_request` | mutation `let a stage that may not write get the write credential`, caught 2026-10-29 | implemented, control-off proven |
| NT-AUTHZ-08 | Unknown tenant binding | s1-apps-composition, api | `negative_nt_authz_08` | none | implemented, control-off missing |
| NT-AUTHZ-09 | App permission audit | s1-github-adapter, github | `negative_nt_authz_09_an_app_that_holds_a_forbidden_permission_gets_no_token`<br>`negative_nt_authz_09_an_app_that_lacks_a_required_permission_is_capped` | mutation `an-app-with-a-forbidden-permission-gets-a-token`, caught 2026-10-29 | implemented, control-off proven |
| NT-BUD-01 | Per-task cost ceiling | s1-egress-and-broker, egress | `negative_nt_bud_01_per_task_cost_ceiling_stops_a_looping_client`<br>`negative_nt_bud_01_a_run_over_its_limit_is_not_retried` | mutation `ignore-the-cost-ceiling`, caught 2026-10-29 | implemented, control-off proven |
| NT-BUD-03 | Turns, tool calls, stagnation | s1-engine-core, workflow (partial) | `negative_nt_bud_03_a_repeated_failure_asks_a_person_after_one_round` | none | implemented, control-off missing |
| NT-BUD-07 | CLI budget ignored, revocation latency | s1-egress-and-broker, egress | `negative_nt_bud_07_a_tool_that_ignores_its_budget_is_still_stopped_and_counted`<br>`negative_nt_bud_07_a_turn_cap_stops_a_tool_that_has_no_turn_limit_of_its_own`<br>`negative_nt_bud_07_failed_attempts_are_counted_per_attempt` | mutation `do-not-count-failed-attempts`, caught 2026-10-29<br>mutation `ignore-the-request-cap`, caught 2026-10-29 | implemented, control-off proven |
| NT-GATE-01 | Test code is additions-only | s1-trusted-gates-and-validation, workflow | `negative_nt_gate_01_the_builder_weakens_a_test_or_edits_a_fixture`<br>`negative_nt_gate_01_a_new_test_file_and_an_appended_test_pass_the_path_rule`<br>`negative_nt_gate_01_a_changed_removed_deleted_or_renamed_test_is_blocked_by_its_group` | mutation `the-workspace-lets-any-edit-in`, caught 2026-10-29 | implemented, control-off proven |
| NT-GATE-02 | Removed, ignored or skipped tests | s1-trusted-gates-and-validation, workflow | `negative_nt_gate_02_a_test_removed_or_ignored_inside_a_source_file_is_found_at_the_sour…`<br>`negative_nt_gate_02_skip_xfail_and_focus_markers_in_new_files_are_found`<br>`negative_nt_gate_02_a_test_missing_from_the_run_of_the_candidate_is_found_by_the_baseli…`<br>and 1 more | none | implemented, control-off missing |
| NT-GATE-03 | CI, gate and instruction file edits | s1-trusted-gates-and-validation, workflow | `negative_nt_gate_03_the_builder_edits_ci_and_gate_files`<br>`negative_nt_gate_03_each_ci_gate_and_instruction_file_edit_fails_before_any_gate_runs`<br>`negative_nt_gate_03_deleting_a_protected_file_is_refused_too`<br>and 1 more | mutation `the-workspace-lets-any-edit-in`, caught 2026-10-29<br>mutation `a-deny-write-path-may-be-written`, caught 2026-10-29 | implemented, control-off proven |
| NT-GATE-04 | Path normalization and rename tricks | s1-policy-evaluation, domain | `negative_nt_gate_04_every_rename_and_normalization_trick_is_blocked_with_its_group`<br>`negative_nt_gate_04_every_path_trick_is_refused_with_its_group_and_the_controls_are_not`<br>`negative_nt_gate_04_the_tricks_that_a_repository_can_hold_fail_the_whole_stage` | mutation `a-deny-write-path-may-be-written`, caught 2026-10-29 | implemented, control-off proven |
| NT-GATE-05 | Builder-supplied gates are ignored | s1-trusted-gates-and-validation, workflow | `negative_nt_gate_05_the_builders_gate_files_do_not_change_what_runs`<br>`negative_nt_gate_05_an_edit_of_the_gate_definitions_fails_the_protected_path_gate`<br>`negative_nt_gate_05_a_test_target_without_the_harness_is_found` | mutation `a-deny-write-path-may-be-written`, caught 2026-10-29 | implemented, control-off proven |
| NT-GATE-06 | Fabricated evidence | s1-trusted-gates-and-validation, workflow | `negative_nt_gate_06_a_forged_report_does_not_hide_a_failing_test`<br>`negative_nt_gate_06_a_forged_summary_with_exit_code_zero_is_not_accepted` | none | implemented, control-off missing |
| NT-GATE-07 | Missing evidence is BLOCKED | s1-trusted-gates-and-validation, workflow | `negative_nt_gate_07_a_missing_build_tool_blocks_the_checks_that_need_it`<br>`negative_nt_gate_07_a_missing_diagram_parser_is_blocked_and_never_passed`<br>`negative_nt_gate_07_a_test_command_that_is_not_found_is_blocked`<br>and 6 more | none | implemented, control-off missing |
| NT-GATE-08 | Holdout visibility | s1-workspace-ingestion, sandbox (partial) | `negative_nt_gate_08_the_holdout_is_invisible_to_the_agent_and_present_in_verify`<br>`negative_nt_gate_08_the_holdout_is_read_only_in_verify_and_a_clean_run_ingests` [Docker] | none | implemented, control-off missing |
| NT-GATE-10 | Evidence binding and flaky retries | s1-trusted-gates-and-validation, workflow | `negative_nt_gate_10_evidence_for_one_commit_does_not_count_for_another`<br>`negative_nt_gate_10_a_changed_policy_or_image_makes_the_evidence_stale`<br>`negative_nt_gate_10_a_test_that_fails_once_and_is_not_in_the_flaky_registry_is_failed`<br>and 1 more | none | implemented, control-off missing |
| NT-INJ-01 | Compromised model obeys issue text | s1-security-review-and-tests, workflow | `negative_nt_inj_01_a_model_that_obeys_the_text_of_a_request_changes_nothing_the_factory…`<br>`negative_nt_inj_01_the_workflow_edit_the_env_the_fetch_and_the_pass_claim_of_the_catalog`<br>`negative_nt_inj_01_every_payload_in_every_input_leaves_the_instructions_as_the_template…`<br>and 2 more | mutation `a-forbidden-command-class-denies-nothing`, caught 2026-10-29<br>mutation `data-lines-are-not-quoted`, caught 2026-10-29<br>mutation `the-workspace-lets-any-edit-in`, caught 2026-10-29<br>and 3 more | implemented, control-off proven |
| NT-INJ-02 | Envelope hardening | s1-prompt-assembly, workflow | `negative_nt_inj_02_a_path_cannot_carry_text_into_the_instruction`<br>`negative_nt_inj_02_envelope_hardening` | mutation `data-lines-are-not-quoted`, caught 2026-10-29 | implemented, control-off proven |
| NT-INJ-03 | Repository document injection | s1-security-review-and-tests, workflow | `negative_nt_inj_03_hostile_text_in_a_code_comment_gives_the_writer_no_authority`<br>`negative_nt_inj_03_a_model_that_obeys_a_document_of_the_repository_changes_nothing_the_…`<br>`negative_nt_inj_03_a_readme_a_contributing_file_and_a_comment_that_ask_for_release_yml_…`<br>and 1 more | mutation `a-forbidden-command-class-denies-nothing`, caught 2026-10-29<br>mutation `the-workspace-lets-any-edit-in`, caught 2026-10-29<br>mutation `the-workspace-skips-the-secret-scan`, caught 2026-10-29<br>and 2 more | implemented, control-off proven |
| NT-INJ-04 | Tool-output injection | s1-security-review-and-tests, workflow | `negative_nt_inj_04_tool_output_that_says_grant_yourself_and_approve_gains_no_authority`<br>`negative_nt_inj_04_the_output_of_a_command_the_factory_ran_sits_in_a_data_envelope`<br>`negative_nt_inj_04_exec_shell_and_approval_grant_are_denied_to_an_agent_that_asks`<br>and 2 more | mutation `an-agent-may-grant-itself-a-tool`, caught 2026-10-29<br>mutation `data-lines-are-not-quoted`, caught 2026-10-29<br>mutation `the-job-token-is-accepted-by-the-webhook-endpoint`, caught 2026-10-29 | implemented, control-off proven |
| NT-INJ-06 | Reviewer manipulation and isolation | s1-stage-implementation-and-review, workflow | `negative_nt_inj_06_a_reviewer_pass_does_not_override_a_failed_gate`<br>`negative_nt_inj_06_a_reviewer_pass_cannot_override_a_failed_gate` | mutation `data-lines-are-not-quoted`, caught 2026-10-29 | implemented, control-off proven |
| NT-INJ-07 | Repository-resident agent configuration | s1-agent-runtime-adapters, runtime | `negative_nt_inj_07_claude_code_ignores_the_repositorys_hooks_servers_settings_and_instr…` [Docker; ran 2026-10-29: passed]<br>`negative_nt_inj_07_codex_ignores_the_repositorys_provider_and_instruction_files` [Docker; ran 2026-10-29: passed] | none | implemented, control-off missing |
| NT-LSE-01 | Stale worker fencing | s1-engine-core, workflow | `negative_nt_lse_01_a_stale_worker_that_comes_back_changes_nothing`<br>`negative_nt_lse_01_a_stale_worker_makes_no_commit` | none | implemented, control-off missing |
| NT-LSE-02 | Claim race and forged renewal | s1-storage-postgres, storage | `negative_nt_lse_02_a_hundred_interleavings_of_two_workers_claim_one_job_with_one_winner`<br>`negative_nt_lse_02_a_renewal_with_the_wrong_owner_epoch_tenant_or_a_lapsed_lease_change…` | mutation `a-renewal-ignores-the-epoch`, caught 2026-10-29<br>mutation `a-renewal-ignores-the-lapse`, caught 2026-10-29<br>mutation `a-renewal-ignores-the-owner`, caught 2026-10-29<br>and 1 more | implemented, control-off proven |
| NT-LSE-03 | Idempotent side effects | s1-stage-delivery-and-approval, workflow | `negative_nt_lse_03_a_retry_after_a_lost_answer_makes_one_pull_request`<br>`negative_nt_lse_03_a_retry_after_a_lost_answer_posts_one_comment_per_key`<br>`negative_nt_lse_03_a_marker_pasted_by_someone_else_does_not_stop_the_factory_from_repor…`<br>and 2 more | mutation `accept a comment marker written by anyone`, caught 2026-10-29 | implemented, control-off proven |
| NT-MRG-01 | Failing gate | s1-stage-delivery-and-approval, workflow | `negative_nt_mrg_01_a_failing_gate_refuses_approval_and_nothing_reaches_the_host`<br>`negative_nt_mrg_01_a_gate_that_is_not_clear_refuses_the_approval` | mutation `a-failing-gate-does-not-stop-an-approval`, caught 2026-10-29 | implemented, control-off proven |
| NT-MRG-02 | Missing, blocked or stale gates | s1-engine-core, workflow | `negative_nt_mrg_02_missing_or_blocked_evidence_never_passes_a_stage`<br>`negative_nt_mrg_02_an_approval_of_stale_evidence_is_refused` | none | implemented, control-off missing |
| NT-MRG-03 | Head moves after approval | s1-stage-delivery-and-approval, workflow | `negative_nt_mrg_03_the_head_moving_after_approval_invalidates_the_approval`<br>`negative_nt_mrg_03_a_refusal_for_a_moved_head_also_ends_the_approvals_on_record`<br>`negative_nt_mrg_03_the_second_approver_alone_does_not_pass_a_critical_change` | mutation `a-moved-head-is-not-noticed`, caught 2026-10-29 | implemented, control-off proven |
| NT-MRG-05 | Auto-merge and deploy are off | s1-stage-delivery-and-approval, workflow | `negative_nt_mrg_05_there_is_no_verb_for_merge_deploy_or_ready` | none | implemented, control-off missing |
| NT-MRG-06 | Self and bot approval | s1-stage-delivery-and-approval, workflow | `negative_nt_mrg_06_a_bot_an_app_and_the_requester_on_a_risky_change_do_not_count` | mutation `a-bot-may-hold-a-designation`, caught 2026-10-29 | implemented, control-off proven |
| NT-MRG-07 | Repository protection preflight | s1-github-adapter, github | `negative_nt_mrg_07_a_repository_that_does_not_meet_the_requirements_runs_at_l0`<br>`negative_nt_mrg_07_the_app_holding_workflows_is_refused_and_nothing_is_pushed` | none | implemented, control-off missing |
| NT-MRG-08 | The factory never marks a pull request ready | s1-stage-delivery-and-approval, workflow | `negative_nt_mrg_08_the_pull_request_stays_a_draft` | none | implemented, control-off missing |
| NT-POL-01 | Policy source | s0-contracts-and-registry, contracts | `negative_nt_pol_01_a_checkout_inside_a_job_workspace_is_refused`<br>`negative_nt_pol_01_a_link_into_an_untrusted_place_is_resolved_and_refused`<br>`negative_nt_pol_01_a_policy_file_that_is_a_symbolic_link_is_refused`<br>and 4 more | none | implemented, control-off missing |
| NT-POL-02 | Tighten-only overrides | s1-policy-evaluation, domain | `negative_nt_pol_02_each_widening_is_refused_and_names_its_key`<br>`negative_nt_pol_02_widenings_of_the_approval_policy_are_refused_too`<br>`negative_nt_pol_02_tightenings_are_accepted`<br>and 1 more | mutation `a-widening-of-a-switch-counts-as-a-tightening`, caught 2026-10-29 | implemented, control-off proven |
| NT-POL-03 | Schema strictness | s0-contracts-and-registry, contracts | `negative_nt_pol_03_control_the_unchanged_files_load_from_a_temporary_checkout`<br>`negative_nt_pol_03_an_unknown_key_is_refused_at_any_depth_and_named`<br>`negative_nt_pol_03_a_wrong_schema_version_is_refused_before_anything_else`<br>and 9 more | none | implemented, control-off missing |
| NT-POL-04 | Deny overrides and the exception flow | s1-policy-evaluation, domain | `negative_nt_pol_04_a_protected_change_is_accepted_only_with_all_three_elements`<br>`negative_nt_pol_04_a_protected_group_beats_write_allow`<br>`negative_nt_pol_04_a_protected_change_needs_all_three_elements`<br>and 1 more | mutation `a-deny-write-path-may-be-written`, caught 2026-10-29 | implemented, control-off proven |
| NT-POL-05 | Specification prose is not authorization | s1-spec-adapter-and-stage, spec_adapter | `negative_nt_pol_05_an_issue_body_that_asks_for_another_skill_cannot_select_one`<br>`negative_nt_pol_05_specification_text_that_claims_authorization_grants_nothing`<br>`negative_nt_pol_05_a_writer_that_arrives_approved_is_refused`<br>and 1 more | none | implemented, control-off missing |
| NT-POL-08 | Stage tool profile denies forbidden Spec Kit skills | s1-spec-adapter-and-stage, spec_adapter | `negative_nt_pol_08_the_specification_stage_may_run_four_skills_in_any_spelling_and_no_o…` | none | implemented, control-off missing |
| NT-SBX-01 | Posture verifier rejects forbidden settings | s1-sandbox-adapter, sandbox | `negative_nt_sbx_01_each_forbidden_setting_is_refused_before_the_start`<br>`negative_nt_sbx_01_a_container_the_policy_allows_is_started_after_the_inspect` | none | implemented, control-off missing |
| NT-SBX-02 | Runtime self-check | s1-sandbox-adapter, sandbox | `negative_nt_sbx_02_each_bad_runtime_value_keeps_the_workload_from_starting` | none | implemented, control-off missing |
| NT-SBX-03 | Network none | s1-sandbox-adapter, sandbox | `negative_nt_sbx_03_the_verify_profile_has_no_network` [Docker; ran 2026-10-29: passed] | none | implemented, control-off missing |
| NT-SBX-04 | Internal network isolation | s1-sandbox-adapter, sandbox | `negative_nt_sbx_04_an_agent_on_its_job_network_reaches_no_other_job_no_external_address…` [Docker; ran 2026-10-29: passed] | none | implemented, control-off missing |
| NT-SBX-05 | Egress sidecar allowlist | s1-egress-and-broker, egress | `negative_nt_sbx_05_a_host_that_is_not_on_the_list_is_refused_before_it_is_resolved`<br>`negative_nt_sbx_05_a_name_that_resolves_to_an_internal_address_is_refused_after_resolut…`<br>`negative_nt_sbx_05_a_rebinding_answer_cannot_redirect_a_connection_that_was_checked`<br>and 3 more | mutation `sidecar-ignores-the-byte-quota`, caught 2026-10-29<br>mutation `sidecar-resolves-before-the-allowlist`, caught 2026-10-29<br>mutation `sidecar-skips-the-resolved-range-check`, caught 2026-10-29 | implemented, control-off proven |
| NT-SBX-06 | Read-only root, tmpfs, capabilities, kernel paths | s1-sandbox-adapter, sandbox | `negative_nt_sbx_06_read_only_root_tmpfs_capabilities_and_masked_paths_hold` [Docker; ran 2026-10-29: passed] | none | implemented, control-off missing |
| NT-SBX-07 | Resource limits | s1-sandbox-adapter, sandbox | `negative_nt_sbx_07_resource_limits_are_in_effect_and_a_memory_hog_is_killed` [Docker; ran 2026-10-29: passed]<br>`negative_nt_sbx_07_the_disk_poll_kills_a_writer_that_passes_its_cap` [Docker; ran 2026-10-29: passed] | none | implemented, control-off missing |
| NT-SBX-08 | Wall-clock deadline | s1-sandbox-adapter, sandbox | `negative_nt_sbx_08_the_supervisor_kills_the_container_at_the_wall_clock` [Docker; ran 2026-10-29: passed] | none | implemented, control-off missing |
| NT-SBX-09 | Ingestion hardening | s1-workspace-ingestion, sandbox | `negative_nt_sbx_09_a_real_sandbox_plants_hostile_entries_and_the_audit_rejects_them` [Docker]<br>`negative_nt_sbx_09_every_hostile_entry_is_rejected_with_its_reason`<br>`negative_nt_sbx_09_a_link_to_a_host_canary_is_never_read`<br>and 1 more | none | implemented, control-off missing |
| NT-SBX-10 | Hostile git | s1-workspace-ingestion, sandbox | `negative_nt_sbx_10_hostile_git_configuration_runs_nothing_on_the_host` | none | implemented, control-off missing |
| NT-SBX-11 | Protected overlay and hidden paths | s1-workspace-ingestion, sandbox | `negative_nt_sbx_11_the_mount_points_exist_and_a_hidden_write_fails_the_job`<br>`negative_nt_sbx_11_moving_a_protected_directory_is_not_stopped_inside_and_is_blocked_at…` [Docker] | none | implemented, control-off missing |
| NT-SBX-12 | No daemon access | s1-sandbox-adapter, sandbox | `negative_nt_sbx_12_no_daemon_socket_is_reachable_and_none_can_be_mounted` [Docker; ran 2026-10-29: passed] | none | implemented, control-off missing |
| NT-SBX-13 | Credential isolation | s1-sandbox-adapter, sandbox | `negative_nt_sbx_13_the_job_token_is_a_file_and_no_other_credential_is_anywhere` [Docker; ran 2026-10-29: passed] | none | implemented, control-off missing |
| NT-SBX-14 | Fail closed | s1-sandbox-adapter, sandbox | `negative_nt_sbx_14_a_stopped_daemon_a_missing_image_and_a_skeleton_sidecar_run_nothing` [Docker]<br>`negative_nt_sbx_14_a_stopped_daemon_a_bad_catalog_and_a_failed_sidecar_run_nothing` | none | implemented, control-off missing |
| NT-SBX-17 | Model broker forwards no provider-side tool, remote server or fetched content (T-17) | s1-egress-and-broker, egress | `negative_nt_sbx_17_the_requests_of_the_real_tools_pass_unchanged`<br>`negative_nt_sbx_17_history_blocks_of_a_long_session_pass`<br>`negative_nt_sbx_17_every_refused_shape_gets_a_fixed_answer_an_audit_event_and_no_provid…`<br>and 6 more | mutation `accept-a-repeated-key`, caught 2026-10-29<br>mutation `accept-an-image-by-address`, caught 2026-10-29<br>mutation `accept-an-unlisted-field`, caught 2026-10-29<br>and 5 more | implemented, control-off proven |
| NT-SEC-01 | Canary sweep of a full job | s1-security-review-and-tests, workflow (partial) | `negative_nt_sec_01_a_full_fixture_job_with_a_canary_of_every_class_leaves_none_in_any_s…`<br>`negative_nt_sec_01_secrets_the_model_pastes_into_its_summary_and_its_change_reach_no_si…`<br>`negative_nt_sec_01_composed_a_full_job_with_a_canary_of_every_class_leaves_none_in_any_…`<br>and 1 more | mutation `the-workspace-skips-the-secret-scan`, caught 2026-10-29<br>break test `break_a_canary_in_a_pull_request_comment_is_found_by_the_sw…`<br>mutation `the-builder-report-is-stored-as-written`, caught 2026-10-29 | implemented, control-off proven |
| NT-SEC-02 | Redaction evasion | s1-redaction, domain | `negative_nt_sec_02_a_token_split_over_two_writes_is_redacted`<br>`negative_nt_sec_02_terminal_codes_between_the_characters_do_not_hide_a_token`<br>`negative_nt_sec_02_control_bytes_between_the_characters_do_not_hide_a_token`<br>and 6 more | none | implemented, control-off missing |
| NT-SEC-03 | GitHub-bound text is blocked | s1-github-adapter, github | `negative_nt_sec_03_text_with_a_secret_is_blocked_everywhere_and_nothing_is_sent` | mutation `the-text-bound-for-github-is-not-checked-for-a-secret`, caught 2026-10-29 | implemented, control-off proven |
| NT-SEC-04 | Markdown exfiltration | s1-github-adapter, github | `negative_nt_sec_04_markdown_cannot_carry_data_out_through_any_path_to_the_code_host`<br>`negative_nt_sec_04_a_body_over_the_length_cap_is_refused_and_not_cut`<br>`negative_nt_sec_04_hostile_text_does_not_reach_the_pull_request`<br>and 1 more | mutation `markdown-bound-for-github-is-sent-as-written`, caught 2026-10-29 | implemented, control-off proven |
| NT-SEC-05 | Secrets in the diff | s1-trusted-gates-and-validation, workflow | `negative_nt_sec_05_a_secret_in_a_document_is_refused_before_the_commit`<br>`negative_nt_sec_05_unsafe_entries_and_secrets_in_the_tree_are_refused`<br>`negative_nt_sec_05_a_token_in_source_blocks_the_change_and_its_text_is_never_kept`<br>and 4 more | mutation `the-workspace-skips-the-secret-scan`, caught 2026-10-29 | implemented, control-off proven |
| NT-SEC-07 | Context builder | s1-stage-intake-and-repository, workflow | `negative_nt_sec_07_secret_bearing_files_are_not_read_and_nothing_secret_reaches_context` | none | implemented, control-off missing |
| NT-SEC-09 | Process arguments and environment | s1-sandbox-adapter, sandbox | `negative_nt_sec_09_the_adapter_starts_no_process_and_prints_no_credential`<br>`negative_nt_sec_09_the_recorded_processes_hold_no_secret_and_start_no_shell` [Docker]<br>`negative_nt_sec_09_no_argument_or_environment_holds_the_job_token` | none | implemented, control-off missing |
| NT-SEC-10 | Token revocation | s1-github-adapter, github | `negative_nt_sec_10_tokens_are_revoked_when_a_job_succeeded_failed_was_cancelled_or_was_…`<br>`negative_nt_sec_10_a_running_job_keeps_its_tokens_through_the_sweep`<br>`negative_nt_sec_10_a_revocation_that_fails_is_kept_and_retried` | none | implemented, control-off missing |
| NT-SEC-11 | Model-context exclusions | s1-prompt-assembly, workflow | `negative_nt_sec_11_model_context_exclusions`<br>`negative_nt_sec_11_reviewer_inputs_hold_no_builder_justification` | none | implemented, control-off missing |
| NT-SUP-01 | Slopsquat and typosquat requests | s1-supply-chain-gates, workflow | `negative_nt_sup_01_nothing_is_fetched_before_the_decision`<br>`negative_nt_sup_01_a_package_no_one_knows_goes_to_a_security_approver_and_nothing_is_fe…`<br>`negative_nt_sup_01_a_decision_for_another_version_starts_nothing`<br>and 14 more | none | implemented, control-off missing |
| NT-SUP-02 | Install and build scripts | s1-supply-chain-gates, workflow | `negative_nt_sup_02_a_build_script_and_an_install_script_never_run_in_the_fetch_profile`<br>`negative_nt_sup_02_the_policy_denies_repository_code_and_installs_in_the_fetch_profile`<br>`negative_nt_sup_02_a_build_script_runs_only_in_the_verify_sandbox_which_has_no_network` | none | implemented, control-off missing |
| NT-SUP-03 | Lockfile and source tampering | s1-supply-chain-gates, workflow | `negative_nt_sup_03_a_tampered_lockfile_fails_the_gate_and_makes_no_container`<br>`negative_nt_sup_03_a_git_dependency_and_a_patch_section_fail_the_gate`<br>`negative_nt_sup_03_a_lockfile_source_edit_fails`<br>and 9 more | none | implemented, control-off missing |
| NT-SUP-05 | Image pinning | s1-sandbox-adapter, sandbox | `negative_nt_sup_05_an_image_that_is_listed_but_not_on_this_host_is_refused` [Docker]<br>`negative_nt_sup_05_a_tag_an_unknown_digest_or_a_missing_image_is_refused` | none | implemented, control-off missing |
| NT-TEN-01 | Row-level security | s1-storage-postgres, storage | `negative_nt_ten_01` | none | implemented, control-off missing |
| NT-TEN-05 | API object references | s1-apps-composition, api | `negative_nt_ten_05` | none | implemented, control-off missing |
| NT-TOOL-01 | No shell interpretation | s1-sandbox-adapter, sandbox | `negative_nt_tool_01_a_shell_string_is_a_literal_argument_and_a_shell_is_denied`<br>`negative_nt_tool_01_shell_metacharacters_are_literals_and_a_payload_runs_unprivileged` [Docker] | mutation `a-forbidden-command-class-denies-nothing`, caught 2026-10-29 | implemented, control-off proven |
| NT-TOOL-02 | Forbidden command class matrix | s1-policy-evaluation, domain | `negative_nt_tool_02_forbidden_command_class_matrix` | mutation `a-forbidden-command-class-denies-nothing`, caught 2026-10-29 | implemented, control-off proven |
| NT-TOOL-03 | Unknown tools, never-grantable tools, self-grant | s1-policy-evaluation, domain | `negative_nt_tool_03_unknown_never_grantable_and_self_granted_tools_are_refused` | mutation `an-agent-may-grant-itself-a-tool`, caught 2026-10-29 | implemented, control-off proven |
| NT-TOOL-04 | Path policy | s1-policy-evaluation, domain | `negative_nt_tool_04_path_policy_refuses_traversal_encoding_and_hidden_files`<br>`negative_nt_tool_04_writes_outside_the_writable_mounts_and_protected_paths_are_refused` [Docker] | none | implemented, control-off missing |
| NT-TOOL-05 | Argument injection | s1-policy-evaluation, domain | `negative_nt_tool_05_argument_injection_is_denied_by_forbidden_args`<br>`negative_nt_tool_05_argument_injection_changes_nothing_outside_the_sandbox` [Docker] | mutation `a-forbidden-argument-is-allowed`, caught 2026-10-29 | implemented, control-off proven |
| NT-TOOL-06 | Environment injection | s1-agent-runtime-adapters, runtime | `negative_nt_tool_06_the_tools_environment_is_the_adapters_list_and_nothing_the_reposito…` [Docker]<br>`negative_nt_tool_06_a_container_created_with_a_loader_variable_is_not_a_target` [Docker]<br>`negative_nt_tool_06_hostile_request_values_never_become_environment_names` | none | implemented, control-off missing |
| NT-TOOL-07 | Output flood, timeout, process group | s1-agent-runtime-adapters, runtime | `negative_nt_tool_07_a_run_that_outlasts_its_deadline_is_interrupted_and_reports_what_it…` [Docker; ran 2026-10-29: passed]<br>`negative_nt_tool_07_a_background_child_in_its_own_session_dies_with_the_container` [Docker; ran 2026-10-29: passed]<br>`negative_nt_tool_07_a_flood_of_output_is_cut_at_the_cap_and_the_run_still_ends` [Docker; ran 2026-10-29: passed] | none | implemented, control-off missing |
| NT-TOOL-09 | Structured output abuse | s0-contracts-and-registry, contracts | `negative_nt_tool_09_the_valid_document_is_accepted_so_the_rejections_below_mean_somethi…`<br>`negative_nt_tool_09_an_unknown_field_is_rejected_and_named`<br>`negative_nt_tool_09_wrong_types_are_rejected`<br>and 13 more | none | implemented, control-off missing |
| NT-WEB-05 | API authentication | s1-apps-composition, api | `negative_nt_web_05` | none | implemented, control-off missing |
| NT-WH-01 | Missing signature | s1-apps-composition, api | `negative_nt_wh_01` | mutation `a-delivery-that-fails-verification-is-acknowledged`, caught 2026-10-29 | implemented, control-off proven |
| NT-WH-02 | Invalid signatures | s1-github-adapter, github | `negative_nt_wh_02`<br>`negative_nt_wh_02_every_forged_signature_is_refused_for_the_right_reason`<br>`negative_nt_wh_02_the_signature_is_compared_with_a_constant_time_primitive` | mutation `skip the signature comparison`, caught 2026-10-29<br>mutation `accept a delivery that has only the legacy SHA-1 header`, caught 2026-10-29 | implemented, control-off proven |
| NT-WH-03 | Raw body is used | s1-github-adapter, github | `negative_nt_wh_03_the_raw_body_decides_and_the_body_is_read_only_after_it` | none | implemented, control-off missing |
| NT-WH-04 | Replay of one delivery | s1-apps-composition, api (partial) | `negative_nt_wh_04` | none | implemented, control-off missing |
| NT-WH-06 | Out-of-order events and payload as a hint | s1-github-adapter, github | `negative_nt_wh_06_the_payload_is_a_hint_and_the_live_state_decides` | mutation `identify a person by the login and not by the numeric id`, caught 2026-10-29 | implemented, control-off proven |
| NT-WH-09 | Self-generated events | s1-github-adapter, github | `negative_nt_wh_09_the_factorys_own_events_and_other_bots_events_are_ignored` | mutation `a-bot-is-not-a-bot`, caught 2026-10-29 | implemented, control-off proven |

### BLOCKED

None.

### Missing

None.

### Implemented, control-off missing

Each of these tests exists and runs, and nothing in the repository shows that it fails when its control is removed.

- **NT-AUD-01**
- **NT-AUTHZ-02**
- **NT-AUTHZ-08**
- **NT-BUD-03** Covered: the engine detects stagnation and escalates to a person. Not covered (gap, needs a decision): a turn cap on the agent tool, because neither accepted CLI has a turn cap flag and only the broker request count could supply one.
- **NT-GATE-02**
- **NT-GATE-06**
- **NT-GATE-07**
- **NT-GATE-08** Covered: sandbox, prompts and sinks. Not covered (gap, Slice 4): held-out evaluation data in the evals component, which does not exist yet.
- **NT-GATE-10**
- **NT-INJ-07** The tests need the Docker daemon and ran against it on 2026-10-29: they passed. They are not run on a machine without the daemon, where they are BLOCKED and never passed. No control-off variant exists for this row yet.
- **NT-LSE-01**
- **NT-MRG-02**
- **NT-MRG-05**
- **NT-MRG-07**
- **NT-MRG-08**
- **NT-POL-01**
- **NT-POL-03**
- **NT-POL-05**
- **NT-POL-08**
- **NT-SBX-01**
- **NT-SBX-02**
- **NT-SBX-03** The tests need the Docker daemon and ran against it on 2026-10-29: they passed. They are not run on a machine without the daemon, where they are BLOCKED and never passed. No control-off variant exists for this row yet.
- **NT-SBX-04** The tests need the Docker daemon and ran against it on 2026-10-29: they passed. They are not run on a machine without the daemon, where they are BLOCKED and never passed. No control-off variant exists for this row yet.
- **NT-SBX-06** The tests need the Docker daemon and ran against it on 2026-10-29: they passed. They are not run on a machine without the daemon, where they are BLOCKED and never passed. No control-off variant exists for this row yet.
- **NT-SBX-07** The tests need the Docker daemon and ran against it on 2026-10-29: they passed. They are not run on a machine without the daemon, where they are BLOCKED and never passed. No control-off variant exists for this row yet.
- **NT-SBX-08** The tests need the Docker daemon and ran against it on 2026-10-29: they passed. They are not run on a machine without the daemon, where they are BLOCKED and never passed. No control-off variant exists for this row yet.
- **NT-SBX-09**
- **NT-SBX-10**
- **NT-SBX-11**
- **NT-SBX-12** The tests need the Docker daemon and ran against it on 2026-10-29: they passed. They are not run on a machine without the daemon, where they are BLOCKED and never passed. No control-off variant exists for this row yet.
- **NT-SBX-13** The tests need the Docker daemon and ran against it on 2026-10-29: they passed. They are not run on a machine without the daemon, where they are BLOCKED and never passed. No control-off variant exists for this row yet.
- **NT-SBX-14**
- **NT-SEC-02**
- **NT-SEC-07**
- **NT-SEC-09**
- **NT-SEC-10**
- **NT-SEC-11**
- **NT-SUP-01**
- **NT-SUP-02**
- **NT-SUP-03**
- **NT-SUP-05**
- **NT-TEN-01**
- **NT-TEN-05**
- **NT-TOOL-04**
- **NT-TOOL-06**
- **NT-TOOL-07** The tests need the Docker daemon and ran against it on 2026-10-29: they passed. They are not run on a machine without the daemon, where they are BLOCKED and never passed. No control-off variant exists for this row yet.
- **NT-TOOL-09**
- **NT-WEB-05**
- **NT-WH-03**
- **NT-WH-04** Covered: one job and one outbox row for fifty concurrent deliveries of one signed request. Not covered (gap, Slice 2): publishing to NATS and the idempotent consumer.

### Rows outside the P0 list

These tests are in the catalog with a priority below P0, so the count above does not include them. They are registered the same way (tests, a control-off variant, a status), and the naming rule does not apply to a test that was written before its row. They move to the P0 list when `negative_tests.entries` of the work packages names an owner for them and the catalog marks them P0.

| Test | Title | Owner (work package, crate) | Tests in the repository | Control-off variant | Status |
|---|---|---|---|---|---|
| NT-KEY-01 | Key files: mode, owner, location and rotation | s1-apps-composition, composition | `held_the_key_file_is_checked_for_mode_link_size_and_kind`<br>`held_a_rotation_to_the_same_key_is_refused`<br>`rr_5_a_key_with_no_entropy_is_refused`<br>`a_secret_key_file_that_group_can_read_blocks_the_github_ports_and_says_why`<br>and 4 more | mutation `a-secret-file-may-be-read-by-group-and-others`, caught 2026-10-29 | implemented, control-off proven |

NT-KEY-01: Added for finding F-5. The mode check of a secret file is proven by a break. The checks of the owner, the directory and the end date of a previous key have tests and no break yet; the break that removes the same-key check of a rotation is MISSED (a second check refuses the same key).

### Parts that are BLOCKED inside a row

A row can be proven for the parts that run and still hold a part that cannot run yet. The part is stated here and never counted as a pass.

- **NT-INJ-01**, part B (docker): The commands of the issue run by docker exec in a hardened agent sandbox (FX-EXEC) need the Docker daemon. The engine-level part runs: the model obeys, the policy denies, the stage refuses, no sink holds a canary.
- **NT-INJ-01**, part C (live provider): A real agent CLI driven by a scripted provider needs an installed CLI and the agent image.
- **NT-INJ-03**, part B (docker): FX-EXEC against the hostile fixture repository needs the Docker daemon.
- **NT-INJ-03**, part C (live provider): A real CLI driven by a scripted provider needs an installed CLI and the agent image.
- **NT-INJ-04**, part C (live provider): BLOCKED until a real runtime and a key exist (work package s0-agent-runtime-spike has run, but no key or installed CLI is available here).

### Notes on rows

- **NT-AUD-03**: Covered: a scripted scenario for each of the fourteen required types in which the engine itself writes the sandbox lifecycle, each command and the egress summary from the results of the attempt (only the two types a stage handler writes, and the one the API writes, are scripted), every record checked for actor, policy hash and correlation id, and the owner matrix below, which the checker compares with the sources. Every type has a correct producer. The webhook type is produced by the API under the required name; the API test of the composed rig checks the name. Finding F-2 is closed.
- **NT-INJ-01**: The sandbox, the code host and the model are labelled fakes in the engine-level tests. The rig's path rules are those of the fixture repository; the policy denial of every other protected path is checked against the real path policy.
- **NT-INJ-04**: The B and S parts: refusals, grants, approvals, audit and the data envelope (the workflow target), and the composed part: a job token of a running job is presented to every operation of apps/api/openapi.json, enumerated from the document, in seven places a credential can sit; each answer is the answer of a request with no credential, the operations that need a credential refuse it, and a digest of every row of every table but the audit log is the same before and after, and the audit log gained one row for each refused webhook delivery and nothing else. The broker is not an operation of the API: it accepts the job token by design, and its own tests are in the egress crate. Part C needs a real runtime and a key.
- **NT-LSE-02**: A hundred interleavings of two workers on one stage run on PostgreSQL (one winner, the other told it lost, one live lease row, the lease owned by the winner) and a renewal with the wrong owner, the wrong epoch, another tenant and after the lease lapsed (the row is as it was; the owner renews a live lease). The separate property that a stale worker changes nothing after takeover is NT-LSE-01.
- **NT-SEC-01**: Covered: a canary of 21 classes planted in the repository, the request, the environment the model reads and the output of commands, and four ways for the model to leak it, swept in the audit log, the outbox, the ledger, every stored artifact, the prompts and the log lines (the workflow target); and the composed run through the real API, engine and stage handlers on PostgreSQL, with a canary of every class in the text of the issue, the repository files, the reports of the builder and the reviewer and the requests the API refuses, swept in the answers of the API, the error bodies, the pull request description and comments of the code host, the audit log, the outbox, the ledger, a dump of every table, the artifacts, the prompts, the log lines and the recording. Red today: the composed test with the issue text and the reviewer report (findings F-6 and F-7); the composed test without them passes. Not covered: the standard output of a command in the composed run, because the fake sandbox stores it without the redaction the real adapter applies (that adapter is tested in the sandbox crate); NATS messages and memory stores, which do not exist (Slice 2 and Slice 4).

### Open findings that a P0 test reports

None.

### Audit event types and their owners (NT-AUD-03)

The policy requires fourteen types of audit event (`audit.must_record`). The scripted scenario of `negative_nt_aud_03` makes each of them appear with an actor, the policy hash and the correlation id of its job. This table says who owns each type and whether production code writes it. The checker compares the table with the sources, so a type that gains an emitter, or loses one, fails the check until the table says so.

| Type | Owner | Written in production code | Where |
|---|---|---|---|
| `webhook_accepted_or_rejected` | s1-apps-composition | yes, by the API under the required name | `apps/api/src/webhook.rs`. The API writes an accepted delivery as webhook_accepted_or_rejected.granted and a rejected one (a bad signature, or a sender who may not ask) as webhook_accepted_or_rejected.denied. A repeat and an unbound installation keep their own names (webhook.duplicate_delivery, webhook.unbound): they are neither an acceptance nor a rejection of the delivery. The database trigger of the API login allows both required names. |
| `authorization_decision` | s1-engine-core | yes, by the engine | `crates/workflow/src/engine/admission.rs`. Admission, the human decision and the intake stage. |
| `tool_grant_issued` | s1-engine-core | yes, by the engine | `crates/workflow/src/scheduler/claim.rs`. One record for each attempt the engine claims. |
| `tool_call_denied` | s1-engine-core | yes, by the engine | `crates/workflow/src/engine/attempt.rs`. One record for each denial the runtime reports. Finding F-1: denials of a run whose report is rejected as invalid are dropped. |
| `command_executed` | s1-trusted-gates-and-validation | yes, by the engine | `crates/workflow/src/engine/sandbox_audit.rs`. The engine wraps the sandbox a stage uses and writes one record for each command the sandbox ran, from the result the supervisor returned: the program (file name only), the exit code, the signal, whether it timed out, was killed for memory or had its output cut, and how long it ran. Arguments are not recorded. At most 256 commands of an attempt get a record each; a record says how many more ran. |
| `sandbox_created_posture_result_destroyed` | s1-sandbox-adapter | yes, by the engine | `crates/workflow/src/engine/sandbox_audit.rs`. The same wrapper writes the lifecycle from what the provider returned: granted when a session came back (its posture matched), denied when the provider refused or failed (a posture mismatch lists the differing parts), ended when the sandbox was removed. |
| `egress_request` | s1-egress-and-broker | yes, by the engine | `crates/workflow/src/engine/attempt.rs`. The engine settles the job token of an attempt and writes one summary record with the counts the broker metered (requests, input and output tokens, cost). One row for each token and not one for each request, so a loop on a model cannot fill the log; the broker keeps its own line for each request and each refusal in its stream. Requests the broker refused before forwarding are not in the usage the port returns, so they are not in the summary. |
| `secret_redacted_or_blocked` | s1-redaction | yes, by a stage handler | `crates/workflow/src/stages/implementation/run.rs`. Written by the stage handlers that scan a change. |
| `protected_path_decision` | s1-stage-implementation-and-review | yes, by a stage handler | `crates/workflow/src/stages/implementation/run.rs`. Written by the stage handlers that take a change in. |
| `gate_result` | s1-engine-core | yes, by the engine | `crates/workflow/src/engine/gate.rs`. One record for each gate the engine evaluates. |
| `approval_granted_or_rejected` | s1-engine-core | yes, by the engine | `crates/workflow/src/engine/decide.rs`. Written when a person decides. |
| `human_override` | s1-engine-core | yes, by the engine | `crates/workflow/src/engine/decide.rs`. Written when a person overrides a block. |
| `credential_minted_and_revoked` | s1-engine-core | yes, by the engine | `crates/workflow/src/engine/attempt.rs`. The job token of an attempt, at its start and its end. |
| `budget_threshold_crossed` | s1-engine-core | yes, by the engine | `crates/workflow/src/engine/attempt.rs`. Written at 80 and 100 percent of the ceiling. |

### Control-off variants that were run for this review

| Script | Variant | Date | Result | Tests that failed |
|---|---|---|---|---|
| `crates/egress/tests/mutations.py` | `accept-a-repeated-key` | 2026-10-29 | CAUGHT | `a_repeated_key_is_refused_even_when_one_spelling_is_escaped`, `held_documents_that_two_readers_could_read_differently_are_refused`, `negative_nt_sbx_17_bodies_that_parsers_read_differently_are_refused` |
| `crates/egress/tests/mutations.py` | `accept-an-image-by-address` | 2026-10-29 | CAUGHT | `content_the_provider_would_fetch_is_refused`, `held_property_no_accepted_body_holds_a_key_a_tag_or_an_address_the_or…`, `held_server_side_features_stay_out_whatever_the_spelling`, `negative_nt_sbx_17_every_refused_shape_gets_a_fixed_answer_an_audit_e…` |
| `crates/egress/tests/mutations.py` | `accept-an-unlisted-field` | 2026-10-29 | CAUGHT | `held_an_escaped_key_is_checked_as_the_key_it_spells`, `held_documents_that_two_readers_could_read_differently_are_refused`, `held_property_no_accepted_body_holds_a_key_a_tag_or_an_address_the_or…`, `held_server_side_features_stay_out_whatever_the_spelling`, `negative_nt_sbx_17_every_refused_shape_gets_a_fixed_answer_an_audit_e…`, `negative_nt_sbx_17_property_the_provider_receives_only_bodies_without…`, `negative_nt_sbx_17_property_the_schema_accepts_no_mutant_that_holds_a…`, `provider_side_tools_and_remote_servers_are_refused_with_their_class` |
| `crates/egress/tests/mutations.py` | `accept-an-unlisted-tool-type` | 2026-10-29 | CAUGHT | `a_tagged_object_takes_only_a_listed_tag_and_the_fields_of_that_variant`, `content_the_provider_would_fetch_is_refused`, `egr_1_openai_server_tools_and_remote_mcp_do_not_cross_the_broker`, `held_an_escaped_key_is_checked_as_the_key_it_spells`, `held_property_no_accepted_body_holds_a_key_a_tag_or_an_address_the_or…`, `held_server_side_features_stay_out_whatever_the_spelling`, `negative_nt_sbx_17_every_refused_shape_gets_a_fixed_answer_an_audit_e…`, `negative_nt_sbx_17_property_the_provider_receives_only_bodies_without…`, `negative_nt_sbx_17_property_the_schema_accepts_no_mutant_that_holds_a…`, `provider_side_tools_and_remote_servers_are_refused_with_their_class` |
| `crates/egress/tests/mutations.py` | `do-not-count-failed-attempts` | 2026-10-29 | CAUGHT | `a_count_tokens_call_never_changes_the_record_of_the_turns`, `a_looping_client_is_stopped_at_the_ceiling_with_a_recorded_reason`, `a_provider_error_is_passed_on_and_counted_as_a_request_with_no_cost`, `a_provider_that_rejects_the_brokers_key_or_redirects_is_not_passed_on…`, `a_request_cap_refuses_the_next_request_and_revokes_the_token`, `a_stream_cut_before_its_usage_report_is_charged_the_worst_case_for_on…`, `a_valid_token_is_admitted_and_counted_and_a_garbage_credential_is_unk…`, `an_answer_that_ended_the_turn_is_recorded_for_both_providers_and_both…`, `failed_and_abandoned_requests_still_count_and_an_unread_answer_is_cha…`, `negative_nt_bud_07_a_tool_that_ignores_its_budget_is_still_stopped_an…`, `negative_nt_bud_07_a_turn_cap_stops_a_tool_that_has_no_turn_limit_of_…`, `negative_nt_bud_07_failed_attempts_are_counted_per_attempt`, `negative_nt_sbx_17_every_refused_shape_gets_a_fixed_answer_an_audit_e…`, `non_streamed_answers_and_the_token_count_route_are_metered_too`, `streamed_usage_of_both_providers_is_metered_and_the_events_are_passed…`, `the_http_listener_passes_the_broker_contract`, `the_key_is_not_in_a_response_even_when_a_cap_stops_the_job` |
| `crates/egress/tests/mutations.py` | `forward-the-beta-header-unchanged` | 2026-10-29 | CAUGHT | `a_claude_request_reaches_the_provider_with_the_real_key_and_with_noth…`, `held_beta_header_variants_never_enable_a_provider_side_feature`, `negative_nt_sbx_17_only_the_recorded_betas_and_the_beta_query_cross`, `the_recorded_betas_pass_and_unknown_well_formed_ones_are_dropped` |
| `crates/egress/tests/mutations.py` | `forward-the-body-without-the-schema` | 2026-10-29 | CAUGHT | `egr_1_openai_server_tools_and_remote_mcp_do_not_cross_the_broker`, `negative_nt_sbx_17_bodies_that_parsers_read_differently_are_refused`, `negative_nt_sbx_17_every_refused_shape_gets_a_fixed_answer_an_audit_e…`, `negative_nt_sbx_17_property_the_provider_receives_only_bodies_without…` |
| `crates/egress/tests/mutations.py` | `forward-the-provider-request-ids` | 2026-10-29 | CAUGHT | `held_the_answer_headers_are_a_closed_set_even_for_a_hostile_provider`, `negative_nt_sbx_17_the_answer_headers_are_a_closed_set`, `real_key_never_leaves_the_broker` |
| `crates/egress/tests/mutations.py` | `ignore-the-cost-ceiling` | 2026-10-29 | CAUGHT | `a_looping_client_is_stopped_at_the_ceiling_with_a_recorded_reason`, `negative_nt_bud_01_per_task_cost_ceiling_stops_a_looping_client`, `revoke_for_job_and_metering_through_the_core`, `revoke_for_job_and_metering_through_the_http_listener`, `the_http_listener_passes_the_broker_contract`, `the_real_broker_passes_the_broker_contract` |
| `crates/egress/tests/mutations.py` | `ignore-the-expiry` | 2026-10-29 | CAUGHT | `an_expired_token_and_a_revoked_token_are_refused_with_401`, `the_http_listener_passes_the_broker_contract`, `the_real_broker_passes_the_broker_contract` |
| `crates/egress/tests/mutations.py` | `ignore-the-request-cap` | 2026-10-29 | CAUGHT | `a_request_cap_refuses_the_next_request_and_revokes_the_token`, `negative_nt_bud_07_a_turn_cap_stops_a_tool_that_has_no_turn_limit_of_…`, `the_key_is_not_in_a_response_even_when_a_cap_stops_the_job` |
| `crates/egress/tests/mutations.py` | `revoke-for-job-revokes-one-token` | 2026-10-29 | CAUGHT | `revoke_for_job_and_metering_through_the_core`, `revoke_for_job_and_metering_through_the_http_listener`, `the_http_listener_passes_the_broker_contract`, `the_real_broker_passes_the_broker_contract` |
| `crates/egress/tests/mutations.py` | `sidecar-ignores-the-byte-quota` | 2026-10-29 | CAUGHT | `negative_nt_sbx_05_the_byte_quota_ends_a_transfer_at_the_cap`, `the_byte_quota_applies_in_broker_mode_too` |
| `crates/egress/tests/mutations.py` | `sidecar-matches-a-host-by-suffix` | 2026-10-29 | CAUGHT | `lookalikes_userinfo_literals_ports_and_malformed_targets_are_refused_…` |
| `crates/egress/tests/mutations.py` | `sidecar-resolves-a-name-from-the-sandbox` | 2026-10-29 | CAUGHT | `a_request_through_the_relay_reaches_the_broker_and_the_provider_sees_…`, `whatever_the_sandbox_asks_for_the_relay_connects_to_the_broker_only_a…` |
| `crates/egress/tests/mutations.py` | `sidecar-resolves-before-the-allowlist` | 2026-10-29 | CAUGHT | `negative_nt_sbx_05_a_host_that_is_not_on_the_list_is_refused_before_i…`, `negative_nt_sbx_05_a_name_that_resolves_to_an_internal_address_is_ref…`, `negative_nt_sbx_05_a_rebinding_answer_cannot_redirect_a_connection_th…` |
| `crates/egress/tests/mutations.py` | `sidecar-skips-the-resolved-range-check` | 2026-10-29 | CAUGHT | `connect_mode_with_the_system_resolver_refuses_a_name_that_resolves_to…`, `negative_nt_sbx_05_a_name_that_resolves_to_an_internal_address_is_ref…`, `negative_nt_sbx_05_a_rebinding_answer_cannot_redirect_a_connection_th…`, `one_refused_address_in_an_answer_refuses_the_name` |
| `crates/github/tests/mutations/run_mutations.py` | `accept a comment marker written by anyone` | 2026-10-29 | CAUGHT | `negative_nt_lse_03_a_marker_pasted_by_someone_else_does_not_stop_the_…` |
| `crates/github/tests/mutations/run_mutations.py` | `accept a delivery that has only the legacy SHA-1 header` | 2026-10-29 | CAUGHT | `negative_nt_wh_02_every_forged_signature_is_refused_for_the_right_rea…`, `the_github_verifier_passes_the_webhook_contract` |
| `crates/github/tests/mutations/run_mutations.py` | `follow a next link to any host` | 2026-10-29 | CAUGHT | `a_link_to_another_host_is_never_followed` |
| `crates/github/tests/mutations/run_mutations.py` | `identify a person by the login and not by the numeric id` | 2026-10-29 | CAUGHT | `negative_nt_authz_01_a_label_that_came_with_issue_creation_names_its_…`, `negative_nt_authz_01_the_actor_is_the_numeric_id_and_a_lookalike_logi…`, `negative_nt_wh_06_the_payload_is_a_hint_and_the_live_state_decides` |
| `crates/github/tests/mutations/run_mutations.py` | `ignore the replay table` | 2026-10-29 | CAUGHT | `a_delivery_is_recorded_once_and_a_replay_is_a_repeat_by_id_by_body_an…` |
| `crates/github/tests/mutations/run_mutations.py` | `let a stage that may not write get the write credential` | 2026-10-29 | CAUGHT | `negative_nt_authz_07_every_stage_gets_exactly_its_permissions_and_onl…` |
| `crates/github/tests/mutations/run_mutations.py` | `open the pull request as a ready one` | 2026-10-29 | CAUGHT | `the_github_change_host_passes_the_whole_change_host_contract`, `the_source_has_no_merge_no_ready_call_no_workflow_write_and_one_delete` |
| `crates/github/tests/mutations/run_mutations.py` | `print a header value (the request wrapper shows its headers)` | 2026-10-29 | CAUGHT | `wire::tests::a_request_prints_no_header_value_and_no_body` |
| `crates/github/tests/mutations/run_mutations.py` | `print a token (the token wrapper shows its text)` | 2026-10-29 | CAUGHT | `token::tests::a_bearer_and_a_live_token_print_nothing_of_the_token` |
| `crates/github/tests/mutations/run_mutations.py` | `report BLOCKED as success` | 2026-10-29 | CAUGHT | `changes::tests::a_gate_that_did_not_run_is_never_a_success`, `gate_outcomes_reach_the_code_host_as_check_conclusions_and_blocked_is…` |
| `crates/github/tests/mutations/run_mutations.py` | `skip the head commit in the body tag` | 2026-10-29 | CAUGHT | `the_body_tag_covers_the_head_commit_so_a_push_makes_a_stale_manifest_…` |
| `crates/github/tests/mutations/run_mutations.py` | `skip the signature comparison` | 2026-10-29 | CAUGHT | `negative_nt_wh_02_every_forged_signature_is_refused_for_the_right_rea…`, `the_github_verifier_passes_the_webhook_contract` |
| `crates/github/tests/mutations/run_mutations.py` | `use an over-broad token without looking` | 2026-10-29 | CAUGHT | `negative_nt_authz_06_a_token_that_is_wider_than_the_request_is_revoke…` |
| `crates/sandbox/tests/mutations.py` | `a-bidi-file-name` | 2026-10-29 | CAUGHT | `a_name_that_hides_or_reorders_text_is_unsafe_in_every_script` |
| `crates/sandbox/tests/mutations.py` | `a-container-that-is-never-stopped-for-an-unmeasured-disk` | 2026-10-29 | CAUGHT | `failed_measurements_in_a_running_container_kill_after_the_limit_and_n…`, `sbx_3_a_disk_that_keeps_failing_to_be_measured_ends_the_attempt_as_a_…` |
| `crates/sandbox/tests/mutations.py` | `a-deny-list-spelling` | 2026-10-29 | CAUGHT | `held_the_spellings_docker_accepts_for_a_weaker_container_are_refused`, `namespaces_of_the_host_or_of_another_container_are_denied_for_every_n…`, `sbx_1_the_deny_list_reads_the_spellings_docker_accepts` |
| `crates/sandbox/tests/mutations.py` | `a-failed-disk-measurement-as-zero` | 2026-10-29 | CAUGHT | `sbx_3_a_disk_that_keeps_failing_to_be_measured_ends_the_attempt_as_a_…` |
| `crates/sandbox/tests/mutations.py` | `a-limit-of-zero` | 2026-10-29 | CAUGHT | `a_limit_must_be_a_number_above_zero`, `held_the_spellings_docker_accepts_for_a_weaker_container_are_refused`, `sbx_1_the_deny_list_reads_the_spellings_docker_accepts` |
| `crates/sandbox/tests/mutations.py` | `a-mount-key-in-another-case` | 2026-10-29 | CAUGHT | `a_mount_is_read_with_its_aliases_and_checked_by_what_it_mounts` |
| `crates/sandbox/tests/mutations.py` | `a-mount-of-a-sensitive-tree` | 2026-10-29 | CAUGHT | `a_bind_mount_that_the_factory_does_not_provision_is_refused` |
| `crates/sandbox/tests/mutations.py` | `a-name-that-ends-in-a-blank` | 2026-10-29 | CAUGHT | `names_that_print_blank_or_as_another_name_are_refused`, `rr_13_names_that_print_as_blank_or_as_another_name_are_refused` |
| `crates/sandbox/tests/mutations.py` | `a-negative-ulimit` | 2026-10-29 | CAUGHT | `rr_12_weakening_values_of_the_flags_the_builder_uses_are_refused`, `the_weakening_values_of_the_flags_the_builder_uses_are_refused` |
| `crates/sandbox/tests/mutations.py` | `a-seccomp-colon-option` | 2026-10-29 | CAUGHT | `a_security_option_is_read_as_key_and_value_with_either_separator`, `held_the_spellings_docker_accepts_for_a_weaker_container_are_refused`, `sbx_1_the_deny_list_reads_the_spellings_docker_accepts`, `weakening_values_of_allowed_flags_are_found` |
| `crates/sandbox/tests/mutations.py` | `a-source-outside-the-allowlist` | 2026-10-29 | CAUGHT | `a_bind_mount_that_the_factory_does_not_provision_is_refused`, `a_mount_key_in_another_case_does_not_hide_the_source_and_the_last_one…`, `rr_11_a_bind_mount_of_the_runtime_socket_or_a_home_directory_is_refus…` |
| `crates/sandbox/tests/mutations.py` | `a-tag-character-name` | 2026-10-29 | CAUGHT | `a_name_that_hides_or_reorders_text_is_unsafe_in_every_script`, `legitimate_names_in_any_script_are_not_unsafe` |
| `crates/sandbox/tests/mutations.py` | `a-tmpfs-with-exec` | 2026-10-29 | CAUGHT | `the_weakening_values_of_the_flags_the_builder_uses_are_refused` |
| `crates/sandbox/tests/mutations.py` | `a-variation-selector-with-no-base` | 2026-10-29 | CAUGHT | `names_that_print_blank_or_as_another_name_are_refused`, `rr_13_names_that_print_as_blank_or_as_another_name_are_refused` |
| `crates/sandbox/tests/mutations.py` | `init-switched-off` | 2026-10-29 | CAUGHT | `rr_12_weakening_values_of_the_flags_the_builder_uses_are_refused`, `the_weakening_values_of_the_flags_the_builder_uses_are_refused` |
| `crates/sandbox/tests/mutations.py` | `the-first-mount-source-wins` | 2026-10-29 | CAUGHT | `a_mount_is_read_with_its_aliases_and_checked_by_what_it_mounts`, `a_mount_key_in_another_case_does_not_hide_the_source_and_the_last_one…` |
| `tests/security/mutations.py` | `a-bot-is-not-a-bot` | 2026-10-29 | CAUGHT | `negative_nt_wh_09_the_factorys_own_events_and_other_bots_events_are_i…` |
| `tests/security/mutations.py` | `a-bot-may-hold-a-designation` | 2026-10-29 | CAUGHT | `negative_nt_authz_01_only_the_numeric_id_on_the_allowlist_grants_a_de…`, `negative_nt_mrg_06_a_bot_an_app_and_the_requester_on_a_risky_change_d…` |
| `tests/security/mutations.py` | `a-delivery-that-fails-verification-is-acknowledged` | 2026-10-29 | CAUGHT | `negative_nt_wh_01` |
| `tests/security/mutations.py` | `a-deny-write-path-may-be-written` | 2026-10-29 | CAUGHT | `negative_nt_gate_03_deleting_a_protected_file_is_refused_too`, `negative_nt_gate_03_each_ci_gate_and_instruction_file_edit_fails_befo…`, `negative_nt_gate_04_every_path_trick_is_refused_with_its_group_and_th…`, `negative_nt_gate_04_every_rename_and_normalization_trick_is_blocked_w…`, `negative_nt_gate_04_the_tricks_that_a_repository_can_hold_fail_the_wh…`, `negative_nt_gate_05_an_edit_of_the_gate_definitions_fails_the_protect…`, `negative_nt_inj_01_a_model_that_obeys_the_text_of_a_request_changes_n…`, `negative_nt_inj_01_the_workflow_edit_the_env_the_fetch_and_the_pass_c…`, `negative_nt_inj_03_a_model_that_obeys_a_document_of_the_repository_ch…`, `negative_nt_inj_03_a_readme_a_contributing_file_and_a_comment_that_as…`, `negative_nt_pol_04_a_protected_change_is_accepted_only_with_all_three…`, `negative_nt_pol_04_a_protected_change_needs_all_three_elements`, `negative_nt_pol_04_a_protected_group_beats_write_allow` |
| `tests/security/mutations.py` | `a-failing-gate-does-not-stop-an-approval` | 2026-10-29 | CAUGHT | `negative_nt_mrg_01_a_failing_gate_refuses_approval_and_nothing_reache…`, `negative_nt_mrg_01_a_gate_that_is_not_clear_refuses_the_approval` |
| `tests/security/mutations.py` | `a-forbidden-argument-is-allowed` | 2026-10-29 | CAUGHT | `negative_nt_tool_05_argument_injection_is_denied_by_forbidden_args` |
| `tests/security/mutations.py` | `a-forbidden-command-class-denies-nothing` | 2026-10-29 | CAUGHT | `negative_nt_inj_01_a_model_that_obeys_the_text_of_a_request_changes_n…`, `negative_nt_inj_03_a_model_that_obeys_a_document_of_the_repository_ch…`, `negative_nt_tool_01_a_shell_string_is_a_literal_argument_and_a_shell_…`, `negative_nt_tool_02_forbidden_command_class_matrix` |
| `tests/security/mutations.py` | `a-moved-head-is-not-noticed` | 2026-10-29 | CAUGHT | `negative_nt_mrg_03_a_refusal_for_a_moved_head_also_ends_the_approvals…`, `negative_nt_mrg_03_the_head_moving_after_approval_invalidates_the_app…` |
| `tests/security/mutations.py` | `a-parent-component-is-not-refused` | 2026-10-29 | MISSED | none |
| `tests/security/mutations.py` | `a-privileged-container-is-not-refused` | 2026-10-29 | MISSED | none |
| `tests/security/mutations.py` | `a-renewal-ignores-the-epoch` | 2026-10-29 | CAUGHT | `negative_nt_lse_02_a_renewal_with_the_wrong_owner_epoch_tenant_or_a_l…` |
| `tests/security/mutations.py` | `a-renewal-ignores-the-lapse` | 2026-10-29 | CAUGHT | `negative_nt_lse_02_a_renewal_with_the_wrong_owner_epoch_tenant_or_a_l…` |
| `tests/security/mutations.py` | `a-renewal-ignores-the-owner` | 2026-10-29 | CAUGHT | `negative_nt_lse_02_a_renewal_with_the_wrong_owner_epoch_tenant_or_a_l…` |
| `tests/security/mutations.py` | `a-rotation-to-the-same-key-is-accepted` | 2026-10-29 | MISSED | none |
| `tests/security/mutations.py` | `a-second-claimant-is-not-told-it-lost` | 2026-10-29 | CAUGHT | `negative_nt_lse_02_a_hundred_interleavings_of_two_workers_claim_one_j…` |
| `tests/security/mutations.py` | `a-secret-file-may-be-read-by-group-and-others` | 2026-10-29 | CAUGHT | `a_secret_key_file_that_group_can_read_blocks_the_github_ports_and_say…`, `held_the_key_file_is_checked_for_mode_link_size_and_kind` |
| `tests/security/mutations.py` | `a-widening-of-a-switch-counts-as-a-tightening` | 2026-10-29 | CAUGHT | `negative_nt_pol_02_each_widening_is_refused_and_names_its_key`, `negative_nt_pol_02_tightenings_are_accepted`, `negative_nt_pol_02_widenings_of_the_approval_policy_are_refused_too` |
| `tests/security/mutations.py` | `an-agent-may-grant-itself-a-tool` | 2026-10-29 | CAUGHT | `negative_nt_inj_04_exec_shell_and_approval_grant_are_denied_to_an_age…`, `negative_nt_tool_03_unknown_never_grantable_and_self_granted_tools_ar…` |
| `tests/security/mutations.py` | `an-app-with-a-forbidden-permission-gets-a-token` | 2026-10-29 | CAUGHT | `negative_nt_authz_09_an_app_that_holds_a_forbidden_permission_gets_no…` |
| `tests/security/mutations.py` | `an-expired-allowlist-entry-still-grants` | 2026-10-29 | CAUGHT | `negative_nt_authz_01_only_the_numeric_id_on_the_allowlist_grants_a_de…` |
| `tests/security/mutations.py` | `data-lines-are-not-quoted` | 2026-10-29 | CAUGHT | `negative_nt_authz_05_an_edit_after_the_snapshot_waits_for_the_request…`, `negative_nt_inj_01_every_payload_in_every_input_leaves_the_instructio…`, `negative_nt_inj_02_envelope_hardening`, `negative_nt_inj_04_the_output_of_a_command_the_factory_ran_sits_in_a_…`, `negative_nt_inj_06_a_reviewer_pass_cannot_override_a_failed_gate` |
| `tests/security/mutations.py` | `markdown-bound-for-github-is-sent-as-written` | 2026-10-29 | CAUGHT | `negative_nt_sec_04_markdown_cannot_carry_data_out_through_any_path_to…` |
| `tests/security/mutations.py` | `stale-evidence-does-not-stop-an-approval` | 2026-10-29 | MISSED | none |
| `tests/security/mutations.py` | `the-api-writes-the-old-webhook-name` | 2026-10-29 | CAUGHT | `negative_nt_aud_03_the_api_writes_a_webhook_under_the_required_type_n…` |
| `tests/security/mutations.py` | `the-budget-threshold-is-never-recorded` | 2026-10-29 | CAUGHT | `every_required_event_type`, `negative_nt_aud_03_every_required_event_type_appears_with_actor_polic…` |
| `tests/security/mutations.py` | `the-builder-report-is-stored-as-written` | 2026-10-29 | CAUGHT | `negative_nt_sec_01_a_full_fixture_job_with_a_canary_of_every_class_le…`, `negative_nt_sec_01_composed_canaries_in_the_repository_the_builder_re…` |
| `tests/security/mutations.py` | `the-egress-allowlist-matches-any-host` | 2026-10-29 | CAUGHT | `negative_nt_inj_01_a_model_that_obeys_the_text_of_a_request_changes_n…`, `negative_nt_inj_01_the_workflow_edit_the_env_the_fetch_and_the_pass_c…`, `negative_nt_inj_03_a_model_that_obeys_a_document_of_the_repository_ch…` |
| `tests/security/mutations.py` | `the-engine-does-not-write-command-executed` | 2026-10-29 | CAUGHT | `negative_nt_aud_03_every_required_event_type_appears_with_actor_polic…`, `negative_nt_aud_03_the_engine_writes_the_sandbox_lifecycle_the_comman…`, `negative_nt_aud_03_the_facts_of_an_attempt_name_who_wrote_them` |
| `tests/security/mutations.py` | `the-job-token-is-accepted-by-the-webhook-endpoint` | 2026-10-29 | CAUGHT | `negative_nt_inj_04_composed_a_job_token_is_refused_by_every_operation…` |
| `tests/security/mutations.py` | `the-text-bound-for-github-is-not-checked-for-a-secret` | 2026-10-29 | CAUGHT | `negative_nt_sec_03_text_with_a_secret_is_blocked_everywhere_and_nothi…` |
| `tests/security/mutations.py` | `the-workspace-lets-any-edit-in` | 2026-10-29 | CAUGHT | `negative_nt_gate_01_the_builder_weakens_a_test_or_edits_a_fixture`, `negative_nt_gate_03_the_builder_edits_ci_and_gate_files`, `negative_nt_inj_01_a_model_that_obeys_the_text_of_a_request_changes_n…`, `negative_nt_inj_01_the_workflow_edit_the_env_the_fetch_and_the_pass_c…`, `negative_nt_inj_03_a_model_that_obeys_a_document_of_the_repository_ch…`, `negative_nt_inj_03_a_readme_a_contributing_file_and_a_comment_that_as…`, `negative_nt_inj_03_hostile_text_in_a_code_comment_gives_the_writer_no…` |
| `tests/security/mutations.py` | `the-workspace-skips-the-secret-scan` | 2026-10-29 | CAUGHT | `negative_nt_inj_01_a_model_that_obeys_the_text_of_a_request_changes_n…`, `negative_nt_inj_03_a_model_that_obeys_a_document_of_the_repository_ch…`, `negative_nt_sec_01_secrets_the_model_pastes_into_its_summary_and_its_…`, `negative_nt_sec_05_a_secret_in_a_document_is_refused_before_the_commit`, `negative_nt_sec_05_unsafe_entries_and_secrets_in_the_tree_are_refused` |

<!-- GENERATED:end matrix -->
