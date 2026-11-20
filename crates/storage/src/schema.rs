// @generated automatically by Diesel CLI.

diesel::table! {
    api_tokens (tenant_id, id) {
        tenant_id -> Uuid,
        id -> Uuid,
        principal_id -> Uuid,
        token_hash -> Bytea,
        audience -> Text,
        label -> Nullable<Text>,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
        last_used_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    approvals (tenant_id, id) {
        tenant_id -> Uuid,
        id -> Uuid,
        job_id -> Uuid,
        stage_run_id -> Uuid,
        decision -> Text,
        approver_principal_id -> Uuid,
        approver_kind -> Text,
        approver_github_user_id -> Int8,
        approver_designation -> Text,
        allowlist_version_hash -> Text,
        pr_head_sha -> Nullable<Text>,
        tree_hash -> Nullable<Text>,
        base_sha -> Nullable<Text>,
        evidence_manifest_hash -> Nullable<Text>,
        spec_version -> Nullable<Int4>,
        policy_hash -> Text,
        reason -> Text,
        channel -> Text,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
        invalidated_at -> Nullable<Timestamptz>,
        invalidation_reason -> Nullable<Text>,
    }
}

diesel::table! {
    artifacts (tenant_id, content_sha256) {
        tenant_id -> Uuid,
        content_sha256 -> Text,
        size_bytes -> Int8,
        media_type -> Text,
        backend -> Text,
        retention_class -> Text,
        created_by_job_id -> Nullable<Uuid>,
        created_by_stage_run_id -> Nullable<Uuid>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    attempts (tenant_id, id) {
        tenant_id -> Uuid,
        id -> Uuid,
        job_id -> Uuid,
        stage_run_id -> Uuid,
        attempt_number -> Int4,
        status -> Text,
        version -> Int8,
        lease_owner -> Nullable<Text>,
        lease_epoch -> Int8,
        lease_expires_at -> Nullable<Timestamptz>,
        last_heartbeat_at -> Nullable<Timestamptz>,
        deadline_at -> Timestamptz,
        teardown_deadline_at -> Nullable<Timestamptz>,
        failure_class -> Nullable<Text>,
        output_sha256 -> Nullable<Text>,
        sandbox_id -> Nullable<Text>,
        sandbox_leaked -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        ended_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    audit_events (tenant_id, sequence) {
        tenant_id -> Uuid,
        sequence -> Int8,
        event_id -> Uuid,
        actor_type -> Text,
        actor_id -> Text,
        action -> Text,
        subject -> Text,
        decision -> Text,
        reason -> Text,
        policy_hash -> Text,
        job_id -> Nullable<Uuid>,
        stage_run_id -> Nullable<Uuid>,
        correlation_id -> Uuid,
        created_at -> Timestamptz,
        prev_sequence -> Nullable<Int8>,
        prev_hash -> Nullable<Text>,
        canonical_json -> Text,
        hash -> Text,
    }
}

diesel::table! {
    inbox (tenant_id, consumer, event_id) {
        tenant_id -> Uuid,
        consumer -> Text,
        event_id -> Uuid,
        processed_at -> Timestamptz,
    }
}

diesel::table! {
    jobs (tenant_id, id) {
        tenant_id -> Uuid,
        id -> Uuid,
        repository_id -> Uuid,
        requester_principal_id -> Uuid,
        status -> Text,
        version -> Int8,
        execution_mode -> Text,
        autonomy_level -> Text,
        pipeline_scope -> Array<Nullable<Text>>,
        correlation_id -> Uuid,
        idempotency_key -> Nullable<Text>,
        webhook_delivery_id -> Nullable<Uuid>,
        policy_hash -> Nullable<Text>,
        normalized_request_sha256 -> Nullable<Text>,
        ledger_head_sequence -> Int8,
        ledger_head_hash -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        terminal_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    ledger_entries (tenant_id, job_id, sequence) {
        tenant_id -> Uuid,
        job_id -> Uuid,
        sequence -> Int8,
        entry_id -> Uuid,
        stage_run_id -> Uuid,
        attempt_id -> Nullable<Uuid>,
        recorded_at -> Timestamptz,
        inserted_at -> Timestamptz,
        execution_mode -> Text,
        recorded_component -> Text,
        recorded_fidelity -> Text,
        claim_kind -> Text,
        assurance_level -> Nullable<Text>,
        confidence_level -> Text,
        invalidates -> Array<Nullable<Uuid>>,
        prev_sequence -> Nullable<Int8>,
        prev_entry_hash -> Nullable<Text>,
        entry_hash -> Text,
        canonical_json -> Text,
    }
}

diesel::table! {
    original_requests (tenant_id, id) {
        tenant_id -> Uuid,
        id -> Uuid,
        job_id -> Uuid,
        revision -> Int4,
        source -> Text,
        source_ref -> Nullable<Text>,
        author_github_user_id -> Nullable<Int8>,
        request_text -> Text,
        content_sha256 -> Text,
        captured_at -> Timestamptz,
    }
}

diesel::table! {
    outbox (tenant_id, event_id) {
        seq -> Int8,
        tenant_id -> Uuid,
        event_id -> Uuid,
        event_type -> Text,
        event_version -> Int4,
        job_id -> Uuid,
        aggregate_type -> Text,
        aggregate_id -> Uuid,
        aggregate_version -> Int8,
        transition_id -> Text,
        reason_code -> Nullable<Text>,
        correlation_id -> Uuid,
        causation_id -> Nullable<Uuid>,
        occurred_at -> Timestamptz,
        producer -> Text,
        traceparent -> Nullable<Text>,
        payload -> Jsonb,
        payload_schema_name -> Nullable<Text>,
        payload_schema_version -> Nullable<Int4>,
        created_at -> Timestamptz,
        published_at -> Nullable<Timestamptz>,
        publish_attempts -> Int4,
    }
}

diesel::table! {
    principals (tenant_id, id) {
        tenant_id -> Uuid,
        id -> Uuid,
        kind -> Text,
        github_user_id -> Nullable<Int8>,
        login -> Nullable<Text>,
        created_at -> Timestamptz,
        disabled_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    repositories (tenant_id, id) {
        tenant_id -> Uuid,
        id -> Uuid,
        github_installation_id -> Int8,
        github_repository_id -> Int8,
        full_name -> Text,
        default_branch -> Text,
        enabled -> Bool,
        protection_preflight_passed -> Bool,
        autonomy_ceiling -> Text,
        version -> Int8,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        bypass_attested_by_principal_id -> Nullable<Uuid>,
        bypass_attested_at -> Nullable<Timestamptz>,
        project_map_commit -> Nullable<Text>,
        project_map_attested_by_principal_id -> Nullable<Uuid>,
        project_map_attested_at -> Nullable<Timestamptz>,
        enabled_project_map_commit -> Nullable<Text>,
        enabled_by_principal_id -> Nullable<Uuid>,
        enabled_at -> Nullable<Timestamptz>,
        single_maintainer -> Bool,
    }
}

diesel::table! {
    stage_run_artifacts (tenant_id, stage_run_id, direction, role) {
        tenant_id -> Uuid,
        job_id -> Uuid,
        stage_run_id -> Uuid,
        direction -> Text,
        role -> Text,
        content_sha256 -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    stage_runs (tenant_id, id) {
        tenant_id -> Uuid,
        id -> Uuid,
        job_id -> Uuid,
        stage_kind -> Text,
        run_number -> Int4,
        status -> Text,
        version -> Int8,
        lease_epoch -> Int8,
        max_attempts -> Int2,
        not_before -> Timestamptz,
        rework_of_stage_run_id -> Nullable<Uuid>,
        stage_contract_sha256 -> Nullable<Text>,
        gate_outcome -> Nullable<Text>,
        gate_report_sha256 -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        finished_at -> Nullable<Timestamptz>,
        superseded_at -> Nullable<Timestamptz>,
        attempts_before_last_answer -> Int4,
        failing_set_sha256 -> Nullable<Text>,
    }
}

diesel::table! {
    state_machine_edges (machine, from_status, transition_id) {
        machine -> Text,
        from_status -> Text,
        transition_id -> Text,
    }
}

diesel::table! {
    state_machine_states (machine, status) {
        machine -> Text,
        status -> Text,
        is_initial -> Bool,
        is_terminal -> Bool,
    }
}

diesel::table! {
    state_machine_transitions (machine, transition_id) {
        machine -> Text,
        transition_id -> Text,
        event -> Text,
        to_status -> Text,
        emits -> Nullable<Text>,
    }
}

diesel::table! {
    task_node_dependencies (tenant_id, task_node_id, depends_on_task_node_id) {
        tenant_id -> Uuid,
        stage_run_id -> Uuid,
        task_node_id -> Uuid,
        depends_on_task_node_id -> Uuid,
    }
}

diesel::table! {
    task_nodes (tenant_id, id) {
        tenant_id -> Uuid,
        id -> Uuid,
        job_id -> Uuid,
        stage_run_id -> Uuid,
        task_key -> Text,
        plan_sha256 -> Text,
        status -> Text,
        version -> Int8,
        retry_count -> Int2,
        current_attempt_id -> Nullable<Uuid>,
        commit_sha -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        finished_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    tenants (id) {
        id -> Uuid,
        slug -> Text,
        display_name -> Text,
        kind -> Text,
        created_at -> Timestamptz,
        disabled_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    troubleshooting_daily_counters (tenant_id, day) {
        tenant_id -> Uuid,
        day -> Date,
        agent_runs -> Int4,
        new_issues -> Int4,
        comments -> Int4,
        spend_micro_usd -> Int8,
    }
}

diesel::table! {
    troubleshooting_issues (tenant_id, fingerprint) {
        tenant_id -> Uuid,
        fingerprint -> Text,
        category -> Text,
        component -> Text,
        title -> Text,
        repository -> Text,
        issue_number -> Int8,
        opened_at -> Timestamptz,
        last_comment_day -> Nullable<Date>,
        comments_on_last_day -> Int4,
    }
}

diesel::table! {
    troubleshooting_probe_state (tenant_id, probe_id) {
        tenant_id -> Uuid,
        probe_id -> Text,
        last_outcome -> Text,
        last_value -> Nullable<Text>,
        last_call_id -> Nullable<Text>,
        last_run_id -> Nullable<Text>,
        last_checked_at -> Timestamptz,
        last_tripped_at -> Nullable<Timestamptz>,
        cooldown_until -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    troubleshooting_runs (tenant_id, id) {
        tenant_id -> Uuid,
        id -> Text,
        trigger -> Text,
        state -> Text,
        started_at -> Timestamptz,
        ended_at -> Nullable<Timestamptz>,
        spend_micro_usd -> Int8,
        report_sha256 -> Nullable<Text>,
        gateway_record_sha256 -> Nullable<Text>,
        outcome -> Nullable<Text>,
        agent_ran -> Bool,
        dry_run -> Bool,
        datadog_enabled -> Bool,
        issues_opened -> Int4,
        comments_posted -> Int4,
        deferred_fingerprints -> Array<Nullable<Text>>,
    }
}

diesel::table! {
    webhook_deliveries (tenant_id, id) {
        tenant_id -> Uuid,
        id -> Uuid,
        delivery_id -> Text,
        event_name -> Text,
        action -> Nullable<Text>,
        github_installation_id -> Int8,
        github_repository_id -> Nullable<Int8>,
        sender_github_user_id -> Nullable<Int8>,
        body_sha256 -> Text,
        semantic_key -> Nullable<Text>,
        received_at -> Timestamptz,
    }
}

diesel::joinable!(api_tokens -> tenants (tenant_id));
diesel::joinable!(approvals -> tenants (tenant_id));
diesel::joinable!(artifacts -> tenants (tenant_id));
diesel::joinable!(attempts -> tenants (tenant_id));
diesel::joinable!(audit_events -> tenants (tenant_id));
diesel::joinable!(inbox -> tenants (tenant_id));
diesel::joinable!(jobs -> tenants (tenant_id));
diesel::joinable!(ledger_entries -> tenants (tenant_id));
diesel::joinable!(original_requests -> tenants (tenant_id));
diesel::joinable!(outbox -> tenants (tenant_id));
diesel::joinable!(principals -> tenants (tenant_id));
diesel::joinable!(repositories -> tenants (tenant_id));
diesel::joinable!(stage_run_artifacts -> tenants (tenant_id));
diesel::joinable!(stage_runs -> tenants (tenant_id));
diesel::joinable!(task_node_dependencies -> tenants (tenant_id));
diesel::joinable!(task_nodes -> tenants (tenant_id));
diesel::joinable!(troubleshooting_daily_counters -> tenants (tenant_id));
diesel::joinable!(troubleshooting_issues -> tenants (tenant_id));
diesel::joinable!(troubleshooting_probe_state -> tenants (tenant_id));
diesel::joinable!(troubleshooting_runs -> tenants (tenant_id));
diesel::joinable!(webhook_deliveries -> tenants (tenant_id));

diesel::allow_tables_to_appear_in_same_query!(
    api_tokens,
    approvals,
    artifacts,
    attempts,
    audit_events,
    inbox,
    jobs,
    ledger_entries,
    original_requests,
    outbox,
    principals,
    repositories,
    stage_run_artifacts,
    stage_runs,
    state_machine_edges,
    state_machine_states,
    state_machine_transitions,
    task_node_dependencies,
    task_nodes,
    tenants,
    troubleshooting_daily_counters,
    troubleshooting_issues,
    troubleshooting_probe_state,
    troubleshooting_runs,
    webhook_deliveries,
);
