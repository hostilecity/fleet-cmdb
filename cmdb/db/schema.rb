# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2026_11_23_295001) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"
  enable_extension "pg_trgm"

  create_table "advisories", force: :cascade do |t|
    t.string "advisory_id", limit: 128, null: false
    t.string "source", limit: 256, null: false
    t.string "summary", limit: 512
    t.string "aliases", default: [], null: false, array: true
    t.string "severity", limit: 16, null: false
    t.string "severity_raw", limit: 512
    t.string "reference_url", limit: 2048
    t.datetime "published_at"
    t.datetime "modified_at", null: false
    t.datetime "withdrawn_at"
    t.string "withdrawn_reason", limit: 16
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "cvss_av", limit: 1
    t.string "cvss_pr", limit: 1
    t.string "cvss_ui", limit: 1
    t.index ["advisory_id"], name: "index_advisories_on_advisory_id", unique: true
    t.index ["aliases"], name: "index_advisories_on_aliases", using: :gin
    t.check_constraint "(cvss_av::text = ANY (ARRAY['N'::character varying, 'A'::character varying, 'L'::character varying, 'P'::character varying]::text[])) AND (cvss_pr::text = ANY (ARRAY['N'::character varying, 'L'::character varying, 'H'::character varying]::text[])) AND (cvss_ui::text = ANY (ARRAY['N'::character varying, 'R'::character varying]::text[])) OR cvss_av IS NULL AND cvss_pr IS NULL AND cvss_ui IS NULL", name: "advisories_cvss_parts_valid"
    t.check_constraint "(withdrawn_at IS NULL) = (withdrawn_reason IS NULL) AND (withdrawn_reason::text = ANY (ARRAY['withdrawn'::character varying, 'absent'::character varying]::text[]))", name: "advisories_withdrawn_reason_valid"
    t.check_constraint "severity::text = ANY (ARRAY['critical'::character varying, 'high'::character varying, 'medium'::character varying, 'low'::character varying, 'unknown'::character varying]::text[])", name: "advisories_severity_valid"
  end

  create_table "advisory_imports", force: :cascade do |t|
    t.bigint "operator_id"
    t.string "origin", limit: 8, null: false
    t.string "source", limit: 256, null: false
    t.boolean "full", default: false, null: false
    t.string "state", limit: 16, null: false
    t.string "ecosystems", default: [], null: false, array: true
    t.jsonb "counts", default: {}, null: false
    t.jsonb "problems", default: [], null: false
    t.string "reason", limit: 512
    t.string "etag", limit: 256
    t.string "last_modified", limit: 64
    t.datetime "started_at", null: false
    t.datetime "finished_at"
    t.jsonb "matching"
    t.jsonb "changed_packages"
    t.index ["finished_at"], name: "index_advisory_imports_on_finished_at"
    t.index ["operator_id"], name: "index_advisory_imports_on_operator_id"
    t.check_constraint "(finished_at IS NULL) = (state::text = ANY (ARRAY['queued'::character varying, 'importing'::character varying]::text[]))", name: "advisory_imports_finished_iff_done"
    t.check_constraint "origin::text = ANY (ARRAY['feed'::character varying, 'file'::character varying]::text[])", name: "advisory_imports_origin_valid"
    t.check_constraint "state::text = ANY (ARRAY['queued'::character varying, 'importing'::character varying, 'succeeded'::character varying, 'failed'::character varying, 'held_back'::character varying]::text[])", name: "advisory_imports_state_valid"
  end

  create_table "advisory_packages", force: :cascade do |t|
    t.bigint "advisory_id", null: false
    t.string "ecosystem", limit: 64, null: false
    t.string "package", limit: 128, null: false
    t.jsonb "ranges", null: false
    t.string "fixed_version", limit: 256
    t.index ["advisory_id", "ecosystem", "package"], name: "index_advisory_packages_unique", unique: true
    t.index ["ecosystem", "package"], name: "index_advisory_packages_on_ecosystem_and_package"
  end

  create_table "advisory_refresh_attempts", force: :cascade do |t|
    t.string "kind", limit: 16, null: false
    t.bigint "operator_id"
    t.datetime "started_at", null: false
    t.index ["operator_id"], name: "index_advisory_refresh_attempts_on_operator_id"
    t.index ["started_at"], name: "index_advisory_refresh_attempts_on_started_at"
    t.check_constraint "(kind::text = 'manual'::text) = (operator_id IS NOT NULL)", name: "advisory_refresh_attempts_operator_iff_manual"
    t.check_constraint "kind::text = ANY (ARRAY['manual'::character varying, 'scheduled'::character varying, 'task'::character varying]::text[])", name: "advisory_refresh_attempts_kind_valid"
  end

  create_table "advisory_uploads", force: :cascade do |t|
    t.bigint "advisory_import_id", null: false
    t.bigint "operator_id", null: false
    t.string "filename", limit: 256, null: false
    t.bigint "byte_size", null: false
    t.binary "data", null: false
    t.jsonb "allowed_withdrawals", default: {}, null: false
    t.datetime "created_at", null: false
    t.datetime "expires_at", null: false
    t.index ["advisory_import_id"], name: "index_advisory_uploads_on_advisory_import_id", unique: true
    t.index ["expires_at"], name: "index_advisory_uploads_on_expires_at"
    t.index ["operator_id"], name: "index_advisory_uploads_on_operator_id"
    t.check_constraint "byte_size = octet_length(data) AND byte_size <= 67108864", name: "advisory_uploads_size_bounded"
  end

  create_table "agent_credentials", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.string "key_id", limit: 64, null: false
    t.string "secret_digest", limit: 64, null: false
    t.string "state", default: "active", null: false
    t.string "machine_id", limit: 32
    t.datetime "revoked_at"
    t.datetime "last_used_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["host_id"], name: "index_agent_credentials_on_host_id"
    t.index ["host_id"], name: "index_agent_credentials_one_active_per_host", unique: true, where: "((state)::text = 'active'::text)"
    t.index ["key_id"], name: "index_agent_credentials_on_key_id", unique: true
    t.check_constraint "(state::text = 'revoked'::text) = (revoked_at IS NOT NULL)", name: "agent_credentials_revoked_at_matches_state"
    t.check_constraint "state::text = ANY (ARRAY['active'::character varying::text, 'revoked'::character varying::text])", name: "agent_credentials_state_valid"
  end

  create_table "agent_release_imports", force: :cascade do |t|
    t.string "version", limit: 64, null: false
    t.string "state", limit: 16, default: "queued", null: false
    t.text "reason"
    t.bigint "operator_id", null: false
    t.bigint "agent_release_id"
    t.string "request_id", limit: 255
    t.datetime "finished_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["created_at"], name: "index_agent_release_imports_on_created_at"
    t.index ["version"], name: "index_agent_release_imports_one_in_flight", unique: true, where: "((state)::text = ANY ((ARRAY['queued'::character varying, 'running'::character varying])::text[]))"
    t.check_constraint "(state::text = ANY (ARRAY['queued'::character varying, 'running'::character varying]::text[])) = (finished_at IS NULL)", name: "agent_release_imports_finished_at_matches_state"
    t.check_constraint "state::text = ANY (ARRAY['queued'::character varying, 'running'::character varying, 'imported'::character varying, 'refused'::character varying, 'failed'::character varying]::text[])", name: "agent_release_imports_state_valid"
  end

  create_table "agent_releases", force: :cascade do |t|
    t.string "version", limit: 64, null: false
    t.string "target", limit: 64, null: false
    t.string "sha256", limit: 64, null: false
    t.bigint "size", null: false
    t.binary "manifest", null: false
    t.binary "signature", null: false
    t.text "trusted_comment", null: false
    t.string "key_id", limit: 16, null: false
    t.string "key_role", limit: 16, null: false
    t.string "source", limit: 16, null: false
    t.bigint "imported_by_id", null: false
    t.datetime "imported_at", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["version"], name: "index_agent_releases_on_version", unique: true
    t.check_constraint "key_role::text = ANY (ARRAY['current'::character varying, 'next'::character varying]::text[])", name: "agent_releases_key_role_valid"
    t.check_constraint "sha256::text ~ '^[0-9a-f]{64}$'::text", name: "agent_releases_sha256_valid"
    t.check_constraint "size >= 1 AND size <= 67108864", name: "agent_releases_size_valid"
    t.check_constraint "source::text = ANY (ARRAY['github'::character varying, 'upload'::character varying]::text[])", name: "agent_releases_source_valid"
  end

  create_table "agent_updates", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.bigint "rollout_id", null: false
    t.uuid "report_id", null: false
    t.string "version", limit: 64, null: false
    t.string "outcome", limit: 16, null: false
    t.text "reason"
    t.string "reported_agent_version", limit: 64, null: false
    t.datetime "occurred_at", null: false
    t.datetime "received_at", null: false
    t.index ["host_id", "received_at"], name: "index_agent_updates_on_host_id_and_received_at"
    t.index ["host_id", "report_id"], name: "index_agent_updates_on_host_id_and_report_id", unique: true
    t.index ["rollout_id"], name: "index_agent_updates_on_rollout_id"
    t.check_constraint "outcome::text = ANY (ARRAY['succeeded'::character varying, 'failed'::character varying, 'rolled_back'::character varying]::text[])", name: "agent_updates_outcome_valid"
  end

  create_table "audit_entries", primary_key: ["id", "occurred_at"], options: "PARTITION BY RANGE (occurred_at)", force: :cascade do |t|
    t.bigserial "id", null: false
    t.string "actor_type", null: false
    t.bigint "actor_id"
    t.string "action", null: false
    t.string "target_type"
    t.bigint "target_id"
    t.jsonb "changeset", default: {}, null: false
    t.string "request_id", limit: 255
    t.datetime "occurred_at", default: -> { "CURRENT_TIMESTAMP" }, null: false
    t.index "((changeset #>> '{host_id,1}'::text[]))", name: "index_audit_entries_on_approved_host", where: "((action)::text = 'onboarding.approved'::text)"
    t.index "((changeset #>> '{onboarding_request_id,1}'::text[]))", name: "index_audit_entries_on_enrolled_onboarding_request", where: "((action)::text = 'host.enrolled'::text)"
    t.index ["action", "occurred_at"], name: "index_audit_entries_on_action_and_occurred_at"
    t.index ["actor_type", "actor_id", "occurred_at"], name: "index_audit_entries_on_actor"
    t.index ["occurred_at"], name: "index_audit_entries_on_occurred_at"
    t.index ["target_type", "target_id", "occurred_at"], name: "index_audit_entries_on_target"
    t.check_constraint "(actor_type::text = 'system'::text) = (actor_id IS NULL)", name: "audit_entries_actor_id_matches_type"
    t.check_constraint "actor_type::text = ANY (ARRAY['operator'::character varying::text, 'host'::character varying::text, 'system'::character varying::text])", name: "audit_entries_actor_type_valid"
  end

  create_table "chunk_evaluations", primary_key: ["package_chunk_id", "ecosystem"], force: :cascade do |t|
    t.bigint "package_chunk_id", null: false
    t.string "ecosystem", limit: 64, null: false
    t.jsonb "not_evaluated", default: [], null: false
    t.bigint "advisory_import_id", null: false
    t.datetime "evaluated_at", null: false
    t.index ["advisory_import_id", "ecosystem"], name: "index_chunk_evaluations_on_advisory_import_id_and_ecosystem"
  end

  create_table "chunk_matches", primary_key: ["package_chunk_id", "ecosystem", "advisory_id", "package", "architecture"], force: :cascade do |t|
    t.bigint "package_chunk_id", null: false
    t.string "ecosystem", limit: 64, null: false
    t.bigint "advisory_id", null: false
    t.string "package", limit: 128, null: false
    t.string "architecture", limit: 32, null: false
    t.string "source", limit: 128, null: false
    t.string "installed_version", limit: 256, null: false
    t.string "fixed_version", limit: 256
    t.integer "base_bucket", limit: 2
    t.integer "base_rule", limit: 2
    t.boolean "kev"
    t.string "triage_fixed_version", limit: 256
    t.string "from_fixed_version", limit: 256
    t.boolean "keep_only", default: false, null: false
    t.index ["advisory_id"], name: "index_chunk_matches_on_advisory_id"
  end
  add_check_constraint "chunk_matches", "(base_rule IS NULL) = (base_bucket IS NULL) AND (base_rule IS NULL) = (kev IS NULL) AND (base_rule IS NULL OR base_bucket =\nCASE\n    WHEN base_rule = ANY (ARRAY[3, 4, 5, 6]) THEN 1\n    WHEN base_rule = ANY (ARRAY[10, 11, 13, 14, 15]) THEN 2\n    WHEN base_rule = ANY (ARRAY[9, 16, 17, 18, 19]) THEN 3\n    WHEN base_rule = ANY (ARRAY[1, 2, 7, 8, 12]) THEN 4\n    ELSE NULL::integer\nEND)", name: "chunk_matches_base_valid"

  create_table "cis_result_changes", primary_key: ["id", "occurred_at"], options: "PARTITION BY RANGE (occurred_at)", force: :cascade do |t|
    t.bigserial "id", null: false
    t.bigint "host_id", null: false
    t.bigint "cis_rule_id", null: false
    t.bigint "cis_rule_version_id"
    t.bigint "config_snapshot_id"
    t.string "from_result", limit: 16
    t.string "to_result", limit: 16, null: false
    t.jsonb "observed"
    t.string "reason", limit: 512
    t.datetime "occurred_at", null: false
    t.index ["cis_rule_id", "occurred_at"], name: "index_cis_result_changes_on_cis_rule_id_and_occurred_at"
    t.index ["config_snapshot_id"], name: "index_cis_result_changes_on_config_snapshot_id"
    t.index ["host_id", "occurred_at"], name: "index_cis_result_changes_on_host_id_and_occurred_at"
    t.index ["occurred_at"], name: "index_cis_result_changes_on_occurred_at"
    t.check_constraint "from_result IS NULL OR (from_result::text = ANY (ARRAY['pass'::character varying, 'fail'::character varying, 'not_applicable'::character varying, 'not_readable'::character varying, 'not_evaluated'::character varying]::text[]))", name: "cis_result_changes_from_valid"
    t.check_constraint "from_result::text IS DISTINCT FROM to_result::text", name: "cis_result_changes_is_a_change"
    t.check_constraint "to_result::text = ANY (ARRAY['pass'::character varying, 'fail'::character varying, 'not_applicable'::character varying, 'not_readable'::character varying, 'not_evaluated'::character varying]::text[])", name: "cis_result_changes_to_valid"
  end

  create_table "cis_results", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.bigint "cis_rule_id", null: false
    t.bigint "cis_rule_version_id"
    t.bigint "config_snapshot_id"
    t.string "result", limit: 16, null: false
    t.jsonb "observed"
    t.string "reason", limit: 512
    t.datetime "evaluated_at", null: false
    t.datetime "changed_at", null: false
    t.index ["cis_rule_id"], name: "index_cis_results_failing_without_version", where: "(((result)::text = 'fail'::text) AND (cis_rule_version_id IS NULL))"
    t.index ["cis_rule_id"], name: "index_cis_results_on_cis_rule_id"
    t.index ["config_snapshot_id"], name: "index_cis_results_on_config_snapshot_id"
    t.index ["host_id", "cis_rule_id"], name: "index_cis_results_on_host_id_and_cis_rule_id", unique: true
    t.check_constraint "result::text = ANY (ARRAY['pass'::character varying, 'fail'::character varying, 'not_applicable'::character varying, 'not_readable'::character varying, 'not_evaluated'::character varying]::text[])", name: "cis_results_result_valid"
  end

  create_table "cis_rule_versions", force: :cascade do |t|
    t.bigint "cis_rule_id", null: false
    t.integer "version", null: false
    t.string "reference", limit: 128, null: false
    t.string "title", limit: 200, null: false
    t.string "severity", limit: 16, null: false
    t.jsonb "applies_to", null: false
    t.string "fact", limit: 220, null: false
    t.jsonb "condition", null: false
    t.text "remediation", null: false
    t.string "content_hash", limit: 64, null: false
    t.datetime "created_at", null: false
    t.index ["cis_rule_id", "version"], name: "index_cis_rule_versions_on_cis_rule_id_and_version", unique: true
    t.index ["fact"], name: "index_cis_rule_versions_on_fact"
    t.check_constraint "severity::text = ANY (ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying]::text[])", name: "cis_rule_versions_severity"
    t.check_constraint "version > 0", name: "cis_rule_versions_version_positive"
  end

  create_table "cis_rules", force: :cascade do |t|
    t.string "key", limit: 64, null: false
    t.boolean "enabled", default: true, null: false
    t.bigint "current_version_id"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["current_version_id"], name: "index_cis_rules_on_current_version_id", unique: true
    t.index ["key"], name: "index_cis_rules_on_key", unique: true
  end

  create_table "config_report_receipts", primary_key: ["id", "received_at"], options: "PARTITION BY RANGE (received_at)", force: :cascade do |t|
    t.bigserial "id", null: false
    t.bigint "host_id", null: false
    t.uuid "report_id", null: false
    t.datetime "received_at", null: false
    t.index ["host_id", "report_id"], name: "index_config_report_receipts_on_host_id_and_report_id"
    t.index ["received_at"], name: "index_config_report_receipts_on_received_at"
  end

  create_table "config_snapshots", primary_key: ["id", "stored_at"], options: "PARTITION BY RANGE (stored_at)", force: :cascade do |t|
    t.bigserial "id", null: false
    t.bigint "host_id", null: false
    t.jsonb "facts", null: false
    t.string "content_hash", limit: 64, null: false
    t.jsonb "state_counts", default: {}, null: false
    t.integer "manifest_version", null: false
    t.uuid "report_id", null: false
    t.datetime "collected_at", null: false
    t.datetime "received_at", null: false
    t.datetime "stored_at", default: -> { "now()" }, null: false
    t.index ["host_id", "received_at"], name: "index_config_snapshots_on_host_id_and_received_at"
    t.index ["received_at"], name: "index_config_snapshots_on_received_at"
  end

  create_table "enrollment_tokens", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.string "token_digest", limit: 64, null: false
    t.datetime "expires_at", null: false
    t.datetime "redeemed_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["host_id"], name: "index_enrollment_tokens_on_host_id"
    t.index ["token_digest"], name: "index_enrollment_tokens_on_token_digest", unique: true
  end

  create_table "epss_scores", force: :cascade do |t|
    t.string "cve_id", limit: 32, null: false
    t.decimal "score", precision: 11, scale: 10, null: false
    t.decimal "percentile", precision: 11, scale: 10, null: false
    t.string "band", limit: 8, null: false
    t.date "score_date", null: false
    t.index ["cve_id"], name: "index_epss_scores_on_cve_id", unique: true
    t.check_constraint "band::text = ANY (ARRAY['high'::character varying::text, 'normal'::character varying::text])", name: "epss_scores_band_valid"
    t.check_constraint "cve_id::text ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'::text", name: "epss_scores_cve_id_valid"
    t.check_constraint "score >= 0::numeric AND score <= 1::numeric AND percentile >= 0::numeric AND percentile <= 1::numeric", name: "epss_scores_range_valid"
  end

  create_table "evaluation_batches", force: :cascade do |t|
    t.bigint "evaluation_run_id", null: false
    t.integer "position", null: false
    t.bigint "first_host_id", null: false
    t.bigint "last_host_id", null: false
    t.integer "host_count", null: false
    t.index ["evaluation_run_id", "position"], name: "index_evaluation_batches_on_evaluation_run_id_and_position", unique: true
  end

  create_table "evaluation_runs", force: :cascade do |t|
    t.string "kind", limit: 16, null: false
    t.jsonb "scope", default: {}, null: false
    t.string "state", limit: 16, default: "queued", null: false
    t.integer "batch_count", default: 0, null: false
    t.integer "batches_done", default: 0, null: false
    t.integer "host_count", default: 0, null: false
    t.integer "hosts_done", default: 0, null: false
    t.boolean "shown_changed", default: false, null: false
    t.bigint "superseded_by_id"
    t.datetime "started_at"
    t.datetime "finished_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "prepare_step", limit: 80
    t.bigint "prepare_cursor"
    t.index ["finished_at"], name: "index_evaluation_runs_on_finished_at"
    t.index ["kind", "state"], name: "index_evaluation_runs_unfinished", where: "((state)::text = ANY ((ARRAY['queued'::character varying, 'running'::character varying])::text[]))"
    t.check_constraint "kind::text = ANY (ARRAY['cis_rules'::character varying, 'advisories'::character varying, 'triage'::character varying]::text[])", name: "evaluation_runs_kind_valid"
    t.check_constraint "state::text = ANY (ARRAY['queued'::character varying, 'running'::character varying, 'finished'::character varying, 'superseded'::character varying, 'failed'::character varying]::text[])", name: "evaluation_runs_state_valid"
  end

  create_table "finding_decisions", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.bigint "advisory_id", null: false
    t.string "kind", limit: 16, null: false
    t.text "reason", null: false
    t.date "expires_on", null: false
    t.bigint "created_by_id", null: false
    t.boolean "confirmed", default: false, null: false
    t.jsonb "evidence", null: false
    t.string "request_id", limit: 128
    t.bigint "operator_session_id"
    t.datetime "ended_at"
    t.bigint "ended_by_id"
    t.string "ended_why", limit: 16
    t.jsonb "ended_evidence"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["advisory_id"], name: "index_finding_decisions_active_advisory", where: "(ended_at IS NULL)"
    t.index ["created_by_id", "created_at"], name: "index_finding_decisions_operator_window"
    t.index ["expires_on"], name: "index_finding_decisions_active_expiry", where: "(ended_at IS NULL)"
    t.index ["host_id", "advisory_id", "id"], name: "index_finding_decisions_history"
    t.index ["host_id", "advisory_id"], name: "index_finding_decisions_active", unique: true, where: "(ended_at IS NULL)"
    t.index ["id"], name: "index_finding_decisions_active_id", where: "(ended_at IS NULL)"
    t.check_constraint "(ended_at IS NULL) = (ended_why IS NULL)", name: "finding_decisions_ended_why"
    t.check_constraint "(ended_by_id IS NOT NULL) = (NOT ended_why::text IS DISTINCT FROM 'operator'::text)", name: "finding_decisions_ended_by"
    t.check_constraint "char_length(reason) >= 10 AND char_length(reason) <= 1000", name: "finding_decisions_reason_length"
    t.check_constraint "ended_evidence IS NULL OR jsonb_typeof(ended_evidence) = 'object'::text AND octet_length(ended_evidence::text) <= 8192", name: "finding_decisions_ended_evidence_object"
    t.check_constraint "ended_why IS NULL OR (ended_why::text = ANY (ARRAY['operator'::character varying, 'expired'::character varying, 'fixed'::character varying, 'suspended'::character varying, 'resolved'::character varying]::text[]))", name: "finding_decisions_ended_why_valid"
    t.check_constraint "expires_on <= (created_at::date + 366)", name: "finding_decisions_expires_within_limit"
    t.check_constraint "jsonb_typeof(evidence) = 'object'::text AND octet_length(evidence::text) <= 8192", name: "finding_decisions_evidence_object"
    t.check_constraint "kind::text <> 'control'::text OR confirmed", name: "finding_decisions_control_confirmed"
    t.check_constraint "kind::text = ANY (ARRAY['control'::character varying, 'accepted'::character varying]::text[])", name: "finding_decisions_kind_valid"
  end

  create_table "host_applicability", primary_key: "host_id", id: :bigint, default: nil, force: :cascade do |t|
    t.boolean "reboot_required"
    t.string "reboot_packages", default: [], null: false, array: true
    t.string "kernel_build", limit: 256
    t.datetime "reboot_changed_at"
    t.boolean "in_use_reported", default: false, null: false
    t.string "listening_network", default: [], null: false, array: true
    t.string "listening_loopback", default: [], null: false, array: true
    t.string "running_services", default: [], null: false, array: true
    t.integer "unnamed_network", default: 0, null: false
    t.integer "unnamed_loopback", default: 0, null: false
    t.string "library_scan", limit: 8
    t.string "libraries", default: [], null: false, array: true
    t.string "stale_libraries", default: [], null: false, array: true
    t.jsonb "loaded_by_listeners", default: []
    t.datetime "library_scanned_at"
    t.datetime "library_scan_received_at"
    t.datetime "in_use_changed_at"
    t.index ["library_scan_received_at"], name: "index_host_applicability_listener_expiry", where: "(((library_scan)::text = 'ran'::text) AND (jsonb_array_length(loaded_by_listeners) > 0))"
    t.check_constraint "in_use_reported = (library_scan IS NOT NULL)", name: "host_applicability_in_use_reported"
    t.check_constraint "loaded_by_listeners IS NULL OR jsonb_typeof(loaded_by_listeners) = 'array'::text", name: "host_applicability_loaded_by_listeners_array"
    t.check_constraint "library_scan::text = ANY (ARRAY['off'::character varying, 'ran'::character varying, 'failed'::character varying]::text[])", name: "host_applicability_library_scan_valid"
    t.check_constraint "reboot_required IS NULL OR reboot_required", name: "host_applicability_reboot_true_or_null"
  end

  create_table "host_compliance_flushes", primary_key: "xact_id", id: :bigint, default: nil, force: :cascade do |t|
  end

  create_table "host_compliance_pending", primary_key: ["xact_id", "host_id"], force: :cascade do |t|
    t.bigint "xact_id", null: false
    t.bigint "host_id", null: false
    t.integer "kinds", limit: 2, null: false
  end

  create_table "host_compliance_recounts", primary_key: "host_id", id: :bigint, default: nil, force: :cascade do |t|
    t.datetime "queued_at", default: -> { "CURRENT_TIMESTAMP" }, null: false
  end

  create_table "host_compliance_summaries", primary_key: "host_id", id: :bigint, default: nil, force: :cascade do |t|
    t.string "enrollment_state", limit: 16, null: false
    t.integer "status_rank", limit: 2, null: false
    t.text "name_key", null: false
    t.string "hostname", limit: 253, null: false
    t.text "tags_key"
    t.decimal "agent_key", array: true
    t.text "os_name"
    t.integer "cis_passed", default: 0, null: false
    t.integer "cis_failed", default: 0, null: false
    t.integer "cis_not_readable", default: 0, null: false
    t.integer "cis_critical", default: 0, null: false
    t.integer "cis_high", default: 0, null: false
    t.integer "cis_medium", default: 0, null: false
    t.integer "cis_low", default: 0, null: false
    t.integer "vuln_critical", default: 0, null: false
    t.integer "vuln_high", default: 0, null: false
    t.integer "vuln_medium", default: 0, null: false
    t.integer "vuln_low", default: 0, null: false
    t.integer "vuln_unknown", default: 0, null: false
    t.boolean "vuln_evaluated", default: false, null: false
    t.virtual "cis_counted", type: :integer, as: "((cis_passed + cis_failed) + cis_not_readable)", stored: true
    t.virtual "vuln_open", type: :integer, as: "((((vuln_critical + vuln_high) + vuln_medium) + vuln_low) + vuln_unknown)", stored: true
    t.virtual "pass_rate", type: :decimal, as: "\nCASE\n    WHEN (((cis_passed + cis_failed) + cis_not_readable) > 0) THEN ((cis_passed)::numeric / (((cis_passed + cis_failed) + cis_not_readable))::numeric)\n    ELSE NULL::numeric\nEND", stored: true
    t.virtual "nothing_evaluated", type: :boolean, as: "((((cis_passed + cis_failed) + cis_not_readable) = 0) AND (NOT (vuln_evaluated OR (((((vuln_critical + vuln_high) + vuln_medium) + vuln_low) + vuln_unknown) > 0))))", stored: true
    t.virtual "fleet_cis_key", type: :decimal, as: "\nCASE\n    WHEN (((enrollment_state)::text = 'active'::text) AND (((cis_passed + cis_failed) + cis_not_readable) > 0)) THEN ((cis_passed)::numeric / (((cis_passed + cis_failed) + cis_not_readable))::numeric)\n    ELSE NULL::numeric\nEND", stored: true
    t.virtual "fleet_vulns_key", type: :integer, as: "\nCASE\n    WHEN (((enrollment_state)::text = 'active'::text) AND (vuln_evaluated OR (((((vuln_critical + vuln_high) + vuln_medium) + vuln_low) + vuln_unknown) > 0))) THEN ((((vuln_critical + vuln_high) + vuln_medium) + vuln_low) + vuln_unknown)\n    ELSE NULL::integer\nEND", stored: true
    t.integer "vuln_fix", default: 0, null: false
    t.integer "vuln_attention", default: 0, null: false
    t.integer "vuln_low_risk", default: 0, null: false
    t.integer "vuln_ignorable", default: 0, null: false
    t.integer "vuln_kev_open", default: 0, null: false
    t.integer "exposure_tier", limit: 2
    t.integer "exposure_points"
    t.integer "work_upgrades"
    t.integer "work_items"
    t.datetime "fixable_critical_since"
    t.datetime "no_fixable_critical_since"
    t.integer "vuln_kev_advisories", default: 0, null: false
    t.integer "vuln_fix_critical", default: 0, null: false
    t.integer "vuln_attention_undecided", default: 0, null: false
    t.boolean "work_kernel_install", default: false, null: false
    t.boolean "work_reboot", default: false, null: false
    t.index "(\nCASE\n    WHEN ((enrollment_state)::text = 'active'::text) THEN exposure_tier\n    ELSE NULL::smallint\nEND) DESC NULLS LAST, (\nCASE\n    WHEN ((enrollment_state)::text = 'active'::text) THEN exposure_points\n    ELSE NULL::integer\nEND) DESC NULLS LAST, name_key, host_id", name: "host_compliance_summaries_exposure", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index "(\nCASE\n    WHEN ((enrollment_state)::text = 'active'::text) THEN work_items\n    ELSE NULL::integer\nEND) DESC NULLS LAST, name_key, host_id", name: "host_compliance_summaries_work", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index "lower(os_name) DESC NULLS LAST, name_key, host_id", name: "host_compliance_summaries_os_desc", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index "lower(os_name), name_key, host_id", name: "host_compliance_summaries_os", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index "nothing_evaluated, ((- (cis_critical + vuln_critical))), ((- (cis_high + vuln_high))), ((- (cis_medium + vuln_medium))), ((- (cis_low + vuln_low))), ((- vuln_unknown)), COALESCE(pass_rate, (2)::numeric), name_key, host_id", name: "host_compliance_summaries_worst", where: "((enrollment_state)::text = 'active'::text)"
    t.index ["agent_key", "name_key", "host_id"], name: "host_compliance_summaries_agent", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["agent_key", "name_key", "host_id"], name: "host_compliance_summaries_agent_desc", order: { agent_key: "DESC NULLS LAST" }, where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["fleet_cis_key", "name_key", "host_id"], name: "host_compliance_summaries_cis", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["fleet_cis_key", "name_key", "host_id"], name: "host_compliance_summaries_cis_desc", order: { fleet_cis_key: "DESC NULLS LAST" }, where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["fleet_vulns_key", "name_key", "host_id"], name: "host_compliance_summaries_vulns", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["fleet_vulns_key", "name_key", "host_id"], name: "host_compliance_summaries_vulns_desc", order: { fleet_vulns_key: "DESC NULLS LAST" }, where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["hostname", "name_key", "host_id"], name: "host_compliance_summaries_hostname", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["name_key", "host_id"], name: "host_compliance_summaries_name", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["status_rank", "name_key", "host_id"], name: "host_compliance_summaries_status", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["status_rank", "name_key", "host_id"], name: "host_compliance_summaries_status_desc", order: { status_rank: :desc }, where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["tags_key", "name_key", "host_id"], name: "host_compliance_summaries_tags", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["tags_key", "name_key", "host_id"], name: "host_compliance_summaries_tags_desc", order: { tags_key: "DESC NULLS LAST" }, where: "((enrollment_state)::text <> 'retired'::text)"
    t.check_constraint "status_rank >= 0 AND status_rank <= 5", name: "host_compliance_summaries_status_rank"
  end

  create_table "host_configs", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.jsonb "facts", null: false
    t.string "content_hash", limit: 64, null: false
    t.jsonb "state_counts", default: {}, null: false
    t.integer "manifest_version", null: false
    t.jsonb "ignored_keys", default: [], null: false
    t.uuid "report_id", null: false
    t.integer "schema_version", null: false
    t.datetime "collected_at", null: false
    t.datetime "received_at", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["host_id"], name: "index_host_configs_on_host_id", unique: true
  end

  create_table "host_inventories", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.jsonb "stable", null: false
    t.jsonb "volatile", null: false
    t.jsonb "warnings", default: [], null: false
    t.string "stable_hash", limit: 64, null: false
    t.uuid "report_id", null: false
    t.integer "schema_version", null: false
    t.datetime "collected_at", null: false
    t.datetime "received_at", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["host_id"], name: "index_host_inventories_on_host_id", unique: true
  end

  create_table "host_liveness", primary_key: "host_id", id: :bigint, default: nil, force: :cascade, options: "WITH (fillfactor = 50, autovacuum_vacuum_scale_factor = 0.01)" do |t|
    t.string "liveness_status", null: false
    t.datetime "last_seen_at", null: false
    t.datetime "agent_reported_at"
    t.boolean "evaluated", default: true, null: false
    t.check_constraint "liveness_status::text = ANY (ARRAY['online'::text, 'stale'::text, 'offline'::text])", name: "host_liveness_status_valid"
  end

  create_table "host_package_sets", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.string "manager", limit: 16, null: false
    t.string "unsupported_reason", limit: 512
    t.integer "package_count", null: false
    t.string "content_hash", limit: 64, null: false
    t.jsonb "warnings", default: [], null: false
    t.uuid "report_id", null: false
    t.integer "schema_version", null: false
    t.datetime "collected_at", null: false
    t.datetime "received_at", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.jsonb "skipped", default: [], null: false
    t.bigint "package_set_id"
    t.index ["host_id"], name: "index_host_package_sets_on_host_id", unique: true
    t.index ["package_set_id"], name: "index_host_package_sets_on_package_set_id"
    t.check_constraint "manager::text = ANY (ARRAY['dpkg'::character varying, 'unsupported'::character varying, 'unreadable'::character varying]::text[])", name: "host_package_sets_manager_valid"
    t.check_constraint "(manager::text = 'dpkg'::text) = (unsupported_reason IS NULL)", name: "host_package_sets_reason_iff_not_dpkg"
  end


  create_table "host_status_events", primary_key: ["id", "stored_at"], options: "PARTITION BY RANGE (stored_at)", force: :cascade do |t|
    t.bigserial "id", null: false
    t.bigint "host_id", null: false
    t.string "from_status"
    t.string "to_status", null: false
    t.string "reason", null: false
    t.datetime "occurred_at", null: false
    t.datetime "stored_at", default: -> { "now()" }, null: false
    t.index ["host_id", "occurred_at"], name: "index_host_status_events_on_host_id_and_occurred_at"
    t.index ["occurred_at"], name: "index_host_status_events_on_occurred_at"
    t.check_constraint "from_status IS NULL OR (from_status::text = ANY (ARRAY['online'::character varying::text, 'stale'::character varying::text, 'offline'::character varying::text]))", name: "host_status_events_from_status_valid"
    t.check_constraint "from_status::text IS DISTINCT FROM to_status::text", name: "host_status_events_is_a_change"
    t.check_constraint "reason::text = ANY (ARRAY['heartbeat'::character varying::text, 'evaluation'::character varying::text])", name: "host_status_events_reason_valid"
    t.check_constraint "to_status::text = ANY (ARRAY['online'::character varying::text, 'stale'::character varying::text, 'offline'::character varying::text])", name: "host_status_events_to_status_valid"
  end

  create_table "host_vulnerability_evaluations", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.string "ecosystem", limit: 64
    t.string "state", limit: 16, null: false
    t.string "reason", limit: 32
    t.string "detail", limit: 512
    t.jsonb "not_evaluated", default: [], null: false
    t.integer "not_evaluated_count", default: 0, null: false
    t.datetime "evaluated_at", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.bigint "package_set_id"
    t.index ["host_id"], name: "index_host_vulnerability_evaluations_on_host_id", unique: true
    t.index ["package_set_id"], name: "index_host_vulnerability_evaluations_on_package_set_id"
    t.check_constraint "(state::text = 'not_evaluated'::text) = (reason IS NOT NULL)", name: "host_vulnerability_evaluations_reason_iff_not_evaluated"
    t.check_constraint "state::text = ANY (ARRAY['evaluated'::character varying, 'not_evaluated'::character varying]::text[])", name: "host_vulnerability_evaluations_state_valid"
  end

  create_table "hosts", force: :cascade do |t|
    t.string "name", limit: 100, null: false
    t.string "hostname", limit: 253, null: false
    t.text "description"
    t.text "notes"
    t.string "tags", default: [], null: false, array: true
    t.string "enrollment_state", default: "pending", null: false
    t.datetime "first_seen_at"
    t.string "agent_version", limit: 64
    t.integer "agent_schema_version"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.datetime "machine_id_mismatch_at"
    t.string "reported_machine_id", limit: 32
    t.integer "task_catalog_version"
    t.string "task_types_supported", default: [], null: false, array: true
    t.string "task_types_enabled", default: [], null: false, array: true
    t.datetime "task_capabilities_reported_at"
    t.string "task_services_allowed", default: [], null: false, array: true
    t.datetime "agent_recovery_since"
    t.datetime "agent_recovery_entered_at"
    t.datetime "agent_recovery_retry_at"
    t.string "agent_recovery_reason", limit: 256
    t.string "agent_recovery_coverage", limit: 16
    t.index ["agent_version"], name: "index_hosts_in_fleet_on_agent_version", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["enrollment_state"], name: "index_hosts_on_enrollment_state"
    t.index ["hostname"], name: "index_hosts_on_hostname"
    t.index ["hostname"], name: "index_hosts_on_hostname_trigram", opclass: :gin_trgm_ops, using: :gin
    t.index ["name"], name: "index_hosts_on_name_trigram", opclass: :gin_trgm_ops, using: :gin
    t.index ["tags"], name: "index_hosts_on_tags", using: :gin
    t.index ["id"], name: "index_hosts_without_recovery_mode", where: "(((enrollment_state)::text = 'active'::text) AND (first_seen_at IS NOT NULL) AND ((agent_recovery_coverage)::text IS DISTINCT FROM 'set_up'::text))"
    t.check_constraint "agent_recovery_coverage::text = ANY (ARRAY['set_up'::character varying, 'not_set_up'::character varying, 'unchecked'::character varying]::text[])", name: "hosts_agent_recovery_coverage_valid"
    t.check_constraint "enrollment_state::text = ANY (ARRAY['pending'::character varying::text, 'active'::character varying::text, 'revoked'::character varying::text, 'retired'::character varying::text])", name: "hosts_enrollment_state_valid"
  end

  create_table "inventory_report_receipts", primary_key: ["id", "received_at"], options: "PARTITION BY RANGE (received_at)", force: :cascade do |t|
    t.bigserial "id", null: false
    t.bigint "host_id", null: false
    t.uuid "report_id", null: false
    t.datetime "received_at", null: false
    t.index ["host_id", "report_id"], name: "index_inventory_report_receipts_on_host_id_and_report_id"
    t.index ["received_at"], name: "index_inventory_report_receipts_on_received_at"
  end

  create_table "inventory_snapshots", primary_key: ["id", "stored_at"], options: "PARTITION BY RANGE (stored_at)", force: :cascade do |t|
    t.bigserial "id", null: false
    t.bigint "host_id", null: false
    t.jsonb "stable", null: false
    t.jsonb "warnings", default: [], null: false
    t.string "stable_hash", limit: 64, null: false
    t.uuid "report_id", null: false
    t.datetime "collected_at", null: false
    t.datetime "received_at", null: false
    t.datetime "stored_at", default: -> { "now()" }, null: false
    t.index ["host_id", "received_at"], name: "index_inventory_snapshots_on_host_id_and_received_at"
    t.index ["received_at"], name: "index_inventory_snapshots_on_received_at"
  end

  create_table "kev_entries", force: :cascade do |t|
    t.string "cve_id", limit: 32, null: false
    t.date "date_added", null: false
    t.date "due_date"
    t.boolean "known_ransomware", default: false, null: false
    t.string "vendor", limit: 128
    t.string "product", limit: 128
    t.index ["cve_id"], name: "index_kev_entries_on_cve_id", unique: true
    t.check_constraint "cve_id::text ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'::text", name: "kev_entries_cve_id_valid"
  end

  create_table "onboarding_requests", force: :cascade do |t|
    t.string "device_code_digest", limit: 64, null: false
    t.string "user_code", limit: 9, null: false
    t.string "state", default: "open", null: false
    t.string "hostname", limit: 253
    t.string "machine_id", limit: 32
    t.jsonb "os"
    t.string "agent_version", limit: 64, null: false
    t.string "client_ip", limit: 45, null: false
    t.bigint "decided_by_id"
    t.datetime "decided_at"
    t.jsonb "host_attributes"
    t.boolean "reenroll", default: false, null: false
    t.bigint "host_id"
    t.datetime "expires_at", null: false
    t.datetime "last_polled_at"
    t.datetime "collected_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["client_ip", "state"], name: "index_onboarding_requests_on_client_ip_and_state"
    t.index ["device_code_digest"], name: "index_onboarding_requests_on_device_code_digest", unique: true
    t.index ["host_id"], name: "index_onboarding_requests_on_host_id"
    t.index ["state", "expires_at"], name: "index_onboarding_requests_on_state_and_expires_at"
    t.index ["user_code"], name: "index_onboarding_requests_open_user_code", unique: true, where: "((state)::text = 'open'::text)"
    t.check_constraint "(state::text = 'collected'::text) = (collected_at IS NOT NULL)", name: "onboarding_requests_collected_at_matches_state"
    t.check_constraint "(state::text = 'open'::text) = (decided_at IS NULL)", name: "onboarding_requests_decided_at_matches_state"
    t.check_constraint "NOT reenroll OR host_id IS NOT NULL", name: "onboarding_requests_reenroll_has_host"
    t.check_constraint "state::text = ANY (ARRAY['open'::character varying, 'approved'::character varying, 'rejected'::character varying, 'collected'::character varying]::text[])", name: "onboarding_requests_state_valid"
  end

  create_table "operator_allowlist_entries", force: :cascade do |t|
    t.string "email", limit: 254, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["email"], name: "index_operator_allowlist_entries_on_email", unique: true
    t.check_constraint "email::text = lower(email::text)", name: "operator_allowlist_entries_email_lowercase"
  end

  create_table "operator_sessions", force: :cascade do |t|
    t.bigint "operator_id", null: false
    t.string "token_digest", limit: 64, null: false
    t.datetime "last_seen_at", null: false
    t.datetime "revoked_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.datetime "google_authenticated_at"
    t.datetime "second_factor_passed_at"
    t.text "pending_second_factor_secret"
    t.datetime "second_factor_replacement_approved_at"
    t.index ["operator_id"], name: "index_operator_sessions_on_operator_id"
    t.index ["token_digest"], name: "index_operator_sessions_on_token_digest", unique: true
  end

  create_table "operators", force: :cascade do |t|
    t.string "google_uid", limit: 255, null: false
    t.string "email", limit: 254, null: false
    t.string "name", limit: 255
    t.datetime "last_signed_in_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["email"], name: "index_operators_on_email"
    t.index ["email"], name: "index_operators_on_email_trigram", opclass: :gin_trgm_ops, using: :gin
    t.index ["google_uid"], name: "index_operators_on_google_uid", unique: true
  end

  create_table "package_chunk_entries", primary_key: ["package_chunk_id", "name", "architecture"], force: :cascade do |t|
    t.bigint "package_chunk_id", null: false
    t.string "name", limit: 128, null: false
    t.string "architecture", limit: 32, null: false
    t.string "version", limit: 256, null: false
    t.string "source", limit: 128
    t.index "COALESCE(source, name), package_chunk_id", name: "index_package_chunk_entries_on_backports", where: "((version)::text ~~ '%~bpo%'::text)"
    t.index "COALESCE(source, name), package_chunk_id", name: "index_package_chunk_entries_on_source_package"
  end

  create_table "package_chunks", force: :cascade do |t|
    t.integer "bucket", limit: 2, null: false
    t.binary "content_hash", null: false
    t.integer "package_count", null: false
    t.datetime "created_at", null: false
    t.datetime "last_used_at", null: false
    t.index ["content_hash"], name: "index_package_chunks_on_content_hash", unique: true
    t.check_constraint "bucket >= 0 AND bucket <= 63", name: "package_chunks_bucket_valid"
  end

  create_table "package_report_receipts", primary_key: ["id", "received_at"], options: "PARTITION BY RANGE (received_at)", force: :cascade do |t|
    t.bigserial "id", null: false
    t.bigint "host_id", null: false
    t.uuid "report_id", null: false
    t.datetime "received_at", null: false
    t.index ["host_id", "report_id"], name: "index_package_report_receipts_on_host_id_and_report_id"
    t.index ["received_at"], name: "index_package_report_receipts_on_received_at"
  end

  create_table "package_sets", force: :cascade do |t|
    t.binary "content_hash", null: false
    t.bigint "chunk_ids", null: false, array: true
    t.integer "package_count", null: false
    t.datetime "created_at", null: false
    t.datetime "last_used_at", null: false
    t.index ["chunk_ids"], name: "index_package_sets_on_chunk_ids", using: :gin
    t.index ["content_hash"], name: "index_package_sets_on_content_hash", unique: true
    t.check_constraint "cardinality(chunk_ids) = 64", name: "package_sets_chunk_ids_by_bucket"
  end

  create_table "package_snapshots", primary_key: ["id", "stored_at"], options: "PARTITION BY RANGE (stored_at)", force: :cascade do |t|
    t.bigserial "id", null: false
    t.bigint "host_id", null: false
    t.string "manager", limit: 16, null: false
    t.string "unsupported_reason", limit: 512
    t.integer "package_count", null: false
    t.string "content_hash", limit: 64, null: false
    t.jsonb "warnings", default: [], null: false
    t.uuid "report_id", null: false
    t.datetime "collected_at", null: false
    t.datetime "received_at", null: false
    t.jsonb "skipped", default: [], null: false
    t.datetime "stored_at", default: -> { "now()" }, null: false
    t.bigint "package_set_id"
    t.index ["host_id", "received_at"], name: "index_package_snapshots_on_host_id_and_received_at"
    t.index ["package_set_id"], name: "index_package_snapshots_on_package_set_id"
    t.index ["received_at"], name: "index_package_snapshots_on_received_at"
    t.check_constraint "manager::text = ANY (ARRAY['dpkg'::character varying, 'unsupported'::character varying, 'unreadable'::character varying]::text[])", name: "package_snapshots_manager_valid"
  end

  create_table "pending_refreshes", primary_key: "stream", id: { type: :string, limit: 128 }, force: :cascade do |t|
    t.datetime "requested_at", default: -> { "statement_timestamp()" }, null: false
  end

  create_table "report_requests", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.string "report_type", limit: 16, null: false
    t.string "state", limit: 16, default: "pending", null: false
    t.bigint "requested_by_id", null: false
    t.datetime "requested_at", null: false
    t.datetime "expires_at", null: false
    t.datetime "sent_at"
    t.datetime "delivered_agent_time"
    t.datetime "satisfied_at"
    t.uuid "satisfied_by_report_id"
    t.datetime "expired_at"
    t.index ["expires_at"], name: "index_report_requests_pending_expiry", where: "((state)::text = 'pending'::text)"
    t.index ["host_id", "report_type"], name: "index_report_requests_one_pending", unique: true, where: "((state)::text = 'pending'::text)"
    t.index ["host_id", "requested_at"], name: "index_report_requests_on_host_id_and_requested_at"
    t.index ["requested_at"], name: "index_report_requests_on_requested_at"
    t.check_constraint "(sent_at IS NULL) = (delivered_agent_time IS NULL)", name: "report_requests_delivery_complete"
    t.check_constraint "(state::text = 'expired'::text) = (expired_at IS NOT NULL)", name: "report_requests_expired_matches_state"
    t.check_constraint "(state::text = 'satisfied'::text) = (satisfied_at IS NOT NULL AND satisfied_by_report_id IS NOT NULL)", name: "report_requests_satisfied_matches_state"
    t.check_constraint "expires_at > requested_at", name: "report_requests_expire_after_request"
    t.check_constraint "report_type::text = ANY (ARRAY['config'::character varying, 'inventory'::character varying, 'packages'::character varying]::text[])", name: "report_requests_type_valid"
    t.check_constraint "state::text <> 'satisfied'::text OR sent_at IS NOT NULL", name: "report_requests_satisfied_after_delivery"
    t.check_constraint "state::text = ANY (ARRAY['pending'::character varying, 'satisfied'::character varying, 'expired'::character varying]::text[])", name: "report_requests_state_valid"
  end

  create_table "rollout_hosts", force: :cascade do |t|
    t.bigint "rollout_id", null: false
    t.bigint "host_id", null: false
    t.integer "stage", null: false
    t.string "state", limit: 16, default: "pending", null: false
    t.datetime "offer_at", null: false
    t.datetime "offered_at"
    t.datetime "resolved_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "from_version", limit: 64
    t.index ["host_id"], name: "index_rollout_hosts_on_host_id"
    t.index ["offered_at"], name: "index_rollout_hosts_updating", where: "((state)::text = 'updating'::text)"
    t.index ["rollout_id", "host_id"], name: "index_rollout_hosts_on_rollout_id_and_host_id", unique: true
    t.index ["rollout_id", "stage", "state"], name: "index_rollout_hosts_on_rollout_id_and_stage_and_state"
    t.check_constraint "state::text = ANY (ARRAY['pending'::character varying, 'updating'::character varying, 'confirmed'::character varying, 'failed'::character varying, 'rolled_back'::character varying, 'unconfirmed'::character varying]::text[])", name: "rollout_hosts_state_valid"
  end

  create_table "rollouts", force: :cascade do |t|
    t.bigint "agent_release_id", null: false
    t.string "state", limit: 16, default: "running", null: false
    t.integer "open_slot", default: 1
    t.bigint "canary_host_ids", default: [], null: false, array: true
    t.string "canary_tag", limit: 32
    t.integer "stage_percents", default: [25, 100], null: false, array: true
    t.integer "current_stage", default: 0, null: false
    t.datetime "stage_opened_at", null: false
    t.text "halt_reason"
    t.bigint "started_by_id", null: false
    t.bigint "halted_by_id"
    t.bigint "resumed_by_id"
    t.datetime "started_at", null: false
    t.datetime "halted_at"
    t.datetime "resumed_at"
    t.datetime "finished_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.integer "halted_seconds", default: 0, null: false
    t.index ["agent_release_id"], name: "index_rollouts_on_agent_release_id"
    t.index ["open_slot"], name: "index_rollouts_one_open", unique: true
    t.check_constraint "(open_slot IS NOT NULL) = (state::text = ANY (ARRAY['running'::character varying, 'halted'::character varying]::text[]))", name: "rollouts_open_slot_matches_state"
    t.check_constraint "cardinality(canary_host_ids) > 0 OR canary_tag IS NOT NULL", name: "rollouts_have_canaries"
    t.check_constraint "current_stage >= 0 AND current_stage <= cardinality(stage_percents)", name: "rollouts_stage_in_range"
    t.check_constraint "state::text = ANY (ARRAY['running'::character varying, 'halted'::character varying, 'completed'::character varying, 'cancelled'::character varying]::text[])", name: "rollouts_state_valid"
  end

  create_table "rule_import_previews", force: :cascade do |t|
    t.bigint "operator_id", null: false
    t.string "token", limit: 64, null: false
    t.string "filename", limit: 255, null: false
    t.text "body", null: false
    t.string "sha256", limit: 64, null: false
    t.boolean "disable_missing", default: false, null: false
    t.string "rules_digest", limit: 64, null: false
    t.datetime "expires_at", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["expires_at"], name: "index_rule_import_previews_on_expires_at"
    t.index ["operator_id"], name: "index_rule_import_previews_on_operator_id", unique: true
    t.index ["token"], name: "index_rule_import_previews_on_token", unique: true
    t.check_constraint "octet_length(body) <= 1048576", name: "rule_import_previews_body_size"
  end

  create_table "second_factor_recovery_codes", force: :cascade do |t|
    t.bigint "second_factor_id", null: false
    t.string "code_digest", limit: 64, null: false
    t.datetime "used_at"
    t.datetime "created_at", null: false
    t.index ["second_factor_id", "code_digest"], name: "index_second_factor_recovery_codes_on_digest", unique: true
  end

  create_table "second_factors", force: :cascade do |t|
    t.bigint "operator_id", null: false
    t.text "secret", null: false
    t.bigint "last_used_step"
    t.integer "failed_attempts", default: 0, null: false
    t.datetime "failures_started_at"
    t.datetime "locked_until"
    t.datetime "enrolled_at", null: false
    t.datetime "last_accepted_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["operator_id"], name: "index_second_factors_on_operator_id", unique: true
  end

  create_table "settings", force: :cascade do |t|
    t.string "key", limit: 100, null: false
    t.jsonb "value", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["key"], name: "index_settings_on_key", unique: true
  end

  create_table "signal_imports", force: :cascade do |t|
    t.string "signal", limit: 8, null: false
    t.string "origin", limit: 8, null: false
    t.string "source", limit: 256, null: false
    t.string "state", limit: 16, null: false
    t.jsonb "counts", default: {}, null: false
    t.jsonb "problems", default: [], null: false
    t.string "reason", limit: 512
    t.string "version", limit: 64
    t.date "score_date"
    t.string "etag", limit: 256
    t.string "last_modified", limit: 64
    t.bigint "operator_id"
    t.datetime "started_at", null: false
    t.datetime "finished_at", null: false
    t.index ["operator_id"], name: "index_signal_imports_on_operator_id"
    t.index ["signal", "finished_at"], name: "index_signal_imports_on_signal_and_finished_at"
    t.check_constraint "origin::text = ANY (ARRAY['feed'::character varying::text, 'file'::character varying::text, 'task'::character varying::text])", name: "signal_imports_origin_valid"
    t.check_constraint "signal::text = ANY (ARRAY['kev'::character varying::text, 'epss'::character varying::text])", name: "signal_imports_signal_valid"
    t.check_constraint "state::text = ANY (ARRAY['succeeded'::character varying::text, 'failed'::character varying::text, 'held_back'::character varying::text, 'cleared'::character varying::text])", name: "signal_imports_state_valid"
  end

  create_table "task_allowed_services", force: :cascade do |t|
    t.string "service", limit: 64, null: false
    t.string "tag", limit: 32
    t.bigint "added_by_id", null: false
    t.datetime "created_at", null: false
    t.index ["service", "tag"], name: "index_task_allowed_services_on_service_and_tag", unique: true, nulls_not_distinct: true
    t.check_constraint "service::text ~ '^[a-z0-9][a-z0-9_.-]{0,55}\\.service$'::text", name: "task_allowed_services_service_format"
    t.check_constraint "tag IS NULL OR tag::text ~ '^[a-z0-9][a-z0-9_-]{0,31}$'::text", name: "task_allowed_services_tag_format"
  end

  create_table "task_batches", force: :cascade do |t|
    t.bigint "operator_id", null: false
    t.string "task_type", limit: 64, null: false
    t.jsonb "parameters", default: {}, null: false
    t.string "selection_method", limit: 16, null: false
    t.string "selection_tag", limit: 32
    t.bigint "selected_host_ids", default: [], null: false, array: true
    t.jsonb "excluded_hosts", default: [], null: false
    t.integer "confirmed_host_count"
    t.integer "catalog_version", null: false
    t.string "catalog_digest", limit: 64, null: false
    t.datetime "created_at", null: false
    t.uuid "confirmation_token"
    t.index ["confirmation_token"], name: "index_task_batches_on_confirmation_token", unique: true
    t.index ["operator_id"], name: "index_task_batches_on_operator_id"
    t.check_constraint "(selection_method::text = 'tag'::text) = (selection_tag IS NOT NULL)", name: "task_batches_selection_tag"
    t.check_constraint "cardinality(selected_host_ids) >= 1 AND cardinality(selected_host_ids) <= 25", name: "task_batches_selection_size"
    t.check_constraint "jsonb_typeof(parameters) = 'object'::text", name: "task_batches_parameters_object"
    t.check_constraint "octet_length(parameters::text) <= 8192", name: "task_batches_parameters_size"
    t.check_constraint "selection_method::text = ANY (ARRAY['explicit'::character varying, 'tag'::character varying]::text[])", name: "task_batches_selection_method"
  end

  create_table "task_late_results", force: :cascade do |t|
    t.bigint "task_id", null: false
    t.uuid "report_id", null: false
    t.string "outcome", limit: 16, null: false
    t.string "reason", limit: 32
    t.integer "exit_status"
    t.datetime "agent_started_at"
    t.datetime "agent_finished_at", null: false
    t.jsonb "details"
    t.text "output"
    t.boolean "output_truncated", default: false, null: false
    t.string "digest", limit: 64, null: false
    t.datetime "received_at", null: false
    t.datetime "created_at", null: false
    t.index ["task_id"], name: "index_task_late_results_on_task_id", unique: true
    t.check_constraint "details IS NULL OR jsonb_typeof(details) = 'object'::text", name: "task_late_results_details_object"
    t.check_constraint "octet_length(details::text) <= 32768", name: "task_late_results_details_size"
    t.check_constraint "octet_length(output) <= 1048576", name: "task_late_results_output_size"
    t.check_constraint "outcome::text = ANY (ARRAY['succeeded'::character varying, 'failed'::character varying, 'timed_out'::character varying, 'cancelled'::character varying, 'refused'::character varying]::text[])", name: "task_late_results_outcome"
  end

  create_table "tasks", force: :cascade do |t|
    t.uuid "uuid", default: -> { "gen_random_uuid()" }, null: false
    t.bigint "task_batch_id", null: false
    t.bigint "host_id", null: false
    t.string "task_type", limit: 64, null: false
    t.jsonb "parameters", default: {}, null: false
    t.string "state", limit: 16, default: "queued", null: false
    t.string "reason", limit: 32
    t.integer "timeout_seconds", null: false
    t.datetime "expires_at", null: false
    t.datetime "lease_expires_at"
    t.datetime "claimed_at"
    t.datetime "started_at"
    t.datetime "finished_at"
    t.integer "exit_status"
    t.text "output"
    t.boolean "output_truncated", default: false, null: false
    t.datetime "cancel_requested_at"
    t.bigint "cancel_requested_by_id"
    t.datetime "agent_started_at"
    t.datetime "agent_finished_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.integer "progress_percent"
    t.datetime "progress_reported_at"
    t.uuid "result_report_id"
    t.string "result_digest", limit: 64
    t.datetime "result_received_at"
    t.jsonb "result_details"
    t.index ["expires_at"], name: "index_tasks_waiting_by_expiry", where: "((state)::text = ANY ((ARRAY['queued'::character varying, 'claimed'::character varying])::text[]))"
    t.index ["host_id", "state"], name: "index_tasks_on_host_id_and_state"
    t.index ["lease_expires_at"], name: "index_tasks_open_by_lease", where: "((state)::text = ANY ((ARRAY['claimed'::character varying, 'running'::character varying])::text[]))"
    t.index ["task_batch_id"], name: "index_tasks_on_task_batch_id"
    t.index ["uuid"], name: "index_tasks_on_uuid", unique: true
    t.check_constraint "(result_digest IS NULL) = (result_received_at IS NULL)", name: "tasks_result_received"
    t.check_constraint "(state::text = ANY (ARRAY['failed'::character varying, 'refused'::character varying]::text[])) = (reason IS NOT NULL)", name: "tasks_reason_for_failed_and_refused"
    t.check_constraint "jsonb_typeof(parameters) = 'object'::text", name: "tasks_parameters_object"
    t.check_constraint "octet_length(output) <= 1048576", name: "tasks_output_size"
    t.check_constraint "octet_length(parameters::text) <= 8192", name: "tasks_parameters_size"
    t.check_constraint "octet_length(result_details::text) <= 32768", name: "tasks_result_details_size"
    t.check_constraint "progress_percent >= 0 AND progress_percent <= 100", name: "tasks_progress_percent"
    t.check_constraint "result_details IS NULL OR jsonb_typeof(result_details) = 'object'::text", name: "tasks_result_details_object"
    t.check_constraint "state::text = ANY (ARRAY['queued'::character varying, 'claimed'::character varying, 'running'::character varying, 'succeeded'::character varying, 'failed'::character varying, 'timed_out'::character varying, 'cancelled'::character varying, 'refused'::character varying, 'expired'::character varying]::text[])", name: "tasks_state"
    t.check_constraint "timeout_seconds >= 1 AND timeout_seconds <= 86400", name: "tasks_timeout"
  end

  create_table "triage_checkpoints", primary_key: "name", id: { type: :string, limit: 64 }, force: :cascade do |t|
    t.datetime "at", null: false
  end

  create_table "triage_entries", force: :cascade do |t|
    t.string "tracker", limit: 16, null: false
    t.string "release", limit: 32, null: false
    t.string "package", limit: 128, null: false
    t.string "cve_id", limit: 32, null: false
    t.string "status", limit: 16, null: false
    t.string "urgency", limit: 16
    t.string "urgency_raw", limit: 64
    t.string "fixed_version", limit: 256
    t.boolean "no_dsa", default: false, null: false
    t.string "no_dsa_note", limit: 512
    t.string "no_dsa_reason", limit: 32
    t.boolean "next_point_update", default: false, null: false
    t.string "scope", limit: 8
    t.index ["tracker", "release", "package", "cve_id"], name: "index_triage_entries_unique", unique: true
    t.check_constraint "no_dsa OR no_dsa_note IS NULL AND no_dsa_reason IS NULL", name: "triage_entries_no_dsa_consistent"
    t.check_constraint "status::text = ANY (ARRAY['open'::character varying, 'resolved'::character varying, 'undetermined'::character varying]::text[])", name: "triage_entries_status_valid"
    t.check_constraint "urgency::text = ANY (ARRAY['unimportant'::character varying, 'low'::character varying, 'medium'::character varying, 'high'::character varying, 'end-of-life'::character varying]::text[])", name: "triage_entries_urgency_valid"
  end

  create_table "triage_imports", force: :cascade do |t|
    t.string "tracker", limit: 16, null: false
    t.string "origin", limit: 8, null: false
    t.string "source", limit: 256, null: false
    t.string "state", limit: 16, null: false
    t.string "releases", default: [], null: false, array: true
    t.string "removed_releases", default: [], null: false, array: true
    t.jsonb "counts", default: {}, null: false
    t.jsonb "problems", default: [], null: false
    t.string "reason", limit: 512
    t.string "etag", limit: 256
    t.string "last_modified", limit: 64
    t.bigint "operator_id"
    t.datetime "started_at", null: false
    t.datetime "finished_at", null: false
    t.index ["operator_id"], name: "index_triage_imports_on_operator_id"
    t.index ["tracker", "finished_at"], name: "index_triage_imports_on_tracker_and_finished_at"
    t.check_constraint "origin::text = ANY (ARRAY['feed'::character varying, 'file'::character varying]::text[])", name: "triage_imports_origin_valid"
    t.check_constraint "state::text = ANY (ARRAY['succeeded'::character varying, 'failed'::character varying, 'held_back'::character varying]::text[])", name: "triage_imports_state_valid"
  end

  create_table "triage_run_chunks", primary_key: ["evaluation_run_id", "package_chunk_id"], force: :cascade do |t|
    t.bigint "evaluation_run_id", null: false
    t.bigint "package_chunk_id", null: false
  end

  create_table "triage_run_sets", primary_key: ["evaluation_run_id", "package_set_id"], force: :cascade do |t|
    t.bigint "evaluation_run_id", null: false
    t.bigint "package_set_id", null: false
  end

  create_table "triage_signal_changes", force: :cascade do |t|
    t.string "kind", limit: 8, null: false
    t.string "cve_id", limit: 32
    t.bigint "advisory_id"
    t.datetime "created_at", null: false
    t.index ["kind", "advisory_id"], name: "index_triage_signal_changes_advisory", unique: true, where: "(advisory_id IS NOT NULL)"
    t.index ["kind", "cve_id"], name: "index_triage_signal_changes_cve", unique: true, where: "(cve_id IS NOT NULL)"
    t.index ["kind"], name: "index_triage_signal_changes_all", unique: true, where: "((kind)::text = 'kev_all'::text)"
    t.check_constraint "(kind::text = ANY (ARRAY['kev'::character varying, 'epss'::character varying, 'tracker'::character varying]::text[])) = (cve_id IS NOT NULL) AND (kind::text = 'advisory'::text) = (advisory_id IS NOT NULL)", name: "triage_signal_changes_target_valid"
    t.check_constraint "kind::text = ANY (ARRAY['kev'::character varying, 'kev_all'::character varying, 'epss'::character varying, 'advisory'::character varying, 'tracker'::character varying]::text[])", name: "triage_signal_changes_kind_valid"
  end

  create_table "vulnerability_findings", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.bigint "advisory_id", null: false
    t.string "package", limit: 128, null: false
    t.string "architecture", limit: 32, null: false
    t.string "state", limit: 16, null: false
    t.string "resolution", limit: 16
    t.datetime "first_seen_at", null: false
    t.datetime "resolved_at"
    t.datetime "reopened_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "last_source", limit: 128
    t.string "last_installed_version", limit: 256
    t.string "last_fixed_version", limit: 256
    t.string "last_ecosystem", limit: 64
    t.integer "bucket", limit: 2
    t.integer "bucket_rule", limit: 2
    t.boolean "kev"
    t.integer "listener", limit: 2
    t.index ["advisory_id"], name: "index_vulnerability_findings_on_advisory_id"
    t.index ["host_id", "advisory_id", "package", "architecture"], name: "index_vulnerability_findings_unique", unique: true
    t.index ["state", "host_id"], name: "index_vulnerability_findings_on_state_and_host_id"
    t.check_constraint "listener IS NULL OR (listener = ANY (ARRAY[1, 2])) AND bucket IS NOT NULL", name: "vulnerability_findings_listener_valid"
    t.check_constraint "(state::text = 'resolved'::text) = (resolution IS NOT NULL) AND (resolution::text = ANY (ARRAY['fixed'::character varying, 'removed'::character varying, 'withdrawn'::character varying, 'not_affected'::character varying]::text[]))", name: "vulnerability_findings_resolution_valid"
    t.check_constraint "state::text = ANY (ARRAY['open'::character varying, 'resolved'::character varying, 'reopened'::character varying]::text[])", name: "vulnerability_findings_state_valid"
  end
  add_check_constraint "vulnerability_findings", "(bucket_rule IS NULL) = (bucket IS NULL) AND (bucket_rule IS NULL) = (kev IS NULL) AND (bucket_rule IS NULL OR state::text <> 'resolved'::text AND bucket =\nCASE\n    WHEN bucket_rule = ANY (ARRAY[3, 4, 5, 6]) THEN 1\n    WHEN bucket_rule = ANY (ARRAY[10, 11, 13, 14, 15]) THEN 2\n    WHEN bucket_rule = ANY (ARRAY[9, 16, 17, 18, 19]) THEN 3\n    WHEN bucket_rule = ANY (ARRAY[1, 2, 7, 8, 12]) THEN 4\n    ELSE NULL::integer\nEND)", name: "vulnerability_findings_bucket_valid"

  create_table "vulnerability_work_events", primary_key: ["id", "occurred_at"], options: "PARTITION BY RANGE (occurred_at)", force: :cascade do |t|
    t.bigserial "id", null: false
    t.bigint "host_id", null: false
    t.string "kind", limit: 16, null: false
    t.string "subject", limit: 256, null: false
    t.integer "findings_cleared", null: false
    t.datetime "occurred_at", null: false
    t.index ["host_id", "occurred_at"], name: "index_vulnerability_work_events_on_host_id_and_occurred_at"
    t.index ["occurred_at"], name: "index_vulnerability_work_events_on_occurred_at"
    t.check_constraint "findings_cleared > 0", name: "vulnerability_work_events_cleared_positive"
    t.check_constraint "kind::text = ANY (ARRAY['upgrade'::character varying, 'kernel_installed'::character varying, 'reboot'::character varying]::text[])", name: "vulnerability_work_events_kind_valid"
  end

  add_foreign_key "advisory_imports", "operators"
  add_foreign_key "advisory_packages", "advisories", on_delete: :cascade
  add_foreign_key "advisory_refresh_attempts", "operators"
  add_foreign_key "advisory_uploads", "advisory_imports", on_delete: :cascade
  add_foreign_key "advisory_uploads", "operators"
  add_foreign_key "agent_credentials", "hosts"
  add_foreign_key "agent_release_imports", "agent_releases"
  add_foreign_key "agent_release_imports", "operators"
  add_foreign_key "agent_releases", "operators", column: "imported_by_id"
  add_foreign_key "agent_updates", "hosts"
  add_foreign_key "agent_updates", "rollouts"
  add_foreign_key "cis_results", "cis_rule_versions"
  add_foreign_key "cis_results", "cis_rules"
  add_foreign_key "cis_results", "hosts"
  add_foreign_key "cis_rule_versions", "cis_rules"
  add_foreign_key "cis_rules", "cis_rule_versions", column: "current_version_id"
  add_foreign_key "enrollment_tokens", "hosts"
  add_foreign_key "evaluation_batches", "evaluation_runs", on_delete: :cascade
  add_foreign_key "evaluation_runs", "evaluation_runs", column: "superseded_by_id", on_delete: :nullify
  add_foreign_key "finding_decisions", "advisories"
  add_foreign_key "finding_decisions", "hosts"
  add_foreign_key "finding_decisions", "operators", column: "created_by_id"
  add_foreign_key "finding_decisions", "operators", column: "ended_by_id"
  add_foreign_key "host_applicability", "hosts"
  add_foreign_key "host_compliance_summaries", "hosts"
  add_foreign_key "host_configs", "hosts"
  add_foreign_key "host_inventories", "hosts"
  add_foreign_key "host_liveness", "hosts"
  add_foreign_key "host_package_sets", "hosts"
  add_foreign_key "host_vulnerability_evaluations", "hosts"
  add_foreign_key "rule_import_previews", "operators", on_delete: :cascade
  add_foreign_key "signal_imports", "operators"
  add_foreign_key "task_allowed_services", "operators", column: "added_by_id"
  add_foreign_key "task_batches", "operators"
  add_foreign_key "task_late_results", "tasks"
  add_foreign_key "tasks", "hosts"
  add_foreign_key "tasks", "operators", column: "cancel_requested_by_id"
  add_foreign_key "tasks", "task_batches"
  add_foreign_key "triage_imports", "operators"
  add_foreign_key "triage_run_chunks", "evaluation_runs", on_delete: :cascade
  add_foreign_key "triage_run_sets", "evaluation_runs", on_delete: :cascade
  add_foreign_key "vulnerability_findings", "advisories"
  add_foreign_key "vulnerability_findings", "hosts"
  add_foreign_key "onboarding_requests", "hosts"
  add_foreign_key "onboarding_requests", "operators", column: "decided_by_id"
  add_foreign_key "operator_sessions", "operators"
  add_foreign_key "report_requests", "hosts"
  add_foreign_key "report_requests", "operators", column: "requested_by_id"
  add_foreign_key "rollout_hosts", "hosts"
  add_foreign_key "rollout_hosts", "rollouts"
  add_foreign_key "rollouts", "agent_releases", on_delete: :restrict
  add_foreign_key "rollouts", "operators", column: "halted_by_id"
  add_foreign_key "rollouts", "operators", column: "resumed_by_id"
  add_foreign_key "rollouts", "operators", column: "started_by_id"
  add_foreign_key "second_factor_recovery_codes", "second_factors", on_delete: :cascade
  add_foreign_key "second_factors", "operators"

  create_function :hosts_guard, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.hosts_guard()
       RETURNS trigger
       LANGUAGE plpgsql
      AS $function$
      BEGIN
        -- Hosts are retired, never deleted (P1-S02).
        IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
          RAISE EXCEPTION 'hosts are retired, never deleted: % is not allowed', TG_OP
            USING ERRCODE = 'insufficient_privilege';
        END IF;

        -- New hosts start pending (FR-1.1).
        IF TG_OP = 'INSERT' THEN
          IF NEW.enrollment_state <> 'pending' THEN
            RAISE EXCEPTION 'new hosts start pending, not %', NEW.enrollment_state
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END IF;

        -- Only the FR-1.1 transitions, whichever code path writes the column; retired is terminal.
        IF NEW.enrollment_state IS DISTINCT FROM OLD.enrollment_state
           AND (OLD.enrollment_state::text, NEW.enrollment_state::text) NOT IN (
             ('pending', 'active'),
             ('active', 'revoked'),
             ('revoked', 'pending'),
             ('active', 'pending'),
             ('pending', 'retired'),
             ('active', 'retired'),
             ('revoked', 'retired')
           ) THEN
          RAISE EXCEPTION 'invalid enrollment state transition: % -> %', OLD.enrollment_state, NEW.enrollment_state
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $function$
  SQL

  create_function :audit_entries_append_only, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.audit_entries_append_only()
       RETURNS trigger
       LANGUAGE plpgsql
      AS $function$
      BEGIN
        RAISE EXCEPTION 'audit_entries is append-only: % is not allowed', TG_OP
          USING ERRCODE = 'insufficient_privilege';
      END;
      $function$
  SQL

  create_function :agent_releases_guard, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.agent_releases_guard()
       RETURNS trigger
       LANGUAGE plpgsql
      AS $function$
      BEGIN
        IF TG_OP = 'TRUNCATE' THEN
          RAISE EXCEPTION 'agent releases are not truncated'
            USING ERRCODE = 'insufficient_privilege';
        END IF;

        -- A release is never deleted while a host in the fleet runs it (P1-RELEASES).
        IF TG_OP = 'DELETE' THEN
          IF EXISTS (SELECT 1 FROM hosts WHERE hosts.agent_version = OLD.version AND hosts.enrollment_state <> 'retired') THEN
            RAISE EXCEPTION 'agent release % is in use by a host and cannot be deleted', OLD.version
              USING ERRCODE = 'foreign_key_violation';
          END IF;
          RETURN OLD;
        END IF;

        -- A published release is never replaced (docs/releases.md): what was verified is what is served.
        IF (NEW.version, NEW.target, NEW.sha256, NEW.size, NEW.manifest, NEW.signature)
           IS DISTINCT FROM (OLD.version, OLD.target, OLD.sha256, OLD.size, OLD.manifest, OLD.signature) THEN
          RAISE EXCEPTION 'agent releases are immutable'
            USING ERRCODE = 'insufficient_privilege';
        END IF;
        RETURN NEW;
      END;
      $function$
  SQL

  create_function :task_batches_guard, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.task_batches_guard()
       RETURNS trigger
       LANGUAGE plpgsql
      AS $function$
      BEGIN
        -- A batch records what an operator asked for and what it resolved to (P3-S02); it is never changed or deleted.
        RAISE EXCEPTION 'task batches are never changed or deleted: % is not allowed', TG_OP
          USING ERRCODE = 'insufficient_privilege';
      END;
      $function$
  SQL

  create_function :tasks_guard, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.tasks_guard()
       RETURNS trigger
       LANGUAGE plpgsql
      AS $function$
      BEGIN
        -- Tasks are kept as the record of what ran (P3-S02, P3-S07).
        IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
          RAISE EXCEPTION 'tasks are never deleted: % is not allowed', TG_OP
            USING ERRCODE = 'insufficient_privilege';
        END IF;

        -- A task starts queued, with no lease, claim, start, or result (P3-S02).
        IF TG_OP = 'INSERT' THEN
          IF NEW.state <> 'queued' OR NEW.claimed_at IS NOT NULL OR NEW.started_at IS NOT NULL OR NEW.finished_at IS NOT NULL
             OR NEW.lease_expires_at IS NOT NULL THEN
            RAISE EXCEPTION 'new tasks start queued, not %', NEW.state
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END IF;

        -- Terminal states are immutable: nothing about a finished task changes.
        IF OLD.state IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'refused', 'expired') THEN
          RAISE EXCEPTION 'task % is %, which is final; it cannot change', OLD.id, OLD.state
            USING ERRCODE = 'check_violation';
        END IF;

        -- What a task is never changes: no code path can retarget it or change its parameters after validation.
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.uuid IS DISTINCT FROM OLD.uuid
           OR NEW.task_batch_id IS DISTINCT FROM OLD.task_batch_id OR NEW.host_id IS DISTINCT FROM OLD.host_id
           OR NEW.task_type IS DISTINCT FROM OLD.task_type OR NEW.parameters IS DISTINCT FROM OLD.parameters
           OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR NEW.timeout_seconds IS DISTINCT FROM OLD.timeout_seconds
           OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
          RAISE EXCEPTION 'a task''s id, batch, host, type, parameters, expiry, and timeout never change'
            USING ERRCODE = 'check_violation';
        END IF;

        -- A cancel request (P3-S05) is recorded once, on a running task, and never changed or withdrawn afterwards.
        IF OLD.cancel_requested_at IS NOT NULL
           AND (NEW.cancel_requested_at IS DISTINCT FROM OLD.cancel_requested_at
                OR NEW.cancel_requested_by_id IS DISTINCT FROM OLD.cancel_requested_by_id) THEN
          RAISE EXCEPTION 'a task''s cancel request never changes once recorded'
            USING ERRCODE = 'check_violation';
        END IF;
        IF OLD.cancel_requested_at IS NULL AND NEW.cancel_requested_at IS NOT NULL
           AND (OLD.state <> 'running' OR NEW.cancel_requested_by_id IS NULL) THEN
          RAISE EXCEPTION 'a cancel request is recorded only on a running task, with the operator who made it'
            USING ERRCODE = 'check_violation';
        END IF;

        -- A queued task fails only as not_run: its agent closing a task it held and never ran (P3-S05).
        IF OLD.state = 'queued' AND NEW.state = 'failed' AND NEW.reason IS DISTINCT FROM 'not_run' THEN
          RAISE EXCEPTION 'a queued task fails only as not_run'
            USING ERRCODE = 'check_violation';
        END IF;

        -- Only the transitions in Task::TRANSITIONS.
        IF NEW.state IS DISTINCT FROM OLD.state
           AND (OLD.state::text, NEW.state::text) NOT IN (
             ('queued', 'claimed'),
             ('queued', 'cancelled'),
             ('queued', 'refused'),
             ('queued', 'expired'),
             ('queued', 'failed'),
             ('claimed', 'queued'),
             ('claimed', 'running'),
             ('claimed', 'failed'),
             ('claimed', 'cancelled'),
             ('claimed', 'refused'),
             ('running', 'succeeded'),
             ('running', 'failed'),
             ('running', 'timed_out'),
             ('running', 'cancelled'),
             ('running', 'refused')
           ) THEN
          RAISE EXCEPTION 'invalid task state transition: % -> %', OLD.state, NEW.state
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $function$
  SQL

  create_function :task_late_results_guard, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.task_late_results_guard()
       RETURNS trigger
       LANGUAGE plpgsql
      AS $function$
      BEGIN
        -- A late result is kept as the agent sent it, beside a task that had already ended (P3-S04): never changed or deleted.
        RAISE EXCEPTION 'late task results are never changed or deleted: % is not allowed', TG_OP
          USING ERRCODE = 'insufficient_privilege';
      END;
      $function$
  SQL

  create_function :host_compliance_status_rank, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.host_compliance_status_rank(enrollment_state text, liveness_status text)
       RETURNS smallint
       LANGUAGE sql
       IMMUTABLE
      AS $function$
        -- The fleet list's status order (FleetList::STATUSES): online, stale, offline, awaiting first contact, pending,
        -- revoked (#193).
        SELECT (CASE
          WHEN enrollment_state = 'active' AND liveness_status = 'online' THEN 0
          WHEN enrollment_state = 'active' AND liveness_status = 'stale' THEN 1
          WHEN enrollment_state = 'active' AND liveness_status = 'offline' THEN 2
          WHEN enrollment_state = 'active' THEN 3
          WHEN enrollment_state = 'pending' THEN 4
          ELSE 5
        END)::smallint;
      $function$
  SQL

  create_function :vulnerability_exposure_points, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.vulnerability_exposure_points(worst smallint, severity text, kev boolean, listener smallint)
       RETURNS integer
       LANGUAGE sql
       IMMUTABLE PARALLEL SAFE
      AS $function$
        -- The points of one open advisory on one host (VT-SCORES #262, the epic's VT-M3, owner decision 13), the published
        -- table, as VulnerabilityExposure::POINTS and LISTENER_POINTS say it in Ruby (a spec checks they agree):
        --
        --   worst bucket of the advisory's findings     critical  high  medium  low or unknown
        --   5 Needs attention                               40      20      8        2
        --   4 Fix available                                 20      10      4        1
        --   3 Low risk by a control (O1)                    10       5      2        1
        --   2 Low risk                                       2       1      0        0
        --   1 Ignorable                                      0       0      0        0
        --
        -- A known exploited (KEV) advisory scores double, except in Ignorable. A package a process holding a listening socket
        -- loads (rule N5's evidence, in whatever bucket its finding ends up, Ignorable aside; epic decision 27) adds, once per
        -- advisory, its listener's row on top (not doubled): 2 a listener on the network, 1 one on loopback only.
        --
        --   listener                                    critical  high  medium  low or unknown
        --   2 on the network                                10       5      2        1
        --   1 loopback only                                  4       2      1        0
        SELECT CASE WHEN worst IS NULL OR worst <= 1 THEN 0 ELSE
                 (CASE worst
                    WHEN 5 THEN CASE severity WHEN 'critical' THEN 40 WHEN 'high' THEN 20 WHEN 'medium' THEN 8 ELSE 2 END
                    WHEN 4 THEN CASE severity WHEN 'critical' THEN 20 WHEN 'high' THEN 10 WHEN 'medium' THEN 4 ELSE 1 END
                    WHEN 3 THEN CASE severity WHEN 'critical' THEN 10 WHEN 'high' THEN 5 WHEN 'medium' THEN 2 ELSE 1 END
                    ELSE CASE severity WHEN 'critical' THEN 2 WHEN 'high' THEN 1 ELSE 0 END
                  END) * (CASE WHEN kev THEN 2 ELSE 1 END)
                 + CASE listener
                     WHEN 2 THEN CASE severity WHEN 'critical' THEN 10 WHEN 'high' THEN 5 WHEN 'medium' THEN 2 ELSE 1 END
                     WHEN 1 THEN CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END
                     ELSE 0
                   END
               END;
      $function$
  SQL

  create_function :host_compliance_counts, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.host_compliance_counts(host_ids bigint[])
       RETURNS TABLE(host_id bigint, cis_passed integer, cis_failed integer, cis_not_readable integer, cis_critical integer, cis_high integer, cis_medium integer, cis_low integer, vuln_critical integer, vuln_high integer, vuln_medium integer, vuln_low integer, vuln_unknown integer, vuln_evaluated boolean, vuln_fix integer, vuln_attention integer, vuln_low_risk integer, vuln_ignorable integer, vuln_kev_open integer, exposure_tier smallint, exposure_points integer, vuln_kev_advisories integer, vuln_fix_critical integer, vuln_attention_undecided integer, work_upgrades integer, work_kernel_install boolean, work_reboot boolean, work_items integer)
       LANGUAGE sql
       STABLE
      AS $function$
        -- A host's compliance counts, computed from the rows the host pages show (P2-D05, #193): CIS results with the
        -- severity of the rule version that produced them (the current version when a result names none), open and
        -- reopened findings with their advisory's severity, and whether its last matching run evaluated it.
        --
        -- v02 (VT-FIXABLE, #256): of the open and reopened findings, how many have a fix (the finding's stored flag), how
        -- many distinct binary packages and architectures they are on, and which severities have one (a bit per severity,
        -- critical 1, high 2, medium 4, low 8, unknown 16, for the Compliance page's "of this severity, with a fix"). A
        -- host its last matching run did not evaluate counts none of them (#252 question 6), though its kept findings are
        -- still open.
        --
        -- v03 (VT-BUCKETS, #259): the open and reopened findings per triage bucket (1 Fix available, 2 Needs attention,
        -- 3 Low risk, 4 Ignorable), and those with the KEV flag. Counted for every host, evaluated or not, so the four
        -- always add up to the open count: a host that is not evaluated keeps its findings and their buckets as they were.
        --
        -- v04 (VT-SCORES, #262; the epic's VT-M3 and VT-M4): v02's fix counts are gone (the buckets replace them on every
        -- page, #281 item 1; the findings keep their fix flag), and the host's exposure and work are counted, scored only when its last matching
        -- run evaluated it and every open finding has a bucket (else NULL: never a 0 or a lower tier that stands for data
        -- not there yet). Each open advisory counts once, in the worst bucket of its findings (Needs attention, Fix
        -- available, Low risk by a control, Low risk, Ignorable), with the stored KEV flag of any of them and the widest
        -- listener among them outside Ignorable (vulnerability_findings.listener: 2 network, 1 loopback):
        -- - exposure_points: vulnerability_exposure_points over those advisories;
        -- - exposure_tier: 4 Known exploited (a KEV advisory in Needs attention, Fix available, or under a control), else 3
        --   Exposed, no fix (a critical or high in Needs attention), else 2 Fixes waiting (a critical or high in Fix
        --   available), else 1 Low (any points), else 0 Minimal;
        -- - vuln_kev_advisories: KEV advisories outside Ignorable; vuln_fix_critical: critical advisories with a finding in
        --   Fix available (the run badge's "fixable critical"); vuln_attention_undecided: advisories with a finding in Needs
        --   attention and no decision in force (#298: an accepted risk or a control whose ended_at is NULL), as the host
        --   tab's decisions due count them, less the decisions ending soon, lapsed, or suspended, which depend on the date
        --   and stay a read-time part (HostDecisions);
        -- - work: one upgrade per source package with F1 or F2 findings, the new kernel package to install (K2), and a reboot
        --   (K1, or the agent's reboot flag, host_applicability.reboot_required); work_items is their sum.
        -- The KEV, EPSS, and tracker sources' freshness is not here: it is a read-time qualifier, so a feed going stale
        -- rewrites no summary and never lowers a score.
        SELECT h.id,
               cis.passed, cis.failed, cis.not_readable, cis.critical, cis.high, cis.medium, cis.low,
               vulns.critical, vulns.high, vulns.medium, vulns.low, vulns.unknown,
               COALESCE(hve.state = 'evaluated', false),
               vulns.bucket_fix, vulns.bucket_attention, vulns.bucket_low_risk, vulns.bucket_ignorable, vulns.kev_open,
               CASE WHEN scored.yes THEN
                 (CASE WHEN vulns.known_exploited THEN 4 WHEN vulns.exposed THEN 3 WHEN vulns.fixes_waiting THEN 2 WHEN vulns.points > 0 THEN 1 ELSE 0 END)::smallint
               END,
               CASE WHEN scored.yes THEN vulns.points END,
               vulns.kev_advisories, vulns.fix_critical, vulns.undecided,
               CASE WHEN scored.yes THEN vulns.upgrades END,
               scored.yes AND vulns.kernel_install,
               scored.yes AND (vulns.reboot OR COALESCE(ha.reboot_required, false)),
               CASE WHEN scored.yes THEN vulns.upgrades + vulns.kernel_install::integer + (vulns.reboot OR COALESCE(ha.reboot_required, false))::integer END
          FROM (SELECT DISTINCT unnest(host_ids) AS id) h
          LEFT JOIN LATERAL (
            SELECT count(*) FILTER (WHERE r.result = 'pass')::integer AS passed,
                   count(*) FILTER (WHERE r.result = 'fail')::integer AS failed,
                   count(*) FILTER (WHERE r.result = 'not_readable')::integer AS not_readable,
                   count(*) FILTER (WHERE r.result = 'fail' AND COALESCE(rv.severity, cv.severity) = 'critical')::integer AS critical,
                   count(*) FILTER (WHERE r.result = 'fail' AND COALESCE(rv.severity, cv.severity) = 'high')::integer AS high,
                   count(*) FILTER (WHERE r.result = 'fail' AND COALESCE(rv.severity, cv.severity) = 'medium')::integer AS medium,
                   count(*) FILTER (WHERE r.result = 'fail' AND COALESCE(rv.severity, cv.severity) = 'low')::integer AS low
              FROM cis_results r
              JOIN cis_rules ru ON ru.id = r.cis_rule_id
              LEFT JOIN cis_rule_versions rv ON rv.id = r.cis_rule_version_id
              LEFT JOIN cis_rule_versions cv ON cv.id = ru.current_version_id
             WHERE r.host_id = h.id
          ) cis ON true
          -- The host's open findings are read once (one index scan and one join to advisories), grouped two ways in that one
          -- pass (v04): by advisory, for the severity and bucket counts and the exposure, and by source package, for the
          -- upgrades. Each finding is in exactly one group of each set.
          LEFT JOIN LATERAL (
            SELECT COALESCE(sum(g.n) FILTER (WHERE g.set = 0 AND g.severity = 'critical'), 0)::integer AS critical,
                   COALESCE(sum(g.n) FILTER (WHERE g.set = 0 AND g.severity = 'high'), 0)::integer AS high,
                   COALESCE(sum(g.n) FILTER (WHERE g.set = 0 AND g.severity = 'medium'), 0)::integer AS medium,
                   COALESCE(sum(g.n) FILTER (WHERE g.set = 0 AND g.severity = 'low'), 0)::integer AS low,
                   COALESCE(sum(g.n) FILTER (WHERE g.set = 0 AND g.severity = 'unknown'), 0)::integer AS unknown,
                   COALESCE(sum(g.in_fix) FILTER (WHERE g.set = 0), 0)::integer AS bucket_fix,
                   COALESCE(sum(g.in_attention) FILTER (WHERE g.set = 0), 0)::integer AS bucket_attention,
                   COALESCE(sum(g.in_low_risk) FILTER (WHERE g.set = 0), 0)::integer AS bucket_low_risk,
                   COALESCE(sum(g.in_ignorable) FILTER (WHERE g.set = 0), 0)::integer AS bucket_ignorable,
                   COALESCE(sum(g.kev_findings) FILTER (WHERE g.set = 0), 0)::integer AS kev_open,
                   COALESCE(sum(g.untriaged) FILTER (WHERE g.set = 0), 0)::integer AS untriaged,
                   count(*) FILTER (WHERE g.set = 1 AND g.upgrade)::integer AS upgrades,
                   COALESCE(bool_or(g.kernel_install) FILTER (WHERE g.set = 0), false) AS kernel_install,
                   COALESCE(bool_or(g.reboot) FILTER (WHERE g.set = 0), false) AS reboot,
                   COALESCE(sum(vulnerability_exposure_points(g.worst, g.severity, g.kev, g.listener)) FILTER (WHERE g.set = 0), 0)::integer AS points,
                   COALESCE(bool_or(g.kev AND g.worst >= 3) FILTER (WHERE g.set = 0), false) AS known_exploited,
                   COALESCE(bool_or(g.severity IN ('critical', 'high') AND g.worst = 5) FILTER (WHERE g.set = 0), false) AS exposed,
                   COALESCE(bool_or(g.severity IN ('critical', 'high') AND g.worst = 4) FILTER (WHERE g.set = 0), false) AS fixes_waiting,
                   count(*) FILTER (WHERE g.set = 0 AND g.kev AND g.worst >= 2)::integer AS kev_advisories,
                   count(*) FILTER (WHERE g.set = 0 AND g.severity = 'critical' AND g.in_fix > 0)::integer AS fix_critical,
                   count(*) FILTER (WHERE g.set = 0 AND g.in_attention > 0 AND NOT (g.advisory_id = ANY (dec.ids)))::integer AS undecided
              FROM (
                -- Set 0, one row per open advisory, in the worst bucket of its triaged findings (5 Needs attention, 4 Fix
                -- available, 3 Low risk by a control (rule O1, 9), 2 Low risk, 1 Ignorable), with the KEV flag of any of them
                -- and the widest listener outside Ignorable; set 1, one per source package.
                SELECT CASE WHEN GROUPING(f.advisory_id) = 0 THEN 0 ELSE 1 END AS set,
                       f.advisory_id,
                       a.severity::text AS severity,
                       count(*) AS n,
                       count(*) FILTER (WHERE f.bucket = 1) AS in_fix,
                       count(*) FILTER (WHERE f.bucket = 2) AS in_attention,
                       count(*) FILTER (WHERE f.bucket = 3) AS in_low_risk,
                       count(*) FILTER (WHERE f.bucket = 4) AS in_ignorable,
                       count(*) FILTER (WHERE f.kev) AS kev_findings,
                       count(*) FILTER (WHERE f.bucket IS NULL) AS untriaged,
                       -- rules F1 and F2 (5, 6) are package upgrades, K2 (4) a new kernel package, K1 (3) a reboot
                       bool_or(f.bucket_rule IN (5, 6)) AS upgrade,
                       bool_or(f.bucket_rule = 4) AS kernel_install,
                       bool_or(f.bucket_rule = 3) AS reboot,
                       max(CASE WHEN f.bucket = 2 THEN 5 WHEN f.bucket = 1 THEN 4 WHEN f.bucket_rule = 9 THEN 3 WHEN f.bucket = 3 THEN 2 WHEN f.bucket = 4 THEN 1 END)::smallint AS worst,
                       COALESCE(bool_or(f.kev), false) AS kev,
                       max(f.listener) FILTER (WHERE f.bucket <> 4) AS listener
                  FROM vulnerability_findings f
                  JOIN advisories a ON a.id = f.advisory_id
                 WHERE f.host_id = h.id AND f.state IN ('open', 'reopened')
                 GROUP BY GROUPING SETS ((f.advisory_id, a.severity), (COALESCE(f.last_source, f.package)))
              ) g
              -- The advisories with a decision in force on the host (VT-OVERRIDES #261: an accepted risk keeps its finding in
              -- Needs attention, a control moves it to Low risk), read as ended_at IS NULL, one probe of the active index.
              CROSS JOIN (SELECT COALESCE(array_agg(d.advisory_id), '{}'::bigint[]) AS ids
                            FROM finding_decisions d WHERE d.host_id = h.id AND d.ended_at IS NULL) dec
          ) vulns ON true
          LEFT JOIN host_vulnerability_evaluations hve ON hve.host_id = h.id
          LEFT JOIN host_applicability ha ON ha.host_id = h.id
          CROSS JOIN LATERAL (SELECT COALESCE(hve.state = 'evaluated', false) AND vulns.untriaged = 0 AS yes) scored;
      $function$
  SQL

  create_function :host_compliance_summaries_refresh, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.host_compliance_summaries_refresh(host_ids bigint[])
       RETURNS void
       LANGUAGE plpgsql
      AS $function$
      DECLARE
        grace interval;
      BEGIN
        -- Recomputes the hosts' compliance counts (#193). Called from host_compliance_summaries_flush at commit, which has
        -- already locked these rows in one sorted statement, and by the rebuild and the recount queue. v02 (VT-FIXABLE,
        -- #256): also the open findings with a fix, their packages, and their severities. v03 (VT-BUCKETS, #259): also the
        -- open findings per triage bucket and those with the KEV flag. v04 (VT-SCORES, #262): not v02's fix counts, whose
        -- columns are dropped, but the exposure tier and points, the work items, and the run's two times:
        -- - fixable_critical_since: when the host last went from no critical advisory in Fix available to one (NULL while
        --   it has none);
        -- - no_fixable_critical_since: when its current run began, kept while a fixable critical is open. When the last one
        --   goes, the run carries on if it was open for less than the grace, and starts again now otherwise (a run's badge
        --   is read from these with the same grace: VulnerabilityExposure::Run). A host that is not scored (not evaluated
        --   now, or not every open finding triaged) has neither: its run ends, and a new one starts when it is scored again,
        --   so a run never counts days the server could not see (S4 of the review of #305). A gap in package reports ends a
        --   run too (host_compliance_summaries_flush v03).
        IF host_ids IS NULL OR cardinality(host_ids) = 0 THEN
          RETURN;
        END IF;

        -- The run's grace for a new fixable critical (owner decision 7; the vulnerabilities.run_grace_days setting), read only
        -- when there is something to recount. A value that is not a whole number of days (Setting writes only those) reads as
        -- the default rather than failing every flush.
        grace := COALESCE((SELECT CASE WHEN jsonb_typeof(st.value) = 'number' AND st.value::text ~ '^[0-9]{1,4}$' THEN (st.value::text)::integer END
                             FROM settings st WHERE st.key = 'vulnerabilities.run_grace_days'), 7) * interval '1 day';

        -- Lock first, in host order, then count in a later statement: under READ COMMITTED that statement takes a new
        -- snapshot, so a transaction that waited here for another one counts what that one committed. Two transactions
        -- changing one host's rows at once therefore leave the counts of both, whichever commits first.
        PERFORM 1 FROM host_compliance_summaries s WHERE s.host_id = ANY (host_ids) ORDER BY s.host_id FOR UPDATE;

        UPDATE host_compliance_summaries s
           SET cis_passed = c.cis_passed, cis_failed = c.cis_failed, cis_not_readable = c.cis_not_readable,
               cis_critical = c.cis_critical, cis_high = c.cis_high, cis_medium = c.cis_medium, cis_low = c.cis_low,
               vuln_critical = c.vuln_critical, vuln_high = c.vuln_high, vuln_medium = c.vuln_medium, vuln_low = c.vuln_low,
               vuln_unknown = c.vuln_unknown, vuln_evaluated = c.vuln_evaluated,
               vuln_fix = c.vuln_fix, vuln_attention = c.vuln_attention, vuln_low_risk = c.vuln_low_risk, vuln_ignorable = c.vuln_ignorable,
               vuln_kev_open = c.vuln_kev_open,
               exposure_tier = c.exposure_tier, exposure_points = c.exposure_points, vuln_kev_advisories = c.vuln_kev_advisories,
               vuln_fix_critical = c.vuln_fix_critical, vuln_attention_undecided = c.vuln_attention_undecided,
               work_upgrades = c.work_upgrades, work_kernel_install = c.work_kernel_install, work_reboot = c.work_reboot, work_items = c.work_items,
               fixable_critical_since = r.fixable_since, no_fixable_critical_since = r.run_since
          FROM host_compliance_counts(host_ids) c
          JOIN host_compliance_summaries o ON o.host_id = c.host_id
          CROSS JOIN LATERAL (
            SELECT CASE WHEN c.exposure_tier IS NULL THEN NULL
                        WHEN c.vuln_fix_critical > 0 THEN COALESCE(o.fixable_critical_since, now())
                   END AS fixable_since,
                   CASE WHEN c.exposure_tier IS NULL THEN NULL
                        WHEN c.vuln_fix_critical > 0 THEN o.no_fixable_critical_since
                        WHEN o.fixable_critical_since IS NULL THEN COALESCE(o.no_fixable_critical_since, now())
                        WHEN o.no_fixable_critical_since <= o.fixable_critical_since AND now() - o.fixable_critical_since < grace THEN o.no_fixable_critical_since
                        ELSE now()
                   END AS run_since
          ) r
         WHERE s.host_id = c.host_id
           AND (s.cis_passed, s.cis_failed, s.cis_not_readable, s.cis_critical, s.cis_high, s.cis_medium, s.cis_low,
                s.vuln_critical, s.vuln_high, s.vuln_medium, s.vuln_low, s.vuln_unknown, s.vuln_evaluated,
                s.vuln_fix, s.vuln_attention, s.vuln_low_risk, s.vuln_ignorable, s.vuln_kev_open,
                s.exposure_tier, s.exposure_points, s.vuln_kev_advisories, s.vuln_fix_critical, s.vuln_attention_undecided,
                s.work_upgrades, s.work_kernel_install, s.work_reboot, s.work_items, s.fixable_critical_since, s.no_fixable_critical_since)
               IS DISTINCT FROM
               (c.cis_passed, c.cis_failed, c.cis_not_readable, c.cis_critical, c.cis_high, c.cis_medium, c.cis_low,
                c.vuln_critical, c.vuln_high, c.vuln_medium, c.vuln_low, c.vuln_unknown, c.vuln_evaluated,
                c.vuln_fix, c.vuln_attention, c.vuln_low_risk, c.vuln_ignorable, c.vuln_kev_open,
                c.exposure_tier, c.exposure_points, c.vuln_kev_advisories, c.vuln_fix_critical, c.vuln_attention_undecided,
                c.work_upgrades, c.work_kernel_install, c.work_reboot, c.work_items, r.fixable_since, r.run_since);
      END;
      $function$
  SQL

  create_function :host_compliance_summaries_sync, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.host_compliance_summaries_sync(host_ids bigint[])
       RETURNS void
       LANGUAGE plpgsql
      AS $function$
      BEGIN
        -- Copies the host's own fields the fleet list sorts and filters by, and its operating system name, into its
        -- summary row (#193), creating the row for a new host, so every sort has one index with the name tie-break.
        IF host_ids IS NULL OR cardinality(host_ids) = 0 THEN
          RETURN;
        END IF;

        -- Lock first, then read the hosts in a later statement (a new snapshot under READ COMMITTED), as the refresh does.
        -- Called from host_compliance_summaries_flush, which has already locked these rows in one sorted statement.
        PERFORM 1 FROM host_compliance_summaries s WHERE s.host_id = ANY (host_ids) ORDER BY s.host_id FOR UPDATE;

        INSERT INTO host_compliance_summaries AS s (host_id, enrollment_state, status_rank, name_key, hostname, tags_key, agent_key, os_name)
        SELECT h.id, h.enrollment_state,
               host_compliance_status_rank(h.enrollment_state, l.liveness_status),
               lower(h.name), h.hostname,
               -- By the tag list as displayed (in entry order); no tags is NULL, so it sorts last.
               NULLIF(array_to_string(h.tags, ','), ''),
               -- Numeric by release (0.10.0 after 0.9.0); pre-release and build suffixes are ignored. numeric, not int:
               -- SemVer components are unbounded (review of #53). Anything but dotted numbers sorts last, never fails.
               CASE WHEN h.agent_version ~ '^[0-9]+(\.[0-9]+)*([-+].*)?$'
                    THEN string_to_array(regexp_replace(h.agent_version, '[-+].*$', ''), '.')::numeric[] END,
               i.stable #>> '{os,pretty_name}'
          FROM hosts h
          LEFT JOIN host_liveness l ON l.host_id = h.id -- the status (#192); no row is no heartbeat yet
          LEFT JOIN host_inventories i ON i.host_id = h.id
         WHERE h.id = ANY (host_ids)
        ON CONFLICT (host_id) DO UPDATE
           SET enrollment_state = EXCLUDED.enrollment_state, status_rank = EXCLUDED.status_rank, name_key = EXCLUDED.name_key,
               hostname = EXCLUDED.hostname, tags_key = EXCLUDED.tags_key, agent_key = EXCLUDED.agent_key, os_name = EXCLUDED.os_name
         WHERE (s.enrollment_state, s.status_rank, s.name_key, s.hostname, s.tags_key, s.agent_key, s.os_name)
               IS DISTINCT FROM
               (EXCLUDED.enrollment_state, EXCLUDED.status_rank, EXCLUDED.name_key, EXCLUDED.hostname, EXCLUDED.tags_key,
                EXCLUDED.agent_key, EXCLUDED.os_name);
      END;
      $function$
  SQL

  create_function :host_compliance_summaries_mark, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.host_compliance_summaries_mark(host_ids bigint[], kinds smallint)
       RETURNS void
       LANGUAGE plpgsql
      AS $function$
      BEGIN
        -- Notes that this transaction changed what the hosts' summaries are built from (#193). kinds is a bit set: 1 the
        -- host's own fields or operating system (a sync), 2 its liveness only (the status sort key), 4 its counts, 8 a
        -- package report after a gap that ends its run (v02, VT-SCORES #262: host_compliance_summaries_flush v03). Nothing
        -- here locks a summary row: host_compliance_summaries_flush does it once, sorted, at commit. The rows are keyed by
        -- transaction, so two transactions marking one host never wait for each other.
        IF host_ids IS NULL OR cardinality(host_ids) = 0 THEN
          RETURN;
        END IF;

        INSERT INTO host_compliance_pending AS p (xact_id, host_id, kinds)
        SELECT txid_current(), h.id, kinds FROM (SELECT DISTINCT unnest(host_ids) AS id) h
        ON CONFLICT (xact_id, host_id) DO UPDATE SET kinds = p.kinds | EXCLUDED.kinds
         WHERE p.kinds | EXCLUDED.kinds <> p.kinds;

        -- One row a transaction; its deferred constraint trigger runs the flush once, at commit.
        INSERT INTO host_compliance_flushes (xact_id) VALUES (txid_current()) ON CONFLICT DO NOTHING;
      END;
      $function$
  SQL

  create_function :host_compliance_summaries_flush, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.host_compliance_summaries_flush()
       RETURNS trigger
       LANGUAGE plpgsql
      AS $function$
      DECLARE
        all_ids bigint[];
        sync_ids bigint[];
        status_ids bigint[];
        count_ids bigint[];
        gap_ids bigint[];
      BEGIN
        -- Runs once a transaction, at commit (a deferred constraint trigger on host_compliance_flushes, #193): syncs and
        -- recounts every host the transaction marked. Every summary row it needs is locked in one statement, in host id
        -- order, so locks are held only while the transaction commits, and always taken in the same order: two
        -- transactions can wait for each other's commit, but never deadlock on summaries, and a transaction never waits
        -- on a summary row in the middle of its work.
        DELETE FROM host_compliance_flushes WHERE xact_id = NEW.xact_id;
        WITH taken AS (DELETE FROM host_compliance_pending WHERE xact_id = NEW.xact_id RETURNING host_id, kinds)
        SELECT array_agg(host_id ORDER BY host_id),
               array_agg(host_id ORDER BY host_id) FILTER (WHERE kinds & 1 <> 0),
               array_agg(host_id ORDER BY host_id) FILTER (WHERE kinds & 3 = 2),
               array_agg(host_id ORDER BY host_id) FILTER (WHERE kinds & 4 <> 0),
               array_agg(host_id ORDER BY host_id) FILTER (WHERE kinds & 8 <> 0)
          INTO all_ids, sync_ids, status_ids, count_ids, gap_ids
          FROM taken;
        IF all_ids IS NULL THEN
          RETURN NULL;
        END IF;

        PERFORM 1 FROM host_compliance_summaries s WHERE s.host_id = ANY (all_ids) ORDER BY s.host_id FOR UPDATE;

        -- A host with no summary row yet (made in this transaction, or not reached by the migration's fill) is synced,
        -- which makes the row.
        sync_ids := ARRAY(SELECT DISTINCT h FROM unnest(COALESCE(sync_ids, '{}'::bigint[]) || ARRAY(
                      SELECT a FROM unnest(all_ids) a WHERE NOT EXISTS (SELECT 1 FROM host_compliance_summaries s WHERE s.host_id = a))) h ORDER BY h);
        PERFORM host_compliance_summaries_sync(sync_ids);

        -- Liveness alone moves only the status sort key: no join to hosts (the summary has its enrollment state), no regex,
        -- no rewrite of the other copies. The status is in host_liveness (#192); no row there is no heartbeat yet.
        UPDATE host_compliance_summaries s
           SET status_rank = host_compliance_status_rank(s.enrollment_state, l.liveness_status)
          FROM (SELECT a AS host_id FROM unnest(status_ids) a) c
          LEFT JOIN host_liveness l ON l.host_id = c.host_id
         WHERE s.host_id = c.host_id AND NOT s.host_id = ANY (sync_ids)
           AND s.status_rank IS DISTINCT FROM host_compliance_status_rank(s.enrollment_state, l.liveness_status);

        -- v03 (VT-SCORES #262, review of #305 S4): kind 8 is a package report after a gap longer than the badge setting
        -- (host_compliance_summaries_changed, on host_package_sets). The server saw nothing in the gap, so the host's run
        -- ends here; the recount that follows (kind 4 is always marked with it) starts a new one from now.
        UPDATE host_compliance_summaries s SET fixable_critical_since = NULL, no_fixable_critical_since = NULL
         WHERE s.host_id = ANY (gap_ids) AND (s.fixable_critical_since IS NOT NULL OR s.no_fixable_critical_since IS NOT NULL);

        PERFORM host_compliance_summaries_refresh(count_ids);
        RETURN NULL;
      END;
      $function$
  SQL

  create_function :host_compliance_summaries_changed, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.host_compliance_summaries_changed()
       RETURNS trigger
       LANGUAGE plpgsql
      AS $function$
      DECLARE
        counted CONSTANT text[] := ARRAY['pass', 'fail', 'not_readable'];
        open_states CONSTANT text[] := ARRAY['open', 'reopened'];
        host_ids bigint[];
      BEGIN
        -- Notes the hosts whose summaries a change can move (#193), for host_compliance_summaries_flush at commit. No
        -- summary row is locked here. Statement triggers pick out the rows that changed in a way the summary can see.
        --
        -- Every query over a transition table (old_rows, new_rows) runs through EXECUTE, so it is planned for the rows this
        -- statement changed (v02, #224). A static query keeps the plan it got the first time in the session: one without
        -- parameters always reuses its generic plan, and the transition tables' size is frozen into it. So after a one-row
        -- update, a 20,000-row UPDATE of hosts ran a nested loop for 29 to 40 s instead of a merge join for about 0.1 s.

        -- hosts (statement): a new host, or a change to a field the fleet list shows, sorts, or filters by (a sync).
        -- Liveness is in host_liveness (v03, #192; its transition-table queries run through EXECUTE as in v02, #224).
        IF TG_TABLE_NAME = 'hosts' THEN
          IF TG_OP = 'INSERT' THEN
            EXECUTE 'SELECT ARRAY(SELECT n.id FROM new_rows n)' INTO host_ids;
            PERFORM host_compliance_summaries_mark(host_ids, 1::smallint);
          ELSE
            EXECUTE $q$
              SELECT ARRAY(SELECT n.id FROM old_rows o JOIN new_rows n ON n.id = o.id
                            WHERE (o.name, o.hostname, o.tags, o.agent_version, o.enrollment_state)
                                  IS DISTINCT FROM (n.name, n.hostname, n.tags, n.agent_version, n.enrollment_state))
            $q$ INTO host_ids;
            PERFORM host_compliance_summaries_mark(host_ids, 1::smallint);
          END IF;
          RETURN NULL;
        END IF;

        -- host_liveness (row, its status changed; #192): the status sort key only. A row trigger with a WHEN clause, so the
        -- heartbeats that leave the status as it was, nearly all of them, queue nothing and call nothing.
        IF TG_TABLE_NAME = 'host_liveness' THEN
          PERFORM host_compliance_summaries_mark(ARRAY[CASE TG_OP WHEN 'DELETE' THEN OLD.host_id ELSE NEW.host_id END], 2::smallint);
          RETURN NULL;
        END IF;

        -- host_inventories (row, its operating system name changed).
        IF TG_TABLE_NAME = 'host_inventories' THEN
          PERFORM host_compliance_summaries_mark(CASE TG_OP WHEN 'INSERT' THEN ARRAY[NEW.host_id] WHEN 'DELETE' THEN ARRAY[OLD.host_id]
                                                            ELSE ARRAY[OLD.host_id, NEW.host_id] END, 1::smallint);
          RETURN NULL;
        END IF;

        -- advisories (statement): a new severity moves the counts of every host with an open finding for it, which can
        -- be the whole fleet. Those hosts are queued, not recounted here: an import is one long transaction, and must not
        -- hold their summary rows. ComplianceSummaryRecountJob recounts them in short sorted batches after it commits.
        IF TG_TABLE_NAME = 'advisories' THEN
          EXECUTE $q$
            INSERT INTO host_compliance_recounts (host_id)
            SELECT DISTINCT f.host_id
              FROM old_rows o JOIN new_rows n ON n.id = o.id
              JOIN vulnerability_findings f ON f.advisory_id = n.id
             WHERE o.severity <> n.severity AND f.state = ANY ($1)
            ON CONFLICT DO NOTHING
          $q$ USING open_states;
          RETURN NULL;
        END IF;

        -- host_package_sets (row, VT-SCORES #262, review of #305 S4): a package report after a gap longer than the badge
        -- setting (vulnerabilities.badge_report_max_age_days, 3 by default) ends the host's run: kind 8, with a recount. The
        -- trigger's WHEN clause lets through only gaps over a day (the setting's least), so the reports that keep to
        -- their schedule call nothing.
        IF TG_TABLE_NAME = 'host_package_sets' THEN
          IF NEW.received_at - OLD.received_at > COALESCE((SELECT CASE WHEN jsonb_typeof(st.value) = 'number' AND st.value::text ~ '^[0-9]{1,4}$' THEN (st.value::text)::integer END
                                                             FROM settings st WHERE st.key = 'vulnerabilities.badge_report_max_age_days'), 3) * interval '1 day' THEN
            PERFORM host_compliance_summaries_mark(ARRAY[NEW.host_id], 12::smallint);
          END IF;
          RETURN NULL;
        END IF;

        -- finding_decisions (row, VT-SCORES #262 folding in #298): an accepted risk recorded or ended moves the host's
        -- decisions due (vuln_attention_undecided); it changes no bucket, so the findings' triggers do not see it. A control
        -- cannot move that count (every Needs attention rule comes after O1, and recording or ending one re-triages its
        -- findings, which the findings' triggers see), so the trigger's WHEN clause leaves controls out. The host is queued
        -- for ComplianceSummaryRecountJob, as an advisory's new severity queues its hosts, rather than recounted at commit:
        -- the hourly sweep ends decisions under its slice's host locks, and must not hold them for a recount a host
        -- (re-check of #305, S2).
        IF TG_TABLE_NAME = 'finding_decisions' THEN
          INSERT INTO host_compliance_recounts (host_id) VALUES (NEW.host_id) ON CONFLICT DO NOTHING;
          RETURN NULL;
        END IF;

        -- host_vulnerability_evaluations (row, its state changed).
        IF TG_TABLE_NAME = 'host_vulnerability_evaluations' THEN
          host_ids := CASE TG_OP WHEN 'INSERT' THEN ARRAY[NEW.host_id] WHEN 'DELETE' THEN ARRAY[OLD.host_id] ELSE ARRAY[OLD.host_id, NEW.host_id] END;

        -- host_applicability (row, VT-SCORES #262): the agent's reboot flag, a work item, appeared or went. A row trigger
        -- with a WHEN clause on update, so the in-use reports that leave the flag as it was queue nothing.
        ELSIF TG_TABLE_NAME = 'host_applicability' THEN
          host_ids := CASE TG_OP WHEN 'INSERT' THEN ARRAY[NEW.host_id] WHEN 'DELETE' THEN ARRAY[OLD.host_id] ELSE ARRAY[OLD.host_id, NEW.host_id] END;

        -- cis_rules (row, its current version changed): a failure that names no version takes the current one's severity.
        ELSIF TG_TABLE_NAME = 'cis_rules' THEN
          host_ids := ARRAY(SELECT DISTINCT r.host_id FROM cis_results r
                             WHERE r.cis_rule_id = NEW.id AND r.result = 'fail' AND r.cis_rule_version_id IS NULL);

        -- cis_results (statement): a counted result appeared or went, a result changed, or the rule version a failure is
        -- counted under changed.
        ELSIF TG_TABLE_NAME = 'cis_results' THEN
          IF TG_OP = 'INSERT' THEN
            EXECUTE 'SELECT ARRAY(SELECT DISTINCT n.host_id FROM new_rows n WHERE n.result = ANY ($1))' INTO host_ids USING counted;
          ELSIF TG_OP = 'DELETE' THEN
            EXECUTE 'SELECT ARRAY(SELECT DISTINCT o.host_id FROM old_rows o WHERE o.result = ANY ($1))' INTO host_ids USING counted;
          ELSE
            EXECUTE $q$
              SELECT ARRAY(
                SELECT DISTINCT v.host_id
                  FROM old_rows o JOIN new_rows n ON n.id = o.id, LATERAL (VALUES (o.host_id), (n.host_id)) v(host_id)
                 WHERE o.host_id <> n.host_id OR o.cis_rule_id <> n.cis_rule_id
                    OR (o.result <> n.result AND (o.result = ANY ($1) OR n.result = ANY ($1)))
                    OR (n.result = 'fail' AND o.cis_rule_version_id IS DISTINCT FROM n.cis_rule_version_id))
            $q$ INTO host_ids USING counted;
          END IF;

        -- vulnerability_findings (statement): a finding opened, reopened, or resolved, an open one moved, or an open one's
        -- fix appeared or disappeared (v04, VT-FIXABLE #256: an advisory import that adds or takes back a fixed version
        -- writes last_fixed_version with no change of state; a fix moving from one version to another changes no count).
        -- v05 (VT-BUCKETS, #259): or an open one's triage bucket or KEV flag changed (a re-triage, or a host fact).
        -- v06 (VT-SCORES, #262): or its rule (K2 to K1 is a new kernel installed: a work item changes, not the bucket), its
        -- listener (exposure points), or its source package (the upgrades are counted by source).
        ELSIF TG_TABLE_NAME = 'vulnerability_findings' THEN
          IF TG_OP = 'INSERT' THEN
            EXECUTE 'SELECT ARRAY(SELECT DISTINCT n.host_id FROM new_rows n WHERE n.state = ANY ($1))' INTO host_ids USING open_states;
          ELSIF TG_OP = 'DELETE' THEN
            EXECUTE 'SELECT ARRAY(SELECT DISTINCT o.host_id FROM old_rows o WHERE o.state = ANY ($1))' INTO host_ids USING open_states;
          ELSE
            EXECUTE $q$
              SELECT ARRAY(
                SELECT DISTINCT v.host_id
                  FROM old_rows o JOIN new_rows n ON n.id = o.id, LATERAL (VALUES (o.host_id), (n.host_id)) v(host_id)
                 WHERE (o.state = ANY ($1) OR n.state = ANY ($1))
                   AND ((o.state = ANY ($1)) <> (n.state = ANY ($1)) OR o.advisory_id <> n.advisory_id OR o.host_id <> n.host_id
                        OR (o.last_fixed_version IS NULL) <> (n.last_fixed_version IS NULL)
                        OR o.bucket IS DISTINCT FROM n.bucket OR o.kev IS DISTINCT FROM n.kev
                        OR o.bucket_rule IS DISTINCT FROM n.bucket_rule OR o.listener IS DISTINCT FROM n.listener
                        OR o.last_source IS DISTINCT FROM n.last_source))
            $q$ INTO host_ids USING open_states;
          END IF;
        END IF;

        PERFORM host_compliance_summaries_mark(host_ids, 4::smallint);
        RETURN NULL;
      END;
      $function$
  SQL

  create_function :host_compliance_summaries_truncate_guard, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.host_compliance_summaries_truncate_guard()
       RETURNS trigger
       LANGUAGE plpgsql
      AS $function$
      BEGIN
        -- TRUNCATE fires no row or statement triggers, so it would leave the compliance summaries wrong (#193).
        RAISE EXCEPTION '% is not truncated: the compliance summaries are built from it (delete the rows instead, or run bin/rails compliance_summaries:rebuild afterwards with this trigger disabled)', TG_TABLE_NAME
          USING ERRCODE = 'insufficient_privilege';
      END;
      $function$
  SQL

  create_function :host_liveness_follow_enrollment, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.host_liveness_follow_enrollment()
       RETURNS trigger
       LANGUAGE plpgsql
      AS $function$
      BEGIN
        -- Only active hosts are evaluated (FR-1.4, #192). A host's host_liveness row records whether it is, so the liveness
        -- run never finds revoked, pending, or retired hosts again: retired is terminal and hosts are never deleted, so
        -- without this every run would read them all, forever. Runs in the transaction that changed the enrollment state,
        -- which holds the host row lock, as every writer of host_liveness does.
        UPDATE host_liveness
           SET evaluated = (NEW.enrollment_state = 'active')
         WHERE host_id = NEW.id AND evaluated IS DISTINCT FROM (NEW.enrollment_state = 'active');
        RETURN NULL;
      END;
      $function$
  SQL

  create_function :finding_decisions_guard, sql_definition: <<-'SQL'
      CREATE OR REPLACE FUNCTION public.finding_decisions_guard()
       RETURNS trigger
       LANGUAGE plpgsql
      AS $function$
      BEGIN
        -- Operator decisions are kept as the record of what was decided (VT-OVERRIDES #261): never deleted.
        IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
          RAISE EXCEPTION 'finding decisions are never deleted: % is not allowed', TG_OP
            USING ERRCODE = 'insufficient_privilege';
        END IF;

        -- A decision starts active.
        IF TG_OP = 'INSERT' THEN
          IF NEW.ended_at IS NOT NULL THEN
            RAISE EXCEPTION 'new finding decisions start active'
              USING ERRCODE = 'check_violation';
          END IF;
          RETURN NEW;
        END IF;

        -- Ended is final: an ended decision never changes.
        IF OLD.ended_at IS NOT NULL THEN
          RAISE EXCEPTION 'finding decision % ended (%); it cannot change', OLD.id, OLD.ended_why
            USING ERRCODE = 'check_violation';
        END IF;

        -- What a decision is, on what, by whom, and the evidence it was recorded on never change. Only its reason and
        -- expiry (an operator's change) and its end may.
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.host_id IS DISTINCT FROM OLD.host_id OR NEW.advisory_id IS DISTINCT FROM OLD.advisory_id
           OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.created_by_id IS DISTINCT FROM OLD.created_by_id
           OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.evidence IS DISTINCT FROM OLD.evidence
           OR NEW.confirmed IS DISTINCT FROM OLD.confirmed OR NEW.request_id IS DISTINCT FROM OLD.request_id
           OR NEW.operator_session_id IS DISTINCT FROM OLD.operator_session_id THEN
          RAISE EXCEPTION 'a finding decision''s host, advisory, kind, author, evidence, and confirmation never change'
            USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
      END;
      $function$
  SQL

  create_trigger :audit_entries_no_update_or_delete, sql_definition: <<-SQL
      CREATE TRIGGER audit_entries_no_update_or_delete BEFORE DELETE OR UPDATE ON public.audit_entries FOR EACH ROW EXECUTE FUNCTION audit_entries_append_only()
  SQL

  create_trigger :audit_entries_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER audit_entries_no_truncate BEFORE TRUNCATE ON public.audit_entries FOR EACH STATEMENT EXECUTE FUNCTION audit_entries_append_only()
  SQL

  create_trigger :hosts_enrollment_state_guard, sql_definition: <<-SQL
      CREATE TRIGGER hosts_enrollment_state_guard BEFORE INSERT OR UPDATE OF enrollment_state ON public.hosts FOR EACH ROW EXECUTE FUNCTION hosts_guard()
  SQL

  create_trigger :hosts_no_delete, sql_definition: <<-SQL
      CREATE TRIGGER hosts_no_delete BEFORE DELETE ON public.hosts FOR EACH ROW EXECUTE FUNCTION hosts_guard()
  SQL

  create_trigger :hosts_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER hosts_no_truncate BEFORE TRUNCATE ON public.hosts FOR EACH STATEMENT EXECUTE FUNCTION hosts_guard()
  SQL

  create_trigger :agent_releases_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER agent_releases_no_truncate BEFORE TRUNCATE ON public.agent_releases FOR EACH STATEMENT EXECUTE FUNCTION agent_releases_guard()
  SQL

  create_trigger :agent_releases_immutable, sql_definition: <<-SQL
      CREATE TRIGGER agent_releases_immutable BEFORE DELETE OR UPDATE ON public.agent_releases FOR EACH ROW EXECUTE FUNCTION agent_releases_guard()
  SQL

  create_trigger :task_batches_immutable, sql_definition: <<-SQL
      CREATE TRIGGER task_batches_immutable BEFORE DELETE OR UPDATE ON public.task_batches FOR EACH ROW EXECUTE FUNCTION task_batches_guard()
  SQL

  create_trigger :task_batches_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER task_batches_no_truncate BEFORE TRUNCATE ON public.task_batches FOR EACH STATEMENT EXECUTE FUNCTION task_batches_guard()
  SQL

  create_trigger :tasks_guard, sql_definition: <<-SQL
      CREATE TRIGGER tasks_guard BEFORE INSERT OR DELETE OR UPDATE ON public.tasks FOR EACH ROW EXECUTE FUNCTION tasks_guard()
  SQL

  create_trigger :tasks_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER tasks_no_truncate BEFORE TRUNCATE ON public.tasks FOR EACH STATEMENT EXECUTE FUNCTION tasks_guard()
  SQL

  create_trigger :task_late_results_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER task_late_results_no_truncate BEFORE TRUNCATE ON public.task_late_results FOR EACH STATEMENT EXECUTE FUNCTION task_late_results_guard()
  SQL

  create_trigger :task_late_results_immutable, sql_definition: <<-SQL
      CREATE TRIGGER task_late_results_immutable BEFORE DELETE OR UPDATE ON public.task_late_results FOR EACH ROW EXECUTE FUNCTION task_late_results_guard()
  SQL

  create_trigger :host_compliance_summaries_advisories_update, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_advisories_update AFTER UPDATE ON public.advisories REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_cis_insert, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_cis_insert AFTER INSERT ON public.cis_results REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :cis_results_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER cis_results_no_truncate BEFORE TRUNCATE ON public.cis_results FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_truncate_guard()
  SQL

  create_trigger :host_compliance_summaries_cis_delete, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_cis_delete AFTER DELETE ON public.cis_results REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_cis_update, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_cis_update AFTER UPDATE ON public.cis_results REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_rule_version, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_rule_version AFTER UPDATE OF current_version_id ON public.cis_rules FOR EACH ROW WHEN ((old.current_version_id IS DISTINCT FROM new.current_version_id)) EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_inventories_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER host_inventories_no_truncate BEFORE TRUNCATE ON public.host_inventories FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_truncate_guard()
  SQL

  create_trigger :host_compliance_summaries_inventory_insert_delete, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_inventory_insert_delete AFTER INSERT OR DELETE ON public.host_inventories FOR EACH ROW EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_inventory_update, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_inventory_update AFTER UPDATE ON public.host_inventories FOR EACH ROW WHEN ((((old.stable #>> '{os,pretty_name}'::text[]) IS DISTINCT FROM (new.stable #>> '{os,pretty_name}'::text[])) OR (old.host_id <> new.host_id))) EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_evaluation_insert_delete, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_evaluation_insert_delete AFTER INSERT OR DELETE ON public.host_vulnerability_evaluations FOR EACH ROW EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_evaluation_update, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_evaluation_update AFTER UPDATE ON public.host_vulnerability_evaluations FOR EACH ROW WHEN ((((old.state)::text IS DISTINCT FROM (new.state)::text) OR (old.host_id <> new.host_id))) EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_vulnerability_evaluations_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER host_vulnerability_evaluations_no_truncate BEFORE TRUNCATE ON public.host_vulnerability_evaluations FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_truncate_guard()
  SQL

  create_trigger :host_compliance_summaries_hosts_insert, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_hosts_insert AFTER INSERT ON public.hosts REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_liveness_follow_enrollment, sql_definition: <<-SQL
      CREATE TRIGGER host_liveness_follow_enrollment AFTER UPDATE OF enrollment_state ON public.hosts FOR EACH ROW WHEN (((old.enrollment_state)::text IS DISTINCT FROM (new.enrollment_state)::text)) EXECUTE FUNCTION host_liveness_follow_enrollment()
  SQL

  create_trigger :host_compliance_summaries_hosts_update, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_hosts_update AFTER UPDATE ON public.hosts REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_findings_insert, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_findings_insert AFTER INSERT ON public.vulnerability_findings REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_liveness_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER host_liveness_no_truncate BEFORE TRUNCATE ON public.host_liveness FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_truncate_guard()
  SQL

  create_trigger :host_compliance_summaries_liveness_update, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_liveness_update AFTER UPDATE OF liveness_status ON public.host_liveness FOR EACH ROW WHEN (((old.liveness_status)::text IS DISTINCT FROM (new.liveness_status)::text)) EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_liveness_insert_delete, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_liveness_insert_delete AFTER INSERT OR DELETE ON public.host_liveness FOR EACH ROW EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_findings_update, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_findings_update AFTER UPDATE ON public.vulnerability_findings REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :finding_decisions_guard, sql_definition: <<-SQL
      CREATE TRIGGER finding_decisions_guard BEFORE INSERT OR DELETE OR UPDATE ON public.finding_decisions FOR EACH ROW EXECUTE FUNCTION finding_decisions_guard()
  SQL

  create_trigger :finding_decisions_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER finding_decisions_no_truncate BEFORE TRUNCATE ON public.finding_decisions FOR EACH STATEMENT EXECUTE FUNCTION finding_decisions_guard()
  SQL

  create_trigger :vulnerability_findings_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER vulnerability_findings_no_truncate BEFORE TRUNCATE ON public.vulnerability_findings FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_truncate_guard()
  SQL

  create_trigger :host_compliance_summaries_findings_delete, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_findings_delete AFTER DELETE ON public.vulnerability_findings REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_decisions, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_decisions AFTER INSERT OR UPDATE OF ended_at ON public.finding_decisions FOR EACH ROW WHEN (((new.kind)::text = 'accepted'::text)) EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_package_sets_gap, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_package_sets_gap AFTER UPDATE OF received_at ON public.host_package_sets FOR EACH ROW WHEN (((new.received_at - old.received_at) > 'P1D'::interval)) EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_applicability_update, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_applicability_update AFTER UPDATE OF reboot_required ON public.host_applicability FOR EACH ROW WHEN ((old.reboot_required IS DISTINCT FROM new.reboot_required)) EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_applicability_insert_delete, sql_definition: <<-SQL
      CREATE TRIGGER host_compliance_summaries_applicability_insert_delete AFTER INSERT OR DELETE ON public.host_applicability FOR EACH ROW EXECUTE FUNCTION host_compliance_summaries_changed()
  SQL

  create_trigger :host_compliance_summaries_flush, sql_definition: <<-SQL
      CREATE CONSTRAINT TRIGGER host_compliance_summaries_flush AFTER INSERT ON public.host_compliance_flushes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION host_compliance_summaries_flush()
  SQL
end
