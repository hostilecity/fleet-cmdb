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

ActiveRecord::Schema[8.1].define(version: 2026_10_31_030000) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"
  enable_extension "pg_trgm"

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
    t.index ["version"], name: "index_agent_release_imports_one_in_flight", unique: true, where: "((state)::text = ANY (ARRAY[('queued'::character varying)::text, ('running'::character varying)::text]))"
    t.check_constraint "(state::text = ANY (ARRAY['queued'::character varying::text, 'running'::character varying::text])) = (finished_at IS NULL)", name: "agent_release_imports_finished_at_matches_state"
    t.check_constraint "state::text = ANY (ARRAY['queued'::character varying::text, 'running'::character varying::text, 'imported'::character varying::text, 'refused'::character varying::text, 'failed'::character varying::text])", name: "agent_release_imports_state_valid"
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
    t.check_constraint "key_role::text = ANY (ARRAY['current'::character varying::text, 'next'::character varying::text])", name: "agent_releases_key_role_valid"
    t.check_constraint "sha256::text ~ '^[0-9a-f]{64}$'::text", name: "agent_releases_sha256_valid"
    t.check_constraint "size >= 1 AND size <= 67108864", name: "agent_releases_size_valid"
    t.check_constraint "source::text = ANY (ARRAY['github'::character varying::text, 'upload'::character varying::text])", name: "agent_releases_source_valid"
  end

  create_table "audit_entries", force: :cascade do |t|
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

  create_table "host_status_events", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.string "from_status"
    t.string "to_status", null: false
    t.string "reason", null: false
    t.datetime "occurred_at", null: false
    t.index ["host_id", "occurred_at"], name: "index_host_status_events_on_host_id_and_occurred_at"
    t.index ["occurred_at"], name: "index_host_status_events_on_occurred_at"
    t.check_constraint "from_status IS NULL OR (from_status::text = ANY (ARRAY['online'::character varying::text, 'stale'::character varying::text, 'offline'::character varying::text]))", name: "host_status_events_from_status_valid"
    t.check_constraint "from_status::text IS DISTINCT FROM to_status::text", name: "host_status_events_is_a_change"
    t.check_constraint "reason::text = ANY (ARRAY['heartbeat'::character varying::text, 'evaluation'::character varying::text])", name: "host_status_events_reason_valid"
    t.check_constraint "to_status::text = ANY (ARRAY['online'::character varying::text, 'stale'::character varying::text, 'offline'::character varying::text])", name: "host_status_events_to_status_valid"
  end

  create_table "hosts", force: :cascade do |t|
    t.string "name", limit: 100, null: false
    t.string "hostname", limit: 253, null: false
    t.text "description"
    t.text "notes"
    t.string "tags", default: [], null: false, array: true
    t.string "enrollment_state", default: "pending", null: false
    t.datetime "first_seen_at"
    t.datetime "last_seen_at"
    t.string "agent_version", limit: 64
    t.integer "agent_schema_version"
    t.string "liveness_status"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.datetime "agent_reported_at"
    t.datetime "machine_id_mismatch_at"
    t.string "reported_machine_id", limit: 32
    t.index ["agent_version"], name: "index_hosts_in_fleet_on_agent_version", where: "((enrollment_state)::text <> 'retired'::text)"
    t.index ["enrollment_state"], name: "index_hosts_on_enrollment_state"
    t.index ["hostname"], name: "index_hosts_on_hostname"
    t.index ["hostname"], name: "index_hosts_on_hostname_trigram", opclass: :gin_trgm_ops, using: :gin
    t.index ["liveness_status"], name: "index_hosts_on_liveness_status"
    t.index ["name"], name: "index_hosts_on_name_trigram", opclass: :gin_trgm_ops, using: :gin
    t.index ["tags"], name: "index_hosts_on_tags", using: :gin
    t.check_constraint "enrollment_state::text = ANY (ARRAY['pending'::character varying::text, 'active'::character varying::text, 'revoked'::character varying::text, 'retired'::character varying::text])", name: "hosts_enrollment_state_valid"
    t.check_constraint "liveness_status IS NULL OR (liveness_status::text = ANY (ARRAY['online'::character varying::text, 'stale'::character varying::text, 'offline'::character varying::text]))", name: "hosts_liveness_status_valid"
  end

  create_table "inventory_report_receipts", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.uuid "report_id", null: false
    t.datetime "received_at", null: false
    t.index ["host_id", "report_id"], name: "index_inventory_report_receipts_on_host_id_and_report_id", unique: true
    t.index ["received_at"], name: "index_inventory_report_receipts_on_received_at"
  end

  create_table "inventory_snapshots", force: :cascade do |t|
    t.bigint "host_id", null: false
    t.jsonb "stable", null: false
    t.jsonb "warnings", default: [], null: false
    t.string "stable_hash", limit: 64, null: false
    t.uuid "report_id", null: false
    t.datetime "collected_at", null: false
    t.datetime "received_at", null: false
    t.index ["host_id", "received_at"], name: "index_inventory_snapshots_on_host_id_and_received_at"
    t.index ["received_at"], name: "index_inventory_snapshots_on_received_at"
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
    t.check_constraint "state::text = ANY (ARRAY['open'::character varying::text, 'approved'::character varying::text, 'rejected'::character varying::text, 'collected'::character varying::text])", name: "onboarding_requests_state_valid"
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

  create_table "settings", force: :cascade do |t|
    t.string "key", limit: 100, null: false
    t.jsonb "value", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["key"], name: "index_settings_on_key", unique: true
  end

  add_foreign_key "agent_credentials", "hosts"
  add_foreign_key "agent_release_imports", "agent_releases"
  add_foreign_key "agent_release_imports", "operators"
  add_foreign_key "agent_releases", "operators", column: "imported_by_id"
  add_foreign_key "enrollment_tokens", "hosts"
  add_foreign_key "host_inventories", "hosts"
  add_foreign_key "host_status_events", "hosts"
  add_foreign_key "inventory_report_receipts", "hosts"
  add_foreign_key "inventory_snapshots", "hosts"
  add_foreign_key "onboarding_requests", "hosts"
  add_foreign_key "onboarding_requests", "operators", column: "decided_by_id"
  add_foreign_key "operator_sessions", "operators"

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

  create_trigger :agent_releases_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER agent_releases_no_truncate BEFORE TRUNCATE ON public.agent_releases FOR EACH STATEMENT EXECUTE FUNCTION agent_releases_guard()
  SQL

  create_trigger :agent_releases_immutable, sql_definition: <<-SQL
      CREATE TRIGGER agent_releases_immutable BEFORE DELETE OR UPDATE ON public.agent_releases FOR EACH ROW EXECUTE FUNCTION agent_releases_guard()
  SQL

  create_trigger :audit_entries_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER audit_entries_no_truncate BEFORE TRUNCATE ON public.audit_entries FOR EACH STATEMENT EXECUTE FUNCTION audit_entries_append_only()
  SQL

  create_trigger :audit_entries_no_update_or_delete, sql_definition: <<-SQL
      CREATE TRIGGER audit_entries_no_update_or_delete BEFORE DELETE OR UPDATE ON public.audit_entries FOR EACH ROW EXECUTE FUNCTION audit_entries_append_only()
  SQL

  create_trigger :hosts_no_delete, sql_definition: <<-SQL
      CREATE TRIGGER hosts_no_delete BEFORE DELETE ON public.hosts FOR EACH ROW EXECUTE FUNCTION hosts_guard()
  SQL

  create_trigger :hosts_enrollment_state_guard, sql_definition: <<-SQL
      CREATE TRIGGER hosts_enrollment_state_guard BEFORE INSERT OR UPDATE OF enrollment_state ON public.hosts FOR EACH ROW EXECUTE FUNCTION hosts_guard()
  SQL

  create_trigger :hosts_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER hosts_no_truncate BEFORE TRUNCATE ON public.hosts FOR EACH STATEMENT EXECUTE FUNCTION hosts_guard()
  SQL
end
