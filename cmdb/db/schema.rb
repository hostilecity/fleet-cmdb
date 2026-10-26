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

ActiveRecord::Schema[8.1].define(version: 2026_10_26_193100) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"

  create_table "audit_entries", force: :cascade do |t|
    t.string "actor_type", null: false
    t.bigint "actor_id"
    t.string "action", null: false
    t.string "target_type"
    t.bigint "target_id"
    t.jsonb "changeset", default: {}, null: false
    t.string "request_id", limit: 255
    t.datetime "occurred_at", default: -> { "CURRENT_TIMESTAMP" }, null: false
    t.index ["action", "occurred_at"], name: "index_audit_entries_on_action_and_occurred_at"
    t.index ["actor_type", "actor_id", "occurred_at"], name: "index_audit_entries_on_actor"
    t.index ["occurred_at"], name: "index_audit_entries_on_occurred_at"
    t.index ["target_type", "target_id", "occurred_at"], name: "index_audit_entries_on_target"
    t.check_constraint "(actor_type::text = 'system'::text) = (actor_id IS NULL)", name: "audit_entries_actor_id_matches_type"
    t.check_constraint "actor_type::text = ANY (ARRAY['operator'::character varying, 'host'::character varying, 'system'::character varying]::text[])", name: "audit_entries_actor_type_valid"
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
    t.index ["enrollment_state"], name: "index_hosts_on_enrollment_state"
    t.index ["hostname"], name: "index_hosts_on_hostname"
    t.index ["liveness_status"], name: "index_hosts_on_liveness_status"
    t.index ["tags"], name: "index_hosts_on_tags", using: :gin
    t.check_constraint "enrollment_state::text = ANY (ARRAY['pending'::character varying, 'active'::character varying, 'revoked'::character varying, 'retired'::character varying]::text[])", name: "hosts_enrollment_state_valid"
    t.check_constraint "liveness_status IS NULL OR (liveness_status::text = ANY (ARRAY['online'::character varying, 'stale'::character varying, 'offline'::character varying]::text[]))", name: "hosts_liveness_status_valid"
  end

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

  create_trigger :hosts_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER hosts_no_truncate BEFORE TRUNCATE ON public.hosts FOR EACH STATEMENT EXECUTE FUNCTION hosts_guard()
  SQL

  create_trigger :hosts_no_delete, sql_definition: <<-SQL
      CREATE TRIGGER hosts_no_delete BEFORE DELETE ON public.hosts FOR EACH ROW EXECUTE FUNCTION hosts_guard()
  SQL

  create_trigger :hosts_enrollment_state_guard, sql_definition: <<-SQL
      CREATE TRIGGER hosts_enrollment_state_guard BEFORE INSERT OR UPDATE OF enrollment_state ON public.hosts FOR EACH ROW EXECUTE FUNCTION hosts_guard()
  SQL

  create_trigger :audit_entries_no_truncate, sql_definition: <<-SQL
      CREATE TRIGGER audit_entries_no_truncate BEFORE TRUNCATE ON public.audit_entries FOR EACH STATEMENT EXECUTE FUNCTION audit_entries_append_only()
  SQL

  create_trigger :audit_entries_no_update_or_delete, sql_definition: <<-SQL
      CREATE TRIGGER audit_entries_no_update_or_delete BEFORE DELETE OR UPDATE ON public.audit_entries FOR EACH ROW EXECUTE FUNCTION audit_entries_append_only()
  SQL
end
