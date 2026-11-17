-- The audit log's hardened guard (ADR 0027, "The audit log's guards"; FR-S.3; threat model A3, F-5).
--
-- Run ONCE as the PostgreSQL superuser, in the production database, AFTER the app has migrated audit_entries to a
-- partitioned table, and again after every restore (ops/backup/restore.sh skips event triggers, which only a
-- superuser can create):
--
--   psql -v ON_ERROR_STOP=1 -U postgres -d cmdb_production -f ops/postgres/audit-guard.sql
--
-- It is safe to run again. It does three things, none of which the app's own role can undo:
--   1. the superuser takes ownership of the guard function audit_entries_append_only(), so the app's role can no
--      longer replace it with a function that lets changes through (its triggers still call it);
--   2. an sql_drop event trigger refuses dropping an audit table (the parent or any partition), a trigger or rule on
--      one, or the guard function;
--   3. a ddl_command_end event trigger refuses ALTER TABLE (DETACH, DISABLE TRIGGER, ...), CREATE TRIGGER, ALTER
--      TRIGGER (a rename), and CREATE RULE on an audit table: the parent or any partition of it, whatever its name. One trigger is allowed, by
--      its definition and not its name: the per-partition truncate guard (BEFORE TRUNCATE, statement level, calling
--      the guard function, on a partition and not the parent).
-- Creating a new audit partition (CREATE TABLE ... PARTITION OF) is still allowed: the app does it every month. The
-- event trigger adds the new partition's truncate guard itself, so no partition is ever without one.
--
-- A later migration that alters audit_entries or its guard function needs the superuser to disable the event
-- triggers for it (ALTER EVENT TRIGGER fleet_audit_guard_ddl DISABLE; ... ENABLE). That is deliberate.
-- /health shows audit_guard as "warning" until this has run.

DO $$
BEGIN
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    RAISE EXCEPTION 'run ops/postgres/audit-guard.sql as the PostgreSQL superuser, not as %', current_user;
  END IF;
  IF to_regclass('public.audit_entries') IS NULL
     OR (SELECT relkind FROM pg_class WHERE oid = 'public.audit_entries'::regclass) <> 'p' THEN
    RAISE EXCEPTION 'audit_entries is not partitioned yet: deploy the app (its migrations convert it), then run this again';
  END IF;
END
$$;

-- The event trigger functions live in a schema of their own, owned by the superuser, so the app's schema dump never
-- holds them and the app's role cannot replace them.
CREATE SCHEMA IF NOT EXISTS fleet_audit_guard;
ALTER SCHEMA fleet_audit_guard OWNER TO CURRENT_USER;
REVOKE ALL ON SCHEMA fleet_audit_guard FROM PUBLIC;

-- 1. The guard function belongs to the superuser.
ALTER FUNCTION public.audit_entries_append_only() OWNER TO CURRENT_USER;

-- 2. No audit table, trigger or rule on one, or the guard function, is ever dropped. A partition is recognised by the
--    row guard every audit partition carries (PostgreSQL clones it from the parent and drops it with the partition),
--    so a partition the app's role created under another name is covered too.
CREATE OR REPLACE FUNCTION fleet_audit_guard.refuse_drop() RETURNS event_trigger
LANGUAGE plpgsql AS $$
DECLARE
  dropped record;
  tree oid[] := ARRAY(SELECT relid FROM pg_partition_tree(to_regclass('public.audit_entries')));
BEGIN
  FOR dropped IN SELECT * FROM pg_event_trigger_dropped_objects() LOOP
    IF dropped.object_identity LIKE 'public.audit\_entries%'
       OR dropped.object_identity LIKE '% on public.audit\_entries%'
       OR (dropped.object_type = 'trigger' AND dropped.object_identity LIKE 'audit\_entries\_no\_update\_or\_delete on %')
       -- a trigger or rule dropped from a table that is still part of the audit log
       OR (dropped.object_type IN ('trigger', 'rule') AND to_regclass(split_part(dropped.object_identity, ' on ', 2)) = ANY (tree))
       OR dropped.object_identity = 'public.audit_entries_append_only()' THEN
      RAISE EXCEPTION 'the audit log is append-only: % is not dropped (ops/postgres/audit-guard.sql)', dropped.object_identity
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
END
$$;

-- 3. No ALTER TABLE, rule, or trigger on an audit table (the parent or any of its partitions, whatever its name), except
--    a partition's truncate guard. A new partition gets its truncate guard here, at once: a statement trigger is not
--    cloned from the parent, and without one the partition could be truncated.
CREATE OR REPLACE FUNCTION fleet_audit_guard.refuse_ddl() RETURNS event_trigger
LANGUAGE plpgsql AS $$
DECLARE
  command record;
  added record;
  tree oid[] := ARRAY(SELECT relid FROM pg_partition_tree(to_regclass('public.audit_entries')));
BEGIN
  FOR command IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
    IF command.command_tag = 'CREATE TABLE' AND command.objid = ANY (tree) AND command.objid <> 'public.audit_entries'::regclass
       AND NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = command.objid AND t.tgtype = 34
                         AND t.tgfoid = 'public.audit_entries_append_only()'::regprocedure) THEN
      EXECUTE format('CREATE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION public.audit_entries_append_only()',
                     command.objid::regclass);
    END IF;
    IF command.command_tag = 'ALTER TABLE' AND (command.objid = ANY (tree) OR command.object_identity LIKE 'public.audit\_entries%') THEN
      RAISE EXCEPTION 'the audit log is append-only: % is not altered (ops/postgres/audit-guard.sql)', command.object_identity
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF command.command_tag = 'CREATE RULE' AND (SELECT r.ev_class FROM pg_rewrite r WHERE r.oid = command.objid) = ANY (tree) THEN
      RAISE EXCEPTION 'the audit log is append-only: no rule on an audit table (%)', command.object_identity
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF command.command_tag = 'ALTER TRIGGER' AND (SELECT t.tgrelid FROM pg_trigger t WHERE t.oid = command.objid) = ANY (tree) THEN
      RAISE EXCEPTION 'the audit log is append-only: % is not altered (ops/postgres/audit-guard.sql)', command.object_identity
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF command.command_tag = 'CREATE TRIGGER' THEN
      SELECT t.tgrelid, t.tgtype, t.tgfoid INTO added FROM pg_trigger t WHERE t.oid = command.objid;
      IF added.tgrelid = ANY (tree) AND NOT (
           added.tgtype = 34 -- BEFORE (2) + TRUNCATE (32), FOR EACH STATEMENT
           AND added.tgfoid = 'public.audit_entries_append_only()'::regprocedure
           AND added.tgrelid <> 'public.audit_entries'::regclass) THEN
        RAISE EXCEPTION 'the audit log is append-only: only the truncate guard may be added to an audit partition (%)', command.object_identity
          USING ERRCODE = 'insufficient_privilege';
      END IF;
    END IF;
  END LOOP;
END
$$;

ALTER FUNCTION fleet_audit_guard.refuse_drop() OWNER TO CURRENT_USER;
ALTER FUNCTION fleet_audit_guard.refuse_ddl() OWNER TO CURRENT_USER;

DROP EVENT TRIGGER IF EXISTS fleet_audit_guard_drop;
DROP EVENT TRIGGER IF EXISTS fleet_audit_guard_ddl;
CREATE EVENT TRIGGER fleet_audit_guard_drop ON sql_drop
  EXECUTE FUNCTION fleet_audit_guard.refuse_drop();
CREATE EVENT TRIGGER fleet_audit_guard_ddl ON ddl_command_end
  WHEN TAG IN ('ALTER TABLE', 'CREATE TABLE', 'CREATE TRIGGER', 'ALTER TRIGGER', 'CREATE RULE')
  EXECUTE FUNCTION fleet_audit_guard.refuse_ddl();
