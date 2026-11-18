-- The audit log's hardened guard (ADR 0027, "The audit log's guards"; FR-S.3; threat model A3, F-5).
--
-- Run ONCE as the PostgreSQL superuser, in the production database, AFTER the app has migrated audit_entries to a
-- partitioned table, and again after every restore (ops/backup/restore.sh leaves this file's objects out: only a
-- superuser can create an event trigger). With the official image, as its superuser whatever it is called:
--
--   docker exec -i postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d cmdb_production' < ops/postgres/audit-guard.sql
--
-- It is safe to run again. It refuses to run as a role that is not a superuser, before audit_entries is partitioned,
-- or when the app's role (the owner of audit_entries) is a superuser itself: a superuser can turn any guard off, so
-- the guard would protect nothing.
--
-- What it does, none of which the app's role can undo:
--   1. the superuser takes ownership of the guard function audit_entries_append_only(), so the app's role can no longer
--      replace it (its triggers still call it);
--   2. it records the audit log by OID, not by name, in fleet_audit_guard.protected: the schema that holds it, the
--      parent table, every partition, and the guard function. A rename cannot hide them. New partitions are added as
--      they are created;
--   3. a ddl_command_end event trigger, for every command whatever its tag, refuses one whose object is a protected
--      relation, schema, or function, or a trigger, rule, or policy on a protected table. Two things stay allowed:
--      creating a new partition of audit_entries (the app does it every month), which the event trigger records and
--      gives its truncate guard at once; and that truncate guard itself, recognised by its definition (BEFORE
--      TRUNCATE, statement level, calling the guard function, on a partition);
--   4. an sql_drop event trigger refuses dropping any protected object, or a trigger, rule, or policy of a protected
--      table.
-- Both event trigger functions run as their owner, the superuser, with search_path pinned to pg_catalog, pg_temp and
-- every catalog name qualified, so no temporary table, function, or operator of the app's role can shadow what they
-- read.
--
-- A later migration that alters audit_entries or its guard function needs the superuser to disable the event
-- triggers for it (ALTER EVENT TRIGGER fleet_audit_guard_ddl DISABLE; ... ENABLE), and to run this file again after.
-- That is deliberate. /health shows audit_guard as "warning" until this has run.

SET search_path = pg_catalog, pg_temp;

DO $$
BEGIN
  IF NOT (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) THEN
    RAISE EXCEPTION 'run ops/postgres/audit-guard.sql as the PostgreSQL superuser, not as %', current_user;
  END IF;
  IF pg_catalog.to_regclass('public.audit_entries') IS NULL
     OR (SELECT c.relkind FROM pg_catalog.pg_class c WHERE c.oid = pg_catalog.to_regclass('public.audit_entries')) <> 'p' THEN
    RAISE EXCEPTION 'audit_entries is not partitioned yet: deploy the app (its migrations convert it), then run this again';
  END IF;
  IF (SELECT r.rolsuper FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
      WHERE c.oid = pg_catalog.to_regclass('public.audit_entries')) THEN
    RAISE EXCEPTION 'audit_entries is owned by a superuser: the app''s role must not be a superuser, or no guard can hold (see docs/operations/install-server.md)';
  END IF;
END
$$;

-- While this runs, the guard must not stop the superuser changing what it protects.
DROP EVENT TRIGGER IF EXISTS fleet_audit_guard_drop;
DROP EVENT TRIGGER IF EXISTS fleet_audit_guard_ddl;

-- Everything of the guard lives in a schema of its own, owned by the superuser, so the app's schema dump never holds
-- it and the app's role cannot change it. Anyone may read what it protects (/health does).
CREATE SCHEMA IF NOT EXISTS fleet_audit_guard;
ALTER SCHEMA fleet_audit_guard OWNER TO CURRENT_USER;
REVOKE ALL ON SCHEMA fleet_audit_guard FROM PUBLIC;
GRANT USAGE ON SCHEMA fleet_audit_guard TO PUBLIC;

-- 1. The guard function belongs to the superuser.
ALTER FUNCTION public.audit_entries_append_only() OWNER TO CURRENT_USER;
ALTER FUNCTION public.audit_entries_append_only() SET search_path = pg_catalog, pg_temp;

-- 2. What is protected, by OID: kind is schema, parent, partition, or function.
CREATE TABLE IF NOT EXISTS fleet_audit_guard.protected (kind text NOT NULL, objid oid NOT NULL, PRIMARY KEY (kind, objid));
ALTER TABLE fleet_audit_guard.protected OWNER TO CURRENT_USER;
REVOKE ALL ON fleet_audit_guard.protected FROM PUBLIC;
GRANT SELECT ON fleet_audit_guard.protected TO PUBLIC;
DELETE FROM fleet_audit_guard.protected;
INSERT INTO fleet_audit_guard.protected (kind, objid)
  SELECT 'schema', c.relnamespace FROM pg_catalog.pg_class c WHERE c.oid = pg_catalog.to_regclass('public.audit_entries')
  UNION ALL SELECT 'parent', pg_catalog.to_regclass('public.audit_entries')
  UNION ALL SELECT 'partition', t.relid FROM pg_catalog.pg_partition_tree(pg_catalog.to_regclass('public.audit_entries')) t WHERE t.level > 0
  UNION ALL SELECT 'function', 'public.audit_entries_append_only()'::pg_catalog.regprocedure;

-- The table a command's object belongs to (itself for a relation), for triggers, rules, and policies.
CREATE OR REPLACE FUNCTION fleet_audit_guard.relation_of(cls oid, obj oid) RETURNS oid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE cls
    WHEN 'pg_catalog.pg_class'::pg_catalog.regclass THEN obj
    WHEN 'pg_catalog.pg_trigger'::pg_catalog.regclass THEN (SELECT t.tgrelid FROM pg_catalog.pg_trigger t WHERE t.oid = obj)
    WHEN 'pg_catalog.pg_rewrite'::pg_catalog.regclass THEN (SELECT r.ev_class FROM pg_catalog.pg_rewrite r WHERE r.oid = obj)
    WHEN 'pg_catalog.pg_policy'::pg_catalog.regclass THEN (SELECT p.polrelid FROM pg_catalog.pg_policy p WHERE p.oid = obj)
  END
$$;

CREATE OR REPLACE FUNCTION fleet_audit_guard.is_protected(cls oid, obj oid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM fleet_audit_guard.protected p
                 WHERE (p.kind IN ('parent', 'partition') AND p.objid = fleet_audit_guard.relation_of(cls, obj))
                    OR (p.kind = 'schema' AND cls = 'pg_catalog.pg_namespace'::pg_catalog.regclass AND p.objid = obj)
                    OR (p.kind = 'function' AND cls = 'pg_catalog.pg_proc'::pg_catalog.regclass AND p.objid = obj))
$$;

-- 3. No command on anything protected, except a new partition of audit_entries and its truncate guard.
CREATE OR REPLACE FUNCTION fleet_audit_guard.refuse_ddl() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  command record;
  added record;
  parent oid := (SELECT p.objid FROM fleet_audit_guard.protected p WHERE p.kind = 'parent');
  guard oid := (SELECT p.objid FROM fleet_audit_guard.protected p WHERE p.kind = 'function');
BEGIN
  FOR command IN SELECT * FROM pg_catalog.pg_event_trigger_ddl_commands() LOOP
    -- A new partition of the audit log: recorded, and given its truncate guard (a statement trigger is not cloned).
    IF command.command_tag = 'CREATE TABLE' AND command.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_inherits i JOIN fleet_audit_guard.protected p ON p.objid = i.inhparent AND p.kind IN ('parent', 'partition')
                   WHERE i.inhrelid = command.objid) THEN
      INSERT INTO fleet_audit_guard.protected (kind, objid) VALUES ('partition', command.objid) ON CONFLICT DO NOTHING;
      IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid = command.objid AND t.tgtype = 34 AND t.tgfoid = guard) THEN
        EXECUTE pg_catalog.format('CREATE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION %s()',
                                  command.objid::pg_catalog.regclass, guard::pg_catalog.regproc);
      END IF;
      CONTINUE;
    END IF;
    IF command.classid = 'pg_catalog.pg_trigger'::pg_catalog.regclass AND command.command_tag = 'CREATE TRIGGER' THEN
      SELECT t.tgrelid, t.tgtype, t.tgfoid, t.tgparentid INTO added FROM pg_catalog.pg_trigger t WHERE t.oid = command.objid;
      -- The truncate guard on a partition, or a trigger PostgreSQL clones from the parent's own guard to a new partition.
      IF (added.tgtype = 34 AND added.tgfoid = guard AND added.tgrelid <> parent) OR added.tgparentid <> 0 THEN
        CONTINUE;
      END IF;
    END IF;
    IF fleet_audit_guard.is_protected(command.classid, command.objid) THEN
      RAISE EXCEPTION 'the audit log is append-only: % % is not allowed (ops/postgres/audit-guard.sql)', command.command_tag, command.object_identity
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
END
$$;

-- 4. No protected object, and no trigger, rule, or policy of a protected table, is dropped. A dropped trigger's,
--    rule's, or policy's table is found by the names the drop reports (a protected table cannot be renamed).
CREATE OR REPLACE FUNCTION fleet_audit_guard.refuse_drop() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  dropped record;
  owner_table oid;
BEGIN
  FOR dropped IN SELECT * FROM pg_catalog.pg_event_trigger_dropped_objects() LOOP
    owner_table := NULL;
    IF dropped.object_type IN ('trigger', 'rule', 'policy') AND pg_catalog.array_length(dropped.address_names, 1) >= 3 THEN
      owner_table := pg_catalog.to_regclass(pg_catalog.quote_ident(dropped.address_names[1]) || '.'
                                            || pg_catalog.quote_ident(dropped.address_names[2]));
    END IF;
    IF EXISTS (SELECT 1 FROM fleet_audit_guard.protected p
               WHERE (p.objid = dropped.objid AND (
                        (p.kind IN ('parent', 'partition') AND dropped.classid = 'pg_catalog.pg_class'::pg_catalog.regclass)
                        OR (p.kind = 'schema' AND dropped.classid = 'pg_catalog.pg_namespace'::pg_catalog.regclass)
                        OR (p.kind = 'function' AND dropped.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass)))
                  OR (p.kind IN ('parent', 'partition') AND p.objid = owner_table)) THEN
      RAISE EXCEPTION 'the audit log is append-only: % is not dropped (ops/postgres/audit-guard.sql)', dropped.object_identity
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
END
$$;

ALTER FUNCTION fleet_audit_guard.relation_of(oid, oid) OWNER TO CURRENT_USER;
ALTER FUNCTION fleet_audit_guard.is_protected(oid, oid) OWNER TO CURRENT_USER;
ALTER FUNCTION fleet_audit_guard.refuse_drop() OWNER TO CURRENT_USER;
ALTER FUNCTION fleet_audit_guard.refuse_ddl() OWNER TO CURRENT_USER;
REVOKE ALL ON FUNCTION fleet_audit_guard.relation_of(oid, oid), fleet_audit_guard.is_protected(oid, oid) FROM PUBLIC;

CREATE EVENT TRIGGER fleet_audit_guard_drop ON sql_drop
  EXECUTE FUNCTION fleet_audit_guard.refuse_drop();
CREATE EVENT TRIGGER fleet_audit_guard_ddl ON ddl_command_end
  EXECUTE FUNCTION fleet_audit_guard.refuse_ddl();

RESET search_path;
