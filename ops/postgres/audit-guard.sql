-- The audit log's hardened guard (ADR 0027, "The audit log's guards"; FR-S.3; threat model A3, C12, F-5).
--
-- Run ONCE as the PostgreSQL superuser, in the production database, AFTER the app has migrated audit_entries to a
-- partitioned table, and again after every restore (ops/backup/restore.sh leaves this file's objects out: only a
-- superuser can create an event trigger). With the official image, as its superuser whatever it is called:
--
--   docker exec -i postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d cmdb_production' < ops/postgres/audit-guard.sql
--
-- It is one transaction: it installs everything or nothing, and an error or a dropped connection leaves whatever guard
-- was there before. It is safe to run again.
--
-- It trusts nothing the app's role (the owner of audit_entries) could have prepared before it ran. It refuses to run
-- when that role could defeat any guard (a superuser; a member of pg_execute_server_program, pg_write_server_files, or
-- pg_create_subscription; CREATEROLE before PostgreSQL 16), when a fleet_audit_guard schema exists that a superuser does
-- not own, or when the audit tables carry anything but their own guards (another trigger, a WHEN condition, a disabled
-- trigger, a rule, a policy, row security, an unlogged or detaching partition, rows in a default partition). It writes
-- the guard function's body itself rather than adopting the one it finds, and every name it uses is schema-qualified,
-- with search_path pinned.
--
-- What it does, none of which the app's role can undo:
--   1. the guard function audit_entries_append_only() gets its known body and belongs to the superuser;
--   2. a default partition, audit_entries_default, owned by the superuser, refuses every row (CHECK (false)): the log
--      still fails closed when its months run out, and PostgreSQL refuses DETACH PARTITION ... CONCURRENTLY while a
--      default partition exists (the concurrent form commits its first step before any event trigger could stop it);
--   3. the id sequence belongs to the superuser, and the app's role may only use it (nextval): it cannot setval, alter,
--      or drop it;
--   4. it records by OID, in fleet_audit_guard.protected: the schema of the audit log, the parent, every partition, the
--      sequence, and the guard function. A rename cannot hide them. New partitions are recorded as they are created;
--   5. a ddl_command_end event trigger, for every command whatever its tag, refuses one whose object is a protected
--      relation, schema, or function, or a trigger, rule, or policy on a protected table (so CREATE OR REPLACE TRIGGER
--      too), or a relation named audit_entries anywhere else. One thing stays allowed: creating a plain, logged
--      partition of audit_entries for a range, with no check constraint of its own (the app does it every month),
--      which the event trigger records and gives its truncate guard itself;
--   6. an sql_drop event trigger refuses dropping any protected object, or a trigger, rule, policy, default value, or
--      constraint of a protected table.
-- Both event trigger functions run as their owner, the superuser, with search_path pinned to pg_catalog, pg_temp and
-- every name qualified, so no temporary table, function, or operator of the app's role can shadow what they read.
--
-- A later migration that alters audit_entries or its guard function needs the superuser to disable the event
-- triggers for it (ALTER EVENT TRIGGER fleet_audit_guard_ddl DISABLE; ... ENABLE), and to run this file again after.
-- That is deliberate. /health shows audit_guard as "warning" until this has run.

BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;

DO $$
DECLARE
  parent oid := pg_catalog.to_regclass('public.audit_entries');
  app name;
  problems text[] := ARRAY[]::text[];
  dangerous text;
BEGIN
  IF NOT (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) THEN
    RAISE EXCEPTION 'run ops/postgres/audit-guard.sql as the PostgreSQL superuser, not as %', current_user;
  END IF;
  IF parent IS NULL OR (SELECT c.relkind FROM pg_catalog.pg_class c WHERE c.oid = parent) <> 'p' THEN
    RAISE EXCEPTION 'audit_entries is not partitioned yet: deploy the app (its migrations convert it), then run this again';
  END IF;

  -- The app's role: no guard holds against a superuser, or a role that can become one or replay rows unguarded.
  SELECT r.rolname INTO app FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON r.oid = c.relowner WHERE c.oid = parent;
  IF (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = app) THEN
    RAISE EXCEPTION 'audit_entries is owned by a superuser (%): the app''s role must not be a superuser, or no guard can hold (see docs/operations/install-server.md)', app;
  END IF;
  FOR dangerous IN SELECT g.rolname FROM pg_catalog.pg_roles g
                   WHERE g.rolname IN ('pg_execute_server_program', 'pg_write_server_files', 'pg_create_subscription')
                     AND pg_catalog.pg_has_role(app, g.oid, 'MEMBER') LOOP
    problems := problems || pg_catalog.format('%s is a member of %s', app, dangerous);
  END LOOP;
  IF pg_catalog.current_setting('server_version_num')::int < 160000 AND (SELECT r.rolcreaterole FROM pg_catalog.pg_roles r WHERE r.rolname = app) THEN
    problems := problems || pg_catalog.format('%s has CREATEROLE, which before PostgreSQL 16 can grant itself any role', app);
  END IF;

  -- Nothing of the guard may be the app role's: it could hold a trigger that would run as the superuser below.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
             WHERE n.nspname = 'fleet_audit_guard' AND NOT r.rolsuper) THEN
    problems := problems || 'a fleet_audit_guard schema exists that no superuser owns: inspect it, then DROP SCHEMA fleet_audit_guard CASCADE'::text;
  END IF;

  -- The audit tables carry their own guards and nothing else.
  problems := problems || ARRAY(
    SELECT pg_catalog.format('trigger %s on %s is not one of the audit log''s guards', t.tgname, t.tgrelid::pg_catalog.regclass)
    FROM pg_catalog.pg_partition_tree(parent) p JOIN pg_catalog.pg_trigger t ON t.tgrelid = p.relid
    WHERE NOT t.tgisinternal
      AND NOT (t.tgfoid = 'public.audit_entries_append_only()'::pg_catalog.regprocedure AND t.tgqual IS NULL AND t.tgenabled = 'O' AND t.tgnargs = 0
               AND ((p.level = 0 AND t.tgname = 'audit_entries_no_update_or_delete' AND t.tgtype = 27)
                    OR (p.level = 0 AND t.tgname = 'audit_entries_no_truncate' AND t.tgtype = 34)
                    OR (p.level > 0 AND t.tgname = 'audit_entries_no_update_or_delete' AND t.tgtype = 27 AND t.tgparentid <> 0)
                    OR (p.level > 0 AND t.tgname = 'audit_entries_partition_no_truncate' AND t.tgtype = 34))));
  problems := problems || ARRAY(
    SELECT pg_catalog.format('%s has a rule', r.ev_class::pg_catalog.regclass) FROM pg_catalog.pg_rewrite r
    WHERE r.ev_class IN (SELECT p.relid FROM pg_catalog.pg_partition_tree(parent) p));
  problems := problems || ARRAY(
    SELECT pg_catalog.format('%s has a row security policy', p.polrelid::pg_catalog.regclass) FROM pg_catalog.pg_policy p
    WHERE p.polrelid IN (SELECT t.relid FROM pg_catalog.pg_partition_tree(parent) t));
  problems := problems || ARRAY(
    SELECT pg_catalog.format('%s %s', c.oid::pg_catalog.regclass,
             CASE WHEN c.relrowsecurity THEN 'has row security on' WHEN c.relpersistence <> 'p' THEN 'is not a logged table'
                  WHEN c.relkind NOT IN ('r', 'p') THEN 'is not a plain table' ELSE 'is detaching' END)
    FROM pg_catalog.pg_partition_tree(parent) t JOIN pg_catalog.pg_class c ON c.oid = t.relid
    LEFT JOIN pg_catalog.pg_inherits i ON i.inhrelid = c.oid
    WHERE c.relrowsecurity OR c.relpersistence <> 'p' OR c.relkind NOT IN ('r', 'p') OR COALESCE(i.inhdetachpending, false));
  problems := problems || ARRAY(
    SELECT pg_catalog.format('%s is being detached (a DETACH ... CONCURRENTLY that did not finish): the superuser finishes or reverts it first', i.inhrelid::pg_catalog.regclass)
    FROM pg_catalog.pg_inherits i WHERE i.inhparent = parent AND i.inhdetachpending);
  problems := problems || ARRAY(
    SELECT pg_catalog.format('%s is a default partition other than audit_entries_default with CHECK (false): drop it once it is empty', c.oid::pg_catalog.regclass)
    FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
    WHERE i.inhparent = parent AND pg_catalog.pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'
      AND (c.relname <> 'audit_entries_default' OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint k
                                                               WHERE k.conrelid = c.oid AND k.contype = 'c' AND pg_catalog.pg_get_constraintdef(k.oid) = 'CHECK (false)')));

  IF pg_catalog.array_length(problems, 1) > 0 THEN
    RAISE EXCEPTION 'the audit guard was not installed: %', pg_catalog.array_to_string(problems, '; ');
  END IF;
END
$$;

-- While this runs, the guard must not stop the superuser changing what it protects. All in this transaction.
DROP EVENT TRIGGER IF EXISTS fleet_audit_guard_drop;
DROP EVENT TRIGGER IF EXISTS fleet_audit_guard_ddl;

-- Everything of the guard lives in a schema of its own, owned by the superuser and built afresh, so the app's schema dump
-- never holds it and the app's role can change none of it. Anyone may read what it protects (/health does).
DROP SCHEMA IF EXISTS fleet_audit_guard CASCADE;
CREATE SCHEMA fleet_audit_guard AUTHORIZATION CURRENT_USER;
REVOKE ALL ON SCHEMA fleet_audit_guard FROM PUBLIC;
GRANT USAGE ON SCHEMA fleet_audit_guard TO PUBLIC;

-- 1. The guard function, from its known body, the superuser's. Its triggers keep calling it by OID.
CREATE OR REPLACE FUNCTION public.audit_entries_append_only() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'audit_entries is append-only: % is not allowed', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;
ALTER FUNCTION public.audit_entries_append_only() OWNER TO CURRENT_USER;

DO $$
DECLARE
  parent oid := pg_catalog.to_regclass('public.audit_entries');
  app name := (SELECT r.rolname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON r.oid = c.relowner WHERE c.oid = parent);
  seq oid;
  part oid;
  max_id bigint;
BEGIN
  -- 2. A default partition that refuses every row, the superuser's. One restored as the app role's is taken over once
  --    its CHECK (false) is checked above.
  IF pg_catalog.to_regclass('public.audit_entries_default') IS NULL THEN
    CREATE TABLE public.audit_entries_default PARTITION OF public.audit_entries DEFAULT;
    ALTER TABLE public.audit_entries_default ADD CONSTRAINT audit_entries_default_refuses_rows CHECK (false);
  END IF;
  ALTER TABLE public.audit_entries_default OWNER TO CURRENT_USER;
  -- Every partition has its truncate guard (one made while the guard was off may not).
  FOR part IN SELECT t.relid FROM pg_catalog.pg_partition_tree(parent) t
             WHERE t.level > 0 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger g WHERE g.tgrelid = t.relid AND g.tgname = 'audit_entries_partition_no_truncate') LOOP
    EXECUTE pg_catalog.format('CREATE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION public.audit_entries_append_only()',
                              part::pg_catalog.regclass);
  END LOOP;

  -- 3. The id sequence, found through the id column's default, the superuser's; the app's role may only use it.
  SELECT d.refobjid INTO seq
  FROM pg_catalog.pg_attrdef a JOIN pg_catalog.pg_attribute att ON att.attrelid = a.adrelid AND att.attnum = a.adnum
  JOIN pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_attrdef'::pg_catalog.regclass AND d.objid = a.oid
                             AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
  JOIN pg_catalog.pg_class s ON s.oid = d.refobjid AND s.relkind = 'S'
  WHERE a.adrelid = parent AND att.attname = 'id';
  IF seq IS NULL THEN
    RAISE EXCEPTION 'the audit guard was not installed: audit_entries.id has no sequence default';
  END IF;
  EXECUTE pg_catalog.format('SELECT max(id) FROM %s', parent::pg_catalog.regclass) INTO max_id;
  IF max_id IS NOT NULL AND max_id > (SELECT s.last_value FROM pg_catalog.pg_sequences s WHERE (s.schemaname || '.' || s.sequencename)::pg_catalog.regclass = seq) THEN
    RAISE EXCEPTION 'the audit guard was not installed: the id sequence is behind the highest id (% > its last value); ids would repeat', max_id;
  END IF;
  EXECUTE pg_catalog.format('ALTER SEQUENCE %s OWNED BY NONE', seq::pg_catalog.regclass);
  EXECUTE pg_catalog.format('ALTER SEQUENCE %s OWNER TO CURRENT_USER', seq::pg_catalog.regclass);
  EXECUTE pg_catalog.format('REVOKE ALL ON SEQUENCE %s FROM PUBLIC', seq::pg_catalog.regclass);
  EXECUTE pg_catalog.format('GRANT USAGE ON SEQUENCE %s TO %I', seq::pg_catalog.regclass, app);

  -- 4. What is protected, by OID: kind is schema, parent, partition, sequence, or function.
  CREATE TABLE fleet_audit_guard.protected (kind text NOT NULL, objid oid NOT NULL, PRIMARY KEY (kind, objid));
  INSERT INTO fleet_audit_guard.protected (kind, objid)
    SELECT 'schema', c.relnamespace FROM pg_catalog.pg_class c WHERE c.oid = parent
    UNION ALL SELECT 'parent', parent
    UNION ALL SELECT 'partition', t.relid FROM pg_catalog.pg_partition_tree(parent) t WHERE t.level > 0
    UNION ALL SELECT 'sequence', seq
    UNION ALL SELECT 'function', 'public.audit_entries_append_only()'::pg_catalog.regprocedure;
END
$$;
REVOKE ALL ON fleet_audit_guard.protected FROM PUBLIC;
GRANT SELECT ON fleet_audit_guard.protected TO PUBLIC;

-- The table a command's object belongs to (itself for a relation), for triggers, rules, and policies.
CREATE FUNCTION fleet_audit_guard.relation_of(cls oid, obj oid) RETURNS oid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE cls
    WHEN 'pg_catalog.pg_class'::pg_catalog.regclass THEN obj
    WHEN 'pg_catalog.pg_trigger'::pg_catalog.regclass THEN (SELECT t.tgrelid FROM pg_catalog.pg_trigger t WHERE t.oid = obj)
    WHEN 'pg_catalog.pg_rewrite'::pg_catalog.regclass THEN (SELECT r.ev_class FROM pg_catalog.pg_rewrite r WHERE r.oid = obj)
    WHEN 'pg_catalog.pg_policy'::pg_catalog.regclass THEN (SELECT p.polrelid FROM pg_catalog.pg_policy p WHERE p.oid = obj)
  END
$$;

CREATE FUNCTION fleet_audit_guard.is_protected(cls oid, obj oid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM fleet_audit_guard.protected p
                 WHERE (p.kind IN ('parent', 'partition', 'sequence') AND p.objid = fleet_audit_guard.relation_of(cls, obj))
                    OR (p.kind = 'schema' AND cls = 'pg_catalog.pg_namespace'::pg_catalog.regclass AND p.objid = obj)
                    OR (p.kind = 'function' AND cls = 'pg_catalog.pg_proc'::pg_catalog.regclass AND p.objid = obj))
$$;

-- 5. No command on anything protected, and no other audit_entries; a new plain partition is recorded and guarded.
CREATE FUNCTION fleet_audit_guard.refuse_ddl() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  command record;
  added record;
  replication text;
BEGIN
  FOR command IN SELECT * FROM pg_catalog.pg_event_trigger_ddl_commands() LOOP
    IF command.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
       AND (SELECT c.relname FROM pg_catalog.pg_class c WHERE c.oid = command.objid) = 'audit_entries'
       AND NOT EXISTS (SELECT 1 FROM fleet_audit_guard.protected p WHERE p.kind = 'parent' AND p.objid = command.objid) THEN
      RAISE EXCEPTION 'the audit log is append-only: no other relation may be named audit_entries (%)', command.object_identity
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- A new partition of the audit log: plain, logged, for a range, recorded, and given its truncate guard (a statement
    -- trigger is not cloned). The guard is added with event triggers paused (session_replication_role, which only a
    -- superuser may set), so no CREATE TRIGGER on an audit table is ever let through.
    IF command.command_tag = 'CREATE TABLE' AND command.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_inherits i JOIN fleet_audit_guard.protected p ON p.objid = i.inhparent AND p.kind IN ('parent', 'partition')
                   WHERE i.inhrelid = command.objid) THEN
      SELECT c.relkind, c.relpersistence, pg_catalog.pg_get_expr(c.relpartbound, c.oid) AS bound INTO added
      FROM pg_catalog.pg_class c WHERE c.oid = command.objid;
      IF added.relkind <> 'r' OR added.relpersistence <> 'p' OR added.bound = 'DEFAULT'
         OR EXISTS (SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.conrelid = command.objid AND k.contype = 'c' AND k.conislocal) THEN
        RAISE EXCEPTION 'the audit log is append-only: a partition of it must be a plain, logged table for a range, with no check of its own (%)', command.object_identity
          USING ERRCODE = 'insufficient_privilege';
      END IF;
      INSERT INTO fleet_audit_guard.protected (kind, objid) VALUES ('partition', command.objid) ON CONFLICT DO NOTHING;
      replication := pg_catalog.current_setting('session_replication_role');
      PERFORM pg_catalog.set_config('session_replication_role', 'replica', true);
      EXECUTE pg_catalog.format('CREATE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION public.audit_entries_append_only()',
                                command.objid::pg_catalog.regclass);
      PERFORM pg_catalog.set_config('session_replication_role', replication, true);
      CONTINUE;
    END IF;
    IF fleet_audit_guard.is_protected(command.classid, command.objid) THEN
      RAISE EXCEPTION 'the audit log is append-only: % % is not allowed (ops/postgres/audit-guard.sql)', command.command_tag, command.object_identity
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
END
$$;

-- 6. No protected object, and no trigger, rule, policy, default value, or constraint of a protected table, is dropped.
--    The table of such an object is found by the names the drop reports (a protected table cannot be renamed).
CREATE FUNCTION fleet_audit_guard.refuse_drop() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  dropped record;
  owner_table oid;
BEGIN
  FOR dropped IN SELECT * FROM pg_catalog.pg_event_trigger_dropped_objects() LOOP
    owner_table := NULL;
    IF dropped.object_type IN ('trigger', 'rule', 'policy', 'default value', 'table constraint') AND pg_catalog.array_length(dropped.address_names, 1) >= 2 THEN
      owner_table := pg_catalog.to_regclass(pg_catalog.quote_ident(dropped.address_names[1]) || '.' || pg_catalog.quote_ident(dropped.address_names[2]));
    END IF;
    IF EXISTS (SELECT 1 FROM fleet_audit_guard.protected p
               WHERE (p.objid = dropped.objid AND (
                        (p.kind IN ('parent', 'partition', 'sequence') AND dropped.classid = 'pg_catalog.pg_class'::pg_catalog.regclass)
                        OR (p.kind = 'schema' AND dropped.classid = 'pg_catalog.pg_namespace'::pg_catalog.regclass)
                        OR (p.kind = 'function' AND dropped.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass)))
                  OR (p.kind IN ('parent', 'partition') AND p.objid = owner_table)) THEN
      RAISE EXCEPTION 'the audit log is append-only: % is not dropped (ops/postgres/audit-guard.sql)', dropped.object_identity
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
END
$$;

REVOKE ALL ON FUNCTION fleet_audit_guard.relation_of(oid, oid), fleet_audit_guard.is_protected(oid, oid) FROM PUBLIC;

CREATE EVENT TRIGGER fleet_audit_guard_drop ON sql_drop
  EXECUTE FUNCTION fleet_audit_guard.refuse_drop();
CREATE EVENT TRIGGER fleet_audit_guard_ddl ON ddl_command_end
  EXECUTE FUNCTION fleet_audit_guard.refuse_ddl();

COMMIT;
