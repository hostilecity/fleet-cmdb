-- The audit log's hardened guard (ADR 0027, "The audit log's guards"; FR-S.3; threat model A3, C12, F-5).
--
-- Run ONCE as the PostgreSQL superuser, in the production database, AFTER the app has migrated audit_entries to a
-- partitioned table, and again after every restore (ops/backup/restore.sh leaves this file's objects out: only a
-- superuser can create an event trigger). With the official image, as its superuser whatever it is called, and
-- CONNECTED WITH event triggers off and search_path pinned (PGOPTIONS), so nothing the app's role left in the database
-- runs as the superuser when the session starts (a login event trigger, PostgreSQL 17 and later) or resolves a name.
-- PostgreSQL 17 and later (the file refuses to run in a session that connected without event_triggers=off):
--
--   docker exec -i -e PGOPTIONS='-c event_triggers=off -c search_path=pg_catalog,pg_temp' postgres \
--     sh -c 'psql -X -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d cmdb_production' < ops/postgres/audit-guard.sql
--
-- PostgreSQL 16, which has no login event triggers and refuses that setting at connect:
--
--   docker exec -i -e PGOPTIONS='-c search_path=pg_catalog,pg_temp' postgres \
--     sh -c 'psql -X -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d cmdb_production' < ops/postgres/audit-guard.sql
--
-- It is one transaction: it installs everything or nothing, and an error or a dropped connection leaves whatever guard
-- was there before. It is safe to run again. It locks the audit tables first (ACCESS EXCLUSIVE, so nothing changes them
-- between its checks and its changes), waiting at most 5 seconds: audit writes queue behind it for up to about 5
-- seconds (the step itself takes well under a second once it has the lock). If the lock times out (a backup holds the
-- tables for hours), run it again when the backup has finished.
--
-- It runs no code the app's role (the owner of audit_entries) could have written, and adopts nothing that role could
-- have prepared. Before it touches or queries any audit table, it checks from the catalogs alone that no index,
-- statistics object, default, constraint, partition key, or column type of an audit table uses a function, operator,
-- or type that is not a superuser's built-in one in pg_catalog: PostgreSQL evaluates such code as whoever plans or
-- builds over the table, here the superuser (review 3 of #239, B1). Only then does it deparse anything. It also refuses
-- to run when that role could defeat any guard (a superuser, or a member of one, directly or not; a member of
-- pg_execute_server_program, pg_write_server_files, or pg_create_subscription; CREATEROLE before PostgreSQL 16), when a
-- fleet_audit_guard schema exists that a superuser does not own, when the audit tables carry anything but their own
-- guards (another trigger, a WHEN condition, a disabled trigger, a rule, a policy, row security, an unlogged or
-- detaching partition), or when a table named audit_entries_default is anything but the superuser's default partition
-- refusing every row. It writes every function body itself rather than adopting one it finds, every name it uses is
-- schema-qualified, and search_path is pinned. It refuses to run while any event trigger other than its own exists
-- (each DDL statement here would run it as the superuser), and on PostgreSQL 17 and later also turns event triggers
-- off for its transaction. The catalog check is the control: its one query over the audit rows (max(id)) runs as the
-- superuser, and is safe only because that check passed.
--
-- What it does, none of which the app's role can undo:
--   1. the guard function audit_entries_append_only() gets its known body and belongs to the superuser;
--   2. a default partition, audit_entries_default, owned by the superuser, refuses every row (CHECK (false)): the log
--      still fails closed when its months run out, and PostgreSQL refuses DETACH PARTITION ... CONCURRENTLY while a
--      default partition exists (the concurrent form commits its first step before any event trigger could stop it).
--      The app's role may read it (SELECT), so its nightly pg_dump works;
--   3. the id sequence belongs to the superuser, and the app's role may only use and read it (nextval, and the
--      SELECT pg_dump needs): it cannot setval, alter, or drop it. A BEFORE INSERT trigger, the superuser's, gives every
--      new entry its id from that sequence, whatever id the insert names: no entry can repeat or choose an id. Entry
--      times cannot be checked in the database: occurred_at is the partition key, and a BEFORE trigger may not move
--      a row to another partition, so a backdated time can only be caught by reading the ids in order;
--   4. it records by OID, in fleet_audit_guard.protected: the schema of the audit log, the parent, every partition, the
--      sequence, and the guard's two trigger functions. A rename cannot hide them. New partitions are recorded as they
--      are created;
--   5. a ddl_command_end event trigger, for every command whatever its tag, refuses one whose object is a protected
--      relation, schema, or function, or an index, statistics object, trigger, rule, or policy on a protected table (so
--      CREATE OR REPLACE TRIGGER, CREATE INDEX, and CREATE STATISTICS too), or a relation or type named audit_entries
--      anywhere else. One thing stays allowed: creating a plain, logged partition of audit_entries for a range, with no
--      check constraint of its own (the app does it every month), which the event trigger records and gives its
--      truncate guard itself;
--   6. an sql_drop event trigger refuses dropping any protected object, or a trigger, rule, policy, default value, or
--      constraint of a protected table.
-- Both event trigger functions run as their owner, the superuser, with search_path pinned to pg_catalog, pg_temp and
-- every name qualified, so no temporary table, function, or operator of the app's role can shadow what they read.
--
-- The superuser must not otherwise query or alter the audit tables (psql, a migration, a restore): planning a query
-- over them runs the code their indexes name as the superuser. This file checks that first; ad hoc work does not.
-- A later migration that alters audit_entries or its guard function needs the superuser to disable the event
-- triggers for it (ALTER EVENT TRIGGER fleet_audit_guard_ddl DISABLE; ... ENABLE), and to run this file again after.
-- That is deliberate. /health shows audit_guard as "warning" until this has run.

BEGIN;
-- The session's own role, even if the database or the login set another one (ALTER DATABASE ... SET role).
SET LOCAL ROLE NONE;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '5s';
-- Rebuilding the guard's schema drops its old id trigger with it; that NOTICE is expected and not shown.
SET LOCAL client_min_messages = warning;

DO $$
DECLARE
  parent oid := pg_catalog.to_regclass('public.audit_entries');
  named oid := pg_catalog.to_regclass('public.audit_entries_default');
  app_oid oid;
  app name;
  defpart oid;
  problems text[] := ARRAY[]::text[];
  found text[];
  dangerous text;
BEGIN
  -- The code check (B1 of review 3 of #239), written once: run below, and installed as fleet_audit_guard.untrusted_code()
  -- for ops/postgres/audit-guard-recover.sql and /health, so all three flag exactly the same objects. $1 is the parent.
  PERFORM pg_catalog.set_config('fleet_audit_guard.code_check', $q$
    WITH tree AS (SELECT t.relid FROM pg_catalog.pg_partition_tree($1) t),
    -- A partition's copies of the parent's indexes, constraints, and defaults are left out: the parent's is listed once.
    attached (classid, objid) AS (
      SELECT 'pg_catalog.pg_class'::pg_catalog.regclass::pg_catalog.oid, t.relid FROM tree t
      UNION ALL SELECT 'pg_catalog.pg_class'::pg_catalog.regclass, i.indexrelid FROM pg_catalog.pg_index i JOIN tree t ON t.relid = i.indrelid
                WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_inherits h WHERE h.inhrelid = i.indexrelid)
      UNION ALL SELECT 'pg_catalog.pg_statistic_ext'::pg_catalog.regclass, s.oid FROM pg_catalog.pg_statistic_ext s JOIN tree t ON t.relid = s.stxrelid
      UNION ALL SELECT 'pg_catalog.pg_constraint'::pg_catalog.regclass, k.oid FROM pg_catalog.pg_constraint k JOIN tree t ON t.relid = k.conrelid
                WHERE k.conparentid = 0
      UNION ALL SELECT 'pg_catalog.pg_attrdef'::pg_catalog.regclass, a.oid FROM pg_catalog.pg_attrdef a JOIN tree t ON t.relid = a.adrelid
                WHERE a.adrelid = $1 OR NOT EXISTS (
                  SELECT 1 FROM pg_catalog.pg_attribute pa JOIN pg_catalog.pg_attribute ca ON ca.attname = pa.attname
                  JOIN pg_catalog.pg_attrdef pd ON pd.adrelid = pa.attrelid AND pd.adnum = pa.attnum
                  WHERE pa.attrelid = $1 AND ca.attrelid = a.adrelid AND ca.attnum = a.adnum AND pd.adbin::text = a.adbin::text))
    SELECT DISTINCT a.classid, a.objid, d.objsubid,
           pg_catalog.format('%s uses %s', pg_catalog.pg_describe_object(a.classid, a.objid, d.objsubid), pg_catalog.pg_describe_object(d.refclassid, d.refobjid, 0)) AS what
    FROM attached a JOIN pg_catalog.pg_depend d ON d.classid = a.classid AND d.objid = a.objid
    WHERE d.refclassid IN ('pg_catalog.pg_proc'::pg_catalog.regclass, 'pg_catalog.pg_operator'::pg_catalog.regclass, 'pg_catalog.pg_type'::pg_catalog.regclass,
                           'pg_catalog.pg_opclass'::pg_catalog.regclass, 'pg_catalog.pg_opfamily'::pg_catalog.regclass)
      AND NOT COALESCE(CASE d.refclassid
        WHEN 'pg_catalog.pg_proc'::pg_catalog.regclass THEN (SELECT o.pronamespace = 'pg_catalog'::pg_catalog.regnamespace AND r.rolsuper
                                                          FROM pg_catalog.pg_proc o JOIN pg_catalog.pg_roles r ON r.oid = o.proowner WHERE o.oid = d.refobjid)
        WHEN 'pg_catalog.pg_operator'::pg_catalog.regclass THEN (SELECT o.oprnamespace = 'pg_catalog'::pg_catalog.regnamespace AND r.rolsuper
                                                              FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_roles r ON r.oid = o.oprowner WHERE o.oid = d.refobjid)
        WHEN 'pg_catalog.pg_type'::pg_catalog.regclass THEN (SELECT o.typnamespace = 'pg_catalog'::pg_catalog.regnamespace AND r.rolsuper
                                                          FROM pg_catalog.pg_type o JOIN pg_catalog.pg_roles r ON r.oid = o.typowner WHERE o.oid = d.refobjid)
        WHEN 'pg_catalog.pg_opclass'::pg_catalog.regclass THEN (SELECT o.opcnamespace = 'pg_catalog'::pg_catalog.regnamespace AND r.rolsuper
                                                             FROM pg_catalog.pg_opclass o JOIN pg_catalog.pg_roles r ON r.oid = o.opcowner WHERE o.oid = d.refobjid)
        WHEN 'pg_catalog.pg_opfamily'::pg_catalog.regclass THEN (SELECT o.opfnamespace = 'pg_catalog'::pg_catalog.regnamespace AND r.rolsuper
                                                              FROM pg_catalog.pg_opfamily o JOIN pg_catalog.pg_roles r ON r.oid = o.opfowner WHERE o.oid = d.refobjid)
      END, false)
$q$, true);
  IF NOT (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) THEN
    RAISE EXCEPTION 'run ops/postgres/audit-guard.sql as the PostgreSQL superuser, not as %', current_user;
  END IF;
  -- PostgreSQL 17 and later: a login event trigger fires when a session connects, before anything here runs, as the
  -- connecting superuser (final check of #249, B1). Only a session that connected with event_triggers=off is safe, so
  -- refuse any other: the operator then connects as install-server.md says.
  IF pg_catalog.current_setting('server_version_num')::int >= 170000 AND pg_catalog.current_setting('event_triggers') <> 'off' THEN
    RAISE EXCEPTION 'connect with event triggers off: this session connected with them on, so a login event trigger in this database may already have run as the superuser'
      USING HINT = 'Run it as docs/operations/install-server.md says, with PGOPTIONS=''-c event_triggers=off -c search_path=pg_catalog,pg_temp''. If an event trigger other than fleet_audit_guard_* exists, drop it in a session connected that way, then run this again.';
  END IF;
  -- No event trigger but the guard's own may exist: every DDL statement below would run it as the superuser, and one
  -- made by a role that was a superuser at the time (a container created with POSTGRES_USER=cmdb, then demoted) keeps
  -- running that role's function (second review of #249, S1). On PostgreSQL 17 and later event triggers are already off
  -- for this session (checked above), and a login trigger is named as such; before 17, this refusal is the only control.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_event_trigger e
             WHERE NOT (e.evtname IN ('fleet_audit_guard_drop', 'fleet_audit_guard_ddl')
                        AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace n ON n.oid = f.pronamespace
                                    JOIN pg_catalog.pg_roles fo ON fo.oid = f.proowner JOIN pg_catalog.pg_roles no ON no.oid = n.nspowner
                                    WHERE f.oid = e.evtfoid AND n.nspname = 'fleet_audit_guard' AND fo.rolsuper AND no.rolsuper))) THEN
    RAISE EXCEPTION 'the audit guard was not installed: event triggers other than the guard''s exist (%), and this file''s DDL would run them as the superuser: inspect them, then drop them (DROP EVENT TRIGGER) or move what they do elsewhere',
      (SELECT pg_catalog.string_agg(pg_catalog.format('%s, on %s%s, owned by %s, running %s', e.evtname, e.evtevent,
                                                      CASE WHEN e.evtevent = 'login' THEN ' (it runs as whoever connects, every superuser included)' ELSE '' END,
                                                      e.evtowner::pg_catalog.regrole, e.evtfoid::pg_catalog.regprocedure), '; ' ORDER BY e.evtname)
       FROM pg_catalog.pg_event_trigger e
       WHERE NOT (e.evtname IN ('fleet_audit_guard_drop', 'fleet_audit_guard_ddl')
                  AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace n ON n.oid = f.pronamespace
                              JOIN pg_catalog.pg_roles fo ON fo.oid = f.proowner JOIN pg_catalog.pg_roles no ON no.oid = n.nspowner
                              WHERE f.oid = e.evtfoid AND n.nspname = 'fleet_audit_guard' AND fo.rolsuper AND no.rolsuper)));
  END IF;
  IF parent IS NULL OR (SELECT c.relkind FROM pg_catalog.pg_class c WHERE c.oid = parent) <> 'p' THEN
    RAISE EXCEPTION 'audit_entries is not partitioned yet: deploy the app (its migrations convert it), then run this again';
  END IF;
  -- The parent and every partition, held to the end: no index, statistics object, trigger, constraint, or partition can
  -- be added between the checks below and the changes after them (review of #249). Taking a lock runs no code.
  LOCK TABLE public.audit_entries IN ACCESS EXCLUSIVE MODE;

  -- The app's role: no guard holds against a superuser, or a role that can become one or replay rows unguarded.
  SELECT r.oid, r.rolname INTO app_oid, app FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON r.oid = c.relowner WHERE c.oid = parent;
  IF (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.oid = app_oid) THEN
    RAISE EXCEPTION 'audit_entries is owned by a superuser (%): the app''s role must not be a superuser, or no guard can hold (see docs/operations/install-server.md)', app;
  END IF;
  -- A member of a superuser role, directly or through other roles, can SET ROLE to it (review 3 of #239, S1).
  FOR dangerous IN SELECT g.rolname || CASE WHEN g.rolsuper THEN ', a superuser' ELSE '' END FROM pg_catalog.pg_roles g
                   WHERE g.oid <> app_oid AND (g.rolsuper OR g.rolname IN ('pg_execute_server_program', 'pg_write_server_files', 'pg_create_subscription'))
                     AND pg_catalog.pg_has_role(app_oid, g.oid, 'MEMBER') ORDER BY 1 LOOP
    problems := problems || pg_catalog.format('%s is a member of %s', app, dangerous);
  END LOOP;
  IF pg_catalog.current_setting('server_version_num')::int < 160000 AND (SELECT r.rolcreaterole FROM pg_catalog.pg_roles r WHERE r.oid = app_oid) THEN
    problems := problems || pg_catalog.format('%s has CREATEROLE, which before PostgreSQL 16 can grant itself any role', app);
  END IF;

  -- Nothing of the guard may be the app role's: it could hold a trigger that would run as the superuser below.
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
             WHERE n.nspname = 'fleet_audit_guard' AND NOT r.rolsuper) THEN
    problems := problems || 'a fleet_audit_guard schema exists that no superuser owns: inspect it, then DROP SCHEMA fleet_audit_guard CASCADE'::text;
  END IF;

  -- No code but a superuser's built-ins on the audit tables, found from the catalogs alone (review 3 of #239, B1): the
  -- planner folds an immutable function with constant arguments in an index predicate or expression, or in a statistics
  -- expression, and an index build or a new partition's cloned indexes evaluate them, all as the session's user. So an
  -- index, statistics object, constraint, or default of a table in the tree, or the tables themselves (their column types
  -- and partition key), must use no function, operator, operator class or family, or type that is not in pg_catalog
  -- and a superuser's. Triggers are checked exactly below, and their function is rewritten before anything could fire one.
  EXECUTE 'SELECT pg_catalog.array_agg(u.what ORDER BY u.what) FROM (' || pg_catalog.current_setting('fleet_audit_guard.code_check') || ') u'
    INTO found USING parent;
  problems := problems || COALESCE(found, ARRAY[]::text[]);
  -- Nothing below deparses an expression (pg_get_expr, pg_get_constraintdef) unless that check found nothing.
  IF pg_catalog.array_length(problems, 1) > 0 THEN
    RAISE EXCEPTION 'the audit guard was not installed: %', pg_catalog.array_to_string(problems, '; ')
      USING HINT = 'Code other than PostgreSQL''s own on an audit table would run as the superuser here. Before the guard is installed, drop each object named as the app''s role, never as the superuser. Once it is installed, the app''s role may still drop an index or statistics object; a column default or constraint is dropped with ops/postgres/audit-guard-recover.sql (docs/operations/install-server.md).';
  END IF;

  -- The audit tables carry their own guards and nothing else: the append-only triggers, and the id trigger of an earlier
  -- run (its function in the superuser's fleet_audit_guard, which is rebuilt below).
  problems := problems || ARRAY(
    SELECT pg_catalog.format('trigger %s on %s is not one of the audit log''s guards', t.tgname, t.tgrelid::pg_catalog.regclass)
    FROM pg_catalog.pg_partition_tree(parent) p JOIN pg_catalog.pg_trigger t ON t.tgrelid = p.relid
    WHERE NOT t.tgisinternal
      AND NOT (t.tgqual IS NULL AND t.tgenabled = 'O' AND t.tgnargs = 0
               AND ((t.tgfoid = 'public.audit_entries_append_only()'::pg_catalog.regprocedure
                     AND ((p.level = 0 AND t.tgname = 'audit_entries_no_update_or_delete' AND t.tgtype = 27)
                          OR (p.level = 0 AND t.tgname = 'audit_entries_no_truncate' AND t.tgtype = 34)
                          OR (p.level > 0 AND t.tgname = 'audit_entries_no_update_or_delete' AND t.tgtype = 27 AND t.tgparentid <> 0)
                          OR (p.level > 0 AND t.tgname = 'audit_entries_partition_no_truncate' AND t.tgtype = 34)))
                    OR (t.tgfoid = pg_catalog.to_regprocedure('fleet_audit_guard.audit_entries_id()') AND t.tgname = 'audit_entries_id_from_sequence'
                        AND t.tgtype = 7 AND (p.level = 0) = (t.tgparentid = 0)))));
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

  -- The default partition, matched by OID (review 3 of #239, B2): public.audit_entries_default is either absent (it is
  -- made below) or already the superuser's default partition of audit_entries refusing every row, and no other table is
  -- the default. A restore leaves it out (ops/backup/restore.sh), so this file makes a new one.
  SELECT pt.partdefid INTO defpart FROM pg_catalog.pg_partitioned_table pt WHERE pt.partrelid = parent;
  IF named IS NOT NULL AND named IS DISTINCT FROM defpart THEN
    problems := problems || 'public.audit_entries_default exists but is not the default partition of audit_entries: inspect it, then drop or rename it'::text;
  ELSIF named IS NOT NULL AND NOT (SELECT r.rolsuper FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON r.oid = c.relowner WHERE c.oid = named) THEN
    problems := problems || 'public.audit_entries_default is not the superuser''s: inspect it, then drop it once it is empty (this file makes a new one)'::text;
  ELSIF named IS NOT NULL AND (SELECT pg_catalog.array_agg(pg_catalog.pg_get_constraintdef(k.oid)) FROM pg_catalog.pg_constraint k
                               WHERE k.conrelid = named AND k.contype = 'c' AND k.conislocal) IS DISTINCT FROM ARRAY['CHECK (false)'] THEN
    problems := problems || 'public.audit_entries_default has checks of its own other than one CHECK (false): inspect it, then drop it once it is empty (this file makes a new one)'::text;
  END IF;
  IF defpart IS NOT NULL AND defpart <> 0 AND defpart IS DISTINCT FROM named THEN
    problems := problems || pg_catalog.format('%s is a default partition of audit_entries other than public.audit_entries_default: drop it once it is empty', defpart::pg_catalog.regclass);
  END IF;

  IF pg_catalog.array_length(problems, 1) > 0 THEN
    RAISE EXCEPTION 'the audit guard was not installed: %', pg_catalog.array_to_string(problems, '; ');
  END IF;
END
$$;

-- While this runs, the guard must not stop the superuser changing what it protects. All in this transaction.
DROP EVENT TRIGGER IF EXISTS fleet_audit_guard_drop;
DROP EVENT TRIGGER IF EXISTS fleet_audit_guard_ddl;

-- Everything of the guard lives in a schema of its own, owned by the superuser and built afresh, so the app's schema dump
-- never holds it and the app's role can change none of it. Anyone may read what it protects (/health does). Dropping
-- it drops an earlier run's id trigger with its function; both are made again below.
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
  grantee oid;
  max_id bigint;
  last_id bigint;
BEGIN
  -- 2. A default partition that refuses every row, the superuser's, which the app's role may read (its pg_dump does:
  --    review 3 of #239, B3). One already there passed the checks above.
  IF pg_catalog.to_regclass('public.audit_entries_default') IS NULL THEN
    CREATE TABLE public.audit_entries_default PARTITION OF public.audit_entries DEFAULT;
    ALTER TABLE public.audit_entries_default ADD CONSTRAINT audit_entries_default_refuses_rows CHECK (false);
  END IF;
  ALTER TABLE public.audit_entries_default OWNER TO CURRENT_USER; -- its grants are set with the sequence's, below
  IF (SELECT pt.partdefid FROM pg_catalog.pg_partitioned_table pt WHERE pt.partrelid = parent) IS DISTINCT FROM pg_catalog.to_regclass('public.audit_entries_default') THEN
    RAISE EXCEPTION 'the audit guard was not installed: public.audit_entries_default is not the default partition of audit_entries';
  END IF;
  -- The parent's guards, if the app's role dropped them before this ran (review of #249): the row guard is cloned to
  -- every partition. Then every table of the log must have it.
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid = parent AND t.tgname = 'audit_entries_no_update_or_delete') THEN
    CREATE TRIGGER audit_entries_no_update_or_delete BEFORE UPDATE OR DELETE ON public.audit_entries FOR EACH ROW EXECUTE FUNCTION public.audit_entries_append_only();
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid = parent AND t.tgname = 'audit_entries_no_truncate') THEN
    CREATE TRIGGER audit_entries_no_truncate BEFORE TRUNCATE ON public.audit_entries FOR EACH STATEMENT EXECUTE FUNCTION public.audit_entries_append_only();
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_partition_tree(parent) t
             WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger g WHERE g.tgrelid = t.relid AND g.tgtype = 27
                                 AND g.tgfoid = 'public.audit_entries_append_only()'::pg_catalog.regprocedure)) THEN
    RAISE EXCEPTION 'the audit guard was not installed: a table of the audit log has no update and delete guard';
  END IF;
  -- Every partition has its truncate guard (one made while the guard was off may not).
  FOR part IN SELECT t.relid FROM pg_catalog.pg_partition_tree(parent) t
             WHERE t.level > 0 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger g WHERE g.tgrelid = t.relid AND g.tgname = 'audit_entries_partition_no_truncate') LOOP
    EXECUTE pg_catalog.format('CREATE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION public.audit_entries_append_only()',
                              part::pg_catalog.regclass);
  END LOOP;

  -- 3. The id sequence, found through the id column's default, the superuser's; the app's role may only use and read it.
  SELECT d.refobjid INTO seq
  FROM pg_catalog.pg_attrdef a JOIN pg_catalog.pg_attribute att ON att.attrelid = a.adrelid AND att.attnum = a.adnum
  JOIN pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_attrdef'::pg_catalog.regclass AND d.objid = a.oid
                             AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
  JOIN pg_catalog.pg_class s ON s.oid = d.refobjid AND s.relkind = 'S'
  WHERE a.adrelid = parent AND att.attname = 'id';
  IF seq IS NULL THEN
    RAISE EXCEPTION 'the audit guard was not installed: audit_entries.id has no sequence default';
  END IF;
  -- Taken over first, so the app's role can no longer alter it while it is checked; then no grant is left but the app
  -- role's USAGE and SELECT: ownership moves a role's grants with it, and REVOKE ... FROM PUBLIC leaves the rest (a grant
  -- of UPDATE to pg_database_owner, which the database's owner belongs to, would allow setval: review of #249).
  EXECUTE pg_catalog.format('ALTER SEQUENCE %s OWNED BY NONE', seq::pg_catalog.regclass);
  EXECUTE pg_catalog.format('ALTER SEQUENCE %s OWNER TO CURRENT_USER', seq::pg_catalog.regclass);
  FOR grantee IN SELECT DISTINCT a.grantee FROM pg_catalog.pg_class c, pg_catalog.aclexplode(c.relacl) a
                 WHERE c.oid IN (seq, pg_catalog.to_regclass('public.audit_entries_default')) AND a.grantee <> c.relowner LOOP
    EXECUTE pg_catalog.format('REVOKE ALL ON SEQUENCE %s FROM %s CASCADE', seq::pg_catalog.regclass,
                              CASE WHEN grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.quote_ident((SELECT r.rolname FROM pg_catalog.pg_roles r WHERE r.oid = grantee)) END);
    EXECUTE pg_catalog.format('REVOKE ALL ON public.audit_entries_default FROM %s CASCADE',
                              CASE WHEN grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.quote_ident((SELECT r.rolname FROM pg_catalog.pg_roles r WHERE r.oid = grantee)) END);
  END LOOP;
  EXECUTE pg_catalog.format('GRANT USAGE, SELECT ON SEQUENCE %s TO %I', seq::pg_catalog.regclass, app);
  EXECUTE pg_catalog.format('GRANT SELECT ON public.audit_entries_default TO %I', app);
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE pg_catalog.pg_has_role(app, r.oid, 'MEMBER')
               AND (pg_catalog.has_sequence_privilege(r.oid, seq, 'UPDATE')
                    OR pg_catalog.has_table_privilege(r.oid, 'public.audit_entries_default', 'INSERT, UPDATE, DELETE, TRUNCATE'))) THEN
    RAISE EXCEPTION 'the audit guard was not installed: % or a role it belongs to can still reset the id sequence or write the default partition', app;
  END IF;
  -- It must be logged: an unlogged sequence restarts at its first value after a crash or a replica's promotion, and the
  -- id trigger would hand out old ids again (second review of #249, S2). Now the superuser's, and protected, its
  -- persistence cannot be changed by the app's role.
  IF (SELECT c.relpersistence FROM pg_catalog.pg_class c WHERE c.oid = seq) <> 'p' THEN
    RAISE EXCEPTION 'the audit guard was not installed: the id sequence % is not logged, so it would restart after a crash and ids would repeat (ALTER SEQUENCE ... SET LOGGED, as the app''s role, first)', seq::pg_catalog.regclass;
  END IF;
  -- It must count up and never wrap round, or the id trigger would hand out old ids again (review of #249).
  IF NOT (SELECT s.seqincrement > 0 AND NOT s.seqcycle FROM pg_catalog.pg_sequence s WHERE s.seqrelid = seq) THEN
    RAISE EXCEPTION 'the audit guard was not installed: the id sequence % counts down or cycles; ids would repeat (ALTER SEQUENCE ... INCREMENT BY 1 NO CYCLE, as the app''s role, first)', seq::pg_catalog.regclass;
  END IF;
  -- The one query over the audit rows, as the superuser. It is safe only because the catalog check above found no code
  -- of the app's role on these tables, and the lock keeps it so; switching to the app's role would not be a boundary
  -- (code run after SET ROLE can SET ROLE NONE back: second review of #249, N1). The sequence is read by OID: a name could
  -- be mixed-case or shadowed (review 3 of #239, S2). pg_sequence_last_value is NULL before the first nextval.
  EXECUTE pg_catalog.format('SELECT max(id) FROM %s', parent::pg_catalog.regclass) INTO max_id;
  last_id := pg_catalog.pg_sequence_last_value(seq);
  IF max_id IS NOT NULL AND max_id > COALESCE(last_id, 0) THEN
    RAISE EXCEPTION 'the audit guard was not installed: the id sequence % is behind the highest id (% > %); ids would repeat', seq::pg_catalog.regclass, max_id, COALESCE(last_id, 0);
  END IF;

  -- Every new entry's id comes from that sequence, by OID (the owner's decision, 2026-11-18; review 3 of #239, S2). The
  -- function runs as the inserting role, which may use the sequence. Cloned to every partition, new ones included.
  -- ops/backup/restore.sh leaves the trigger out with this schema; this file adds it again after a restore.
  EXECUTE pg_catalog.format($f$
    CREATE FUNCTION fleet_audit_guard.audit_entries_id() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $b$
    BEGIN
      NEW.id := pg_catalog.nextval(%s::pg_catalog.oid::pg_catalog.regclass);
      RETURN NEW;
    END
    $b$
  $f$, seq::pg_catalog.oid);
  CREATE TRIGGER audit_entries_id_from_sequence BEFORE INSERT ON public.audit_entries FOR EACH ROW EXECUTE FUNCTION fleet_audit_guard.audit_entries_id();

  -- The code check above, for the recovery file and /health: catalog reads only, as the caller.
  EXECUTE pg_catalog.format('CREATE FUNCTION fleet_audit_guard.untrusted_code(parent oid) RETURNS TABLE (classid oid, objid oid, objsubid integer, what text) '
                            'LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS %L', pg_catalog.current_setting('fleet_audit_guard.code_check'));

  -- 4. What is protected, by OID: kind is schema, parent, partition, sequence, or function.
  CREATE TABLE fleet_audit_guard.protected (kind text NOT NULL, objid oid NOT NULL, PRIMARY KEY (kind, objid));
  INSERT INTO fleet_audit_guard.protected (kind, objid)
    SELECT 'schema', c.relnamespace FROM pg_catalog.pg_class c WHERE c.oid = parent
    UNION ALL SELECT 'parent', parent
    UNION ALL SELECT 'partition', t.relid FROM pg_catalog.pg_partition_tree(parent) t WHERE t.level > 0
    UNION ALL SELECT 'sequence', seq
    UNION ALL SELECT 'function', 'public.audit_entries_append_only()'::pg_catalog.regprocedure
    UNION ALL SELECT 'function', 'fleet_audit_guard.audit_entries_id()'::pg_catalog.regprocedure;
END
$$;
REVOKE ALL ON fleet_audit_guard.protected FROM PUBLIC;
GRANT SELECT ON fleet_audit_guard.protected TO PUBLIC;

-- The table a command's object belongs to (itself for a table), for indexes, statistics objects, triggers, rules, and
-- policies: so CREATE INDEX and CREATE STATISTICS on an audit table are refused like any other command on it (review 3
-- of #239, B1). A new partition's cloned indexes are not separate commands.
CREATE FUNCTION fleet_audit_guard.relation_of(cls oid, obj oid) RETURNS oid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE cls
    WHEN 'pg_catalog.pg_class'::pg_catalog.regclass THEN COALESCE((SELECT i.indrelid FROM pg_catalog.pg_index i WHERE i.indexrelid = obj), obj)
    WHEN 'pg_catalog.pg_statistic_ext'::pg_catalog.regclass THEN (SELECT s.stxrelid FROM pg_catalog.pg_statistic_ext s WHERE s.oid = obj)
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

-- Whether a function, operator, operator class or family, or type a new partition's code depends on is a superuser's
-- built-in in pg_catalog (the same test as the check at the top of this file). Other kinds of object are not code.
CREATE FUNCTION fleet_audit_guard.is_builtin(cls oid, obj oid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE cls
    WHEN 'pg_catalog.pg_proc'::pg_catalog.regclass THEN COALESCE((SELECT o.pronamespace = 'pg_catalog'::pg_catalog.regnamespace AND r.rolsuper
                                                                  FROM pg_catalog.pg_proc o JOIN pg_catalog.pg_roles r ON r.oid = o.proowner WHERE o.oid = obj), false)
    WHEN 'pg_catalog.pg_operator'::pg_catalog.regclass THEN COALESCE((SELECT o.oprnamespace = 'pg_catalog'::pg_catalog.regnamespace AND r.rolsuper
                                                                      FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_roles r ON r.oid = o.oprowner WHERE o.oid = obj), false)
    WHEN 'pg_catalog.pg_type'::pg_catalog.regclass THEN COALESCE((SELECT o.typnamespace = 'pg_catalog'::pg_catalog.regnamespace AND r.rolsuper
                                                                  FROM pg_catalog.pg_type o JOIN pg_catalog.pg_roles r ON r.oid = o.typowner WHERE o.oid = obj), false)
    WHEN 'pg_catalog.pg_opclass'::pg_catalog.regclass THEN COALESCE((SELECT o.opcnamespace = 'pg_catalog'::pg_catalog.regnamespace AND r.rolsuper
                                                                     FROM pg_catalog.pg_opclass o JOIN pg_catalog.pg_roles r ON r.oid = o.opcowner WHERE o.oid = obj), false)
    WHEN 'pg_catalog.pg_opfamily'::pg_catalog.regclass THEN COALESCE((SELECT o.opfnamespace = 'pg_catalog'::pg_catalog.regnamespace AND r.rolsuper
                                                                      FROM pg_catalog.pg_opfamily o JOIN pg_catalog.pg_roles r ON r.oid = o.opfowner WHERE o.oid = obj), false)
    ELSE true
  END
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
    -- A composite type is a pg_class row too, but its command's object is the type (review 3 of #239, N1).
    IF command.classid = 'pg_catalog.pg_type'::pg_catalog.regclass
       AND (SELECT t.typname FROM pg_catalog.pg_type t WHERE t.oid = command.objid) = 'audit_entries' THEN
      RAISE EXCEPTION 'the audit log is append-only: no type may be named audit_entries (%)', command.object_identity
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- A new partition of the audit log: plain, logged, for a range (not the default, read from the catalog rather than
    -- deparsed), recorded, and given its truncate guard (a statement trigger is not cloned). The guard is added with
    -- event triggers paused (session_replication_role, which only a superuser may set), so no CREATE TRIGGER on an
    -- audit table is ever let through.
    IF command.command_tag = 'CREATE TABLE' AND command.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_inherits i JOIN fleet_audit_guard.protected p ON p.objid = i.inhparent AND p.kind IN ('parent', 'partition')
                   WHERE i.inhrelid = command.objid) THEN
      SELECT c.relkind, c.relpersistence,
             EXISTS (SELECT 1 FROM pg_catalog.pg_partitioned_table pt WHERE pt.partdefid = c.oid) AS is_default INTO added
      FROM pg_catalog.pg_class c WHERE c.oid = command.objid;
      IF added.relkind <> 'r' OR added.relpersistence <> 'p' OR added.is_default
         OR EXISTS (SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.conrelid = command.objid AND k.contype = 'c' AND k.conislocal) THEN
        RAISE EXCEPTION 'the audit log is append-only: a partition of it must be a plain, logged table for a range, with no check of its own (%)', command.object_identity
          USING ERRCODE = 'insufficient_privilege';
      END IF;
      -- Nor code other than a superuser's built-ins in its own column defaults or constraints: the next run of this file
      -- would refuse it, and the app's role could not drop it (second review of #249, S3). Catalogs only.
      IF EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                 WHERE ((d.classid = 'pg_catalog.pg_attrdef'::pg_catalog.regclass AND d.objid IN (SELECT a.oid FROM pg_catalog.pg_attrdef a WHERE a.adrelid = command.objid))
                        OR (d.classid = 'pg_catalog.pg_constraint'::pg_catalog.regclass AND d.objid IN (SELECT k.oid FROM pg_catalog.pg_constraint k WHERE k.conrelid = command.objid)))
                   AND NOT fleet_audit_guard.is_builtin(d.refclassid, d.refobjid)) THEN
        RAISE EXCEPTION 'the audit log is append-only: a partition of it may not have a column default or constraint using code other than PostgreSQL''s own (%)', command.object_identity
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
      RAISE EXCEPTION 'the audit log is append-only: % % may not be dropped (ops/postgres/audit-guard.sql)', dropped.object_type, dropped.object_identity
        USING ERRCODE = 'insufficient_privilege';
    END IF;
  END LOOP;
END
$$;

REVOKE ALL ON FUNCTION fleet_audit_guard.relation_of(oid, oid), fleet_audit_guard.is_protected(oid, oid), fleet_audit_guard.is_builtin(oid, oid) FROM PUBLIC;

CREATE EVENT TRIGGER fleet_audit_guard_drop ON sql_drop
  EXECUTE FUNCTION fleet_audit_guard.refuse_drop();
CREATE EVENT TRIGGER fleet_audit_guard_ddl ON ddl_command_end
  EXECUTE FUNCTION fleet_audit_guard.refuse_ddl();

COMMIT;
