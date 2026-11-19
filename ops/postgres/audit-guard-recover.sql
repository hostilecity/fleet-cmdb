-- Recovery for the audit log's guard (ADR 0027, "As built" 13; second review and final check of #249). Run as the
-- PostgreSQL superuser, only when ops/postgres/audit-guard.sql (or /health) names a column default or constraint on an
-- audit table that uses code other than PostgreSQL's own, and only while the guard is installed: then the app's role
-- cannot drop it, and the superuser must not change the audit tables by hand (docs/operations/install-server.md).
-- Before the guard is installed, the app's role drops such objects itself, and this file refuses to run.
--
-- Connect as for audit-guard.sql: event triggers off (PostgreSQL 17 and later) and search_path pinned.
--
--   docker exec -i -e PGOPTIONS='-c event_triggers=off -c search_path=pg_catalog,pg_temp' postgres \
--     sh -c 'psql -X -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d cmdb_production' < ops/postgres/audit-guard-recover.sql
--
-- (on PostgreSQL 16, leave out "-c event_triggers=off"), then run ops/postgres/audit-guard.sql again.
--
-- What it drops is exactly what the guard's own check flags: fleet_audit_guard.untrusted_code(), which audit-guard.sql
-- installs from the same text it checks with, restricted to column defaults and constraints. A partition's copy of the
-- parent's default is not flagged on its own: the parent's is, and dropping it on the parent drops the copies too.
-- After dropping a default on the parent, it sets the app schema's default for that column again (db/schema.rb:
-- occurred_at CURRENT_TIMESTAMP, changeset '{}', id from the guarded sequence), so audited actions keep working.
-- Dropping or setting a default, and dropping a constraint, evaluate nothing. Indexes and statistics objects it only
-- lists: the app's role may drop those itself. It pauses the guard's event triggers for its own transaction, refuses
-- while any other event trigger exists, prints each change, and changes nothing else. One transaction; safe to run again
-- (with nothing to drop, it says so and changes nothing).

BEGIN;
SET LOCAL ROLE NONE;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '5s';

DO $$
DECLARE
  parent oid := pg_catalog.to_regclass('public.audit_entries');
  seq oid;
  flagged record;
  rel oid;
  col name;
  generated "char";
  schema_default text;
  changed int := 0;
BEGIN
  IF NOT (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) THEN
    RAISE EXCEPTION 'run ops/postgres/audit-guard-recover.sql as the PostgreSQL superuser, not as %', current_user;
  END IF;
  IF pg_catalog.current_setting('server_version_num')::int >= 170000 AND pg_catalog.current_setting('event_triggers') <> 'off' THEN
    RAISE EXCEPTION 'connect with event triggers off: this session connected with them on, so a login event trigger in this database may already have run as the superuser'
      USING HINT = 'Run it as docs/operations/install-server.md says, with PGOPTIONS=''-c event_triggers=off -c search_path=pg_catalog,pg_temp''.';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_event_trigger e
             WHERE NOT (e.evtname IN ('fleet_audit_guard_drop', 'fleet_audit_guard_ddl')
                        AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace n ON n.oid = f.pronamespace
                                    JOIN pg_catalog.pg_roles fo ON fo.oid = f.proowner JOIN pg_catalog.pg_roles no ON no.oid = n.nspowner
                                    WHERE f.oid = e.evtfoid AND n.nspname = 'fleet_audit_guard' AND fo.rolsuper AND no.rolsuper))) THEN
    RAISE EXCEPTION 'event triggers other than the audit guard''s exist; ops/postgres/audit-guard.sql lists them: drop them first, connected as install-server.md says';
  END IF;
  -- Only while the guard is installed: both its event triggers, its schema and its check the superuser's.
  IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_event_trigger e WHERE e.evtname IN ('fleet_audit_guard_drop', 'fleet_audit_guard_ddl')) <> 2
     OR NOT COALESCE((SELECT r.rolsuper FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner WHERE n.nspname = 'fleet_audit_guard'), false)
     OR NOT COALESCE((SELECT r.rolsuper FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_roles r ON r.oid = f.proowner
                      WHERE f.oid = pg_catalog.to_regprocedure('fleet_audit_guard.untrusted_code(oid)')), false) THEN
    RAISE EXCEPTION 'the audit guard is not installed (or is from before this file): the app''s role drops what audit-guard.sql names itself; this file is for after the guard is installed'
      USING HINT = 'If the guard is installed but older, run ops/postgres/audit-guard.sql: it lists what it finds and installs the check this file uses.';
  END IF;
  IF parent IS NULL OR (SELECT c.relkind FROM pg_catalog.pg_class c WHERE c.oid = parent) <> 'p' THEN
    RAISE EXCEPTION 'audit_entries is not partitioned: nothing to do';
  END IF;
  -- The guard's own event triggers fire only in the origin role (on PostgreSQL 16 the only way to pause them).
  PERFORM pg_catalog.set_config('session_replication_role', 'replica', true);
  LOCK TABLE public.audit_entries IN ACCESS EXCLUSIVE MODE;
  SELECT p.objid INTO seq FROM fleet_audit_guard.protected p WHERE p.kind = 'sequence';

  FOR flagged IN
    SELECT DISTINCT ON (u.classid, u.objid) u.classid, u.objid, u.what FROM fleet_audit_guard.untrusted_code(parent) u ORDER BY u.classid, u.objid
  LOOP
    IF flagged.classid = 'pg_catalog.pg_attrdef'::pg_catalog.regclass THEN
      SELECT a.adrelid, att.attname, att.attgenerated INTO rel, col, generated
      FROM pg_catalog.pg_attrdef a JOIN pg_catalog.pg_attribute att ON att.attrelid = a.adrelid AND att.attnum = a.adnum WHERE a.oid = flagged.objid;
      IF generated <> '' THEN
        RAISE EXCEPTION '% is a generated column: it cannot be dropped this way (see install-server.md, "Recovery")', flagged.what;
      END IF;
      RAISE WARNING 'dropping: %', flagged.what;
      EXECUTE pg_catalog.format('ALTER TABLE %s ALTER COLUMN %I DROP DEFAULT', rel::pg_catalog.regclass, col);
      IF rel = parent THEN
        schema_default := CASE col WHEN 'occurred_at' THEN 'CURRENT_TIMESTAMP' WHEN 'changeset' THEN '''{}''::jsonb'
                                   WHEN 'id' THEN pg_catalog.format('pg_catalog.nextval(%s::pg_catalog.oid::pg_catalog.regclass)', seq) END;
        IF schema_default IS NOT NULL THEN
          RAISE WARNING 'setting the app''s default again: %.% DEFAULT %', rel::pg_catalog.regclass, pg_catalog.quote_ident(col), schema_default;
          EXECUTE pg_catalog.format('ALTER TABLE %s ALTER COLUMN %I SET DEFAULT %s', rel::pg_catalog.regclass, col, schema_default);
        END IF;
      END IF;
      changed := changed + 1;
    ELSIF flagged.classid = 'pg_catalog.pg_constraint'::pg_catalog.regclass THEN
      RAISE WARNING 'dropping: %', flagged.what;
      EXECUTE pg_catalog.format('ALTER TABLE %s DROP CONSTRAINT %I',
                                (SELECT k.conrelid FROM pg_catalog.pg_constraint k WHERE k.oid = flagged.objid)::pg_catalog.regclass,
                                (SELECT k.conname FROM pg_catalog.pg_constraint k WHERE k.oid = flagged.objid));
      changed := changed + 1;
    ELSE
      RAISE WARNING 'not changed here: % (an index or statistics object: the app''s role drops it; anything else: see install-server.md, "Recovery")', flagged.what;
    END IF;
  END LOOP;
  IF changed = 0 THEN
    RAISE WARNING 'no column default or constraint on the audit tables uses code other than PostgreSQL''s own: nothing dropped';
  END IF;
END
$$;

COMMIT;
