-- Recovery for the audit log's guard (ADR 0027, "As built" 13; second review of #249, S3). Run as the PostgreSQL
-- superuser, only when ops/postgres/audit-guard.sql refused because a partition of audit_entries has a column default
-- that uses code other than PostgreSQL's own (made before its guard refused such partitions, or while the guard was off).
-- With the guard installed, the app's role cannot drop that default itself, and the superuser must not change the audit
-- tables by hand (docs/operations/install-server.md). This file is the one safe way:
--
--   docker exec -i postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d cmdb_production' < ops/postgres/audit-guard-drop-defaults.sql
--
-- then run ops/postgres/audit-guard.sql again.
--
-- It finds those defaults from the catalogs alone, with the same test as audit-guard.sql, and drops exactly those, on
-- partitions only (a partition's own default is used only by inserts that name the partition; the app inserts through
-- the parent, whose defaults it leaves alone). Dropping a default evaluates nothing. It refuses while any event trigger
-- other than the guard's exists, pauses the guard's for its own transaction (session_replication_role), and changes
-- nothing else. One transaction; safe to run again (with nothing to drop, it says so and changes nothing).

BEGIN;
SET LOCAL ROLE NONE;
SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '5s';

DO $$
DECLARE
  parent oid := pg_catalog.to_regclass('public.audit_entries');
  found record;
  dropped int := 0;
BEGIN
  IF NOT (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) THEN
    RAISE EXCEPTION 'run ops/postgres/audit-guard-drop-defaults.sql as the PostgreSQL superuser, not as %', current_user;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_event_trigger e
             WHERE NOT (e.evtname IN ('fleet_audit_guard_drop', 'fleet_audit_guard_ddl')
                        AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace n ON n.oid = f.pronamespace
                                    JOIN pg_catalog.pg_roles fo ON fo.oid = f.proowner JOIN pg_catalog.pg_roles no ON no.oid = n.nspowner
                                    WHERE f.oid = e.evtfoid AND n.nspname = 'fleet_audit_guard' AND fo.rolsuper AND no.rolsuper))) THEN
    RAISE EXCEPTION 'event triggers other than the audit guard''s exist; ops/postgres/audit-guard.sql lists them: drop them first';
  END IF;
  IF pg_catalog.current_setting('server_version_num')::int >= 170000 THEN
    PERFORM pg_catalog.set_config('event_triggers', 'off', true);
  END IF;
  -- The guard's own event triggers fire only in the origin role; this pauses them for this transaction.
  PERFORM pg_catalog.set_config('session_replication_role', 'replica', true);
  IF parent IS NULL OR (SELECT c.relkind FROM pg_catalog.pg_class c WHERE c.oid = parent) <> 'p' THEN
    RAISE EXCEPTION 'audit_entries is not partitioned: nothing to do';
  END IF;
  LOCK TABLE public.audit_entries IN ACCESS EXCLUSIVE MODE;

  FOR found IN
    SELECT DISTINCT t.relid, att.attname
    FROM pg_catalog.pg_partition_tree(parent) t
    JOIN pg_catalog.pg_attrdef a ON a.adrelid = t.relid
    JOIN pg_catalog.pg_attribute att ON att.attrelid = a.adrelid AND att.attnum = a.adnum
    JOIN pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_attrdef'::pg_catalog.regclass AND d.objid = a.oid
    WHERE t.level > 0 AND att.attgenerated = ''
      AND d.refclassid IN ('pg_catalog.pg_proc'::pg_catalog.regclass, 'pg_catalog.pg_operator'::pg_catalog.regclass, 'pg_catalog.pg_type'::pg_catalog.regclass,
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
    ORDER BY 1, 2
  LOOP
    RAISE WARNING 'dropping the default of %.% (it uses code other than PostgreSQL''s own)', found.relid::pg_catalog.regclass, pg_catalog.quote_ident(found.attname);
    EXECUTE pg_catalog.format('ALTER TABLE %s ALTER COLUMN %I DROP DEFAULT', found.relid::pg_catalog.regclass, found.attname);
    dropped := dropped + 1;
  END LOOP;
  IF dropped = 0 THEN
    RAISE WARNING 'no partition of audit_entries has a column default using code other than PostgreSQL''s own: nothing dropped';
  END IF;
END
$$;

COMMIT;
