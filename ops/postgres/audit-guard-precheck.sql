-- Before the audit log's guard (ADR 0027; final check of #249, review 2): is, or was, the app's role cmdb a
-- superuser in this cluster? Run as the PostgreSQL superuser, in the postgres database (never cmdb_production, which
-- cmdb owns), connected as docs/operations/install-server.md says. PostgreSQL 17 and later:
--
--   docker exec -i -e PGOPTIONS='-c event_triggers=off -c search_path=pg_catalog,pg_temp -c role=none -c client_min_messages=warning' postgres \
--     sh -c 'psql -X -At -v ON_ERROR_STOP=1 -U "${POSTGRES_USER:-postgres}" -d postgres' < ops/postgres/audit-guard-precheck.sql
--
-- (on PostgreSQL 16, leave out "-c event_triggers=off"). It changes nothing, and reads only PostgreSQL's catalogs with
-- every name qualified. It prints one line per finding, or one line saying it found none. Any finding about superuser
-- (the first five kinds) means the cluster must be rebuilt (install-server.md, "If cmdb is or was a superuser"):
-- a role that was a superuser can leave code anywhere that later runs as the superuser, and demoting it does not
-- remove that. Finding nothing is not proof: a superuser can also change a built-in function's body, or files and
-- settings outside the database. If you know cmdb was ever a superuser (a container created with POSTGRES_USER=cmdb),
-- rebuild whatever this prints.

\set QUIET on
BEGIN;
SET LOCAL ROLE NONE;
SET LOCAL search_path = pg_catalog, pg_temp;
-- The app's role: cmdb (a spec names another with this setting).
SELECT pg_catalog.set_config('fleet_audit_guard.app_role', COALESCE(NULLIF(pg_catalog.current_setting('fleet_audit_guard.app_role', true), ''), 'cmdb'), true) \g /dev/null

WITH app AS (
  SELECT r.oid, r.rolname, r.rolsuper, r.rolcreaterole FROM pg_catalog.pg_roles r
  WHERE r.rolname = pg_catalog.current_setting('fleet_audit_guard.app_role')::pg_catalog.name
), mine AS (
  SELECT d.oid FROM pg_catalog.pg_database d, app WHERE d.datdba = app.oid AND d.datname OPERATOR(pg_catalog.~~) 'cmdb\_%'::pg_catalog.text
), tripwire AS (
-- tripwire begin
    WITH found (classid, objid, why) AS (
      SELECT 'pg_catalog.pg_class'::pg_catalog.regclass::pg_catalog.oid, o.oid, o.oid >= 16384::pg_catalog.oid FROM pg_catalog.pg_class o
        WHERE o.relnamespace = 11::pg_catalog.oid AND (o.oid >= 16384::pg_catalog.oid OR o.relowner <> 10::pg_catalog.oid)
      UNION ALL SELECT 'pg_catalog.pg_proc'::pg_catalog.regclass, o.oid, o.oid >= 16384::pg_catalog.oid FROM pg_catalog.pg_proc o
        WHERE o.pronamespace = 11::pg_catalog.oid AND (o.oid >= 16384::pg_catalog.oid OR o.proowner <> 10::pg_catalog.oid
                                                       OR o.prolang NOT IN (12::pg_catalog.oid, 13::pg_catalog.oid, 14::pg_catalog.oid))
      UNION ALL SELECT 'pg_catalog.pg_type'::pg_catalog.regclass, o.oid, o.oid >= 16384::pg_catalog.oid FROM pg_catalog.pg_type o
        WHERE o.typnamespace = 11::pg_catalog.oid AND (o.oid >= 16384::pg_catalog.oid OR o.typowner <> 10::pg_catalog.oid)
      UNION ALL SELECT 'pg_catalog.pg_operator'::pg_catalog.regclass, o.oid, o.oid >= 16384::pg_catalog.oid FROM pg_catalog.pg_operator o
        WHERE o.oprnamespace = 11::pg_catalog.oid AND (o.oid >= 16384::pg_catalog.oid OR o.oprowner <> 10::pg_catalog.oid)
      UNION ALL SELECT 'pg_catalog.pg_opclass'::pg_catalog.regclass, o.oid, o.oid >= 16384::pg_catalog.oid FROM pg_catalog.pg_opclass o
        WHERE o.opcnamespace = 11::pg_catalog.oid AND (o.oid >= 16384::pg_catalog.oid OR o.opcowner <> 10::pg_catalog.oid)
      UNION ALL SELECT 'pg_catalog.pg_opfamily'::pg_catalog.regclass, o.oid, o.oid >= 16384::pg_catalog.oid FROM pg_catalog.pg_opfamily o
        WHERE o.opfnamespace = 11::pg_catalog.oid AND (o.oid >= 16384::pg_catalog.oid OR o.opfowner <> 10::pg_catalog.oid)
      UNION ALL SELECT 'pg_catalog.pg_collation'::pg_catalog.regclass, o.oid, o.oid >= 16384::pg_catalog.oid FROM pg_catalog.pg_collation o
        WHERE o.collnamespace = 11::pg_catalog.oid AND (o.oid >= 16384::pg_catalog.oid OR o.collowner <> 10::pg_catalog.oid)
      UNION ALL SELECT 'pg_catalog.pg_conversion'::pg_catalog.regclass, o.oid, o.oid >= 16384::pg_catalog.oid FROM pg_catalog.pg_conversion o
        WHERE o.connamespace = 11::pg_catalog.oid AND (o.oid >= 16384::pg_catalog.oid OR o.conowner <> 10::pg_catalog.oid)
      UNION ALL SELECT 'pg_catalog.pg_ts_config'::pg_catalog.regclass, o.oid, o.oid >= 16384::pg_catalog.oid FROM pg_catalog.pg_ts_config o
        WHERE o.cfgnamespace = 11::pg_catalog.oid AND (o.oid >= 16384::pg_catalog.oid OR o.cfgowner <> 10::pg_catalog.oid)
      UNION ALL SELECT 'pg_catalog.pg_ts_dict'::pg_catalog.regclass, o.oid, o.oid >= 16384::pg_catalog.oid FROM pg_catalog.pg_ts_dict o
        WHERE o.dictnamespace = 11::pg_catalog.oid AND (o.oid >= 16384::pg_catalog.oid OR o.dictowner <> 10::pg_catalog.oid)
      UNION ALL SELECT 'pg_catalog.pg_ts_parser'::pg_catalog.regclass, o.oid, true FROM pg_catalog.pg_ts_parser o
        WHERE o.prsnamespace = 11::pg_catalog.oid AND o.oid >= 16384::pg_catalog.oid
      UNION ALL SELECT 'pg_catalog.pg_ts_template'::pg_catalog.regclass, o.oid, true FROM pg_catalog.pg_ts_template o
        WHERE o.tmplnamespace = 11::pg_catalog.oid AND o.oid >= 16384::pg_catalog.oid
      UNION ALL SELECT 'pg_catalog.pg_statistic_ext'::pg_catalog.regclass, o.oid, true FROM pg_catalog.pg_statistic_ext o
        WHERE o.stxnamespace = 11::pg_catalog.oid
      UNION ALL SELECT 'pg_catalog.pg_cast'::pg_catalog.regclass, o.oid, true FROM pg_catalog.pg_cast o
        JOIN pg_catalog.pg_type s ON s.oid = o.castsource JOIN pg_catalog.pg_type t ON t.oid = o.casttarget
        WHERE o.oid >= 16384::pg_catalog.oid AND s.typnamespace = 11::pg_catalog.oid AND t.typnamespace = 11::pg_catalog.oid
      UNION ALL SELECT 'pg_catalog.pg_amop'::pg_catalog.regclass, o.oid, true FROM pg_catalog.pg_amop o JOIN pg_catalog.pg_opfamily f ON f.oid = o.amopfamily
        WHERE o.oid >= 16384::pg_catalog.oid AND f.opfnamespace = 11::pg_catalog.oid
      UNION ALL SELECT 'pg_catalog.pg_amproc'::pg_catalog.regclass, o.oid, true FROM pg_catalog.pg_amproc o JOIN pg_catalog.pg_opfamily f ON f.oid = o.amprocfamily
        WHERE o.oid >= 16384::pg_catalog.oid AND f.opfnamespace = 11::pg_catalog.oid
      UNION ALL SELECT 'pg_catalog.pg_constraint'::pg_catalog.regclass, o.oid, true FROM pg_catalog.pg_constraint o
        WHERE o.connamespace = 11::pg_catalog.oid AND o.oid >= 16384::pg_catalog.oid
      UNION ALL SELECT 'pg_catalog.pg_trigger'::pg_catalog.regclass, o.oid, true FROM pg_catalog.pg_trigger o JOIN pg_catalog.pg_class c ON c.oid = o.tgrelid
        WHERE c.relnamespace = 11::pg_catalog.oid
      UNION ALL SELECT 'pg_catalog.pg_rewrite'::pg_catalog.regclass, o.oid, true FROM pg_catalog.pg_rewrite o JOIN pg_catalog.pg_class c ON c.oid = o.ev_class
        WHERE c.relnamespace = 11::pg_catalog.oid AND o.oid >= 16384::pg_catalog.oid
      UNION ALL SELECT 'pg_catalog.pg_attrdef'::pg_catalog.regclass, o.oid, true FROM pg_catalog.pg_attrdef o JOIN pg_catalog.pg_class c ON c.oid = o.adrelid
        WHERE c.relnamespace = 11::pg_catalog.oid
      UNION ALL SELECT 'pg_catalog.pg_policy'::pg_catalog.regclass, o.oid, true FROM pg_catalog.pg_policy o JOIN pg_catalog.pg_class c ON c.oid = o.polrelid
        WHERE c.relnamespace = 11::pg_catalog.oid)
    SELECT pg_catalog.format('%s %s, %s', i.type, i.identity,
                             CASE WHEN f.why THEN 'which initdb did not make' ELSE 'which is not the bootstrap superuser''s, or not in a built-in language' END) AS what
    FROM found f, LATERAL pg_catalog.pg_identify_object(f.classid, f.objid, 0) i
-- tripwire end
), findings (line) AS (
  SELECT pg_catalog.format('there is no role named %I', pg_catalog.current_setting('fleet_audit_guard.app_role')) WHERE NOT EXISTS (SELECT 1 FROM app)
  UNION ALL SELECT pg_catalog.format('%I has OID 10: it is the bootstrap superuser (the container was created with POSTGRES_USER=%I), which cannot be demoted', app.rolname, app.rolname)
    FROM app WHERE app.oid = 10::pg_catalog.oid
  UNION ALL SELECT pg_catalog.format('%I is a superuser', app.rolname) FROM app WHERE app.rolsuper AND app.oid <> 10::pg_catalog.oid
  UNION ALL SELECT pg_catalog.format('%I is a member of %I%s', app.rolname, g.rolname, CASE WHEN g.rolsuper THEN ', a superuser' ELSE '' END)
    FROM app, pg_catalog.pg_roles g
    WHERE NOT app.rolsuper AND g.oid <> app.oid AND (g.rolsuper OR g.rolname IN ('pg_execute_server_program', 'pg_write_server_files', 'pg_create_subscription'))
      AND pg_catalog.pg_has_role(app.oid, g.oid, 'MEMBER')
  UNION ALL SELECT pg_catalog.format('%I has CREATEROLE, which before PostgreSQL 16 can grant itself any role', app.rolname)
    FROM app WHERE app.rolcreaterole AND pg_catalog.current_setting('server_version_num')::int < 160000
  UNION ALL SELECT pg_catalog.format('%I owns the database %I, which only its own databases (cmdb_*) should be: it may have been a superuser', app.rolname, d.datname)
    FROM app JOIN pg_catalog.pg_database d ON d.datdba = app.oid WHERE d.oid NOT IN (SELECT mine.oid FROM mine)
  UNION ALL SELECT pg_catalog.format('%I owns %s objects in the database %I, outside its own: it may have been a superuser', app.rolname, pg_catalog.count(*), d.datname)
    FROM app JOIN pg_catalog.pg_shdepend s ON s.refobjid = app.oid AND s.deptype = 'o'
    JOIN pg_catalog.pg_database d ON d.oid = s.dbid
    WHERE s.dbid NOT IN (SELECT mine.oid FROM mine) GROUP BY app.rolname, d.datname
  UNION ALL SELECT pg_catalog.format('in the database %I, pg_catalog holds %s', pg_catalog.current_database(), tripwire.what) FROM tripwire
)
SELECT findings.line FROM findings
UNION ALL SELECT pg_catalog.format('no sign that %I is or was a superuser (this is not proof: see install-server.md)', pg_catalog.current_setting('fleet_audit_guard.app_role'))
  WHERE NOT EXISTS (SELECT 1 FROM findings);

COMMIT;
