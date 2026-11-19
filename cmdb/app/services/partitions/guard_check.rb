module Partitions
  # Whether the audit log's hardened guard (ops/postgres/audit-guard.sql, ADR 0027) holds, as the app's own connection
  # sees it, and if not, why: the first problem found, as a sentence. /health shows it as a warning, the restore drill
  # as a WARN line, and (in production) the dashboard banner.
  #
  # Besides "is it installed", it looks for the ways around it the reviews of #239 found, in case one got through before
  # the guard was installed or while it was off: a role that is as good as a superuser (a member of one included); a
  # search path or a second audit_entries that would send entries elsewhere; code other than a superuser's built-ins
  # on an audit table (an index, statistics object, constraint, default, or column type), which would run as the
  # superuser when it next runs the step (review 3, B1); a trigger that is not one of the guards, has a WHEN condition,
  # or is disabled, and a table without its truncate or id trigger; a rule, a policy, or row security; an unlogged or
  # detaching partition, one not recorded, or a recorded one no longer attached; a default partition other than the
  # superuser's that refuses every row; and an id sequence the app's role could reset, or one behind the highest id.
  # Every catalog is named with pg_catalog, and objects are found by OID, not by name.
  class GuardCheck
    TREE = "pg_catalog.pg_partition_tree('public.audit_entries'::pg_catalog.regclass)".freeze
    GUARD = "'public.audit_entries_append_only()'::pg_catalog.regprocedure".freeze
    ID_GUARD = "pg_catalog.to_regprocedure('fleet_audit_guard.audit_entries_id()')".freeze

    def initialize(connection)
      @c = connection
    end

    def problem
      role_problem("the app's PostgreSQL role", "current_user") || role_problem("the owner of audit_entries", owner_sql) ||
        search_path_problem || installed_problem || function_problem || code_problem || table_problem || trigger_problem ||
        default_problem || sequence_problem
    end

    private

    def value(sql) = @c.select_value(sql)
    def values(sql) = @c.select_values(sql)

    def owner_sql = "(SELECT c.relowner::pg_catalog.regrole::text FROM pg_catalog.pg_class c WHERE c.oid = 'public.audit_entries'::pg_catalog.regclass)"

    def role_problem(who, role)
      return "#{who} is a superuser, so no guard can hold against it" if value("SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = #{role}")

      # Membership, direct or through other roles, of a superuser role is as good as being one: SET ROLE (review 3, S1).
      member, superuser = @c.select_rows(<<~SQL.squish).first
        SELECT g.rolname, g.rolsuper FROM pg_catalog.pg_roles g
        WHERE g.rolname <> #{role} AND (g.rolsuper OR g.rolname IN (#{DANGEROUS_ROLES.map { |n| @c.quote(n) }.join(', ')}))
          AND pg_catalog.pg_has_role(#{role}, g.oid, 'MEMBER')
        ORDER BY g.rolsuper DESC, 1
      SQL
      return "#{who} is a member of the superuser role #{member}, so no guard can hold against it" if superuser
      return "#{who} is a member of #{member}, which is as good as a superuser against the guard" if member

      "#{who} has CREATEROLE, which before PostgreSQL 16 can grant itself any role" if before16? && value("SELECT r.rolcreaterole FROM pg_catalog.pg_roles r WHERE r.rolname = #{role}")
    end

    def before16? = value("SELECT pg_catalog.current_setting('server_version_num')::int < 160000")

    # Entries go to public.audit_entries only if the connection's search path says so and nothing else has its name.
    def search_path_problem
      path = value("SELECT pg_catalog.current_setting('search_path')")
      return "the app's search_path is #{path}, not public (config/database.yml sets schema_search_path)" unless path == "public"

      other = values(<<~SQL.squish).first
        SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'audit_entries' AND n.nspname <> 'public' ORDER BY 1
      SQL
      "another relation is named audit_entries (#{other})" if other
    end

    def installed_problem
      enabled = value("SELECT count(*) FROM pg_catalog.pg_event_trigger WHERE evtname IN (#{AUDIT_EVENT_TRIGGERS.map { |n| @c.quote(n) }.join(', ')}) AND evtenabled <> 'D'")
      return "the audit log's event triggers are not installed (the superuser runs ops/postgres/audit-guard.sql)" if enabled < AUDIT_EVENT_TRIGGERS.size


      owned = value(<<~SQL.squish)
        SELECT r.rolsuper FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner WHERE n.nspname = 'fleet_audit_guard'
      SQL
      return "the fleet_audit_guard schema is missing or not the superuser's (the superuser runs ops/postgres/audit-guard.sql)" unless owned

      # Any other event trigger would run as the superuser in every superuser step, this guard's included, and a role
      # that was once a superuser can have left one running its own function (second review of #249, S1).
      name, event, owner, function = @c.select_rows(<<~SQL.squish).first
        SELECT e.evtname, e.evtevent, e.evtowner::pg_catalog.regrole::text, e.evtfoid::pg_catalog.regprocedure::text
        FROM pg_catalog.pg_event_trigger e
        WHERE NOT (e.evtname IN (#{AUDIT_EVENT_TRIGGERS.map { |n| @c.quote(n) }.join(', ')})
                   AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace n ON n.oid = f.pronamespace
                               JOIN pg_catalog.pg_roles fo ON fo.oid = f.proowner JOIN pg_catalog.pg_roles no ON no.oid = n.nspowner
                               WHERE f.oid = e.evtfoid AND n.nspname = 'fleet_audit_guard' AND fo.rolsuper AND no.rolsuper))
        ORDER BY 1
      SQL
      return unless name

      # A login trigger (PostgreSQL 17 and later) runs on every connection, every superuser's included, before anything
      # the superuser types (final check of #249, B1).
      runs = event == "login" ? "it runs as whoever connects, on every connection to this database, every superuser included" : "the superuser's next step would run it as the superuser"
      "event trigger #{name} (on #{event}, owned by #{owner}, running #{function}) is not the audit guard's: #{runs}. " \
        "The superuser drops it, connected with event triggers off as install-server.md says"
    end

    def function_problem
      owner_super, definer = @c.select_rows(<<~SQL.squish).first
        SELECT r.rolsuper, p.prosecdef FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles r ON r.oid = p.proowner WHERE p.oid = #{GUARD}
      SQL
      return "the guard function audit_entries_append_only() is not owned by the superuser (run ops/postgres/audit-guard.sql)" unless owner_super

      "the guard function audit_entries_append_only() runs as its owner (SECURITY DEFINER); the superuser runs ops/postgres/audit-guard.sql again" if definer
    end

    # Exactly the guards on every table of the audit log: the row trigger and the id trigger (each cloned to every
    # partition) and the truncate guards, enabled, with no condition.
    def trigger_problem
      odd = values(<<~SQL.squish).first
        SELECT t.tgname || ' on ' || t.tgrelid::pg_catalog.regclass::text FROM #{TREE} p JOIN pg_catalog.pg_trigger t ON t.tgrelid = p.relid
        WHERE NOT t.tgisinternal
          AND NOT (t.tgqual IS NULL AND t.tgenabled = 'O' AND t.tgnargs = 0
                   AND ((t.tgfoid = #{GUARD}
                         AND ((t.tgname = 'audit_entries_no_update_or_delete' AND t.tgtype = 27 AND (p.level = 0) = (t.tgparentid = 0))
                              OR (p.level = 0 AND t.tgname = 'audit_entries_no_truncate' AND t.tgtype = 34)
                              OR (p.level > 0 AND t.tgname = 'audit_entries_partition_no_truncate' AND t.tgtype = 34)))
                        OR (t.tgfoid = #{ID_GUARD} AND t.tgname = 'audit_entries_id_from_sequence' AND t.tgtype = 7 AND (p.level = 0) = (t.tgparentid = 0))))
        ORDER BY 1
      SQL
      return "trigger #{odd} is not one of the audit log's guards as installed (a WHEN condition, disabled, or another function)" if odd

      # Each table's guards by type: update and delete (27), truncate (34), and the id trigger (7) (review of #249).
      required = { "update and delete guard" => [ 27, GUARD ], "truncate guard" => [ 34, GUARD ], "id trigger" => [ 7, ID_GUARD ] }
      absent = required.map { |_, (type, function)| "NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid = p.relid AND t.tgtype = #{type} AND t.tgfoid = #{function})" }
      bare, missing = @c.select_rows(<<~SQL.squish).first
        SELECT p.relid::pg_catalog.regclass::text,
               CASE #{required.keys.zip(absent).map { |name, sql| "WHEN #{sql} THEN #{@c.quote(name)}" }.join(' ')} END
        FROM #{TREE} p WHERE #{absent.join(' OR ')}
        ORDER BY 1
      SQL
      "#{bare} has no #{missing} (the superuser runs ops/postgres/audit-guard.sql again)" if bare
    end

    # An index, statistics object, constraint, or default of an audit table, or the table itself (a column type, the
    # partition key), that uses a function, operator, operator class or family, or type other than a superuser's
    # built-in: the planner and index builds run such code as whoever plans over the table, and the superuser does when
    # it runs the step again (review 3 of #239, B1). The check is the step's own, installed with the guard
    # (fleet_audit_guard.untrusted_code), so /health, the step, and the recovery file flag the same objects. This runs
    # only once the guard is installed (installed_problem comes first), so each remedy is one that works under it.
    def code_problem
      unless value("SELECT pg_catalog.to_regprocedure('fleet_audit_guard.untrusted_code(oid)') IS NOT NULL")
        return "the audit guard is from an older version of ops/postgres/audit-guard.sql (the superuser runs it again)"
      end

      what, kind = @c.select_rows(<<~SQL.squish).first
        SELECT u.what, CASE u.classid
                         WHEN 'pg_catalog.pg_attrdef'::pg_catalog.regclass THEN 'recover'
                         WHEN 'pg_catalog.pg_constraint'::pg_catalog.regclass THEN 'recover'
                         WHEN 'pg_catalog.pg_statistic_ext'::pg_catalog.regclass THEN 'statistics'
                         ELSE (SELECT CASE WHEN c.relkind IN ('i', 'I') THEN 'index' ELSE 'table' END FROM pg_catalog.pg_class c WHERE c.oid = u.objid)
                       END
        FROM fleet_audit_guard.untrusted_code('public.audit_entries'::pg_catalog.regclass) u ORDER BY u.what LIMIT 1
      SQL
      return invalid_index_problem unless what

      remedy = {
        "recover" => "the superuser runs ops/postgres/audit-guard-recover.sql, connected as install-server.md says",
        "index" => "the app's role drops it (DROP INDEX)", "statistics" => "the app's role drops it (DROP STATISTICS)",
        "table" => "it can only have been added while the guard was off: see install-server.md, \"Recovery\""
      }.fetch(kind)
      "#{what}, which is not a superuser's built-in: it would run as the superuser in the audit guard's step (#{remedy})"
    end

    # A CREATE INDEX CONCURRENTLY the guard refused leaves its index behind, invalid but kept up to date on every
    # insert (second review of #249, N4). The guard lets the app's role drop it.
    def invalid_index_problem
      invalid = values(<<~SQL.squish).first
        SELECT i.indexrelid::pg_catalog.regclass::text FROM pg_catalog.pg_index i JOIN #{TREE} t ON t.relid = i.indrelid
        WHERE NOT i.indisvalid ORDER BY 1
      SQL
      "index #{invalid} on the audit log is invalid (a CREATE INDEX CONCURRENTLY the guard refused leaves one behind): the app's role drops it (DROP INDEX)" if invalid
    end

    def table_problem
      # A partition left half-detached (DETACH ... CONCURRENTLY interrupted) is in pg_inherits but not in the tree.
      detaching = values(<<~SQL.squish).first
        SELECT i.inhrelid::pg_catalog.regclass::text FROM pg_catalog.pg_inherits i
        WHERE i.inhparent = 'public.audit_entries'::pg_catalog.regclass AND i.inhdetachpending ORDER BY 1
      SQL
      return "#{detaching} is being detached, so its entries are hidden" if detaching

      # A partition the guard recorded that is no longer in the tree: detached or dropped while the guard was off (review
      # 3 of #239, S1).
      gone = values(<<~SQL.squish).first
        SELECT COALESCE(c.oid::pg_catalog.regclass::text, 'the partition with OID ' || g.objid::text) FROM fleet_audit_guard.protected g
        LEFT JOIN pg_catalog.pg_class c ON c.oid = g.objid
        WHERE g.kind = 'partition' AND g.objid NOT IN (SELECT t.relid FROM #{TREE} t) ORDER BY 1
      SQL
      return "#{gone}, recorded by the audit guard, is no longer attached to audit_entries, so its entries are hidden" if gone

      odd = values(<<~SQL.squish).first
        SELECT c.oid::pg_catalog.regclass::text || CASE
                 WHEN NOT EXISTS (SELECT 1 FROM fleet_audit_guard.protected g WHERE g.objid = c.oid AND g.kind IN ('parent', 'partition')) THEN ' is not protected by the audit guard (the superuser runs ops/postgres/audit-guard.sql again)'
                 WHEN c.relpersistence <> 'p' THEN ' is not a logged table'
                 WHEN c.relrowsecurity THEN ' has row security on'
                 WHEN EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite r WHERE r.ev_class = c.oid) THEN ' has a rule'
                 ELSE ' has a row security policy' END
        FROM #{TREE} p JOIN pg_catalog.pg_class c ON c.oid = p.relid
        WHERE NOT EXISTS (SELECT 1 FROM fleet_audit_guard.protected g WHERE g.objid = c.oid AND g.kind IN ('parent', 'partition'))
           OR c.relpersistence <> 'p' OR c.relrowsecurity
           OR EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite r WHERE r.ev_class = c.oid)
           OR EXISTS (SELECT 1 FROM pg_catalog.pg_policy y WHERE y.polrelid = c.oid)
        ORDER BY 1
      SQL
      odd
    end

    # The superuser's default partition, which refuses every row, is what makes PostgreSQL refuse DETACH ... CONCURRENTLY.
    # Matched by OID: the default PostgreSQL knows is public.audit_entries_default (review 3 of #239, B2).
    def default_problem
      found = @c.select_rows(<<~SQL.squish).first
        SELECT c.oid = pg_catalog.to_regclass('public.audit_entries_default'), r.rolsuper,
               (SELECT pg_catalog.array_agg(pg_catalog.pg_get_constraintdef(k.oid)) FROM pg_catalog.pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'c' AND k.conislocal) = ARRAY['CHECK (false)']
        FROM pg_catalog.pg_partitioned_table pt JOIN pg_catalog.pg_class c ON c.oid = pt.partdefid JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
        WHERE pt.partrelid = 'public.audit_entries'::pg_catalog.regclass
      SQL
      return if found == [ true, true, true ]

      "the audit log's default partition is not the superuser's audit_entries_default refusing every row (the superuser runs ops/postgres/audit-guard.sql again)"
    end

    # The id sequence is the superuser's: the app's role may use it but not reset it, and it is not behind the ids. Read
    # by OID: a name could be mixed-case or shadowed (review 3 of #239, S2). Its last value is NULL before the first
    # nextval.
    def sequence_problem
      oid, seq = @c.select_rows("SELECT g.objid, g.objid::pg_catalog.regclass::text FROM fleet_audit_guard.protected g WHERE g.kind = 'sequence'").first
      uses = oid && value(<<~SQL.squish)
        SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_attrdef a JOIN pg_catalog.pg_attribute t ON t.attrelid = a.adrelid AND t.attnum = a.adnum
                       JOIN pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_attrdef'::pg_catalog.regclass AND d.objid = a.oid
                                                  AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.refobjid = #{Integer(oid)}
                       WHERE a.adrelid = 'public.audit_entries'::pg_catalog.regclass AND t.attname = 'id')
      SQL
      return "audit_entries.id no longer takes its value from the guarded sequence" unless uses

      # Resettable through any role the app's role belongs to (pg_database_owner, for one), and it must count up and
      # never wrap round (review of #249).
      super_owned, resettable, wraps, unlogged, behind = @c.select_rows(<<~SQL.squish).first
        SELECT r.rolsuper,
               EXISTS (SELECT 1 FROM pg_catalog.pg_roles g WHERE pg_catalog.pg_has_role(current_user, g.oid, 'MEMBER')
                                                            AND pg_catalog.has_sequence_privilege(g.oid, s.oid, 'UPDATE')),
               (SELECT q.seqincrement <= 0 OR q.seqcycle FROM pg_catalog.pg_sequence q WHERE q.seqrelid = s.oid),
               s.relpersistence <> 'p',
               (SELECT max(id) FROM public.audit_entries) > COALESCE(pg_catalog.pg_sequence_last_value(s.oid), 0)
        FROM pg_catalog.pg_class s JOIN pg_catalog.pg_roles r ON r.oid = s.relowner WHERE s.oid = #{Integer(oid)}
      SQL
      return "the id sequence #{seq} is not the superuser's, or the app's role can reset it" if !super_owned || resettable
      return "the id sequence #{seq} counts down or cycles, so ids would repeat" if wraps
      # An unlogged sequence restarts at its first value after a crash or a replica's promotion (second review, S2).
      return "the id sequence #{seq} is not logged, so it would restart after a crash and ids would repeat" if unlogged

      "the id sequence #{seq} is behind the highest id, so ids would repeat" if behind
    end
  end
end
