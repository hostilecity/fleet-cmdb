module Partitions
  # Whether the audit log's hardened guard (ops/postgres/audit-guard.sql, ADR 0027) holds, as the app's own connection
  # sees it, and if not, why: the first problem found, as a sentence. /health shows it as a warning, the restore drill
  # as a WARN line, and (in production) the dashboard banner.
  #
  # Besides "is it installed", it looks for the ways around it the reviews of #239 found, in case one got through before
  # the guard was installed or while it was off: a role that is as good as a superuser; a search path or a second
  # audit_entries that would send entries elsewhere; a trigger that is not one of the guards, has a WHEN condition, or
  # is disabled; a rule, a policy, or row security; an unlogged or detaching partition, or one not recorded; a default
  # partition other than the superuser's that refuses every row; and an id sequence the app's role could reset, or one
  # behind the highest id. Every catalog is named with pg_catalog.
  class GuardCheck
    TREE = "pg_catalog.pg_partition_tree('public.audit_entries'::pg_catalog.regclass)".freeze
    GUARD = "'public.audit_entries_append_only()'::pg_catalog.regprocedure".freeze

    def initialize(connection)
      @c = connection
    end

    def problem
      role_problem("the app's PostgreSQL role", "current_user") || role_problem("the owner of audit_entries", owner_sql) ||
        search_path_problem || installed_problem || function_problem || table_problem || trigger_problem ||
        default_problem || sequence_problem
    end

    private

    def value(sql) = @c.select_value(sql)
    def values(sql) = @c.select_values(sql)

    def owner_sql = "(SELECT c.relowner::pg_catalog.regrole::text FROM pg_catalog.pg_class c WHERE c.oid = 'public.audit_entries'::pg_catalog.regclass)"

    def role_problem(who, role)
      return "#{who} is a superuser, so no guard can hold against it" if value("SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = #{role}")

      member = values(<<~SQL.squish).first
        SELECT g.rolname FROM pg_catalog.pg_roles g
        WHERE g.rolname IN (#{DANGEROUS_ROLES.map { |n| @c.quote(n) }.join(', ')}) AND pg_catalog.pg_has_role(#{role}, g.oid, 'MEMBER') ORDER BY 1
      SQL
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
      "the fleet_audit_guard schema is missing or not the superuser's (the superuser runs ops/postgres/audit-guard.sql)" unless owned
    end

    def function_problem
      owner_super, definer = @c.select_rows(<<~SQL.squish).first
        SELECT r.rolsuper, p.prosecdef FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles r ON r.oid = p.proowner WHERE p.oid = #{GUARD}
      SQL
      return "the guard function audit_entries_append_only() is not owned by the superuser (run ops/postgres/audit-guard.sql)" unless owner_super

      "the guard function audit_entries_append_only() runs as its owner (SECURITY DEFINER); the superuser runs ops/postgres/audit-guard.sql again" if definer
    end

    # Exactly the guards on every table of the audit log: the row trigger (cloned to each partition) and the truncate
    # guards, enabled, with no condition.
    def trigger_problem
      odd = values(<<~SQL.squish).first
        SELECT t.tgname || ' on ' || t.tgrelid::pg_catalog.regclass::text FROM #{TREE} p JOIN pg_catalog.pg_trigger t ON t.tgrelid = p.relid
        WHERE NOT t.tgisinternal
          AND NOT (t.tgfoid = #{GUARD} AND t.tgqual IS NULL AND t.tgenabled = 'O' AND t.tgnargs = 0
                   AND ((t.tgname = 'audit_entries_no_update_or_delete' AND t.tgtype = 27 AND (p.level = 0) = (t.tgparentid = 0))
                        OR (p.level = 0 AND t.tgname = 'audit_entries_no_truncate' AND t.tgtype = 34)
                        OR (p.level > 0 AND t.tgname = 'audit_entries_partition_no_truncate' AND t.tgtype = 34)))
        ORDER BY 1
      SQL
      return "trigger #{odd} is not one of the audit log's guards as installed (a WHEN condition, disabled, or another function)" if odd

      bare = values(<<~SQL.squish).first
        SELECT p.relid::pg_catalog.regclass::text FROM #{TREE} p
        WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid = p.relid AND t.tgtype = 34 AND t.tgfoid = #{GUARD})
        ORDER BY 1
      SQL
      "#{bare} has no truncate guard" if bare
    end

    def table_problem
      # A partition left half-detached (DETACH ... CONCURRENTLY interrupted) is in pg_inherits but not in the tree.
      detaching = values(<<~SQL.squish).first
        SELECT i.inhrelid::pg_catalog.regclass::text FROM pg_catalog.pg_inherits i
        WHERE i.inhparent = 'public.audit_entries'::pg_catalog.regclass AND i.inhdetachpending ORDER BY 1
      SQL
      return "#{detaching} is being detached, so its entries are hidden" if detaching

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
    def default_problem
      defaults = @c.select_rows(<<~SQL.squish)
        SELECT c.relname, r.rolsuper, EXISTS (SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'c' AND pg_catalog.pg_get_constraintdef(k.oid) = 'CHECK (false)')
        FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
        WHERE i.inhparent = 'public.audit_entries'::pg_catalog.regclass AND pg_catalog.pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'
      SQL
      return if defaults == [ [ "audit_entries_default", true, true ] ]

      "the audit log's default partition is not the superuser's audit_entries_default refusing every row (the superuser runs ops/postgres/audit-guard.sql again)"
    end

    # The id sequence is the superuser's: the app's role may use it but not reset it, and it is not behind the ids.
    def sequence_problem
      seq = value("SELECT g.objid::pg_catalog.regclass::text FROM fleet_audit_guard.protected g WHERE g.kind = 'sequence'")
      default = value(<<~SQL.squish)
        SELECT pg_catalog.pg_get_expr(a.adbin, a.adrelid) FROM pg_catalog.pg_attrdef a JOIN pg_catalog.pg_attribute t ON t.attrelid = a.adrelid AND t.attnum = a.adnum
        WHERE a.adrelid = 'public.audit_entries'::pg_catalog.regclass AND t.attname = 'id'
      SQL
      return "audit_entries.id no longer takes its value from the guarded sequence" unless seq && default == "nextval('#{seq}'::regclass)"

      super_owned, resettable = @c.select_rows(<<~SQL.squish).first
        SELECT r.rolsuper, pg_catalog.has_sequence_privilege(current_user, s.oid, 'UPDATE')
        FROM pg_catalog.pg_class s JOIN pg_catalog.pg_roles r ON r.oid = s.relowner WHERE s.oid = #{@c.quote(seq)}::pg_catalog.regclass
      SQL
      return "the id sequence #{seq} is not the superuser's, or the app's role can reset it" if !super_owned || resettable

      behind = value(<<~SQL.squish)
        SELECT (SELECT max(id) FROM public.audit_entries) > (SELECT s.last_value FROM pg_catalog.pg_sequences s
                                                             WHERE (s.schemaname || '.' || s.sequencename)::pg_catalog.regclass = #{@c.quote(seq)}::pg_catalog.regclass)
      SQL
      "the id sequence #{seq} is behind the highest id, so ids would repeat" if behind
    end
  end
end
