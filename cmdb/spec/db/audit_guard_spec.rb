require "rails_helper"

# The audit log's hardened guard (ADR 0027, "The audit log's guards"; threat model A3, F-5): ops/postgres/audit-guard.sql,
# run once by the PostgreSQL superuser. The role it must stop is set up as `cmdb` is on the server: not a superuser,
# owner of the database, of the public schema, and of every table. Against it the guard refuses every change in the
# ADR's list and the review's bypasses (#239), and still lets the app create a month's partition. Everything here, the
# role and the event triggers included, is rolled back with the example. Installing an event trigger needs a superuser:
# CI's PostgreSQL service is one, and so is a local development cluster's default role.
RSpec.describe "ops/postgres/audit-guard.sql" do
  let(:c) { ApplicationRecord.connection }
  let(:guard_sql) { Rails.root.join("../ops/postgres/audit-guard.sql").read }
  let(:role) { "fleet_audit_guard_spec" }
  let(:audit_tables) { [ "audit_entries" ] + Partitions.list("audit_entries").map(&:name) }
  let(:partition) { Partitions.list("audit_entries").last.name }

  # Each attempt in a savepoint, so the refusal does not abort the example's transaction.
  def attempt(sql) = AuditEntry.transaction(requires_new: true) { c.execute(sql) }

  def refused(sql, message = /the audit log is append-only/)
    expect { attempt(sql) }.to raise_error(ActiveRecord::StatementInvalid, message), sql
  end

  def as_owner
    c.execute("SET ROLE #{role}")
    yield
  ensure
    c.execute("RESET ROLE")
  end

  def entry(at = Time.current) = attempt("INSERT INTO audit_entries (actor_type, action, occurred_at) VALUES ('system', 'host.edited', #{c.quote(at)})")

  def forged = c.select_value("SELECT count(*) FROM audit_entries WHERE action = 'forged'")

  before do
    expect(c.select_value("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")).to be(true)
    create(:host) # an audit entry to protect
    # The server's situation before the step: the app's role owns the database, the schema, the tables, and the guard
    # function, and is not a superuser.
    c.execute("CREATE ROLE #{role} NOLOGIN")
    c.execute("ALTER DATABASE #{c.quote_table_name(c.current_database)} OWNER TO #{role}")
    c.execute("ALTER SCHEMA public OWNER TO #{role}")
    audit_tables.each { |table| c.execute("ALTER TABLE #{table} OWNER TO #{role}") }
    c.execute("ALTER FUNCTION audit_entries_append_only() OWNER TO #{role}")
  end

  it "can only be installed by the superuser, not while the app's role is one, and running it again is safe" do
    as_owner { refused(guard_sql, %r{run ops/postgres/audit-guard.sql as the PostgreSQL superuser}) }
    c.execute("ALTER TABLE audit_entries OWNER TO CURRENT_USER")
    refused(guard_sql, /audit_entries is owned by a superuser/)
    as_owner { expect(Partitions.audit_guard_problem).to eq("audit_entries is owned by a PostgreSQL superuser, so no guard can hold against it") }
    c.execute("ALTER TABLE audit_entries OWNER TO #{role}")
    as_owner { expect(Partitions.audit_guard_problem).to match(/event triggers are not installed/) }

    2.times { c.execute(guard_sql) }
    as_owner { expect(Partitions.audit_guard_problem).to be_nil }
    expect(Partitions.audit_guard_problem).to match(/the app's PostgreSQL role is a superuser/) # this session's role
  end

  it "refuses, for the app's role, every way the first review found to defeat the append-only guard" do
    c.execute(guard_sql)
    as_owner do
      refused("CREATE OR REPLACE FUNCTION audit_entries_append_only() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$", /must be owner/)
      refused("DROP TRIGGER audit_entries_no_update_or_delete ON audit_entries")
      refused("DROP TRIGGER audit_entries_no_truncate ON audit_entries")
      refused("DROP TRIGGER audit_entries_partition_no_truncate ON #{partition}")
      attempt("CREATE FUNCTION fleet_spec_discard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$")
      refused("CREATE TRIGGER fleet_spec_discard BEFORE INSERT ON audit_entries FOR EACH ROW EXECUTE FUNCTION fleet_spec_discard()")
      refused("CREATE TRIGGER fleet_spec_discard BEFORE INSERT ON #{partition} FOR EACH ROW EXECUTE FUNCTION fleet_spec_discard()")
      refused("CREATE TRIGGER audit_entries_partition_no_truncate_2 BEFORE TRUNCATE ON #{partition} FOR EACH STATEMENT EXECUTE FUNCTION fleet_spec_discard()")
      refused("CREATE TRIGGER fleet_spec_parent_truncate BEFORE TRUNCATE ON audit_entries FOR EACH STATEMENT EXECUTE FUNCTION audit_entries_append_only()")
      refused("CREATE RULE fleet_spec_discard AS ON INSERT TO audit_entries DO INSTEAD NOTHING")
      refused("ALTER TABLE audit_entries DETACH PARTITION #{partition}")
      refused("DROP TABLE #{partition}")
      refused("DROP TABLE audit_entries")
      refused("ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_no_update_or_delete")
      refused("ALTER TABLE #{partition} DISABLE TRIGGER audit_entries_partition_no_truncate")
      refused("ALTER TABLE audit_entries ADD COLUMN fleet_spec text")
      refused("ALTER TRIGGER audit_entries_no_update_or_delete ON audit_entries RENAME TO fleet_spec_renamed")
      refused("DROP EVENT TRIGGER fleet_audit_guard_ddl", /must be owner/)
      refused("ALTER EVENT TRIGGER fleet_audit_guard_drop DISABLE", /must be owner/)
      refused("DROP FUNCTION audit_entries_append_only() CASCADE") # the schema's owner may drop what is in it: the guard says no
      refused("CREATE OR REPLACE FUNCTION fleet_audit_guard.refuse_ddl() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN END $$", /permission denied|must be owner/)
      refused("DELETE FROM fleet_audit_guard.protected", /permission denied/)
      expect(Partitions.audit_guard_problem).to be_nil
    end
    expect(c.select_value("SELECT count(*) FROM audit_entries")).to be_positive
  end

  # The second review (#239): a rename hid the parent from a guard that resolved it by name, and a temporary table
  # shadowed the catalog it read. Both forged or discarded entries before the guard recorded OIDs and pinned its
  # search_path.
  it "refuses the rename bypass: hiding the parent under another name and putting a decoy in its place" do
    c.execute(guard_sql)
    as_owner do
      refused("ALTER INDEX audit_entries RENAME TO fleet_spec_hidden")
      refused("ALTER SEQUENCE audit_entries RENAME TO fleet_spec_hidden", /append-only|is not a sequence/)
      refused("ALTER VIEW audit_entries RENAME TO fleet_spec_hidden", /append-only|is not a view/)
      refused("ALTER TABLE audit_entries RENAME TO fleet_spec_hidden")
      refused("ALTER INDEX #{partition} RENAME TO fleet_spec_hidden")
      refused("ALTER SCHEMA public RENAME TO fleet_spec_public")
      # The review's sequence, all in one go: each step is refused, and nothing is forged.
      attempt(<<~SQL) rescue nil # rubocop:disable Style/RescueModifier
        ALTER INDEX audit_entries RENAME TO fleet_spec_hidden;
        CREATE TABLE audit_entries (decoy int);
        ALTER TABLE fleet_spec_hidden DETACH PARTITION #{partition};
        UPDATE #{partition} SET action = 'forged';
      SQL
      expect(forged).to eq(0)
      expect(Partitions.audit_guard_problem).to be_nil
    end
  end

  it "refuses the shadowing bypass: a temporary catalog table, or a search_path that puts the role's own objects first" do
    c.execute(guard_sql)
    as_owner do
      attempt("CREATE FUNCTION fleet_spec_discard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$")
      attempt("CREATE TEMP TABLE pg_trigger (oid oid, tgrelid oid, tgtype int2, tgfoid oid, tgparentid oid)")
      attempt("CREATE TEMP TABLE pg_rewrite (oid oid, ev_class oid)")
      refused("CREATE TRIGGER fleet_spec_discard BEFORE INSERT ON audit_entries FOR EACH ROW EXECUTE FUNCTION fleet_spec_discard()")
      refused("CREATE RULE fleet_spec_discard AS ON INSERT TO audit_entries DO INSTEAD NOTHING")
      refused("ALTER TRIGGER audit_entries_no_update_or_delete ON audit_entries RENAME TO fleet_spec_renamed")

      attempt("CREATE FUNCTION public.pg_partition_tree(regclass) RETURNS TABLE (relid regclass, parentrelid regclass, isleaf boolean, level integer) LANGUAGE sql AS 'SELECT NULL::regclass, NULL::regclass, NULL::boolean, NULL::integer WHERE false'")
      attempt("CREATE FUNCTION public.to_regclass(text) RETURNS regclass LANGUAGE sql AS 'SELECT NULL::regclass'")
      attempt("SET search_path = pg_temp, public, pg_catalog")
      refused("ALTER TABLE audit_entries DETACH PARTITION #{partition}")
      refused("DROP TABLE #{partition}")
      attempt("RESET search_path")

      entry
      expect(c.select_value("SELECT count(*) FROM audit_entries WHERE occurred_at > now() - interval '1 minute'")).to be_positive
    end
  end

  it "refuses the other bypasses tried in the second review's setup" do
    c.execute(guard_sql)
    as_owner do
      attempt("CREATE FUNCTION fleet_spec_discard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$")
      refused("SET session_replication_role = replica", /permission denied/) # event triggers do not fire in replica mode
      refused("ALTER DATABASE #{c.quote_table_name(c.current_database)} SET session_replication_role = replica", /permission denied/)
      refused("ALTER TABLE audit_entries ENABLE REPLICA TRIGGER audit_entries_no_update_or_delete")
      refused("CREATE POLICY fleet_spec ON audit_entries USING (false)")
      refused("ALTER TABLE audit_entries ENABLE ROW LEVEL SECURITY")
      refused("COMMENT ON TABLE audit_entries IS 'renamed'")
      refused("ALTER TABLE audit_entries OWNER TO #{role}")
      refused("DROP OWNED BY #{role} CASCADE")
      refused("DROP SCHEMA public CASCADE")
      # Several commands in one, through CREATE SCHEMA: the new partition is recorded before its trigger is looked at.
      from = Partitions.list("audit_entries").last.to
      refused(<<~SQL.squish)
        CREATE SCHEMA fleet_spec_schema
          CREATE TABLE fleet_spec_month PARTITION OF public.audit_entries FOR VALUES FROM (#{c.quote(from)}) TO (#{c.quote(from + 1.month)})
          CREATE TRIGGER fleet_spec_discard BEFORE INSERT ON fleet_spec_month FOR EACH ROW EXECUTE FUNCTION public.fleet_spec_discard()
      SQL
      expect(Partitions.audit_guard_problem).to be_nil
    end
  end

  it "still lets the app create a month's partition, which the guard records and gives its truncate guard" do
    c.execute(guard_sql)
    last = Partitions.list("audit_entries").last
    as_owner do
      created = Partitions.ensure!(now: last.from, tables: [ "audit_entries" ])["audit_entries"]

      expect(created).to include("audit_entries_p#{last.to.strftime('%Y%m%d')}")
      entry(last.to + 1.day)
      refused("UPDATE audit_entries SET action = 'host.retired' WHERE occurred_at >= #{c.quote(last.to)}", /append-only: UPDATE/)
      refused("TRUNCATE #{created.first}", /append-only: TRUNCATE/)
      refused("ALTER INDEX #{created.first} RENAME TO fleet_spec_hidden")
      expect(c.select_values("SELECT tgname FROM pg_trigger WHERE tgrelid = #{c.quote(created.first)}::regclass ORDER BY 1"))
        .to eq(%w[audit_entries_no_update_or_delete audit_entries_partition_no_truncate])
      expect(Partitions.audit_guard_problem).to be_nil
    end
  end

  it "guards a partition the app's role creates under another name as any other: it is recorded and gets a truncate guard" do
    c.execute(guard_sql)
    as_owner do
      from = Partitions.list("audit_entries").last.to
      attempt("CREATE TABLE fleet_spec_month PARTITION OF audit_entries FOR VALUES FROM (#{c.quote(from)}) TO (#{c.quote(from + 1.month)})")
      entry(from + 1.day)
      attempt("CREATE FUNCTION fleet_spec_discard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$")

      refused("TRUNCATE fleet_spec_month", /append-only: TRUNCATE/)
      refused("DELETE FROM fleet_spec_month", /append-only: DELETE/)
      refused("DROP TABLE fleet_spec_month")
      refused("ALTER TABLE fleet_spec_month DISABLE TRIGGER audit_entries_no_update_or_delete")
      refused("CREATE TRIGGER fleet_spec_discard BEFORE INSERT ON fleet_spec_month FOR EACH ROW EXECUTE FUNCTION fleet_spec_discard()")
      refused("CREATE RULE fleet_spec_discard AS ON INSERT TO fleet_spec_month DO INSTEAD NOTHING")
      refused("DROP TRIGGER audit_entries_partition_no_truncate ON fleet_spec_month")
      refused("ALTER TRIGGER audit_entries_partition_no_truncate ON fleet_spec_month RENAME TO fleet_spec_renamed")
      expect(c.select_value("SELECT count(*) FROM fleet_spec_month")).to eq(1)
    end
  end

  it "says why the guard does not hold: an event trigger disabled, the function not the superuser's, a partition not recorded" do
    c.execute(guard_sql)
    c.execute("ALTER EVENT TRIGGER fleet_audit_guard_ddl DISABLE")
    as_owner { expect(Partitions.audit_guard_problem).to match(/event triggers are not installed/) }
    # A partition made while the guard was off is not protected until the file runs again.
    from = Partitions.list("audit_entries").last.to
    as_owner { attempt("CREATE TABLE fleet_spec_month PARTITION OF audit_entries FOR VALUES FROM (#{c.quote(from)}) TO (#{c.quote(from + 1.month)})") }
    c.execute("ALTER EVENT TRIGGER fleet_audit_guard_ddl ENABLE")
    as_owner { expect(Partitions.audit_guard_problem).to eq("fleet_spec_month not protected by the audit guard (the superuser runs ops/postgres/audit-guard.sql again)") }
    c.execute(guard_sql)
    as_owner { expect(Partitions.audit_guard_problem).to be_nil }
    c.execute("DROP EVENT TRIGGER fleet_audit_guard_ddl") # the superuser may
    c.execute("CREATE EVENT TRIGGER fleet_audit_guard_ddl ON ddl_command_end EXECUTE FUNCTION fleet_audit_guard.refuse_ddl()")
    c.execute("ALTER EVENT TRIGGER fleet_audit_guard_ddl DISABLE")
    c.execute("ALTER FUNCTION audit_entries_append_only() OWNER TO #{role}")
    c.execute("ALTER EVENT TRIGGER fleet_audit_guard_ddl ENABLE")
    as_owner { expect(Partitions.audit_guard_problem).to match(/not owned by the superuser/) }
  end
end
