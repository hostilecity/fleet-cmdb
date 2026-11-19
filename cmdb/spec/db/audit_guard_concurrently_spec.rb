require "rails_helper"

# The second review of #239, bypass 2: DETACH PARTITION ... CONCURRENTLY commits its first step before any event
# trigger can refuse it, which left a month hidden (detach pending) behind a guard that then refused the repair. It
# cannot run in a transaction, so this builds a scratch database with an audit log shaped like the app's, owned by a
# role that owns the database too, installs ops/postgres/audit-guard.sql in it, tries the detach as that role, and drops
# the database and the role afterwards. With the guard's default partition in place, PostgreSQL refuses the concurrent
# form before it changes anything. The same database shows the step running as the superuser it logged in as when the
# database sets the app's role for every session (review 3 of #239, N2), which only a new session can show.
RSpec.describe "ops/postgres/audit-guard.sql against DETACH ... CONCURRENTLY" do
  self.use_transactional_tests = false

  let(:database) { "#{ApplicationRecord.connection.current_database}_guard_#{Process.pid}" }
  let(:role) { "fleet_guard_concurrently_#{Process.pid}" }
  let(:file) { Rails.root.join("../ops/postgres/audit-guard.sql").read }

  # A session on the test's own server: DATABASE_URL's host, port, and user, not libpq's defaults (review 3, N4). With
  # pinned: true, connected as install-server.md says (PGOPTIONS): search_path pinned, and on PostgreSQL 17 and later
  # event triggers off (final check of #249, B1).
  def connect(dbname, pinned: false, options: nil)
    config = ApplicationRecord.connection_db_config.configuration_hash
    options ||= "-c search_path=pg_catalog,pg_temp#{' -c event_triggers=off' if pg17?}" if pinned
    PG.connect({ host: config[:host], port: config[:port], user: config[:username], password: config[:password], dbname:, options: }.compact)
  end

  def pg17? = ApplicationRecord.connection.select_value("SELECT current_setting('server_version_num')::int") >= 170_000

  before do
    admin = connect(ApplicationRecord.connection.current_database)
    admin.exec("CREATE ROLE #{role} NOLOGIN")
    admin.exec("CREATE DATABASE #{database} OWNER #{role}")
    admin.close
    @pg = connect(database, pinned: true)
    @pg.exec(<<~SQL)
      SET search_path = public; -- the app's schema, made as the app makes it; pinned again at the end
      ALTER SCHEMA public OWNER TO #{role};
      SET ROLE #{role};
      CREATE FUNCTION audit_entries_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'audit_entries is append-only: % is not allowed', TG_OP; END $$;
      CREATE TABLE audit_entries (id bigserial NOT NULL, actor_type varchar NOT NULL, action varchar NOT NULL,
                                  occurred_at timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (id, occurred_at)) PARTITION BY RANGE (occurred_at);
      CREATE TRIGGER audit_entries_no_update_or_delete BEFORE UPDATE OR DELETE ON audit_entries FOR EACH ROW EXECUTE FUNCTION audit_entries_append_only();
      CREATE TRIGGER audit_entries_no_truncate BEFORE TRUNCATE ON audit_entries FOR EACH STATEMENT EXECUTE FUNCTION audit_entries_append_only();
      CREATE TABLE audit_entries_p20261101 PARTITION OF audit_entries FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
      CREATE TABLE audit_entries_p20261201 PARTITION OF audit_entries FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');
      CREATE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON audit_entries_p20261101 FOR EACH STATEMENT EXECUTE FUNCTION audit_entries_append_only();
      CREATE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON audit_entries_p20261201 FOR EACH STATEMENT EXECUTE FUNCTION audit_entries_append_only();
      INSERT INTO audit_entries (actor_type, action, occurred_at) VALUES ('system', 'a', '2026-11-05'), ('system', 'b', '2026-12-05');
      RESET ROLE;
      SET search_path = pg_catalog, pg_temp;
    SQL
  end

  after do
    @pg&.close
    admin = connect(ApplicationRecord.connection.current_database)
    admin.exec("DROP DATABASE IF EXISTS #{database} WITH (FORCE)")
    admin.exec("DROP ROLE IF EXISTS #{role}")
    admin.close
  end

  it "is refused before it changes anything, so no month is left hidden" do
    @pg.exec(file)
    @pg.exec("SET ROLE #{role}")
    expect { @pg.exec("ALTER TABLE public.audit_entries DETACH PARTITION public.audit_entries_p20261201 CONCURRENTLY") }
      .to raise_error(PG::Error, /default partition|append-only/)
    @pg.exec("RESET ROLE")

    expect(@pg.exec("SELECT count(*) FROM pg_inherits WHERE inhdetachpending").getvalue(0, 0)).to eq("0")
    expect(@pg.exec("SELECT count(*) FROM public.audit_entries").getvalue(0, 0)).to eq("2")
  end

  it "runs as the superuser it logged in as when the database sets the app's role for every session" do
    @pg.exec("ALTER DATABASE #{database} SET role = #{role}")
    @pg.close
    @pg = connect(database, pinned: true)
    expect(@pg.exec("SELECT current_user").getvalue(0, 0)).to eq(role)
    @pg.exec(file)
    expect(@pg.exec("SELECT count(*) FROM pg_event_trigger WHERE evtname LIKE 'fleet_audit_guard_%'").getvalue(0, 0)).to eq("2")
    expect(@pg.exec("SELECT relowner::regrole::text FROM pg_class WHERE oid = 'public.audit_entries_default'::regclass").getvalue(0, 0)).not_to eq(role)
  end

  it "holds the audit tables from before its checks to its commit, so nothing can be added in between (review of #249)" do
    @pg.exec(file.sub(/^COMMIT;$/, "")) # the step, its transaction still open
    other = connect(database)
    other.exec("SET ROLE #{role}")
    other.exec("SET lock_timeout = '200ms'")
    expect { other.exec("CREATE INDEX ON audit_entries_p20261101 (action)") }.to raise_error(PG::LockNotAvailable)
    expect { other.exec("CREATE STATISTICS fleet_spec_stats ON id, occurred_at FROM audit_entries") }.to raise_error(PG::LockNotAvailable)
    @pg.exec("COMMIT")
  ensure
    other&.close
  end

  it "takes that lock before any check, so an index being built elsewhere makes it wait, not check around it" do
    other = connect(database)
    other.exec("SET ROLE #{role}")
    other.exec("BEGIN")
    other.exec("LOCK TABLE audit_entries_p20261101 IN SHARE MODE") # what CREATE INDEX holds while it builds
    expect { @pg.exec(file) }.to raise_error(PG::LockNotAvailable, /LOCK TABLE public.audit_entries IN ACCESS EXCLUSIVE MODE/)
    @pg.exec("ROLLBACK")
  ensure
    other&.exec("ROLLBACK")
    other&.close
  end

  it "leaves an invalid index behind after a refused CREATE INDEX CONCURRENTLY, which the app's role can drop (second review of #249, N4)" do
    @pg.exec(file)
    app = connect(database) # the app's own kind of session: event triggers on (the superuser's pinned one has them off)
    app.exec("SET ROLE #{role}")
    expect { app.exec("CREATE INDEX CONCURRENTLY fleet_spec_cic ON public.audit_entries_p20261101 (action)") }.to raise_error(PG::InsufficientPrivilege, /append-only/)
    expect(app.exec("SELECT indisvalid FROM pg_index WHERE indexrelid = 'public.fleet_spec_cic'::regclass").getvalue(0, 0)).to eq("f")
    app.exec("DROP INDEX public.fleet_spec_cic")
    expect(app.exec("SELECT to_regclass('public.fleet_spec_cic') IS NULL").getvalue(0, 0)).to eq("t")
  ensure
    app&.close
  end

  it "B1: a login event trigger runs on every plain connection on 17, so the file runs only in a session connected with event triggers off" do
    if pg17?
      @pg.exec(<<~SQL)
        SET ROLE #{role};
        CREATE TABLE public.fleet_spec_logins (who name);
        CREATE FUNCTION public.fleet_spec_login() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO public.fleet_spec_logins VALUES (current_user); END $$;
        RESET ROLE;
        CREATE EVENT TRIGGER fleet_spec_login ON login EXECUTE FUNCTION public.fleet_spec_login(); -- as made while the role was a superuser
      SQL
      plain = connect(database)
      expect(plain.exec("SELECT count(*) FROM public.fleet_spec_logins WHERE who <> '#{role}'").getvalue(0, 0)).to eq("1") # ran as the superuser at connect
      expect { plain.exec(file) }.to raise_error(PG::RaiseException, /connect with event triggers off/)
      plain.close

      pinned = connect(database, pinned: true)
      expect { pinned.exec(file) }.to raise_error(PG::RaiseException, /fleet_spec_login \(on login, so it runs as whoever connects, every superuser included, owned by [^,]+, running public.fleet_spec_login\(\)\): #{role} was a superuser when this was made: rebuild the cluster/)
      pinned.exec("ROLLBACK")
      pinned.exec("DROP EVENT TRIGGER fleet_spec_login") # the remedy, in a session connected the documented way
      expect(pinned.exec("SELECT count(*) FROM public.fleet_spec_logins").getvalue(0, 0)).to eq("1") # no further run
      pinned.exec(file)
      pinned.close
    else
      # PostgreSQL 16 has no login triggers, and refuses the setting at connect: the 17 command fails closed there.
      expect { connect(database, options: "-c event_triggers=off") }.to raise_error(PG::ConnectionBad, /unrecognized configuration parameter/)
      @pg.exec(file)
    end
    expect(@pg.exec("SELECT count(*) FROM pg_catalog.pg_event_trigger WHERE evtname LIKE 'fleet_audit_guard_%'").getvalue(0, 0)).to eq("2")
  end
end
