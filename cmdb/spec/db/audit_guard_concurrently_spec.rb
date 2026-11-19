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

  # A session on the test's own server: DATABASE_URL's host, port, and user, not libpq's defaults (review 3, N4).
  def connect(dbname)
    config = ApplicationRecord.connection_db_config.configuration_hash
    PG.connect({ host: config[:host], port: config[:port], user: config[:username], password: config[:password], dbname: }.compact)
  end

  before do
    admin = connect(ApplicationRecord.connection.current_database)
    admin.exec("CREATE ROLE #{role} NOLOGIN")
    admin.exec("CREATE DATABASE #{database} OWNER #{role}")
    admin.close
    @pg = connect(database)
    @pg.exec(<<~SQL)
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
    expect { @pg.exec("ALTER TABLE audit_entries DETACH PARTITION audit_entries_p20261201 CONCURRENTLY") }
      .to raise_error(PG::Error, /default partition|append-only/)
    @pg.exec("RESET ROLE")

    expect(@pg.exec("SELECT count(*) FROM pg_inherits WHERE inhdetachpending").getvalue(0, 0)).to eq("0")
    expect(@pg.exec("SELECT count(*) FROM audit_entries").getvalue(0, 0)).to eq("2")
  end

  it "runs as the superuser it logged in as when the database sets the app's role for every session" do
    @pg.exec("ALTER DATABASE #{database} SET role = #{role}")
    @pg.close
    @pg = connect(database)
    expect(@pg.exec("SELECT current_user").getvalue(0, 0)).to eq(role)
    @pg.exec(file)
    expect(@pg.exec("SELECT count(*) FROM pg_event_trigger WHERE evtname LIKE 'fleet_audit_guard_%'").getvalue(0, 0)).to eq("2")
    expect(@pg.exec("SELECT relowner::regrole::text FROM pg_class WHERE oid = 'audit_entries_default'::regclass").getvalue(0, 0)).not_to eq(role)
  end
end
