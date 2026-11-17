require "rails_helper"

# The audit log's hardened guard (ADR 0027, "The audit log's guards"; threat model A3, F-5): ops/postgres/audit-guard.sql,
# run once by the PostgreSQL superuser. Against an owner role that is not a superuser, as the app's role is on the
# server, it refuses every change in the ADR's list, and still lets the app create a month's partition with its
# truncate guard. Everything here, the role included, is rolled back with the example. It needs a superuser to install
# the event triggers: CI's PostgreSQL service is one, and so is a local development cluster's default role.
RSpec.describe "ops/postgres/audit-guard.sql" do
  let(:c) { ApplicationRecord.connection }
  let(:guard_sql) { Rails.root.join("../ops/postgres/audit-guard.sql").read }
  let(:role) { "fleet_audit_guard_spec" }
  let(:audit_tables) { [ "audit_entries" ] + Partitions.list("audit_entries").map(&:name) }

  # Each attempt in a savepoint, so the refusal does not abort the example's transaction.
  def attempt(sql) = AuditEntry.transaction(requires_new: true) { c.execute(sql) }

  def refused(sql, message = /the audit log is append-only/)
    expect { attempt(sql) }.to raise_error(ActiveRecord::StatementInvalid, message), sql
  end

  before do
    expect(c.select_value("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")).to be(true)
    create(:host) # an audit entry to protect
    # The server's situation before the step: the app's role, not a superuser, owns the tables and the guard function.
    c.execute("CREATE ROLE #{role} NOLOGIN")
    c.execute("GRANT USAGE, CREATE ON SCHEMA public TO #{role}")
    audit_tables.each { |table| c.execute("ALTER TABLE #{table} OWNER TO #{role}") }
    c.execute("ALTER FUNCTION audit_entries_append_only() OWNER TO #{role}")
  end

  after { c.execute("RESET ROLE") }

  it "can only be installed by the superuser, and running it again is safe" do
    c.execute("SET ROLE #{role}")
    refused(guard_sql, /run ops\/postgres\/audit-guard.sql as the PostgreSQL superuser/)
    c.execute("RESET ROLE")
    expect(Partitions.audit_guard_installed?).to be(false)

    2.times { c.execute(guard_sql) }
    expect(Partitions.audit_guard_installed?).to be(true)
  end

  it "refuses, for the app's role, every way the review found to defeat the append-only guard" do
    c.execute(guard_sql)
    c.execute("SET ROLE #{role}")
    partition = Partitions.list("audit_entries").last.name

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
    refused("DROP EVENT TRIGGER fleet_audit_guard_ddl", /must be owner/)
    refused("ALTER EVENT TRIGGER fleet_audit_guard_drop DISABLE", /must be owner/)
    refused("DROP FUNCTION audit_entries_append_only() CASCADE", /must be owner/)
    refused("CREATE OR REPLACE FUNCTION fleet_audit_guard.refuse_ddl() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN END $$", /permission denied|must be owner/)

    c.execute("RESET ROLE")
    expect(Partitions.audit_guard_installed?).to be(true)
    expect(c.select_value("SELECT count(*) FROM audit_entries")).to be_positive
  end

  it "still lets the app create a month's partition with its truncate guard, and that partition is append-only too" do
    c.execute(guard_sql)
    c.execute("SET ROLE #{role}")
    last = Partitions.list("audit_entries").last

    created = Partitions.ensure!(now: last.from, tables: [ "audit_entries" ])["audit_entries"]

    expect(created).to include("audit_entries_p#{last.to.strftime('%Y%m%d')}")
    c.execute("INSERT INTO audit_entries (actor_type, action, occurred_at) VALUES ('system', 'host.edited', #{c.quote(last.to + 1.day)})")
    refused("UPDATE audit_entries SET action = 'host.retired' WHERE occurred_at >= #{c.quote(last.to)}", /append-only: UPDATE/)
    refused("TRUNCATE #{created.first}", /append-only: TRUNCATE/)
    c.execute("RESET ROLE")
    expect(Partitions.audit_guard_installed?).to be(true)
  end

  it "is reported missing when an event trigger is disabled or the guard function is not the superuser's" do
    c.execute(guard_sql)
    c.execute("ALTER EVENT TRIGGER fleet_audit_guard_ddl DISABLE")
    expect(Partitions.audit_guard_installed?).to be(false)
    c.execute("ALTER EVENT TRIGGER fleet_audit_guard_ddl ENABLE")
    expect(Partitions.audit_guard_installed?).to be(true)
    c.execute("DROP EVENT TRIGGER fleet_audit_guard_drop") # the superuser may
    c.execute("ALTER FUNCTION audit_entries_append_only() OWNER TO #{role}")
    expect(Partitions.audit_guard_installed?).to be(false)
  end
end
