require "rails_helper"

# The audit log's hardened guard (ADR 0027, "The audit log's guards"; threat model A3, C12, F-5): ops/postgres/audit-guard.sql,
# run once by the PostgreSQL superuser. The role it must stop is set up as `cmdb` is on the server: not a superuser,
# owner of the database, of the public schema, of every table, and (as before the step, or after a restore) of the
# guard function. Against it the guard refuses every bypass the reviews of #239 found, and Partitions::GuardCheck
# reports each one that got through while the guard was off. Everything here, the role and the event triggers
# included, is rolled back with the example: the file's own BEGIN and COMMIT are left out (a spec below checks they are
# there). Installing an event trigger needs a superuser: CI's PostgreSQL service is one, and so is a local cluster's
# default role. DETACH ... CONCURRENTLY cannot run in a transaction: spec/db/audit_guard_concurrently_spec.rb.
RSpec.describe "ops/postgres/audit-guard.sql" do
  let(:c) { ApplicationRecord.connection }
  let(:file) { Rails.root.join("../ops/postgres/audit-guard.sql").read }
  let(:role) { "fleet_audit_guard_spec" }
  let(:audit_tables) { [ "audit_entries" ] + Partitions.list("audit_entries").map(&:name) }
  let(:partition) { Partitions.list("audit_entries").reject(&:default?).last.name }

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

  # The file as the superuser, inside the example's transaction; then the connection's own search path again.
  def install
    c.execute(file.sub(/^BEGIN;$/, "").sub(/^COMMIT;$/, ""))
    c.execute("SET LOCAL search_path = public")
  end

  def problem = as_owner { Partitions.audit_guard_problem }

  # The superuser with the guard off for a moment, to put a bypass in place as if it had got through.
  def unguarded
    c.execute("ALTER EVENT TRIGGER fleet_audit_guard_ddl DISABLE")
    c.execute("ALTER EVENT TRIGGER fleet_audit_guard_drop DISABLE")
    yield
  ensure
    c.execute("ALTER EVENT TRIGGER fleet_audit_guard_ddl ENABLE")
    c.execute("ALTER EVENT TRIGGER fleet_audit_guard_drop ENABLE")
  end

  def entry(at = Time.current) = attempt("INSERT INTO audit_entries (actor_type, action, occurred_at) VALUES ('system', 'host.edited', #{c.quote(at)})")

  def superuser? = c.select_value("SELECT rolsuper FROM pg_roles WHERE rolname = '#{role}'")

  before do
    expect(c.select_value("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")).to be(true)
    create(:host) # an audit entry to protect
    c.execute("CREATE ROLE #{role} NOLOGIN")
    c.execute("ALTER DATABASE #{c.quote_table_name(c.current_database)} OWNER TO #{role}")
    c.execute("ALTER SCHEMA public OWNER TO #{role}")
    audit_tables.each { |table| c.execute("ALTER TABLE #{table} OWNER TO #{role}") }
    c.execute("ALTER FUNCTION audit_entries_append_only() OWNER TO #{role}")
  end

  after { c.execute("RESET ROLE") }

  describe "installing it" do
    it "is one transaction, with its search path pinned" do
      expect(file).to match(/^BEGIN;\nSET LOCAL search_path = pg_catalog, pg_temp;$/)
      expect(file.rstrip).to end_with("COMMIT;")
    end

    it "is done by the superuser only, never while the app's role is one or as good as one, and safe to run again" do
      as_owner { refused(file, %r{run ops/postgres/audit-guard.sql as the PostgreSQL superuser}) }
      c.execute("ALTER TABLE audit_entries OWNER TO CURRENT_USER")
      refused(file, /audit_entries is owned by a superuser/)
      c.execute("ALTER TABLE audit_entries OWNER TO #{role}")
      c.execute("GRANT pg_write_server_files TO #{role}")
      refused(file, /#{role} is a member of pg_write_server_files/)
      expect(problem).to eq("the app's PostgreSQL role is a member of pg_write_server_files, which is as good as a superuser against the guard")
      c.execute("REVOKE pg_write_server_files FROM #{role}")
      expect(problem).to match(/event triggers are not installed/)

      2.times { install }
      expect(problem).to be_nil
      expect(Partitions.audit_guard_problem).to eq("the app's PostgreSQL role is a superuser, so no guard can hold against it") # this session
    end

    # The second review (#239): the app's role prepares objects before the step, which the step then trusts.
    it "writes the guard function's body itself, so one the app's role planted never runs as the superuser" do
      as_owner do
        attempt(<<~SQL)
          CREATE OR REPLACE FUNCTION audit_entries_append_only() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
          BEGIN
            IF TG_OP = 'UPDATE' AND NEW.action = 'escalate' THEN EXECUTE 'ALTER ROLE #{role} SUPERUSER'; RETURN NULL; END IF;
            RAISE EXCEPTION 'append-only';
          END $$
        SQL
      end
      install
      as_owner { refused("UPDATE audit_entries SET action = 'escalate'", /audit_entries is append-only: UPDATE/) }
      expect(superuser?).to be(false)
      expect(c.select_rows("SELECT prosecdef, proowner::regrole::text FROM pg_proc WHERE oid = 'audit_entries_append_only()'::regprocedure"))
        .to eq([ [ false, c.select_value("SELECT current_user") ] ])
      expect(problem).to be_nil
    end

    it "refuses a fleet_audit_guard schema the app's role made, before anything in it can run" do
      as_owner do
        attempt("CREATE SCHEMA fleet_audit_guard")
        attempt("CREATE TABLE fleet_audit_guard.protected (kind text, objid oid)")
        attempt("CREATE FUNCTION fleet_audit_guard.escalate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN EXECUTE 'ALTER ROLE #{role} SUPERUSER'; RETURN NEW; END $$")
        attempt("CREATE TRIGGER escalate BEFORE INSERT ON fleet_audit_guard.protected FOR EACH ROW EXECUTE FUNCTION fleet_audit_guard.escalate()")
      end
      refused(file, /a fleet_audit_guard schema exists that no superuser owns/)
      expect(superuser?).to be(false)
    end

    it "refuses audit tables that carry anything but their own guards" do
      as_owner do
        attempt("CREATE OR REPLACE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON #{partition} FOR EACH STATEMENT WHEN (false) EXECUTE FUNCTION audit_entries_append_only()")
        attempt("ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_no_truncate")
        attempt("CREATE RULE fleet_spec AS ON INSERT TO audit_entries DO INSTEAD NOTHING")
      end
      expect { attempt(file) }.to raise_error(ActiveRecord::StatementInvalid) do |error|
        expect(error.message).to include("the audit guard was not installed", "trigger audit_entries_partition_no_truncate on public.#{partition} is not one of the audit log's guards",
                                         "trigger audit_entries_no_truncate on public.audit_entries is not one of the audit log's guards", "public.audit_entries has a rule")
      end
    end
  end

  describe "with the guard installed" do
    before { install }

    it "refuses every way the first review found" do
      as_owner do
        refused("CREATE OR REPLACE FUNCTION audit_entries_append_only() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$", /must be owner/)
        refused("DROP TRIGGER audit_entries_no_update_or_delete ON audit_entries")
        refused("DROP TRIGGER audit_entries_partition_no_truncate ON #{partition}")
        attempt("CREATE FUNCTION fleet_spec_discard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$")
        # On the parent PostgreSQL itself refuses first: the trigger would reach the superuser's default partition.
        refused("CREATE TRIGGER fleet_spec_discard BEFORE INSERT ON audit_entries FOR EACH ROW EXECUTE FUNCTION fleet_spec_discard()", /append-only|permission denied for table audit_entries_default/)
        refused("CREATE TRIGGER fleet_spec_discard BEFORE INSERT ON #{partition} FOR EACH ROW EXECUTE FUNCTION fleet_spec_discard()")
        refused("CREATE RULE fleet_spec_discard AS ON INSERT TO audit_entries DO INSTEAD NOTHING")
        refused("ALTER TABLE audit_entries DETACH PARTITION #{partition}")
        refused("ALTER TABLE audit_entries DETACH PARTITION audit_entries_default")
        refused("DROP TABLE #{partition}")
        refused("DROP TABLE audit_entries_default")
        refused("ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_no_update_or_delete")
        refused("ALTER TABLE audit_entries ADD COLUMN fleet_spec text", /append-only|must be owner of table audit_entries_default/)
        refused("ALTER TRIGGER audit_entries_no_update_or_delete ON audit_entries RENAME TO fleet_spec_renamed")
        refused("DROP EVENT TRIGGER fleet_audit_guard_ddl", /must be owner/)
        refused("DROP FUNCTION audit_entries_append_only() CASCADE") # the schema's owner may try: the guard says no
        refused("DELETE FROM fleet_audit_guard.protected", /permission denied/)
        refused("ALTER INDEX audit_entries RENAME TO fleet_spec_hidden")
        refused("ALTER SCHEMA public RENAME TO fleet_spec_public")
        attempt("CREATE TEMP TABLE pg_trigger (oid oid, tgrelid oid, tgtype int2, tgfoid oid, tgparentid oid)")
        refused("CREATE TRIGGER fleet_spec_discard BEFORE INSERT ON #{partition} FOR EACH ROW EXECUTE FUNCTION fleet_spec_discard()")
        expect(Partitions.audit_guard_problem).to be_nil
      end
    end

    # The second review's blockers and should-fixes (#239), each a spec that fails against the file it reviewed.
    it "refuses replacing a truncate guard, even with one identical to it (bypass 1)" do
      as_owner do
        refused("CREATE OR REPLACE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON #{partition} FOR EACH STATEMENT WHEN (false) EXECUTE FUNCTION audit_entries_append_only()")
        refused("CREATE OR REPLACE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON #{partition} FOR EACH STATEMENT EXECUTE FUNCTION audit_entries_append_only()")
        refused("TRUNCATE #{partition}", /append-only: TRUNCATE/)
      end
    end

    it "refuses an audit_entries anywhere but public, and the app's connections look only in public (bypass 3)" do
      expect(ActiveRecord::Base.connection_db_config.configuration_hash[:schema_search_path]).to eq("public")
      as_owner do
        refused("CREATE SCHEMA #{role} CREATE TABLE audit_entries (LIKE public.audit_entries INCLUDING DEFAULTS)", /no other relation may be named audit_entries/)
        attempt("CREATE SCHEMA #{role}")
        refused("CREATE TABLE #{role}.audit_entries (LIKE public.audit_entries INCLUDING DEFAULTS)", /no other relation may be named audit_entries/)
        refused("CREATE VIEW #{role}.audit_entries AS SELECT * FROM public.audit_entries", /no other relation may be named audit_entries/)
      end
    end

    it "keeps the id sequence away from the app's role: no drop, no alter, no setval (should fix 5)" do
      as_owner do
        refused("DROP SEQUENCE audit_entries_id_seq CASCADE")
        refused("ALTER SEQUENCE audit_entries_id_seq RESTART WITH 1", /append-only|must be owner/)
        refused("ALTER TABLE audit_entries ALTER COLUMN id DROP DEFAULT", /append-only|must be owner of table audit_entries_default/)
        refused("SELECT setval('audit_entries_id_seq', 1)", /permission denied/)
        entry # nextval still works
      end
    end

    it "refuses an unlogged, a default, or a partitioned partition of the audit log (should fix 6)" do
      from = Partitions.list("audit_entries").reject(&:default?).last.to
      as_owner do
        refused("CREATE UNLOGGED TABLE fleet_spec_month PARTITION OF audit_entries FOR VALUES FROM (#{c.quote(from)}) TO (#{c.quote(from + 1.month)})",
                /must be a plain, logged table for a range/)
        refused("CREATE TABLE fleet_spec_month PARTITION OF audit_entries FOR VALUES FROM (#{c.quote(from)}) TO (#{c.quote(from + 1.month)}) PARTITION BY RANGE (occurred_at)",
                /must be a plain, logged table for a range/)
        refused("CREATE TABLE fleet_spec_default PARTITION OF audit_entries DEFAULT", /conflicts with existing default partition/)
        # A month whose every entry would fail: fail-closed, but an outage the app's role could cause.
        refused("CREATE TABLE fleet_spec_month PARTITION OF audit_entries (CONSTRAINT fleet_spec_no CHECK (false)) FOR VALUES FROM (#{c.quote(from)}) TO (#{c.quote(from + 1.month)})",
                /with no check of its own/)
      end
    end

    it "keeps a default partition that refuses every row, so the log still fails closed" do
      after = Partitions.list("audit_entries").reject(&:default?).last.to + 1.day
      expect { entry(after) }.to raise_error(ActiveRecord::StatementInvalid, /audit_entries_default_refuses_rows/)
      expect(Partitions.health(now: 3.months.from_now)).to eq(:failing) # fewer than 2 months ahead still fails
    end

    it "still lets the app create a month's partition, which the guard records and gives its truncate guard" do
      last = Partitions.list("audit_entries").reject(&:default?).last
      as_owner do
        created = Partitions.ensure!(now: last.from, tables: [ "audit_entries" ])["audit_entries"]
        expect(created).to include("audit_entries_p#{last.to.strftime('%Y%m%d')}")
        entry(last.to + 1.day)
        refused("UPDATE audit_entries SET action = 'host.retired' WHERE occurred_at >= #{c.quote(last.to)}", /append-only: UPDATE/)
        refused("TRUNCATE #{created.first}", /append-only: TRUNCATE/)
        expect(c.select_values("SELECT tgname FROM pg_trigger WHERE tgrelid = #{c.quote(created.first)}::regclass ORDER BY 1"))
          .to eq(%w[audit_entries_no_update_or_delete audit_entries_partition_no_truncate])
        expect(Partitions.audit_guard_problem).to be_nil
      end
    end

    it "guards a partition the app's role makes under another name as any other" do
      from = Partitions.list("audit_entries").reject(&:default?).last.to
      as_owner do
        attempt("CREATE TABLE fleet_spec_month PARTITION OF audit_entries FOR VALUES FROM (#{c.quote(from)}) TO (#{c.quote(from + 1.month)})")
        entry(from + 1.day)
        refused("TRUNCATE fleet_spec_month", /append-only: TRUNCATE/)
        refused("DROP TABLE fleet_spec_month")
        refused("CREATE OR REPLACE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON fleet_spec_month FOR EACH STATEMENT WHEN (false) EXECUTE FUNCTION audit_entries_append_only()")
        expect(Partitions.audit_guard_problem).to be_nil
      end
    end

    # Should fix 7: what got through while the guard was off is reported.
    describe "Partitions::GuardCheck" do
      it "reports a truncate guard replaced with a WHEN condition, or disabled (bypass 1)" do
        unguarded { c.execute("CREATE OR REPLACE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON #{partition} FOR EACH STATEMENT WHEN (false) EXECUTE FUNCTION audit_entries_append_only()") }
        expect(problem).to eq("trigger audit_entries_partition_no_truncate on #{partition} is not one of the audit log's guards as installed (a WHEN condition, disabled, or another function)")
      end

      it "reports a partition left detaching, whose entries are hidden (bypass 2)" do
        c.execute("UPDATE pg_inherits SET inhdetachpending = true WHERE inhrelid = #{c.quote(partition)}::regclass")
        expect(problem).to eq("#{partition} is being detached, so its entries are hidden")
      end

      it "reports a search path other than public, and another audit_entries (bypass 3)" do
        as_owner do
          c.execute("SET LOCAL search_path = \"$user\", public")
          expect(Partitions.audit_guard_problem).to eq("the app's search_path is \"$user\", public, not public (config/database.yml sets schema_search_path)")
          c.execute("SET LOCAL search_path = public")
        end
        unguarded { c.execute("CREATE SCHEMA #{role} AUTHORIZATION #{role} CREATE TABLE audit_entries (id bigint)") }
        expect(problem).to eq("another relation is named audit_entries (#{role}.audit_entries)")
      end

      it "reports an id sequence reset behind the ids, or no longer the id's default (should fix 5)" do
        c.execute("SELECT setval('audit_entries_id_seq', 1)")
        expect(problem).to eq("the id sequence audit_entries_id_seq is behind the highest id, so ids would repeat")
        unguarded { c.execute("ALTER TABLE audit_entries ALTER COLUMN id DROP DEFAULT") }
        expect(problem).to eq("audit_entries.id no longer takes its value from the guarded sequence")
      end

      it "reports a sequence the app's role could reset, a missing default partition, an unlogged one, and a definer guard function" do
        c.execute("GRANT UPDATE ON SEQUENCE audit_entries_id_seq TO #{role}")
        expect(problem).to eq("the id sequence audit_entries_id_seq is not the superuser's, or the app's role can reset it")
        c.execute("REVOKE UPDATE ON SEQUENCE audit_entries_id_seq FROM #{role}")
        unguarded { c.execute("ALTER TABLE audit_entries DETACH PARTITION audit_entries_default") }
        expect(problem).to match(/default partition is not the superuser's audit_entries_default/)
        unguarded do
          c.execute("ALTER TABLE audit_entries ATTACH PARTITION audit_entries_default DEFAULT")
          c.execute("ALTER TABLE #{partition} SET UNLOGGED")
        end
        expect(problem).to eq("#{partition} is not a logged table")
        unguarded do
          c.execute("ALTER TABLE #{partition} SET LOGGED")
          c.execute("ALTER FUNCTION audit_entries_append_only() SECURITY DEFINER")
        end
        expect(problem).to match(/runs as its owner \(SECURITY DEFINER\)/)
      end

      it "reports a partition the guard does not record, a missing truncate guard, and the guard not installed" do
        from = Partitions.list("audit_entries").reject(&:default?).last.to
        unguarded { c.execute("CREATE TABLE fleet_spec_month PARTITION OF audit_entries FOR VALUES FROM (#{c.quote(from)}) TO (#{c.quote(from + 1.month)})") }
        expect(problem).to eq("fleet_spec_month is not protected by the audit guard (the superuser runs ops/postgres/audit-guard.sql again)")
        c.execute("INSERT INTO fleet_audit_guard.protected (kind, objid) VALUES ('partition', 'fleet_spec_month'::regclass)")
        expect(problem).to eq("fleet_spec_month has no truncate guard")
        c.execute("ALTER EVENT TRIGGER fleet_audit_guard_drop DISABLE")
        expect(problem).to match(/event triggers are not installed/)
        c.execute("ALTER EVENT TRIGGER fleet_audit_guard_drop ENABLE")
        unguarded { c.execute("ALTER FUNCTION audit_entries_append_only() OWNER TO #{role}") }
        expect(problem).to match(/not owned by the superuser/)
        unguarded { c.execute("ALTER SCHEMA fleet_audit_guard OWNER TO #{role}") }
        expect(problem).to match(/fleet_audit_guard schema is missing or not the superuser's/)
      end
    end
  end
end
