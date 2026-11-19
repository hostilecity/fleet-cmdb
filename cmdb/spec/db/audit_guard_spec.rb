require "rails_helper"

# The audit log's hardened guard (ADR 0027, "The audit log's guards"; threat model A3, C12, F-5): ops/postgres/audit-guard.sql,
# run once by the PostgreSQL superuser. The role it must stop is set up as `cmdb` is on the server: not a superuser,
# owner of the database, of the public schema, of every table and function in it, and so (as before the step, or after
# a restore) of the guard function. Against it the guard refuses every bypass the reviews of #239 found, and Partitions::GuardCheck
# reports each one that got through while the guard was off. Everything here, the role and the event triggers
# included, is rolled back with the example: the file's own BEGIN and COMMIT are left out (a spec below checks they are
# there). Installing an event trigger needs a superuser: CI's PostgreSQL service is one, and so is a local cluster's
# default role. DETACH ... CONCURRENTLY cannot run in a transaction: spec/db/audit_guard_concurrently_spec.rb.
RSpec.describe "ops/postgres/audit-guard.sql" do
  let(:c) { ApplicationRecord.connection }
  let(:file) { Rails.root.join("../ops/postgres/audit-guard.sql").read }
  # The file inside the example's transaction: without its BEGIN and COMMIT, so a run that should have been refused but
  # was not cannot commit the example (a spec below checks they are there).
  let(:bare_script) { file.sub(/^BEGIN;$/, "").sub(/^COMMIT;$/, "") }
  # As the documented connection starts it: on PostgreSQL 17 and later, with event triggers off (PGOPTIONS), which the
  # file insists on (final check of #249, B1).
  let(:script) { (pg17? ? "SET LOCAL event_triggers = off;\n" : "") + bare_script }
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

  # Logged in as the role, as `cmdb` is: the file's SET LOCAL ROLE NONE returns to the login's own role, which SET ROLE
  # would not show.
  def as_login
    c.execute("SET SESSION AUTHORIZATION #{role}")
    yield
  ensure
    c.execute("RESET SESSION AUTHORIZATION")
  end

  # The file as the superuser, inside the example's transaction; then the connection's own search path again.
  def install
    c.execute(script)
    restore_settings
  end

  # The file's SET LOCALs last to the end of the example's transaction: back to what the app's connections use.
  def restore_settings
    c.execute("SET LOCAL search_path = public")
    c.execute("SET LOCAL client_min_messages = notice")
    c.execute("SET LOCAL session_replication_role = origin")
    c.execute("SET LOCAL event_triggers = on") if pg17?
  end

  def pg17? = c.select_value("SELECT current_setting('server_version_num')::int") >= 170_000

  # ops/postgres/audit-guard-recover.sql, in the example's transaction, connected as documented.
  let(:bare_recover) { Rails.root.join("../ops/postgres/audit-guard-recover.sql").read.sub(/^BEGIN;$/, "").sub(/^COMMIT;$/, "") }
  let(:recover) { (pg17? ? "SET LOCAL event_triggers = off;\n" : "") + bare_recover }

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
    c.execute(<<~SQL) # every table, view, and function in public, as the app's migrations leave them
      DO $$
      DECLARE r record;
      BEGIN
        FOR r IN SELECT c.oid::regclass AS rel, c.relkind FROM pg_class c
                 WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm') LOOP
          EXECUTE format('ALTER %s %s OWNER TO #{role}', CASE r.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' ELSE 'TABLE' END, r.rel);
        END LOOP;
        FOR r IN SELECT p.oid::regprocedure AS fn FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace LOOP
          EXECUTE format('ALTER ROUTINE %s OWNER TO #{role}', r.fn);
        END LOOP;
      END $$
    SQL
    expect(audit_tables.map { |table| c.select_value("SELECT relowner::regrole::text FROM pg_class WHERE oid = '#{table}'::regclass") }.uniq).to eq([ role ])
  end

  after { c.execute("RESET ROLE") }

  describe "installing it" do
    it "is one transaction, with its search path pinned" do
      expect(file).to match(/^BEGIN;\n(?:--.*\n)*SET LOCAL ROLE NONE;\nSET LOCAL search_path = pg_catalog, pg_temp;$/)
      expect(file.rstrip).to end_with("COMMIT;")
    end

    it "is done by the superuser only, never while the app's role is one or as good as one, and safe to run again" do
      as_login { refused(bare_script, %r{run ops/postgres/audit-guard.sql as the PostgreSQL superuser, not as #{role}}) }
      c.execute("ALTER TABLE audit_entries OWNER TO CURRENT_USER")
      refused(script, /audit_entries is owned by a superuser/)
      c.execute("ALTER TABLE audit_entries OWNER TO #{role}")
      c.execute("GRANT pg_write_server_files TO #{role}")
      refused(script, /#{role} is a member of pg_write_server_files/)
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
      refused(script, /a fleet_audit_guard schema exists that no superuser owns/)
      expect(superuser?).to be(false)
    end

    it "refuses audit tables that carry anything but their own guards" do
      as_owner do
        attempt("CREATE OR REPLACE TRIGGER audit_entries_partition_no_truncate BEFORE TRUNCATE ON #{partition} FOR EACH STATEMENT WHEN (false) EXECUTE FUNCTION audit_entries_append_only()")
        attempt("ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_no_truncate")
        attempt("CREATE RULE fleet_spec AS ON INSERT TO audit_entries DO INSTEAD NOTHING")
      end
      expect { attempt(script) }.to raise_error(ActiveRecord::StatementInvalid) do |error|
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
          .to eq(%w[audit_entries_id_from_sequence audit_entries_no_update_or_delete audit_entries_partition_no_truncate])
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
        expect(problem).to eq("audit_entries_default, recorded by the audit guard, is no longer attached to audit_entries, so its entries are hidden")
        unguarded { c.execute("ALTER TABLE audit_entries ATTACH PARTITION audit_entries_default DEFAULT") }
        unguarded { c.execute("ALTER TABLE audit_entries_default DROP CONSTRAINT audit_entries_default_refuses_rows") }
        expect(problem).to match(/default partition is not the superuser's audit_entries_default/)
        unguarded do
          c.execute("ALTER TABLE audit_entries_default ADD CONSTRAINT audit_entries_default_refuses_rows CHECK (false)")
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
        expect(problem).to eq("fleet_spec_month has no truncate guard (the superuser runs ops/postgres/audit-guard.sql again)")
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
  # The third review of #239: each spec sets up what the review did, as the role, and fails against the file it reviewed.
  describe "the third review's findings" do
    let(:escalated) { /the audit guard was not installed: .*uses (function|operator|type) public\.(fleet_spec_|##)/ }

    # Code the role writes that makes it a superuser if a superuser ever runs it: an IMMUTABLE function (which the planner
    # folds, and an index build evaluates, as the session's user) calling a VOLATILE one.
    def plant_code
      as_owner do
        attempt(<<~SQL)
          CREATE FUNCTION public.fleet_spec_escalate() RETURNS void LANGUAGE plpgsql VOLATILE AS $$
          BEGIN
            IF (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) THEN EXECUTE 'ALTER ROLE #{role} SUPERUSER'; END IF;
          END $$
        SQL
        attempt("CREATE FUNCTION public.fleet_spec_f(int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN PERFORM public.fleet_spec_escalate(); RETURN $1; END $$")
        attempt("CREATE FUNCTION public.fleet_spec_plus(bigint, int) RETURNS bigint LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN PERFORM public.fleet_spec_escalate(); RETURN $1 + $2; END $$")
        attempt("CREATE OPERATOR public.## (LEFTARG = bigint, RIGHTARG = int, FUNCTION = public.fleet_spec_plus)")
        attempt("CREATE DOMAIN public.fleet_spec_text AS text CHECK (public.fleet_spec_f(1) = 1)")
      end
    end

    # Each way the role can attach its code to an audit table, and how it takes it off again.
    def payloads
      {
        "CREATE INDEX fleet_spec_idx ON #{partition} (id) WHERE public.fleet_spec_f(1) = 1" => "DROP INDEX fleet_spec_idx",
        "CREATE INDEX fleet_spec_idx ON audit_entries ((id + public.fleet_spec_f(3)))" => "DROP INDEX fleet_spec_idx",
        "CREATE INDEX fleet_spec_idx ON #{partition} ((id OPERATOR(public.##) 1))" => "DROP INDEX fleet_spec_idx",
        "CREATE STATISTICS fleet_spec_stats ON (public.fleet_spec_f(2) + 0), id FROM audit_entries" => "DROP STATISTICS fleet_spec_stats",
        "ALTER TABLE #{partition} ADD CONSTRAINT fleet_spec_check CHECK (public.fleet_spec_f(1) = 1) NOT VALID" => "ALTER TABLE #{partition} DROP CONSTRAINT fleet_spec_check",
        "ALTER TABLE audit_entries ALTER COLUMN request_id SET DEFAULT public.fleet_spec_f(1)::text" => "ALTER TABLE audit_entries ALTER COLUMN request_id DROP DEFAULT",
        "ALTER TABLE audit_entries ADD COLUMN fleet_spec public.fleet_spec_text" => "ALTER TABLE audit_entries DROP COLUMN fleet_spec"
      }
    end

    it "B1: refuses to run, from the catalogs alone, while an audit table carries code other than a superuser's built-ins" do
      plant_code
      payloads.each do |plant, remove|
        as_owner { attempt(plant) }
        refused(script, escalated)
        expect(superuser?).to be(false), plant
        as_owner { attempt(remove) }
      end
      install
      expect(superuser?).to be(false)
      expect(problem).to be_nil
    end

    it "B1: refuses CREATE INDEX and CREATE STATISTICS on the audit tables, and a re-run refuses one that got through" do
      install
      plant_code
      from = Partitions.list("audit_entries").reject(&:default?).last.to
      as_owner do
        refused("CREATE INDEX fleet_spec_idx ON #{partition} (id) WHERE public.fleet_spec_f(1) = 1")
        refused("CREATE INDEX fleet_spec_idx ON #{partition} (actor_id)")
        refused("CREATE INDEX fleet_spec_idx ON audit_entries (actor_id)", /append-only|must be owner of table audit_entries_default/)
        refused("CREATE STATISTICS fleet_spec_stats ON (public.fleet_spec_f(2) + 0), id FROM audit_entries")
        refused("CREATE STATISTICS fleet_spec_stats ON id, occurred_at FROM #{partition}")
        refused("ALTER INDEX #{partition}_pkey RENAME TO fleet_spec_pkey")
        refused("CREATE TABLE fleet_spec_month PARTITION OF audit_entries (CONSTRAINT fleet_spec_x EXCLUDE USING btree ((id OPERATOR(public.##) 1) WITH =)) " \
                "FOR VALUES FROM (#{c.quote(from)}) TO (#{c.quote(from + 1.month)})")
      end
      expect(superuser?).to be(false)

      # One made while the guard was off (or before it was installed) is reported, and the step refuses to run over it.
      unguarded { as_owner { attempt("CREATE INDEX fleet_spec_idx ON #{partition} (id) WHERE public.fleet_spec_f(1) = 1") } }
      expect(problem).to match(/\Aindex public.fleet_spec_idx uses function public.fleet_spec_f\(integer\), which is not a superuser's built-in: .*\(the app's role drops it \(DROP INDEX\)\)\z/)
      refused(script, escalated)
      expect(superuser?).to be(false)
    end

    it "B2: refuses a table named audit_entries_default unless it is the superuser's default partition refusing every row" do
      as_owner { attempt("CREATE TABLE public.audit_entries_default (x int)") }
      refused(script, /public.audit_entries_default exists but is not the default partition of audit_entries/)
      as_owner do
        attempt("DROP TABLE public.audit_entries_default")
        attempt("CREATE TABLE public.audit_entries_default PARTITION OF audit_entries (CONSTRAINT fleet_spec_no CHECK (false)) DEFAULT")
      end
      refused(script, /public.audit_entries_default is not the superuser's/)
      as_owner { attempt("DROP TABLE public.audit_entries_default") }
      c.execute("CREATE TABLE public.audit_entries_default PARTITION OF audit_entries DEFAULT") # the superuser's, but it takes rows
      refused(script, /public.audit_entries_default has checks of its own other than one CHECK \(false\)/)
      c.execute("DROP TABLE public.audit_entries_default")
      as_owner { attempt("CREATE TABLE fleet_spec_default PARTITION OF audit_entries DEFAULT") }
      refused(script, /fleet_spec_default is a default partition of audit_entries other than public.audit_entries_default/)
      as_owner { attempt("DROP TABLE fleet_spec_default") }

      install
      install # it takes its own default partition from the run before
      expect(c.select_value("SELECT partdefid::regclass::text FROM pg_partitioned_table WHERE partrelid = 'audit_entries'::regclass")).to eq("audit_entries_default")
      expect(problem).to be_nil
    end

    it "B3: leaves the app's role able to read everything pg_dump reads, and still unable to reset the sequence" do
      install
      as_owner do
        c.select_rows(<<~SQL).each do |relation, kind|
          SELECT c.oid::regclass::text, c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname IN ('public', 'fleet_audit_guard') AND c.relkind IN ('r', 'p', 'S')
        SQL
          if kind == "S"
            attempt("SELECT last_value, is_called FROM #{relation}")
          else
            attempt("LOCK TABLE #{relation} IN ACCESS SHARE MODE")
            attempt("SELECT * FROM ONLY #{relation} LIMIT 0")
          end
        end
        refused("SELECT setval('audit_entries_id_seq', 1)", /permission denied/)
      end
    end

    it "S1: treats a member of a superuser role, directly or through another role, as a superuser" do
      c.execute("CREATE ROLE fleet_spec_super SUPERUSER NOLOGIN")
      c.execute("CREATE ROLE fleet_spec_middle NOLOGIN")
      c.execute("GRANT fleet_spec_super TO fleet_spec_middle")
      c.execute("GRANT fleet_spec_middle TO #{role}")
      refused(script, /#{role} is a member of fleet_spec_super, a superuser/)
      expect(problem).to eq("the app's PostgreSQL role is a member of the superuser role fleet_spec_super, so no guard can hold against it")
      c.execute("REVOKE fleet_spec_middle FROM #{role}")
      c.execute("GRANT fleet_spec_super TO #{role}")
      refused(script, /#{role} is a member of fleet_spec_super, a superuser/)
    end

    it "S1: reports a recorded partition that is no longer attached, detached or dropped while the guard was off" do
      install
      unguarded { c.execute("ALTER TABLE audit_entries DETACH PARTITION #{partition}") }
      expect(problem).to eq("#{partition}, recorded by the audit guard, is no longer attached to audit_entries, so its entries are hidden")
      unguarded { c.execute("DROP TABLE #{partition}") }
      expect(problem).to match(/\Athe partition with OID \d+, recorded by the audit guard, is no longer attached/)
    end

    it "S2: gives every new entry its id from the superuser's sequence, whatever id the insert names" do
      install
      existing = c.select_value("SELECT max(id) FROM audit_entries")
      as_owner do
        insert = ->(id) { c.select_value("INSERT INTO audit_entries (id, actor_type, action) VALUES (#{id}, 'system', 'host.edited') RETURNING id") }
        repeated = insert.call(existing)
        chosen = insert.call(9_000_000_000)
        expect(repeated).to be > existing
        expect(chosen).to be > repeated
        expect(chosen).to be < 9_000_000_000
        expect(c.select_value("SELECT count(*) = count(DISTINCT id) FROM audit_entries")).to be(true)
        refused("DROP TRIGGER audit_entries_id_from_sequence ON audit_entries")
        refused("ALTER TABLE audit_entries DISABLE TRIGGER audit_entries_id_from_sequence")
        refused("CREATE OR REPLACE FUNCTION fleet_audit_guard.audit_entries_id() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
                /permission denied|must be owner/)
      end
      unguarded { c.execute("DROP TRIGGER audit_entries_id_from_sequence ON audit_entries") }
      expect(problem).to eq("audit_entries has no id trigger (the superuser runs ops/postgres/audit-guard.sql again)")
    end

    it "S2: reads the sequence by OID, so a mixed-case name or a decoy cannot hide that it is behind" do
      as_owner do
        attempt('ALTER SEQUENCE audit_entries_id_seq RENAME TO "Audit_Seq"')
        attempt(%q(SELECT setval('"Audit_Seq"', 1)))
        attempt("CREATE SEQUENCE public.audit_seq")
        attempt("SELECT setval('public.audit_seq', 999999999)")
        attempt("INSERT INTO audit_entries (id, actor_type, action) VALUES (500, 'system', 'host.edited')")
      end
      refused(script, /the id sequence public."Audit_Seq" is behind the highest id \(\d+ > 1\)/)
      as_owner { attempt(%q(SELECT setval('"Audit_Seq"', (SELECT max(id) FROM audit_entries)))) }
      install
      c.execute(%q(SELECT setval('"Audit_Seq"', 1)))
      expect(problem).to eq('the id sequence "Audit_Seq" is behind the highest id, so ids would repeat')
    end

    it "N1: refuses a composite type named audit_entries" do
      install
      as_owner do
        attempt("CREATE SCHEMA #{role}")
        refused("CREATE TYPE #{role}.audit_entries AS (id int)", /no type may be named audit_entries/)
      end
    end

    it "N2: runs as the superuser it logged in as, even when its role is set to the app's" do
      c.execute("SET LOCAL event_triggers = off") if pg17? # as PGOPTIONS does at login, before the database's role setting applies
      c.execute("SET ROLE #{role}") # as ALTER DATABASE ... SET role would (spec/db/audit_guard_concurrently_spec.rb does it for real)
      c.execute(bare_script)
      restore_settings
      expect(problem).to be_nil
    end

    # Copilot's review of #249.
    it "puts back the parent's update and delete guard and truncate guard if the app's role dropped them first" do
      as_owner do
        attempt("DROP TRIGGER audit_entries_no_update_or_delete ON audit_entries")
        attempt("DROP TRIGGER audit_entries_no_truncate ON audit_entries")
      end
      install
      as_owner do
        refused("UPDATE audit_entries SET action = 'host.retired'", /append-only: UPDATE/)
        refused("DELETE FROM audit_entries", /append-only: DELETE/)
        refused("TRUNCATE audit_entries", /append-only: TRUNCATE/)
      end
      expect(problem).to be_nil
      unguarded { c.execute("DROP TRIGGER audit_entries_no_update_or_delete ON audit_entries") }
      expect(problem).to eq("audit_entries has no update and delete guard (the superuser runs ops/postgres/audit-guard.sql again)")
    end

    it "refuses an id sequence that counts down or cycles, and reports one changed while the guard was off" do
      as_owner { attempt("ALTER SEQUENCE audit_entries_id_seq INCREMENT BY -1") }
      refused(script, /the id sequence public.audit_entries_id_seq counts down or cycles/)
      as_owner { attempt("ALTER SEQUENCE audit_entries_id_seq INCREMENT BY 1 CYCLE") }
      refused(script, /counts down or cycles/)
      as_owner { attempt("ALTER SEQUENCE audit_entries_id_seq NO CYCLE") }
      install
      expect(problem).to be_nil
      unguarded { c.execute("ALTER SEQUENCE audit_entries_id_seq CYCLE") }
      expect(problem).to eq("the id sequence audit_entries_id_seq counts down or cycles, so ids would repeat")
    end

    it "leaves no grant on the sequence but the app role's own, so a grant to a role it belongs to cannot reset it" do
      as_owner { attempt("GRANT UPDATE ON SEQUENCE audit_entries_id_seq TO pg_database_owner") }
      install
      as_owner { refused("SELECT setval('audit_entries_id_seq', 1)", /permission denied/) }
      expect(problem).to be_nil
      c.execute("GRANT UPDATE ON SEQUENCE audit_entries_id_seq TO pg_database_owner")
      expect(problem).to eq("the id sequence audit_entries_id_seq is not the superuser's, or the app's role can reset it")
    end
  end
  # The second review of #249: each spec sets up what the review did, as the role.
  describe "the second review's findings" do
    def plant_escalation
      as_owner do
        attempt(<<~SQL)
          CREATE FUNCTION public.fleet_spec_escalate() RETURNS void LANGUAGE plpgsql VOLATILE AS $$
          BEGIN
            IF (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) THEN EXECUTE 'ALTER ROLE #{role} SUPERUSER'; END IF;
          END $$
        SQL
        attempt("CREATE FUNCTION public.fleet_spec_f(int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN PERFORM public.fleet_spec_escalate(); RETURN $1; END $$")
      end
    end

    it "S1: refuses to run while an event trigger other than its own exists, and turns event triggers off where it can" do
      as_owner { attempt("CREATE FUNCTION public.fleet_spec_et() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN END $$") }
      c.execute("CREATE EVENT TRIGGER fleet_spec_et ON ddl_command_end EXECUTE FUNCTION public.fleet_spec_et()")
      refused(script, /event triggers other than the guard's exist \(fleet_spec_et, on ddl_command_end, owned by [^,]+, running public.fleet_spec_et\(\)\)/)
      c.execute("DROP EVENT TRIGGER fleet_spec_et")
      c.execute("CREATE EVENT TRIGGER fleet_audit_guard_ddl ON ddl_command_end EXECUTE FUNCTION public.fleet_spec_et()") # the guard's name, not its function
      refused(script, /event triggers other than the guard's exist \(fleet_audit_guard_ddl/)
      c.execute("DROP EVENT TRIGGER fleet_audit_guard_ddl")

      c.execute(script)
      expect(c.select_value("SHOW event_triggers")).to eq("off") if pg17?
      expect(c.select_value("SHOW client_min_messages")).to eq("warning") # no NOTICE that the old id trigger was dropped
      restore_settings
      expect(problem).to be_nil
      c.execute("CREATE EVENT TRIGGER fleet_spec_et ON sql_drop EXECUTE FUNCTION public.fleet_spec_et()")
      expect(problem).to match(/\Aevent trigger fleet_spec_et \(on sql_drop, owned by .*, running fleet_spec_et\(\)\) is not the audit guard's: the superuser's next step/)
    end

    it "S2: refuses an unlogged id sequence, keeps it logged, and reports one made unlogged while the guard was off" do
      as_owner { attempt("ALTER SEQUENCE audit_entries_id_seq SET UNLOGGED") }
      refused(script, /the id sequence public.audit_entries_id_seq is not logged/)
      as_owner { attempt("ALTER SEQUENCE audit_entries_id_seq SET LOGGED") }
      install
      as_owner { refused("ALTER SEQUENCE audit_entries_id_seq SET UNLOGGED", /append-only|must be owner/) }
      unguarded { c.execute("ALTER SEQUENCE audit_entries_id_seq SET UNLOGGED") }
      expect(problem).to eq("the id sequence audit_entries_id_seq is not logged, so it would restart after a crash and ids would repeat")
    end

    it "S3: refuses a new partition whose own default uses the role's code, and recovers one an earlier guard let through" do
      install
      plant_escalation
      from = Partitions.list("audit_entries").reject(&:default?).last.to
      month = "CREATE TABLE fleet_spec_month PARTITION OF audit_entries (action DEFAULT public.fleet_spec_f(1)::text) " \
              "FOR VALUES FROM (#{c.quote(from)}) TO (#{c.quote(from + 1.month)})"
      as_owner { refused(month, /may not have a column default or constraint using code other than PostgreSQL's own/) }

      # As an earlier version of the guard let through: made, then recorded as an audit partition, which the role can then
      # no longer change.
      unguarded { as_owner { attempt(month) } }
      c.execute("INSERT INTO fleet_audit_guard.protected (kind, objid) VALUES ('partition', 'fleet_spec_month'::regclass)")
      expect(problem).to match(%r{\Adefault value for column action of table public.fleet_spec_month uses function public.fleet_spec_f\(integer\), .*audit-guard-recover.sql})
      refused(script, %r{uses function public.fleet_spec_f\(integer\).*audit-guard-recover.sql}m)
      as_owner { refused("ALTER TABLE fleet_spec_month ALTER COLUMN action DROP DEFAULT", /default value for .*fleet_spec_month.action may not be dropped/) }
      as_login { refused(bare_recover, /as the PostgreSQL superuser, not as #{role}/) }

      c.execute(recover) # the recovery: the superuser drops exactly that default, evaluating nothing
      restore_settings
      expect(superuser?).to be(false)
      expect(c.select_value("SELECT count(*) FROM pg_attrdef WHERE adrelid = 'fleet_spec_month'::regclass AND adnum = (SELECT attnum FROM pg_attribute WHERE attrelid = 'fleet_spec_month'::regclass AND attname = 'action')")).to eq(0)
      install
      expect(superuser?).to be(false)
      expect(problem).to be_nil
      c.execute(recover) # nothing left to drop: it says so and changes nothing
      restore_settings
    end

    it "N2: revokes a grant that was passed on, rather than stopping at dependent privileges" do
      c.execute("CREATE ROLE fleet_spec_x NOLOGIN")
      c.execute("CREATE ROLE fleet_spec_y NOLOGIN")
      as_owner { attempt("GRANT UPDATE ON SEQUENCE audit_entries_id_seq TO fleet_spec_x WITH GRANT OPTION") }
      c.execute("SET ROLE fleet_spec_x")
      c.execute("GRANT UPDATE ON SEQUENCE audit_entries_id_seq TO fleet_spec_y")
      c.execute("RESET ROLE")
      install
      expect(c.select_value("SELECT has_sequence_privilege('fleet_spec_y', 'audit_entries_id_seq', 'UPDATE')")).to be(false)
    end

    it "N4: reports an invalid index left on an audit table, which the app's role may drop" do
      install
      unguarded do
        c.execute("CREATE INDEX fleet_spec_cic ON #{partition} (action)")
        c.execute("UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'fleet_spec_cic'::regclass") # as a refused CREATE INDEX CONCURRENTLY leaves it
      end
      expect(problem).to start_with("index fleet_spec_cic on the audit log is invalid")
      as_owner { attempt("DROP INDEX fleet_spec_cic") }
      expect(problem).to be_nil
    end

    it "lists a parent's index once, not once for each partition's copy of it" do
      plant_escalation
      as_owner { attempt("CREATE INDEX fleet_spec_idx ON audit_entries ((id + public.fleet_spec_f(3)))") }
      expect { attempt(script) }.to raise_error(ActiveRecord::StatementInvalid) { |error| expect(error.message.scan(" uses function ").size).to eq(1) }
      expect(superuser?).to be(false)
    end
  end
  # The final check of #249: each set up as the role, as the review did.
  describe "the final check's findings" do
    def plant_code
      as_owner do
        attempt(<<~SQL)
          CREATE FUNCTION public.fleet_spec_escalate() RETURNS void LANGUAGE plpgsql VOLATILE AS $$
          BEGIN
            IF (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) THEN EXECUTE 'ALTER ROLE #{role} SUPERUSER'; END IF;
          END $$
        SQL
        attempt("CREATE FUNCTION public.fleet_spec_f(text) RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN PERFORM public.fleet_spec_escalate(); RETURN $1; END $$")
      end
    end

    def defaults = c.select_rows("SELECT a.attname, pg_get_expr(d.adbin, d.adrelid) FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum WHERE d.adrelid = 'audit_entries'::regclass ORDER BY 1")

    it "B1: on PostgreSQL 17 and later, refuses a session that connected with event triggers on (a login trigger may have run)" do
      if pg17?
        refused(bare_script, /connect with event triggers off: this session connected with them on/)
        install
        refused(bare_recover, /connect with event triggers off/)
      else
        install # PostgreSQL 16 has no login event triggers, and no event_triggers setting to require
      end
      expect(problem).to be_nil
    end

    it "S1: the recovery drops exactly the defaults and constraints the step flags, a parent's on the parent, and puts back the app's defaults" do
      install
      plant_code
      before = defaults
      unguarded do
        # On the parent these recurse into the superuser's default partition, so (as an earlier guard let through) the
        # superuser sets them; setting a default evaluates nothing.
        c.execute("ALTER TABLE audit_entries ALTER COLUMN action SET DEFAULT public.fleet_spec_f('parent')") # copied to every partition
        c.execute("ALTER TABLE audit_entries ALTER COLUMN occurred_at SET DEFAULT public.fleet_spec_f('2026-01-01')::timestamp")
        as_owner do
          attempt("ALTER TABLE #{partition} ALTER COLUMN request_id SET DEFAULT public.fleet_spec_f('own')")
          attempt("ALTER TABLE #{partition} ALTER COLUMN target_type SET DEFAULT 'built-in'") # not flagged, kept
          attempt("ALTER TABLE #{partition} ADD CONSTRAINT fleet_spec_check CHECK (public.fleet_spec_f(action) IS NOT NULL) NOT VALID")
          attempt("CREATE INDEX fleet_spec_idx ON #{partition} ((public.fleet_spec_f(action)))") # flagged, but the role drops it
        end
      end
      flagged = c.select_values("SELECT what FROM fleet_audit_guard.untrusted_code('audit_entries'::regclass) ORDER BY 1")
      expect(flagged.size).to eq(5) # the parent's two defaults (not their 30-odd copies), the partition's own default, the check, the index
      expect { attempt(script) }.to raise_error(ActiveRecord::StatementInvalid) do |error|
        expect(error.message[/not installed: (.*?)\n/, 1].split("; ").sort).to eq(flagged) # the step lists the same objects
      end

      c.execute(recover)
      restore_settings
      expect(superuser?).to be(false)
      expect(c.select_values("SELECT what FROM fleet_audit_guard.untrusted_code('audit_entries'::regclass)")).to eq([ "index public.fleet_spec_idx uses function public.fleet_spec_f(text)" ])
      expect(defaults).to eq(before) # occurred_at is CURRENT_TIMESTAMP again; action has no default, as in the app's schema
      expect(c.select_value("SELECT pg_get_expr(d.adbin, d.adrelid) FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum " \
                            "WHERE d.adrelid = '#{partition}'::regclass AND a.attname = 'target_type'")).to eq("'built-in'::character varying")
      expect(c.select_value("SELECT count(*) FROM pg_constraint WHERE conname IN ('audit_entries_actor_type_valid', 'audit_entries_actor_id_matches_type') AND conrelid = '#{partition}'::regclass")).to eq(2)
      expect(problem).to start_with("index public.fleet_spec_idx uses function public.fleet_spec_f(text), which is not a superuser's built-in: it would run as the superuser in the audit guard's step (the app's role drops it (DROP INDEX))")
      as_owner { attempt("DROP INDEX fleet_spec_idx") }
      install
      expect(problem).to be_nil
      expect(superuser?).to be(false)
    end

    it "S1: the recovery refuses before the guard is installed, when the app's role can drop what the step names itself" do
      plant_code
      as_owner { attempt("ALTER TABLE audit_entries ALTER COLUMN action SET DEFAULT public.fleet_spec_f('parent')") }
      expect { attempt(script) }.to raise_error(ActiveRecord::StatementInvalid) { |error| expect(error.message.scan(" uses function ").size).to eq(1) }
      refused(recover, /the audit guard is not installed/)
      expect(superuser?).to be(false)
    end

    it "S2: /health gives each remedy that works under the guard, and says an older guard needs the step again" do
      install
      plant_code
      unguarded { as_owner { attempt("CREATE STATISTICS fleet_spec_stats ON (public.fleet_spec_f(action)), id FROM audit_entries") } }
      expect(problem).to end_with("(the app's role drops it (DROP STATISTICS))")
      as_owner { attempt("DROP STATISTICS fleet_spec_stats") }
      # A harmless function here: adding the column checks the domain against every row, which evaluates it.
      unguarded do
        as_owner do
          attempt("CREATE FUNCTION public.fleet_spec_plain(text) RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT true'")
          attempt("CREATE DOMAIN public.fleet_spec_text AS text CHECK (public.fleet_spec_plain(VALUE))")
        end
      end
      unguarded { c.execute("ALTER TABLE audit_entries ADD COLUMN fleet_spec public.fleet_spec_text") } # recurses into the superuser's default
      expect(problem).to end_with("(it can only have been added while the guard was off: see install-server.md, \"Recovery\")")
      unguarded { c.execute("ALTER TABLE audit_entries DROP COLUMN fleet_spec") }
      expect(problem).to be_nil
      c.execute("DROP FUNCTION fleet_audit_guard.untrusted_code(oid)")
      expect(problem).to eq("the audit guard is from an older version of ops/postgres/audit-guard.sql (the superuser runs it again)")
    end
  end
end
