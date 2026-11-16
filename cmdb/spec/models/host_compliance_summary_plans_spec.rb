require "rails_helper"

# #224: the summaries' trigger function plans its transition-table queries for each statement. Statically, PL/pgSQL
# kept the plan it made first in the session, for that statement's row count, so after a one-row update a bulk UPDATE
# of hosts ran a nested loop over its transition tables: quadratic, 29 to 40 s for 20,000 rows instead of about 0.1 s.
RSpec.describe "Compliance summary trigger plans" do
  let(:connection) { ActiveRecord::Base.connection }

  it "plans a bulk UPDATE of hosts for its own rows, even right after a one-row update in the same session" do
    now = Time.current
    Host.insert_all!(Array.new(4_000) { |i| { name: "plan-#{i}", hostname: "plan-#{i}.example.lan", tags: [], enrollment_state: "pending", created_at: now, updated_at: now } })
    ids = Host.where("name LIKE 'plan-%'").pluck(:id)
    # notes is no field the summaries copy: the timing is the trigger's query over the transition tables, no recount.
    clock = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
    bulk = ->(notes) { clock.call.then { |started| Host.where(id: ids).update_all(notes:) && clock.call - started } }

    connection.execute("DISCARD PLANS")
    Host.where(id: ids.first).update_all(notes: "one row") # the session's first plan, for one row
    after_one_row = bulk.call("after one row")
    connection.execute("DISCARD PLANS")
    planned_fresh = bulk.call("planned fresh")

    expect(after_one_row).to be < (planned_fresh * 3) + 0.1
  end

  it "runs every query over a transition table through EXECUTE" do
    definition = connection.select_value("SELECT pg_get_functiondef('host_compliance_summaries_changed'::regproc)")
    static = definition.lines.grep(/\b(old_rows|new_rows)\b/).grep_v(/EXECUTE|\A\s*(SELECT|FROM|WHERE|AND|OR|JOIN|INSERT|ON CONFLICT)\b|\$q\$/)
    expect(static).to be_empty
    # Statements, not mentions in comments (review of #226): 2 for hosts, 1 for advisories, 3 each for cis_results and
    # vulnerability_findings.
    expect(definition.scan(/^\s*EXECUTE\b/).size).to eq(9)
  end
end
