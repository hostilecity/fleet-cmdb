require "rails_helper"

# Hosts are looked up by agent version for the release delete guard, AgentRelease#in_use?, the Agents page's
# per-release count, and (P1-UPDATES) rollouts. Without an index each read the whole hosts table, which at
# fleet scale is seconds (review of #74).
RSpec.describe "Agent version index" do
  def plan(sql)
    ActiveRecord::Base.connection.select_values("EXPLAIN #{sql}").join("\n")
  end

  # The test tables are tiny, so the planner would rightly prefer a sequential scan; turning that off for
  # this transaction shows whether an index can serve the query at all.
  around do |example|
    ActiveRecord::Base.connection.execute("SET LOCAL enable_seqscan = off")
    example.run
  end

  it "serves the fleet's hosts on a version, as the model, the Agents page, and the delete guard ask" do
    expect(plan(AgentRelease.new(version: "1.2.0").hosts_running.select(:id).to_sql)).to include("index_hosts_in_fleet_on_agent_version")
    counts = Host.in_fleet.where(agent_version: %w[1.2.0 1.3.0]).group(:agent_version).select("agent_version, count(*)")
    expect(plan(counts.to_sql)).to include("index_hosts_in_fleet_on_agent_version")
    guard = Rails.root.join("db/functions/agent_releases_guard_v01.sql").read[/SELECT 1 FROM hosts WHERE [^)]+/]
    expect(plan(guard.sub("OLD.version", "'1.2.0'"))).to include("index_hosts_in_fleet_on_agent_version")
  end
end
