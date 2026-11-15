require "rails_helper"

# Live fleet updates (P1-D05, #194): which changes refresh which streams, and when. A host's change refreshes the
# fleet stream and that host's stream; what happens to them then is LiveRefresh's (spec/services/live_refresh_spec.rb).
RSpec.describe FleetBroadcast do
  let(:host) { enrolled_host(name: "Media server").first }

  def fleet_and(*hosts) = [ described_class::STREAM, *hosts.map { |h| described_class.host_stream(h.id) } ].sort

  before do
    host
    clear_pending_refreshes
  end

  it "refreshes the fleet stream and the host's own when a heartbeat changes the status, and nothing for an ordinary heartbeat" do
    record_heartbeat(host)
    expect(pending_refreshes).to eq(fleet_and(host))
    clear_pending_refreshes
    record_heartbeat(host)
    expect(pending_refreshes).to eq([])
  end

  it "refreshes when a heartbeat reports a new agent version, so the fleet list's agent column updates (P1-D09)" do
    record_heartbeat(host)
    clear_pending_refreshes
    record_heartbeat(host, agent_version: "0.2.0")
    expect(pending_refreshes).to eq(fleet_and(host))
    clear_pending_refreshes
    record_heartbeat(host, agent_version: "0.2.0")
    expect(pending_refreshes).to eq([])
  end

  it "refreshes the fleet and every host page for every rollout action, and the host for the first offer of an update (P1-D09)" do
    host.update_columns(agent_version: "0.2.0")
    rollout = start_rollout(release: release_for_rollout("0.3.0"), canaries: [ host ])
    expect(pending_refreshes).to eq([ described_class::STREAM, described_class::ALL_HOSTS_STREAM ])
    clear_pending_refreshes
    Host.transaction { Rollouts.directive_for(host_id: host.id, agent_version: "0.2.0") }
    expect(pending_refreshes).to eq(fleet_and(host))
    clear_pending_refreshes
    Host.transaction { Rollouts.directive_for(host_id: host.id, agent_version: "0.2.0") } # a repeat offer changes nothing shown
    expect(pending_refreshes).to eq([])
    operator = rollout.started_by
    [ -> { Rollouts.halt!(rollout, actor: operator) }, -> { Rollouts.resume!(rollout, actor: operator) },
      -> { Rollouts.advance!(rollout, actor: operator) }, -> { Rollouts.cancel!(rollout, actor: operator) } ].each do |action|
      clear_pending_refreshes
      action.call
      expect(pending_refreshes).to include(described_class::STREAM, described_class::ALL_HOSTS_STREAM)
    end
  end

  it "requests once for all hosts a liveness evaluation moves" do
    other = enrolled_host.first
    [ host, other ].each { |h| record_heartbeat(h) }
    record_refresh_requests
    Liveness.evaluate!(now: 20.minutes.from_now)
    expect(fleet_refresh_requests).to contain_exactly(contain_exactly(host.id, other.id))
    Liveness.evaluate!(now: 20.minutes.from_now)
    expect(fleet_refresh_requests.size).to eq(1)
  end

  it "refreshes on enrollment transitions and edits" do
    record_refresh_requests
    host.revoke!(actor: Audit::SYSTEM)
    host.edit!({ name: "Renamed" }, actor: Audit::SYSTEM)
    host.edit!({ name: "Renamed" }, actor: Audit::SYSTEM) # no change, no refresh
    expect(fleet_refresh_requests).to eq([ [ host.id ], [ host.id ] ])
  end

  it "refreshes when a token is issued without a state change: pre-registering, or a new token for a pending host (review of #63)" do
    record_refresh_requests
    registered, = Enrollment::RegisterHost.call({ name: "Lab sandbox", hostname: "vm-06.example.lan" }, actor: Audit::SYSTEM)
    Enrollment::IssueToken.call(host: registered, actor: Audit::SYSTEM)
    Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM) # active -> pending: the transition's one refresh
    expect(fleet_refresh_requests).to eq([ [ registered.id ], [ registered.id ], [ host.id ] ])
  end

  it "refreshes when the first inventory arrives, so the row gains its operating system" do
    record_refresh_requests
    record_inventory(host)
    record_inventory(host)
    expect(fleet_refresh_requests).to eq([ [ host.id ] ])
  end

  it "waits for the outermost transaction to commit, and requests nothing on rollback" do
    Host.transaction do
      host.revoke!(actor: Audit::SYSTEM)
      expect(pending_refreshes).to eq([])
      raise ActiveRecord::Rollback
    end
    expect(pending_refreshes).to eq([])
    expect(host.reload.enrollment_state).to eq("active")

    Host.transaction do
      host.revoke!(actor: Audit::SYSTEM)
      expect(pending_refreshes).to eq([])
    end
    expect(pending_refreshes).to eq(fleet_and(host))
  end

  it "requests nothing for no hosts" do
    described_class.hosts_changed([ nil ])
    expect(pending_refreshes).to eq([])
  end
end
