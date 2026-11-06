require "rails_helper"

# P1-X01 (NFR-5, FR-S.5, ADR 0018): the update path stays open to an agent below the minimum version. This test
# is kept in every later phase and named in the delivery note.
RSpec.describe "Update path compatibility (P1-X01)", type: :request do
  let(:minimum) { "0.5.0" }
  let(:release) { release_for_rollout("0.6.0") }

  before { allow(AgentApi.config).to receive(:minimum_agent_version).and_return(minimum) }

  def heartbeat_body(version) = { schema_version: 1, agent_version: version, hostname: nil, uptime_seconds: 1, agent_time: "2026-01-01T12:00:00Z" }

  %w[0.2.0 0.4.9 0.5.0-rc.1].each do |old_version|
    it "lets agent #{old_version}, below the minimum #{'0.5.0'}, heartbeat, take the directive, download, and post results, while its reports get 426" do
      host, credential = host_running(old_version)
      rollout = start_rollout(release:, canaries: [ host ])

      # 1. The heartbeat is answered 200 and carries the agent_update directive.
      post_api("/api/v1/heartbeat", heartbeat_body(old_version), credential)
      expect(response).to have_http_status(:ok)
      directive = json.dig("directives", "agent_update")
      expect(directive).to include("rollout_id" => rollout.id, "version" => "0.6.0")
      expect(ApiContract.errors("heartbeat.response", "v1", json)).to eq([])

      # 2. The release files named by the directive download without a credential.
      %w[manifest_url signature_url binary_url].zip([ release_manifest, release_signature, release_binary ]).each do |key, expected|
        get URI(directive.fetch(key)).path, headers: { "User-Agent" => "fleet-agent/#{old_version}" }
        expect(response).to have_http_status(:ok), key
        expect(response.body.b).to eq(expected.b), key
      end

      # 3. Reports still get 426, with a body the agent understands.
      post_api("/api/v1/reports/inventory", { schema_version: 1, agent_version: old_version, report_id: SecureRandom.uuid }, credential)
      expect_error(:upgrade_required, "agent_version_unsupported")

      # 4. The result is accepted, and the rollout moves on.
      post_api("/api/v1/update-results", update_result(rollout, agent_version: old_version), credential)
      expect(response).to have_http_status(:ok)
      expect(AgentUpdate.sole).to have_attributes(host:, outcome: "succeeded")
      expect(rollout.reload.state).to eq("completed")
    end
  end

  it "accepts a rolled back result from an agent below the minimum, and halts the rollout" do
    host, credential = host_running("0.2.0")
    rollout = start_rollout(release:, canaries: [ host ])
    post_api("/api/v1/update-results", update_result(rollout, agent_version: "0.2.0", outcome: "rolled_back", reason: "no heartbeat"), credential)
    expect(response).to have_http_status(:ok)
    expect(rollout.reload.state).to eq("halted")
  end

  it "keeps answering 426 to every other endpoint for an agent below the minimum" do
    host, credential = host_running("0.2.0")
    post_api("/api/v1/reports/inventory", { schema_version: 1, agent_version: "0.2.0", report_id: SecureRandom.uuid }, credential)
    expect_error(:upgrade_required, "agent_version_unsupported")
    post_api("/api/v1/reports/packages", { schema_version: 1, agent_version: "0.2.0", report_id: SecureRandom.uuid }, credential)
    expect_error(:upgrade_required, "agent_version_unsupported")
    post "/api/v1/enroll", params: { schema_version: 1, agent_version: "0.2.0", token: "EXAMPLE-token" }.to_json, headers: api_headers
    expect_error(:upgrade_required, "agent_version_unsupported")
    expect(host.reload.agent_version).to eq("0.2.0")
  end

  def release_manifest = release.manifest

  def release_signature = release.signature

  def release_binary = File.binread(release.binary_path)
end
