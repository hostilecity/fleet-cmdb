require "rails_helper"

# POST /api/v1/update-results (P1-UPDATES, FR-S.5, AC-1.9, AC-1.10): the agent reports how an update ended.
RSpec.describe "POST /api/v1/update-results", type: :request do
  let!(:enrolled) { host_running("0.2.0") }
  let(:host) { enrolled.first }
  let(:credential) { enrolled.last }
  let(:release) { release_for_rollout("0.3.0") }
  let!(:rollout) { start_rollout(release:, canaries: [ host ]) }

  def post_result(payload = update_result(rollout), as: credential)
    post "/api/v1/update-results", params: payload.to_json, headers: api_headers(as)
  end

  it "stores the outcome and answers with the report id (update-result.response)" do
    post_result(update_result(rollout, report_id: "00000000-0000-4000-8000-000000000001"))
    expect(response).to have_http_status(:ok)
    expect(json).to eq("report_id" => "00000000-0000-4000-8000-000000000001", "duplicate" => false)
    expect(ApiContract.errors("update-result.response", "v1", json)).to eq([])
    expect(AgentUpdate.sole).to have_attributes(host:, outcome: "succeeded")
    expect(rollout.reload.state).to eq("completed") # the only canary confirmed; 25% and 100% of one host add none
  end

  it "answers a retry with duplicate: true" do
    payload = update_result(rollout)
    post_result(payload)
    expect { post_result(payload) }.not_to change(AgentUpdate, :count)
    expect(json).to include("duplicate" => true)
  end

  it "halts the rollout on a rollback and audits both" do
    post_result(update_result(rollout, outcome: "rolled_back", reason: "no heartbeat within the deadline"))
    expect(response).to have_http_status(:ok)
    expect(rollout.reload).to have_attributes(state: "halted")
    expect(audit_actions.last(2)).to eq([ Audit::Actions::UPDATE_ROLLED_BACK, Audit::Actions::ROLLOUT_HALTED ])
  end

  it "answers 400 for a rollout the host is not part of, naming the field" do
    post_result(update_result(rollout, rollout_id: rollout.id + 100))
    expect_error(:bad_request, "validation_failed")
    expect(json.dig("error", "details")).to eq([ { "pointer" => "/rollout_id", "problem" => "No such rollout." } ])
    expect(AgentUpdate.count).to eq(0)
  end

  it "is limited to the host's own credential" do
    post_result(as: nil)
    expect_error(:unauthorized, "unauthorized")
    post_result(as: "nope.nope")
    expect_error(:unauthorized, "unauthorized")
    expect(AgentUpdate.count).to eq(0)
  end

  it "refuses a host that is not active" do
    Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM)
    post_result
    expect_error(:forbidden, "reenrollment_required")
  end

  it "refuses a body that is not JSON, or too large" do
    post "/api/v1/update-results", params: "x", headers: api_headers(credential).merge("CONTENT_TYPE" => "text/plain")
    expect_error(:bad_request, "validation_failed")
    post "/api/v1/update-results", params: { reason: "x" * 9_000 }.to_json, headers: api_headers(credential)
    expect_error(:content_too_large, "payload_too_large")
  end

  it "is served to an agent below the minimum version (FR-S.5), as the update path requires" do
    allow(AgentApi.config).to receive(:minimum_agent_version).and_return("9.0.0")
    post_result(update_result(rollout, agent_version: "0.2.0"))
    expect(response).to have_http_status(:ok)
  end

  describe "docs/api contract examples (NFR-5)" do
    ApiContract.examples.select { |e| e.version == "v1" && e.schema_name == "update-result.request" }.each do |example|
      it "#{example.kind == 'valid' ? 'accepts' : 'rejects'} #{example.name}" do
        data = example.data
        if example.kind == "valid"
          # The example's ids stand for the rollout and release the test created.
          data = data.merge("rollout_id" => rollout.id, "version" => "0.3.0")
        end
        post_result(data)
        if example.kind == "valid"
          expect(response).to have_http_status(:ok)
          expect(ApiContract.errors("update-result.response", "v1", json)).to eq([])
        else
          expect_error(:bad_request, "validation_failed")
        end
      end
    end
  end
end
