require "rails_helper"

# GET /api/v1/manifest/config (P2-S01, FR-2.1, FR-S.2)
RSpec.describe "GET /api/v1/manifest/config", type: :request do
  let!(:enrolled) { enrolled_host }
  let(:host) { enrolled.first }
  let(:credential) { enrolled.last }

  def fetch(as: credential, headers: {}) = get "/api/v1/manifest/config", headers: api_headers(as).merge(headers)

  it "publishes the manifest to an authenticated host, matching the contract" do
    fetch
    expect(response).to have_http_status(:ok)
    expect(response.media_type).to eq("application/json")
    expect(ApiContract.errors("config-manifest.response", "v1", json)).to eq([])
    expect(json).to include("schema_version" => 1, "manifest_version" => ConfigManifest.current.version)
    expect(json["facts"].map { |f| f["key"] }).to include("sshd.permitrootlogin", "file:/etc/shadow", "service:ssh.service")
    expect(response.body).to eq(ConfigManifest.current.to_json)
  end

  it "answers 304 to an agent that already has the current manifest, and the full manifest when it changes" do
    fetch
    etag = response.headers["ETag"]
    expect(etag).to match(/\A"\h+"\z/) # strong, not W/"..."
    expect(response.headers["Cache-Control"]).to include("private")

    fetch(headers: { "If-None-Match" => etag })
    expect(response).to have_http_status(:not_modified)
    expect(response.body).to be_empty

    fetch(headers: { "If-None-Match" => %("stale") })
    expect(response).to have_http_status(:ok)

    changed = ConfigManifest.load(ConfigManifest::PATH).tap { |m| allow(m).to receive(:etag).and_return("0" * 64) }
    allow(ConfigManifest).to receive(:current).and_return(changed)
    fetch(headers: { "If-None-Match" => etag })
    expect(response).to have_http_status(:ok)
    expect(response.headers["ETag"]).not_to eq(etag)
  end

  it "is exempt from the minimum agent version, since it carries none" do
    allow(AgentApi.config).to receive(:minimum_agent_version).and_return("99.0.0")
    fetch
    expect(response).to have_http_status(:ok)
  end

  it "needs a valid credential from an active host" do
    fetch(as: nil)
    expect_error(:unauthorized, "unauthorized")
    host.revoke!(actor: Audit::SYSTEM)
    fetch
    expect_error(:unauthorized, "unauthorized")
  end

  it "is served on the agent hostname only" do
    get "/api/v1/manifest/config", headers: api_headers(credential).merge("HTTP_HOST" => HostSeparation.dashboard_host)
    expect(response).to have_http_status(:not_found)
  end
end
