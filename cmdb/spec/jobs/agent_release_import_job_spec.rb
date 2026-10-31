require "rails_helper"

# P1-S15: importing a release from its GitHub release in the background. All outbound HTTP is stubbed.
RSpec.describe AgentReleaseImportJob, type: :job do
  include ActiveJob::TestHelper

  let(:operator) { create(:operator) }
  let(:release) { signed_release(version: "1.2.0") }
  let(:base) { "https://github.com/hostilecity/fleet-cmdb/releases/download/agent-v1.2.0/fleet-agent-1.2.0-#{Releases::TARGET}" }

  before { trust_release_keys }

  # GitHub redirects each download to its download host, as it does for release assets.
  def stub_github(manifest: release.manifest, signature: release.signature, binary: release.binary)
    { "" => binary, ".manifest.json" => manifest, ".manifest.json.minisig" => signature }.each do |suffix, body|
      cdn = "https://downloads.example.net/assets/#{SecureRandom.hex(4)}"
      stub_request(:get, "#{base}#{suffix}").to_return(status: 302, headers: { "Location" => cdn })
      stub_request(:get, cdn).to_return(status: 200, body:)
    end
  end

  def run_import(version: "1.2.0")
    import = AgentReleaseImport.create!(version:, operator:, request_id: "req-1")
    perform_enqueued_jobs { described_class.perform_later(import.id) }
    import.reload
  end

  def audit_entry = AuditEntry.where(action: Audit::Actions::ALL.grep(/\Arelease\./)).sole

  it "imports a release signed by the release key, audited with the operator as actor" do
    stub_github
    import = run_import
    expect(import).to have_attributes(state: "imported", reason: nil, finished_at: be_present)
    expect(import.agent_release).to have_attributes(version: "1.2.0", sha256: release.sha256, source: "github", imported_by: operator)
    expect(File.binread(import.agent_release.binary_path)).to eq(release.binary)
    expect(audit_entry).to have_attributes(actor_type: "operator", actor_id: operator.id, action: "release.imported", request_id: "req-1")
    expect(Releases.store.dir.children.map { |p| p.basename.to_s }).to eq([ "fleet-agent-1.2.0-#{Releases::TARGET}" ])
  end

  it "refuses a wrong signature without downloading the binary, and audits the reason" do
    stub_github(signature: signed_release(version: "1.2.0").signature)
    import = run_import
    expect(import).to have_attributes(state: "refused", reason: "the manifest signature is not valid", agent_release: nil)
    expect(a_request(:get, base)).not_to have_been_made
    expect(audit_entry).to have_attributes(actor_id: operator.id, action: "release.import_refused",
                                           changeset: { "version" => "1.2.0", "source" => "github", "reason" => "the manifest signature is not valid" })
    expect(AgentRelease.count).to eq(0)
  end

  it "refuses a modified binary, an unknown key, and a release that is not the version asked for" do
    stub_github(binary: release.binary.reverse)
    expect(run_import.reason).to eq("the binary's SHA-256 does not match the manifest")

    WebMock.reset!
    stub_github(signature: TestReleaseKey.new.sign(release.manifest))
    expect(run_import.reason).to eq("the manifest is signed by a key this server does not trust")

    WebMock.reset!
    other = signed_release(version: "1.1.0")
    stub_github(manifest: other.manifest, signature: other.signature, binary: other.binary)
    expect(run_import).to have_attributes(state: "refused", reason: "the signed manifest is for version 1.1.0, not 1.2.0")
    expect(AuditEntry.where(action: "release.import_refused").count).to eq(3)
    expect(Releases.store.dir.children).to eq([]) # nothing partial left
  end

  it "cuts a binary longer than the manifest says at one byte past the size" do
    stub_github(binary: release.binary + "x" * 1.megabyte)
    expect(run_import.reason).to eq("the binary is larger than the manifest's 4096 bytes")
  end

  it "fails, without retrying, when GitHub has no such release" do
    stub_request(:get, /github\.com/).to_return(status: 404)
    import = run_import
    expect(import).to have_attributes(state: "failed", reason: "GitHub has no release agent-v1.2.0 in hostilecity/fleet-cmdb with the file fleet-agent-1.2.0-#{Releases::TARGET}.manifest.json")
    expect(a_request(:get, /github\.com/)).to have_been_made.once
    expect(audit_entry).to have_attributes(action: "release.import_failed", actor_id: operator.id)
  end

  it "retries while GitHub is unavailable, then fails and says why" do
    stub_request(:get, /github\.com/).to_return(status: 503)
    import = run_import
    expect(a_request(:get, /github\.com/)).to have_been_made.times(described_class::ATTEMPTS)
    expect(import).to have_attributes(state: "failed", reason: "GitHub answered HTTP 503")
    expect(audit_entry).to have_attributes(action: "release.import_failed", changeset: include("reason" => "GitHub answered HTTP 503"))
  end

  it "succeeds when GitHub recovers during the retries" do
    stub_github
    stub_request(:get, "#{base}.manifest.json").to_timeout.then.to_return(status: 302, headers: { "Location" => "https://downloads.example.net/m" })
    stub_request(:get, "https://downloads.example.net/m").to_return(status: 200, body: release.manifest)
    expect(run_import.state).to eq("imported")
  end

  it "shows a retry in progress on the import" do
    stub_request(:get, /github\.com/).to_raise(Errno::ECONNREFUSED)
    import = AgentReleaseImport.create!(version: "1.2.0", operator:)
    described_class.perform_now(import.id)
    expect(import.reload).to have_attributes(state: "running", reason: "could not download from GitHub (ECONNREFUSED). Retrying.")
  end

  it "follows only HTTPS redirects, and only a few" do
    stub_request(:get, "#{base}.manifest.json").to_return(status: 302, headers: { "Location" => "http://downloads.example.net/m" })
    expect(run_import.reason).to eq("GitHub redirected to a URL that is not HTTPS")

    WebMock.reset!
    stub_request(:get, "#{base}.manifest.json").to_return(status: 302, headers: { "Location" => "#{base}.manifest.json" })
    expect(run_import.reason).to eq("GitHub redirected too many times")
    expect(a_request(:get, "#{base}.manifest.json")).to have_been_made.times(described_class::ATTEMPTS * (Releases::Github::MAX_REDIRECTS + 1))

    WebMock.reset!
    stub_request(:get, "#{base}.manifest.json").to_return(status: 302)
    expect(run_import.reason).to eq("GitHub sent a redirect without a location")

    WebMock.reset!
    stub_request(:get, "#{base}.manifest.json").to_return(status: 302, headers: { "Location" => "https://exa mple/" })
    expect(run_import.reason).to eq("GitHub redirected to an invalid URL")
  end

  it "notes a release already imported identically" do
    stub_github
    import_release(release, operator:)
    expect(run_import).to have_attributes(state: "imported", reason: "Already imported.")
    expect(AuditEntry.where(action: "release.imported").count).to eq(1)
  end

  it "does nothing for a finished or missing import" do
    import = AgentReleaseImport.create!(version: "1.2.0", operator:)
    import.finish!("failed", reason: "earlier")
    expect { described_class.perform_now(import.id) }.not_to change { import.reload.attributes }
    expect { described_class.perform_now(0) }.not_to raise_error
  end

  it "reports a fault on this server as a failure, without retrying" do
    stub_github
    allow(File).to receive(:rename).and_raise(Errno::ENOSPC)
    import = nil
    log = captured_log { import = run_import }
    expect(import).to have_attributes(state: "failed", reason: "the import failed on the server (Errno::ENOSPC); see the server log")
    expect(log).to include("[releases] import #{import.id} of 1.2.0 failed: Errno::ENOSPC")
  end

  it "tells open dashboards to refresh when it finishes" do
    stub_github
    expect { run_import }.to have_performed_job(FleetBroadcastJob).at_least(:once)
  end
end
