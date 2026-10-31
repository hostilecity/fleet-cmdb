require "rails_helper"

# The Agents page's releases (P1-RELEASES, P1-S15, FR-1.5, FR-S.3): imports from GitHub and by upload, each
# import and refusal audited with the signed-in operator as actor.
RSpec.describe "Agent releases", type: :request do
  include ActiveJob::TestHelper

  before do
    trust_release_keys
    sign_in_operator
  end

  let(:operator) { Operator.find_by!(email: "operator@example.com") }

  def page = Nokogiri::HTML(response.body)

  def upload_files(release, manifest: release.manifest, signature: release.signature, binary: release.binary)
    { binary: Rack::Test::UploadedFile.new(StringIO.new(binary), "application/octet-stream", true, original_filename: "fleet-agent"),
      manifest: Rack::Test::UploadedFile.new(StringIO.new(manifest), "application/json", original_filename: "m.manifest.json"),
      signature: Rack::Test::UploadedFile.new(StringIO.new(signature), "text/plain", original_filename: "m.manifest.json.minisig") }
  end

  describe "the page" do
    it "lists releases newest first, with their key, importer, and the hosts in the fleet running each" do
      import_release(signed_release(version: "1.1.0"), operator:)
      import_release(signed_release(version: "1.2.0"), operator:)
      running, = enrolled_host
      running.update_columns(agent_version: "1.2.0")
      retired, = enrolled_host
      retired.update_columns(agent_version: "1.2.0")
      retired.retire!(actor: Audit::SYSTEM)

      get "/agents"
      expect(response).to have_http_status(:ok)
      expect(page.at_css("nav a[aria-current='page']").text).to eq("Agents")
      rows = page.css("#releases tbody tr").map { |row| row.css("td").map { |cell| cell.text.squish } }
      expect(rows.map(&:first)).to eq(%w[1.2.0 1.1.0])
      expect(rows.first[1]).to eq("Verified current key #{release_key.id_hex}")
      expect(rows.first[2]).to include("by Example Operator (upload)")
      expect(rows.map { |row| row[3] }).to eq(%w[1 0])
      expect(page.at_css("#releases a[href='/agents/install?version=1.1.0']")).to be_present
      expect(page.at_css("a.btn[href='/agents/install']").text).to eq("Install an agent")
    end

    it "says when there is no release yet, and when no release key is configured" do
      trust_release_keys(current: nil)
      get "/agents"
      expect(page.at_css("#no_releases")).to be_present
      expect(page.at_css(".notice.error strong").text).to eq("No release key is configured.")
      expect(page.at_css("#no_imports")).to be_present
    end
  end

  describe "importing from GitHub" do
    it "queues an import for the version, accepting the tag or a v prefix" do
      [ "1.2.0", "v1.3.0", " agent-v1.4.0-rc.1 " ].each do |input|
        expect { post "/agents/releases/import", params: { version: input } }.to have_enqueued_job(AgentReleaseImportJob)
        expect(response).to redirect_to("/agents")
      end
      expect(AgentReleaseImport.order(:id).pluck(:version, :state, :operator_id)).to eq([ [ "1.2.0", "queued", operator.id ], [ "1.3.0", "queued", operator.id ], [ "1.4.0-rc.1", "queued", operator.id ] ])
      follow_redirect!
      expect(page.at_css(".flash").text.squish).to eq("Importing 1.4.0-rc.1 from GitHub. The result appears under Imports.")
      expect(page.css("#imports tbody tr").first.text.squish).to start_with("1.4.0-rc.1 Queued")
    end

    it "shows the outcome, refusals included, once the job has run" do
      release = signed_release(version: "1.2.0")
      base = "https://github.com/hostilecity/fleet-cmdb/releases/download/agent-v1.2.0/fleet-agent-1.2.0-#{Releases::TARGET}"
      stub_request(:get, "#{base}.manifest.json").to_return(body: release.manifest)
      stub_request(:get, "#{base}.manifest.json.minisig").to_return(body: TestReleaseKey.new.sign(release.manifest))
      perform_enqueued_jobs { post "/agents/releases/import", params: { version: "1.2.0" } }
      get "/agents"
      cells = page.css("#imports tbody tr").first.css("td").map { |cell| cell.text.squish }
      expect(cells.values_at(0, 1, 3)).to eq([ "1.2.0", "Refused", "the manifest is signed by a key this server does not trust" ])
      expect(cells[2]).to end_with("by Example Operator")
      expect(AuditEntry.last).to have_attributes(action: "release.import_refused", actor_type: "operator", actor_id: operator.id)
    end

    it "refuses, in place, a version that is not strict SemVer, already imported, or already being imported" do
      import_release(signed_release(version: "1.2.0"), operator:)
      AgentReleaseImport.create!(version: "1.3.0", operator:)
      { "1.2" => "Enter a version such as 1.2.0, without build metadata.", "1.4.0+build" => "Enter a version such as 1.2.0, without build metadata.",
        "" => "Enter a version such as 1.2.0, without build metadata.", "1.2.0" => "1.2.0 is already imported.",
        "1.3.0" => "1.3.0 is already being imported." }.each do |input, message|
        expect { post "/agents/releases/import", params: { version: input } }.not_to have_enqueued_job
        expect(response).to have_http_status(:unprocessable_content)
        expect(page.at_css("#import_error").text).to eq(message)
        expect(page.at_css("#version")["value"].to_s).to eq(input)
        expect(page.at_css("#version")["aria-invalid"]).to eq("true")
      end
    end

    it "refuses a second import of a version that raced past the check" do
      allow(AgentReleaseImport).to receive(:in_flight).and_return(AgentReleaseImport.none)
      AgentReleaseImport.create!(version: "1.3.0", operator:)
      expect { post "/agents/releases/import", params: { version: "1.3.0" } }.not_to change(AgentReleaseImport, :count)
      expect(page.at_css("#import_error").text).to eq("1.3.0 is already being imported.")
    end
  end

  describe "uploading" do
    it "imports a release signed by the release key and audits it with the operator as actor" do
      release = signed_release(version: "1.2.0")
      post "/agents/releases/upload", params: upload_files(release)
      expect(response).to redirect_to("/agents")
      stored = AgentRelease.sole
      expect(stored).to have_attributes(version: "1.2.0", source: "upload", imported_by: operator, sha256: release.sha256)
      expect(File.binread(stored.binary_path)).to eq(release.binary)
      expect(AuditEntry.last).to have_attributes(action: "release.imported", actor_type: "operator", actor_id: operator.id, target_id: stored.id)
      follow_redirect!
      expect(page.at_css(".flash").text.squish).to eq("Imported 1.2.0. Signature and checksum verified.")

      post "/agents/releases/upload", params: upload_files(release)
      follow_redirect!
      expect(page.at_css(".flash").text.squish).to eq("1.2.0 was already imported.")
    end

    it "refuses a wrong signature, a modified binary, or an unknown key with the reason, and audits each refusal" do
      release = signed_release(version: "1.2.0")
      { upload_files(release, signature: signed_release.signature) => "the manifest signature is not valid",
        upload_files(release, binary: release.binary.reverse) => "the binary's SHA-256 does not match the manifest",
        upload_files(release, binary: release.binary[0, 100]) => "the binary is 100 bytes but the manifest says 4096",
        upload_files(release, signature: TestReleaseKey.new.sign(release.manifest)) => "the manifest is signed by a key this server does not trust" }.each do |files, reason|
        expect { post "/agents/releases/upload", params: files }.to change { AuditEntry.where(action: "release.import_refused").count }.by(1)
        expect(response).to have_http_status(:unprocessable_content)
        expect(page.at_css("#upload_error").text).to eq("Refused: #{reason}.")
        expect(page.at_css("details#upload")["open"]).not_to be_nil
        expect(AuditEntry.last).to have_attributes(actor_type: "operator", actor_id: operator.id, changeset: { "source" => "upload", "reason" => reason })
      end
      expect(AgentRelease.count).to eq(0)
    end

    it "asks for all three files" do
      release = signed_release
      post "/agents/releases/upload", params: upload_files(release).except(:signature)
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#upload_error").text).to start_with("Choose all three files")
      expect(AuditEntry.where(action: "release.import_refused")).to be_empty
    end

    it "refuses an upload larger than a release can be before reading it" do
      post "/agents/releases/upload", headers: { "CONTENT_LENGTH" => (AgentReleasesController::MAX_UPLOAD_BYTES + 1).to_s }
      expect(response).to have_http_status(:content_too_large)
      expect(response.body).to include("larger than an agent release can be (64 MiB)")
    end
  end

  it "shows release audit entries readably on the audit page" do
    stored = import_release(signed_release(version: "1.2.0"), operator:)
    Releases::Import.record_refusal(operator:, source: "github", version: "1.3.0", reason: "the manifest signature is not valid")
    get "/audit"
    rows = page.css("table tbody tr").map { |row| row.text.squish }
    expect(rows.first).to include("Release refused", "Version 1.3.0", "Source github", "Reason the manifest signature is not valid")
    expect(rows.second).to include("Release imported", "Agent release 1.2.0", "SHA-256 #{stored.sha256}", "Release key current")
    expect(page.at_css("a[href='/agents']", text: "Agent release 1.2.0")).to be_present
    get "/audit", params: { action: "release.imported" }
    expect(page.css("table tbody tr").size).to eq(1)
  end
end
