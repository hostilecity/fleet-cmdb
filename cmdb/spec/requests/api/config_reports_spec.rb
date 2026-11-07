require "rails_helper"

# POST /api/v1/reports/config (P2-S02, FR-2.1, FR-S.2, DEC-07, DEC-08, AC-2.1, AC-2.5)
RSpec.describe "POST /api/v1/reports/config", type: :request do
  let!(:enrolled) { enrolled_host }
  let(:host) { enrolled.first }
  let(:credential) { enrolled.last }
  let(:example) { ApiContract.example("config.request", "typical") }
  let(:manifest) { ConfigManifest.current }

  def report(**overrides) = example.merge("report_id" => SecureRandom.uuid).merge(overrides.transform_keys(&:to_s))

  def with_facts(changes) = report(facts: example["facts"].merge(changes))

  def send_report(payload, as: credential, headers: {}) = post_api("/api/v1/reports/config", payload, as, headers:)

  def ok(value) = { "state" => "ok", "value" => value, "reason" => nil }

  def counts = [ HostConfig.count, ConfigSnapshot.count, ConfigReportReceipt.count ]

  it "stores every manifest fact for the host and its first snapshot, and says which manifest version the server has" do
    payload = report
    send_report(payload)
    expect(response).to have_http_status(:ok)
    expect(json).to eq("report_id" => payload["report_id"], "duplicate" => false, "manifest_version" => manifest.version)
    expect(ApiContract.errors("config.response", "v1", json)).to eq([])

    current = host.reload.host_config
    expect(current.facts.keys).to match_array(manifest.facts.map(&:key)) # jsonb keeps its own key order
    expect(current.facts["sshd.permitrootlogin"]).to eq(ok("no"))
    expect(current.facts["services.running"]).to eq(ok(%w[cron.service ssh.service])) # sorted: the order carries no meaning
    expect(current.facts["file:/etc/issue.net"]).to eq(ok(nil)) # no such file: a value, not missing
    expect(current.facts["sshd.usepam"]).to eq("state" => "missing", "value" => nil, "reason" => "The agent's report did not include this fact.")
    expect(current).to have_attributes(manifest_version: 1, report_id: payload["report_id"], schema_version: 1, ignored_keys: [],
                                       collected_at: Time.iso8601(payload["collected_at"]))
    expect(current.state_counts).to eq("ok" => 18, "unreadable" => 1, "unsupported" => 1, "missing" => manifest.facts.size - 20)

    snapshot = host.config_snapshots.sole
    expect(snapshot).to have_attributes(facts: current.facts, content_hash: current.content_hash, report_id: payload["report_id"])
  end

  it "stores unreadable and unsupported facts with their reason (AC-2.5)" do
    send_report(report)
    current = HostConfig.find_by!(host:)
    expect(current.unreadable).to eq("file:/etc/sudoers" => "Permission denied reading /etc/sudoers.")
    expect(current.facts["pwquality.retry"]).to eq("state" => "unsupported", "value" => nil, "reason" => "libpwquality is not installed.")
  end

  describe "idempotency and snapshots (DEC-07)" do
    it "answers a retried report as a duplicate and changes nothing" do
      payload = report
      send_report(payload)
      before = [ HostConfig.find_by!(host:).attributes, counts ]
      send_report(payload.merge("facts" => {})) # same report id, even with different contents
      expect(json).to eq("report_id" => payload["report_id"], "duplicate" => true, "manifest_version" => manifest.version)
      expect([ HostConfig.find_by!(host:).attributes, counts ]).to eq(before)
    end

    it "creates no snapshot for the same facts in another order, but records the report" do
      send_report(report)
      shuffled = example["facts"].to_a.reverse.to_h
      shuffled["services.running"] = ok(shuffled["services.running"]["value"].reverse)
      later = report(facts: shuffled)
      expect { send_report(later) }.not_to change(ConfigSnapshot, :count)
      expect(HostConfig.find_by!(host:).report_id).to eq(later["report_id"])
    end

    it "snapshots a changed fact, and the diff shows it, including a change of state (AC-2.1)" do
      send_report(report)
      send_report(with_facts("sshd.permitrootlogin" => ok("yes"), "file:/etc/shadow" => { "state" => "unreadable", "value" => nil, "reason" => "Permission denied." }))

      first, second = ConfigSnapshot.where(host:).chronological.to_a
      diff = ConfigDiff.for(second)
      expect(diff.changed.map { |c| [ c.key, c.from["state"], c.to["state"], c.from["value"], c.to["value"] ] }).to eq([
        [ "file:/etc/shadow", "ok", "unreadable", { "mode" => "0640", "owner" => "root", "group" => "shadow" }, nil ],
        [ "sshd.permitrootlogin", "ok", "ok", "no", "yes" ]
      ])
      expect([ diff.added, diff.removed ]).to eq([ {}, {} ])
      expect(ConfigDiff.for(first).added.size).to eq(manifest.facts.size)
      expect(HostConfig.find_by!(host:).facts["sshd.permitrootlogin"]).to eq(ok("yes"))
    end

    it "keeps each host's facts apart" do
      other_host, other_credential = enrolled_host
      send_report(report)
      send_report(with_facts("sshd.permitrootlogin" => ok("yes")), as: other_credential)
      expect([ host, other_host ].map { |h| h.reload.host_config.facts["sshd.permitrootlogin"]["value"] }).to eq(%w[no yes])
    end
  end

  describe "the manifest version and unknown keys (DEC-08)" do
    it "ignores a fact key the manifest does not have, and logs the key but not its value" do
      log = captured_log { send_report(report(facts: example["facts"].merge("sshd.someday" => ok("EXAMPLE-value")))) }
      expect(response).to have_http_status(:ok)
      expect(log).to include("ignored unknown facts sshd.someday")
      expect(log).not_to include("EXAMPLE-value")
      expect(HostConfig.find_by!(host:)).to have_attributes(ignored_keys: [ "sshd.someday" ])
      expect(HostConfig.find_by!(host:).facts).not_to have_key("sshd.someday")
    end

    it "ignores and logs an unknown field inside a fact" do
      log = captured_log { send_report(report(facts: { "sshd.permitrootlogin" => ok("no").merge("source" => "sshd -T") })) }
      expect(response).to have_http_status(:ok)
      expect(log).to include("ignored unknown fields /facts/sshd.permitrootlogin/source")
    end

    it "refuses a manifest version newer than the server's, and writes nothing" do
      send_report(report(manifest_version: manifest.version + 1))
      expect_error(:bad_request, "validation_failed")
      expect(json.dig("error", "details")).to eq([ { "pointer" => "/manifest_version", "problem" => "is newer than this server's fact manifest (version #{manifest.version}); fetch GET /api/v1/manifest/config again" } ])
      expect(counts).to eq([ 0, 0, 0 ])
    end
  end

  describe "invalid values" do
    it "refuses a value that does not fit the manifest, and writes nothing, not even the facts that fit" do
      send_report(with_facts("sshd.permitrootlogin" => ok("x" * 33), "sshd.maxauthtries" => ok(-1)))
      expect_error(:bad_request, "validation_failed")
      expect(json.dig("error", "details").map { |d| d["pointer"] }).to contain_exactly("/facts/sshd.permitrootlogin/value", "/facts/sshd.maxauthtries/value")
      expect(json.to_json).not_to include("x" * 33)
      expect(counts).to eq([ 0, 0, 0 ])
    end

    it "leaves the stored facts as they were when a later report is refused" do
      send_report(report)
      before = [ HostConfig.find_by!(host:).attributes, counts ]
      send_report(with_facts("users.login" => ok([ "root", 7 ])))
      expect_error(:bad_request, "validation_failed")
      expect([ HostConfig.find_by!(host:).attributes, counts ]).to eq(before)
    end

    it "refuses a NUL in a value" do
      send_report(with_facts("sshd.banner" => ok("/etc/issue\u0000.net")))
      expect_error(:bad_request, "validation_failed")
      expect(json.dig("error", "details")).to eq([ { "pointer" => "/facts/sshd.banner/value", "problem" => "contains a NUL character (sshd.banner is string)" } ])
    end
  end

  it_behaves_like "the docs/api contract examples", "config.request", accepted: :ok do
    def submit_example(data, valid:) = send_report(data)
  end

  it "accepts a gzip-compressed report" do
    payload = report
    send_report(ActiveSupport::Gzip.compress(payload.to_json), headers: { "Content-Encoding" => "gzip" })
    expect(json).to include("report_id" => payload["report_id"], "duplicate" => false)
  end

  it "takes reports only from active hosts with a valid credential" do
    send_report(report, as: nil)
    expect_error(:unauthorized, "unauthorized")
    host.revoke!(actor: Audit::SYSTEM)
    send_report(report)
    expect_error(:unauthorized, "unauthorized")
    expect(counts).to eq([ 0, 0, 0 ])
  end
end
