require "rails_helper"

# The scheduled refresh of Debian's triage (P2-S16, ADR 0022). All outbound HTTP is stubbed. Advisories::Feed's
# own limits (redirects, deadline, certificate) are specified in advisory_feed_refresh_job_spec.rb.
RSpec.describe DebianTriageRefreshJob, type: :job do
  include ActiveJob::TestHelper

  let(:url) { "https://security-tracker.example.org/tracker/data/json" }
  let(:document) { DebianTrackerHelpers::FIXTURES.join("sample.json").read }

  around do |example|
    saved = DebianTriage.config.tracker_url
    DebianTriage.config.tracker_url = url
    example.run
  ensure
    DebianTriage.config.tracker_url = saved
  end

  # Runs the job and its retries, and returns the import it recorded last.
  def refresh(**)
    perform_enqueued_jobs { described_class.perform_later(**) }
    TriageImport.order(:id).last
  rescue Minitest::UnexpectedError => e
    raise e.error
  end

  def stub_tracker(**response)
    stub_request(:get, url).to_return({ status: 200, body: document, headers: { "ETag" => '"t1"', "Last-Modified" => "Sat, 07 Nov 2026 10:00:00 GMT" } }.merge(response))
  end

  it "downloads the document over HTTPS as JSON, stores it, and records its validators, without touching OSV data or matching" do
    stub_tracker
    expect(Net::HTTP).to receive(:start).with("security-tracker.example.org", 443, hash_including(use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_PEER)).and_call_original
    refresh
    expect(a_request(:get, url).with(headers: { "Accept" => "application/json" })).to have_been_made.once
    expect(TriageImport.sole).to have_attributes(origin: "feed", source: "security-tracker.example.org/tracker/data/json", state: "succeeded",
                                                 etag: '"t1"', last_modified: "Sat, 07 Nov 2026 10:00:00 GMT")
    expect(TriageEntry.count).to eq(6)
    expect(AdvisoryImport.count).to eq(0)
    expect(enqueued_jobs).to be_empty
  end

  it "asks conditionally after a clean success, and records not modified as a refresh of the same releases" do
    stub_tracker(body: tracker_document("curl" => { "CVE-2026-0001" => { "trixie" => tracker_release } }).to_json)
    refresh
    travel 7.hours do
      stub_request(:get, url).with(headers: { "If-None-Match" => '"t1"', "If-Modified-Since" => "Sat, 07 Nov 2026 10:00:00 GMT" }).to_return(status: 304)
      import = refresh
      expect(import).to have_attributes(state: "succeeded", counts: { "not_modified" => true }, releases: %w[bookworm forky sid trixie], etag: '"t1"')
      expect(AuditEntry.count).to eq(1)
      expect(DebianTriage::Freshness.statuses.map(&:updated_at)).to all(be_within(1.minute).of(Time.current))
    end
  end

  it "downloads the whole document again after malformed entries" do
    stub_tracker
    refresh # the sample has malformed entries
    refresh
    expect(a_request(:get, url).with(headers: { "If-None-Match" => /./ })).not_to have_been_made
  end

  it "downloads the whole document again after a release is added to the table" do
    clean = tracker_document("curl" => { "CVE-2026-0001" => { "trixie" => tracker_release } }).to_json
    saved = DebianTriage.config.releases
    DebianTriage.config.releases = { [ "debian", "13" ] => "trixie" }
    stub_tracker(body: clean)
    refresh
    DebianTriage.config.releases = saved
    refresh
    expect(a_request(:get, url).with(headers: { "If-None-Match" => /./ })).not_to have_been_made
    expect(TriageImport.order(:id).last.releases).to eq(%w[bookworm forky sid trixie])
  ensure
    DebianTriage.config.releases = saved
  end

  it "holds back a truncated document without failing the job, so it is not retried" do
    stub_tracker
    refresh
    stub_tracker(body: "{}", headers: { "ETag" => '"t2"' })
    import = refresh
    expect(import).to have_attributes(state: "held_back", releases: [])
    expect(a_request(:get, url)).to have_been_made.twice
    expect(TriageEntry.count).to eq(6)
    expect(AuditEntry.where(action: "advisory.triage_import_held_back").count).to eq(1)
    refresh # not conditionally on the held-back download
    expect(a_request(:get, url).with(headers: { "If-None-Match" => /./ })).not_to have_been_made
  end

  it "stores a held-back release when the operator's confirmation covers the counts" do
    stub_tracker
    refresh
    stub_tracker(body: "{}")
    expect(refresh(allowed_drops: { "trixie" => 3, "bookworm" => 1, "forky" => 1, "sid" => 1 }).state).to eq("succeeded")
    expect(TriageEntry.count).to eq(0)
  end

  it "retries a failing download, then records the failure, audited, and fails the job" do
    stub_request(:get, url).to_return(status: 503)
    expect { refresh }.to raise_error(Advisories::Feed::Unavailable, "the Debian Security Tracker at security-tracker.example.org answered HTTP 503")
    expect(a_request(:get, url)).to have_been_made.times(described_class::ATTEMPTS)
    expect(TriageImport.sole).to have_attributes(state: "failed", reason: "the Debian Security Tracker at security-tracker.example.org answered HTTP 503")
    expect(AuditEntry.sole.action).to eq("advisory.triage_import_failed")
  end

  it "fails a document that cannot be read, and reports a fault on this server without its details" do
    stub_tracker(body: '{"glibc": {')
    expect { refresh }.to raise_error(Advisories::Unreadable, "json ends in the middle of the document, so nothing was imported")
    TriageImport.delete_all
    stub_tracker
    allow_any_instance_of(DebianTriage::Import).to receive(:call).and_raise(ActiveRecord::ConnectionNotEstablished)
    expect { refresh }.to raise_error(ActiveRecord::ConnectionNotEstablished)
    expect(TriageImport.sole.reason).to eq("the refresh failed on the server (ActiveRecord::ConnectionNotEstablished); see the server log")
  end

  it "stops a download larger than the limit" do
    DebianTriage.config.max_download_bytes, saved = 100, DebianTriage.config.max_download_bytes
    stub_tracker
    expect { refresh }.to raise_error(Advisories::Feed::Unavailable, "the Debian Security Tracker at security-tracker.example.org sent more than 0 MiB")
  ensure
    DebianTriage.config.max_download_bytes = saved
  end

  it "does nothing when turned off" do
    DebianTriage.config.tracker_url = nil
    expect(described_class.perform_now).to be_nil
    expect(TriageImport.count).to eq(0)
  end

  # A failure here never blocks OSV: the refreshes are separate jobs on separate schedules.
  it "is scheduled on its own, after the OSV refresh at the same cadence" do
    production = YAML.load_file(Rails.root.join("config/recurring.yml"))["production"]
    expect(production["debian_triage_refresh"]).to eq("class" => "DebianTriageRefreshJob", "schedule" => "56 */6 * * *")
    expect(production["advisory_feed_refresh"]["schedule"]).to eq("41 */6 * * *")
  end
end
