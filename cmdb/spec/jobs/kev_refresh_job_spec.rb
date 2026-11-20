require "rails_helper"

# The scheduled KEV refresh (VT-S02, ADR 0032 point 5), through Advisories::Feed: verified HTTPS, conditional requests,
# no redirect to another host, retries then a recorded failure, and a held-back import that is not a fault. All
# outbound HTTP is stubbed with the recorded catalog; a real fetch from the mirror is not exercised here.
RSpec.describe KevRefreshJob, type: :job do
  include ActiveJob::TestHelper

  let(:url) { "https://kev.example.org/cisagov/kev-data/main/known_exploited_vulnerabilities.json" }
  let(:catalog) { SignalHelpers::SIGNAL_FIXTURES.join("known_exploited_vulnerabilities.json").read }

  around do |example|
    saved = Signals.config.kev_url
    Signals.config.kev_url = url
    example.run
  ensure
    Signals.config.kev_url = saved
  end

  def refresh(**)
    perform_enqueued_jobs { described_class.perform_later(**) }
    SignalImport.order(:id).last
  rescue Minitest::UnexpectedError => e
    raise e.error
  end

  def stub_kev(**response)
    stub_request(:get, url).to_return({ status: 200, body: catalog, headers: { "ETag" => '"k1"', "Last-Modified" => "Thu, 19 Nov 2026 15:00:00 GMT" } }.merge(response))
  end

  it "downloads the catalog over verified HTTPS as JSON, stores it, and records its source (host and path) and validators" do
    stub_kev
    expect(Net::HTTP).to receive(:start).with("kev.example.org", 443, hash_including(use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_PEER)).and_call_original
    import = refresh
    expect(a_request(:get, url).with(headers: { "Accept" => "application/json" })).to have_been_made.once
    expect(import).to have_attributes(signal: "kev", origin: "feed", source: "kev.example.org/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
                                      state: "succeeded", etag: '"k1"', version: "2026.11.19")
    expect(KevEntry.count).to eq(3)
    expect(AdvisoryImport.count + TriageImport.count).to eq(0)
  end

  it "asks conditionally after a clean success and records not modified as a refresh, unaudited" do
    stub_kev
    refresh
    travel 7.hours do
      stub_request(:get, url).with(headers: { "If-None-Match" => '"k1"', "If-Modified-Since" => "Thu, 19 Nov 2026 15:00:00 GMT" }).to_return(status: 304)
      import = refresh
      expect(import).to have_attributes(state: "succeeded", counts: { "not_modified" => true }, version: "2026.11.19")
      expect(Signals::Freshness.status("kev").updated_at).to be_within(1.minute).of(Time.current)
      expect(AuditEntry.where("action LIKE 'signal.%'").count).to eq(1)
    end
  end

  it "downloads the whole catalog again after a file import, malformed entries, or a clear" do
    import_kev(kev_file("CVE-2026-0001"))
    stub_kev
    refresh
    expect(a_request(:get, url).with { |r| !r.headers.key?("If-None-Match") }).to have_been_made.once
    SignalImport.last.update!(counts: SignalImport.last.counts.merge("malformed" => 1))
    refresh
    expect(a_request(:get, url).with { |r| !r.headers.key?("If-None-Match") }).to have_been_made.twice
    SignalImport.last.update!(counts: SignalImport.last.counts.merge("malformed" => 0))
    Signals.clear_kev!
    refresh
    expect(a_request(:get, url).with { |r| !r.headers.key?("If-None-Match") }).to have_been_made.times(3)
  end

  it "downloads again when another import stored data between the request and its not-modified answer" do
    stub_kev
    refresh
    stub_request(:get, url).with(headers: { "If-None-Match" => '"k1"' }).to_return do
      import_kev(kev_file("CVE-2026-90777", "CVE-2026-91402", "CVE-2025-80001"))
      { status: 304 }
    end
    import = refresh
    expect(import).to have_attributes(origin: "feed", state: "succeeded")
    expect(import.counts).not_to have_key("not_modified")
  end

  it "refuses a redirect to another host, naming only that host" do
    stub_request(:get, url).to_return(status: 302, headers: { "Location" => "https://elsewhere.example.net/kev.json?token=secret" })
    expect { refresh }.to raise_error(Advisories::Feed::Unavailable,
                                      "the CISA KEV catalog at kev.example.org redirected to elsewhere.example.net, and redirects to another host are not followed")
    expect(SignalImport.sole).to have_attributes(state: "failed", reason: include("elsewhere.example.net").and(not_include("secret")))
    expect(AuditEntry.where(action: "signal.kev_import_failed").count).to eq(1)
  end

  it "follows a redirect on the same host" do
    stub_request(:get, url).to_return(status: 301, headers: { "Location" => "/v2/kev.json" })
    stub_request(:get, "https://kev.example.org/v2/kev.json").to_return(status: 200, body: catalog)
    expect(refresh.state).to eq("succeeded")
  end

  it "ends normally on a held-back import, so it is not retried or a failed job" do
    import_kev(kev_file(*(1..30).map { |i| format("CVE-2026-%04d", i) }))
    stub_kev
    expect(refresh).to have_attributes(state: "held_back")
    expect(a_request(:get, url)).to have_been_made.once
    expect(KevEntry.count).to eq(30)
  end

  it "retries a failure, then records it with the operator who asked, audited, and raises" do
    operator = create(:operator)
    stub_kev(status: 503)
    expect { refresh(operator_id: operator.id) }.to raise_error(Advisories::Feed::Unavailable, "the CISA KEV catalog at kev.example.org answered HTTP 503")
    expect(a_request(:get, url)).to have_been_made.times(ApplicationJob::ATTEMPTS)
    expect(SignalImport.sole).to have_attributes(state: "failed", operator:, reason: "the CISA KEV catalog at kev.example.org answered HTTP 503")
    expect(AuditEntry.where(action: "signal.kev_import_failed").sole).to have_attributes(actor_type: "operator", actor_id: operator.id)
  end

  it "records an unreadable catalog, and a fault on this server without its details" do
    stub_kev(body: "{")
    expect { refresh }.to raise_error(Advisories::Unreadable)
    expect(SignalImport.sole.reason).to eq("known_exploited_vulnerabilities.json is not valid JSON, so nothing was imported")
    stub_kev
    allow_any_instance_of(Signals::KevImport).to receive(:call).and_raise(ActiveRecord::ConnectionNotEstablished, "secret detail")
    expect { refresh }.to raise_error(ActiveRecord::ConnectionNotEstablished)
    expect(SignalImport.order(:id).last.reason).to eq("the refresh failed on the server (ActiveRecord::ConnectionNotEstablished); see the server log")
  end

  it "does nothing when FLEET_KEV_URL is empty, keeping the stored entries" do
    import_kev(kev_file("CVE-2026-0001"))
    Signals.config.kev_url = nil
    expect(described_class.new.perform).to be_nil
    expect(KevEntry.count).to eq(1)
    expect(SignalImport.count).to eq(1)
  end
end
