require "rails_helper"

# The daily EPSS refresh (VT-S03, ADR 0032 point 5): the gzip file through Advisories::Feed, redirects followed only to
# FLEET_EPSS_REDIRECT_HOSTS, and an older file refused without a retry. All outbound HTTP is stubbed with the recorded
# file; the real download host and where it redirects are not exercised here.
RSpec.describe EpssRefreshJob, type: :job do
  include ActiveJob::TestHelper

  let(:url) { "https://epss.example.org/epss_scores-current.csv.gz" }
  let(:file) { SignalHelpers::SIGNAL_FIXTURES.join("epss_scores-current.csv.gz").binread }

  around do |example|
    saved = Signals.config.to_h.slice(:epss_url, :epss_redirect_hosts)
    Signals.config.epss_url = url
    Signals.config.epss_redirect_hosts = %w[cdn.example.net]
    example.run
  ensure
    Signals.config.epss_url, Signals.config.epss_redirect_hosts = saved.values_at(:epss_url, :epss_redirect_hosts)
  end

  before { advisory_for("CVE-2026-90777") }

  def refresh(**)
    perform_enqueued_jobs { described_class.perform_later(**) }
    SignalImport.order(:id).last
  rescue Minitest::UnexpectedError => e
    raise e.error
  end

  it "follows redirects to an allowed host and stores the fleet's scores" do
    dated = "https://cdn.example.net/epss_scores-2026-11-19.csv.gz"
    stub_request(:get, url).to_return(status: 302, headers: { "Location" => dated })
    stub_request(:get, dated).to_return(status: 200, body: file, headers: { "ETag" => '"e1"' })
    import = refresh
    expect(a_request(:get, url).with(headers: { "Accept" => "application/gzip, application/octet-stream" })).to have_been_made
    expect(import).to have_attributes(signal: "epss", source: "epss.example.org/epss_scores-current.csv.gz", state: "succeeded",
                                      score_date: Date.new(2026, 11, 19), version: "v2025.03.14", etag: '"e1"')
    expect(EpssScore.pluck(:cve_id)).to eq(%w[CVE-2026-90777])
  end

  it "refuses a redirect to a host FLEET_EPSS_REDIRECT_HOSTS does not list, naming only that host" do
    stub_request(:get, url).to_return(status: 302, headers: { "Location" => "https://other.example.com/x.csv.gz?sig=abc" })
    expect { refresh }.to raise_error(Advisories::Feed::Unavailable,
                                      "the FIRST EPSS download at epss.example.org redirected to other.example.com, and FLEET_EPSS_REDIRECT_HOSTS does not list it")
    expect(SignalImport.sole).to have_attributes(state: "failed")
    expect(EpssScore.count).to eq(0)
  end

  it "records an older file as refused, without retrying, and keeps the stored scores" do
    import_epss(epss_file([ %w[CVE-2026-90777 0.5 0.5] ], date: "2026-11-20"))
    stub_request(:get, url).to_return(status: 200, body: file)
    import = refresh
    expect(a_request(:get, url)).to have_been_made.once
    expect(import).to have_attributes(state: "failed", reason: include("older than the stored scores of 2026-11-20"))
    expect(AuditEntry.where(action: "signal.epss_import_failed").count).to eq(1)
    expect(EpssScore.sole.score).to eq(BigDecimal("0.5"))
  end

  it "keeps the score date when the file is not modified" do
    stub_request(:get, url).to_return(status: 200, body: file, headers: { "ETag" => '"e1"' })
    refresh
    stub_request(:get, url).with(headers: { "If-None-Match" => '"e1"' }).to_return(status: 304)
    expect(refresh).to have_attributes(counts: { "not_modified" => true }, score_date: Date.new(2026, 11, 19))
  end

  it "does nothing when FLEET_EPSS_URL is empty" do
    Signals.config.epss_url = nil
    expect(described_class.new.perform).to be_nil
  end
end
