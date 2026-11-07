require "rails_helper"

# The scheduled advisory refresh (P2-S13, DEC-11, NFR-1, NFR-2). All outbound HTTP is stubbed.
RSpec.describe AdvisoryFeedRefreshJob, type: :job do
  include ActiveJob::TestHelper

  # A query-string key and a bearer token, neither of which may appear in a log, an error, or the audit log.
  let(:url) { "https://advisories.example.org/osv/Debian/all.zip?key=QUERY-SECRET-123" }
  let(:token) { "TOKEN-SECRET-456" }
  let(:archive) { osv_zip("DSA-1-1.json" => osv_record(id: "DSA-1-1"), "DSA-2-1.json" => osv_record(id: "DSA-2-1", package: "curl")).binread }

  around do |example|
    config = Advisories.config
    saved = config.to_h.slice(:feed_url, :feed_token)
    config.feed_url = url
    config.feed_token = token
    example.run
  ensure
    config.feed_url, config.feed_token = saved.values_at(:feed_url, :feed_token)
  end

  def secrets = [ "QUERY-SECRET-123", "TOKEN-SECRET-456" ]

  # Runs the job and its retries. The test helper wraps the error the last attempt raises; unwrap it.
  def refresh
    perform_enqueued_jobs { described_class.perform_later }
  rescue Minitest::UnexpectedError => e
    raise e.error
  end

  def stub_feed(**response) = stub_request(:get, url).to_return({ status: 200, body: archive, headers: { "ETag" => '"v1"', "Last-Modified" => "Tue, 03 Nov 2026 10:00:00 GMT" } }.merge(response))

  it "downloads the archive over HTTPS with the token, imports it as a full data set, and records its validators" do
    stub_feed
    refresh
    expect(a_request(:get, url).with(headers: { "Authorization" => "Bearer #{token}" })).to have_been_made.once
    expect(a_request(:get, url).with(headers: { "If-None-Match" => /./ })).not_to have_been_made
    import = AdvisoryImport.sole
    expect(import).to have_attributes(origin: "feed", source: "advisories.example.org/osv/Debian/all.zip", full: true, state: "succeeded",
                                      ecosystems: [ "Debian:13" ], etag: '"v1"', last_modified: "Tue, 03 Nov 2026 10:00:00 GMT",
                                      counts: include("created" => 2))
    expect(Advisory.count).to eq(2)
    expect(AuditEntry.sole).to have_attributes(action: "advisory.imported", actor_type: "system")
    expect(Advisories::Freshness.statuses.sole).to have_attributes(stale: false)
  end

  it "asks conditionally next time, and records a not-modified answer as a refresh of the same ecosystems" do
    stub_feed
    refresh
    travel 7.hours do
      stub_request(:get, url).with(headers: { "If-None-Match" => '"v1"', "If-Modified-Since" => "Tue, 03 Nov 2026 10:00:00 GMT" }).to_return(status: 304)
      refresh
      expect(AdvisoryImport.order(:id).last).to have_attributes(state: "succeeded", full: true, ecosystems: [ "Debian:13" ], etag: '"v1"',
                                                                counts: { "not_modified" => true }, finished_at: be_within(1.minute).of(Time.current))
      expect(AuditEntry.count).to eq(1) # nothing was imported
      expect(Advisories::Freshness.statuses.sole.updated_at).to be_within(1.minute).of(Time.current)
    end
  end

  it "refuses a not-modified answer to a request that was not conditional" do
    stub_request(:get, url).to_return(status: 304)
    expect { refresh }.to raise_error(Advisories::Feed::Unavailable, "the advisory feed at advisories.example.org answered 304 to a request that was not conditional")
  end

  it "retries a timed-out fetch with backoff, then records the failure, audited, and fails the job" do
    stub_request(:get, url).to_timeout
    log = captured_log { expect { refresh }.to raise_error(Advisories::Feed::Unavailable) }
    expect(a_request(:get, url)).to have_been_made.times(described_class::ATTEMPTS)
    reason = "could not download from the advisory feed at advisories.example.org (OpenTimeout)"
    expect(AdvisoryImport.sole).to have_attributes(state: "failed", origin: "feed", full: true, reason:)
    expect(AuditEntry.sole).to have_attributes(action: "advisory.import_failed", changeset: include("reason" => reason))
    expect(log).to include("feed refresh failed (attempt 1 of 5): #{reason}", "feed refresh failed after 5 attempts: #{reason}")
    secrets.each { |secret| expect(log).not_to include(secret) }
  end

  it "succeeds when the feed recovers during the retries" do
    stub_feed.to_timeout.then.to_return(status: 503).then.to_return(status: 200, body: archive)
    refresh
    expect(AdvisoryImport.sole.state).to eq("succeeded")
  end

  {
    "an HTTP error" => [ { status: 403 }, "the advisory feed at advisories.example.org answered HTTP 403" ],
    "a refused connection" => [ Errno::ECONNREFUSED, "could not download from the advisory feed at advisories.example.org (ECONNREFUSED)" ],
    "a certificate that does not verify" => [ OpenSSL::SSL::SSLError.new("certificate verify failed"), "could not download from the advisory feed at advisories.example.org (SSLError)" ],
    "an archive that is not a zip" => [ { status: 200, body: "PK\x03\x04 garbage" }, "all.zip is not a readable zip archive" ]
  }.each do |what, (response, reason)|
    it "reports #{what} after the retries, naming only the feed's host" do
      stub = stub_request(:get, url)
      response.is_a?(Hash) ? stub.to_return(response) : stub.to_raise(response)
      expect { refresh }.to raise_error(StandardError)
      expect(AdvisoryImport.sole).to have_attributes(state: "failed", reason:)
      expect(Advisory.count).to eq(0)
    end
  end

  it "verifies the certificate" do
    expect(Net::HTTP).to receive(:start).with("advisories.example.org", 443, hash_including(use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_PEER)).and_call_original
    stub_feed
    refresh
  end

  it "stops a download larger than the limit, or slower than the deadline" do
    Advisories.config.max_download_bytes, saved = 100, Advisories.config.max_download_bytes
    stub_feed
    expect { refresh }.to raise_error(Advisories::Feed::Unavailable, "the advisory feed at advisories.example.org sent more than 0 MiB")
    Advisories.config.max_download_bytes = saved
  ensure
    Advisories.config.max_download_bytes = saved
  end

  it "bounds the whole exchange, so a server slow to send its status line or headers cannot hold a worker (review of #103)" do
    stub_const("Advisories::Feed::DEADLINE", 0.2)
    stub_request(:get, url).to_return { sleep 1; { status: 200, body: archive } } # stands in for headers trickling in
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    expect { Advisories::Feed.new.fetch }.to raise_error(Advisories::Feed::Unavailable, "the download from the advisory feed at advisories.example.org took longer than 0.2 seconds")
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 0.9
  end

  it "downloads the whole archive again, not conditionally, after an import with malformed records (review of #103)" do
    with_bad = osv_zip("DSA-1-1.json" => osv_record(id: "DSA-1-1"), "bad.json" => "not json").binread
    stub_feed(body: with_bad)
    refresh
    expect(AdvisoryImport.sole.counts["malformed"]).to eq(1)
    stub_feed
    refresh
    expect(a_request(:get, url).with(headers: { "If-None-Match" => /./ })).not_to have_been_made
    expect(AdvisoryImport.order(:id).last.counts).to include("created" => 1, "unchanged" => 1, "malformed" => 0)
  end

  it "follows a few HTTPS redirects, sending the token only to the configured host" do
    mirror = "https://cdn.example.net/osv/all.zip"
    stub_request(:get, url).to_return(status: 302, headers: { "Location" => mirror })
    stub_request(:get, mirror).to_return(status: 200, body: archive)
    refresh
    expect(a_request(:get, mirror).with { |request| !request.headers.key?("Authorization") }).to have_been_made
    expect(AdvisoryImport.sole.state).to eq("succeeded")

    { "http://cdn.example.net/all.zip" => "redirected to a URL that is not HTTPS", "https://exa mple/" => "redirected to an invalid URL" }.each do |location, problem|
      stub_request(:get, url).to_return(status: 302, headers: { "Location" => location })
      expect { refresh }.to raise_error(Advisories::Feed::Unavailable, "the advisory feed at advisories.example.org #{problem}")
    end
    stub_request(:get, url).to_return(status: 302)
    expect { refresh }.to raise_error(Advisories::Feed::Unavailable, "the advisory feed at advisories.example.org sent a redirect without a location")
    stub_request(:get, url).to_return(status: 302, headers: { "Location" => url })
    expect { refresh }.to raise_error(Advisories::Feed::Unavailable, "the advisory feed at advisories.example.org redirected too many times")
  end

  it "reports a fault on this server without its details, which go to the log" do
    stub_feed
    allow(Advisories::Import).to receive(:new).and_call_original
    allow_any_instance_of(Advisories::Import).to receive(:call).and_raise(ActiveRecord::ConnectionNotEstablished, "connection to server lost")
    expect { refresh }.to raise_error(ActiveRecord::ConnectionNotEstablished)
    expect(AdvisoryImport.sole.reason).to eq("the refresh failed on the server (ActiveRecord::ConnectionNotEstablished); see the server log")
  end

  it "does nothing when no feed is configured" do
    Advisories.config.feed_url = nil
    log = captured_log { expect(described_class.perform_now).to be_nil }
    expect(log).to include("no feed configured")
    expect(AdvisoryImport.count).to eq(0)
  end

  it "fails as a job an operator sees on the failed-jobs page and in /health, without the secrets" do
    adapter = described_class.queue_adapter
    stub_request(:get, url).to_return(status: 500, body: "internal error for key=QUERY-SECRET-123")
    described_class.queue_adapter = :solid_queue
    described_class.perform_later
    described_class::ATTEMPTS.times do
      SolidQueue::ScheduledExecution.dispatch_next_batch(100)
      begin
        SolidQueue::ReadyExecution.claim("*", 10, nil).each(&:perform)
      rescue Advisories::Feed::Unavailable
        nil # the last attempt is raised to the worker pool after being recorded as failed
      end
      travel(10.minutes)
    end
    failure = JobHealth.failures.sole
    expect(failure).to have_attributes(job_class: "AdvisoryFeedRefreshJob", error_class: "Advisories::Feed::Unavailable",
                                       error_message: "the advisory feed at advisories.example.org answered HTTP 500")
    expect(JobHealth).to be_failing
    recorded = [ failure.error_message, SolidQueue::FailedExecution.sole.error.to_json, AdvisoryImport.pluck(:source, :reason).to_json, AuditEntry.pluck(:changeset).to_json ]
    secrets.each { |secret| expect(recorded.join).not_to include(secret) }
  ensure
    described_class.queue_adapter = adapter
    travel_back
  end
end
