require "rails_helper"

# The scheduled advisory refresh (P2-S13, DEC-11, NFR-1, NFR-2). All outbound HTTP is stubbed.
RSpec.describe AdvisoryFeedRefreshJob, type: :job do
  include ActiveJob::TestHelper

  # A query-string key and a bearer token, neither of which may appear in a log, an error, or the audit log.
  let(:url) { "https://advisories.example.org/osv/Debian/all.zip?key=QUERY-SECRET-123" }
  let(:token) { "TOKEN-SECRET-456" }
  let(:archive) { osv_zip("DSA-1-1.json" => osv_record(id: "DSA-1-1"), "DSA-2-1.json" => osv_record(id: "DSA-2-1", package: "curl")).binread }

  # Debian's triage refresh after a manual refresh (P2-D08) is turned off here, except where a spec turns it on.
  around do |example|
    config = Advisories.config
    saved = config.to_h.slice(:feed_url, :feed_token)
    saved_tracker = DebianTriage.config.tracker_url
    config.feed_url = url
    config.feed_token = token
    DebianTriage.config.tracker_url = nil
    example.run
  ensure
    config.feed_url, config.feed_token = saved.values_at(:feed_url, :feed_token)
    DebianTriage.config.tracker_url = saved_tracker
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
    expect(AdvisoryRefreshAttempt.count).to eq(0)
  end

  describe "the manual refresh cool-down (P2-S15)" do
    let(:operator) { create(:operator) }

    it "runs on schedule within the cool-down of a manual refresh, and records its start once, not on each retry" do
      expect(Advisories::ManualRefresh.request!(actor: operator)).to be_accepted
      clear_enqueued_jobs
      stub_feed.to_timeout.then.to_return(status: 200, body: archive)
      refresh
      expect(AdvisoryRefreshAttempt.order(:id).pluck(:kind)).to eq(%w[manual scheduled])
      expect(AdvisoryImport.sole).to have_attributes(state: "succeeded", operator: nil)
      # the scheduled run started the cool-down again
      expect(Advisories::ManualRefresh.next_allowed_at).to be_within(1.second).of(AdvisoryRefreshAttempt.maximum(:started_at) + 5.minutes)
    end

    it "records its start on a retry when recording failed on the first execution (review of #125)" do
      stub_feed
      calls = 0
      allow(Advisories::ManualRefresh).to receive(:record_start!).and_wrap_original do |original, **args|
        calls += 1
        raise ActiveRecord::ConnectionFailed, "the database went away" if calls == 1

        original.call(**args)
      end
      refresh
      expect(calls).to eq(2)
      expect(AdvisoryRefreshAttempt.pluck(:kind)).to eq(%w[scheduled])
      expect(AdvisoryImport.sole).to have_attributes(state: "succeeded")
    end

    it "attributes the import from a manual refresh, and its audit entry, to the operator who asked" do
      stub_feed
      Advisories::ManualRefresh.request!(actor: operator)
      perform_enqueued_jobs
      expect(AdvisoryRefreshAttempt.sole.kind).to eq("manual") # the job did not record a second attempt
      expect(AdvisoryImport.sole).to have_attributes(state: "succeeded", operator:)
      expect(AuditEntry.order(:id).pluck(:action, :actor_type, :actor_id))
        .to eq([ [ "advisory.refresh_requested", "operator", operator.id ], [ "advisory.imported", "operator", operator.id ] ])
    end

    it "attributes a manual refresh's failure and a not-modified answer to the operator too" do
      stub_feed
      refresh
      travel 10.minutes
      stub_request(:get, url).with(headers: { "If-None-Match" => '"v1"' }).to_return(status: 304)
      perform_enqueued_jobs { Advisories::ManualRefresh.request!(actor: operator) }
      expect(AdvisoryImport.order(:id).last).to have_attributes(counts: { "not_modified" => true }, operator:)

      travel 10.minutes
      stub_request(:get, url).to_return(status: 500)
      expect { perform_enqueued_jobs { Advisories::ManualRefresh.request!(actor: operator) } }.to raise_error(Minitest::UnexpectedError)
      expect(AdvisoryImport.order(:id).last).to have_attributes(state: "failed", operator:)
      expect(AuditEntry.order(:id).last).to have_attributes(action: "advisory.import_failed", actor_type: "operator", actor_id: operator.id)
    ensure
      travel_back
    end
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

  # Review of #129 (owner decision): the scheduled refresh is guarded against mass withdrawal like every full
  # import. A refusal is not a fault: nothing is written, it is recorded and audited with the counts, and the job
  # ends normally, so it is neither retried nor a failed job.
  describe "the withdrawal guard" do
    before do
      import_advisories(*(1..5).map { |i| osv_record(id: "DSA-#{i}-1") }, full: true, origin: "feed", source: "advisories.example.org/osv/Debian/all.zip")
    end

    let(:archive) { osv_zip("DSA-1-1.json" => osv_record(id: "DSA-1-1")).binread }

    it "refuses a refresh that would withdraw too many advisories: no retry, no failed job, counts audited, data unchanged" do
      stub_feed
      adapter = described_class.queue_adapter
      described_class.queue_adapter = :solid_queue
      described_class.perform_later
      SolidQueue::ReadyExecution.claim("*", 10, nil).each(&:perform)

      refused = AdvisoryImport.order(:id).last
      expect(refused).to have_attributes(origin: "feed", state: "held_back", full: true)
      expect(refused.counts).to eq("would_withdraw" => { "Debian:13" => { "withdraw" => 4, "current" => 5, "records" => 1 } })
      expect(refused.reason).to start_with("this full import would mark 4 of 5 current Debian:13 advisories")
      expect(Advisory.current.count).to eq(5)
      expect(SolidQueue::FailedExecution.count).to eq(0)
      expect(SolidQueue::ScheduledExecution.count).to eq(0) # no retry scheduled
      expect(JobHealth).not_to be_failing
      audit = AuditEntry.where(action: "advisory.import_held_back").sole
      expect(audit).to have_attributes(actor_type: "system")
      expect(audit.changeset["would_withdraw"]).to eq("Debian:13" => { "withdraw" => 4, "current" => 5, "records" => 1 })
      expect(Advisories::Freshness.held_refresh).to eq(refused)
      expect(WebMock).to have_requested(:get, url).once
    ensure
      described_class.queue_adapter = adapter
    end

    it "imports the same archive when an operator confirmed those counts" do
      stub_feed
      result = described_class.perform_now(allowed_withdrawals: { "Debian:13" => 4 })
      expect(result.import).to have_attributes(state: "succeeded")
      expect(result.import.counts["absent"]).to eq(4)
      expect(Advisories::Freshness.held_refresh).to be_nil
    end
  end

  # P2-D08, owner decision T2 on #134: the one "Refresh now" refreshes OSV and then Debian's triage, under the same
  # cool-down and one audit entry; a tracker failure never changes the OSV refresh's outcome.
  describe "Debian's triage after a manual refresh (P2-D08)" do
    let(:operator) { create(:operator) }
    let(:tracker) { "https://security-tracker.example.org/tracker/data/json" }
    let(:document) { DebianTrackerHelpers::FIXTURES.join("sample.json").read }

    before do
      DebianTriage.config.tracker_url = tracker
      debian_host(packages: nil) # a trixie host, so the tracker refresh has a release to import
    end

    def manual_refresh
      perform_enqueued_jobs { Advisories::ManualRefresh.request!(actor: operator) }
    rescue Minitest::UnexpectedError => e
      e.error
    end

    it "refreshes the tracker right after the advisory data, attributed to the operator, under the one cool-down and audit entry" do
      stub_feed
      stub_request(:get, tracker).to_return(status: 200, body: document)
      manual_refresh
      osv = AdvisoryImport.sole
      triage = TriageImport.sole
      expect(osv).to have_attributes(state: "succeeded", operator:)
      expect(triage).to have_attributes(state: "succeeded", origin: "feed", operator:)
      expect(triage.started_at).to be >= osv.finished_at
      expect(AdvisoryRefreshAttempt.sole).to have_attributes(kind: "manual", operator:)
      expect(Advisories::ManualRefresh.next_allowed_at).to be_present
      requested = AuditEntry.where(action: "advisory.refresh_requested").sole
      expect(requested.changeset).to include("source" => "advisories.example.org/osv/Debian/all.zip", "triage_source" => "security-tracker.example.org/tracker/data/json")
      expect(AuditEntry.where("action LIKE ?", "advisory.%").order(:id).pluck(:action)).to eq(%w[advisory.refresh_requested advisory.imported advisory.triage_imported])
      expect(AuditEntry.where(action: "advisory.triage_imported").sole).to have_attributes(actor_type: "operator", actor_id: operator.id)
    end

    it "keeps the advisory import's outcome when the tracker refresh fails" do
      stub_feed
      stub_request(:get, tracker).to_return(status: 503)
      expect(manual_refresh).to be_a(Advisories::ManualRefresh::Result) # nothing raised to the OSV refresh
      expect(a_request(:get, tracker)).to have_been_made.at_least_once
      expect(AdvisoryImport.sole).to have_attributes(state: "succeeded", operator:)
      expect(Advisory.count).to eq(2)
      expect(AuditEntry.where(action: "advisory.import_failed")).to be_empty
      # The tracker job retries and then fails on its own (debian_triage_refresh_job_spec.rb), as the operator's.
      job = DebianTriageRefreshJob.new(operator_id: operator.id)
      expect(job.give_up(Advisories::Feed::Unavailable.new("answered HTTP 503"))).to have_attributes(state: "failed", operator:)
      expect(AdvisoryImport.sole).to have_attributes(state: "succeeded")
    end

    it "still refreshes the tracker after the advisory refresh fails for good, and after one that was not modified" do
      stub_request(:get, url).to_return(status: 500)
      stub_request(:get, tracker).to_return(status: 200, body: document)
      manual_refresh
      expect(AdvisoryImport.sole).to have_attributes(state: "failed", operator:)
      expect(TriageImport.sole).to have_attributes(state: "succeeded", operator:)
      expect(a_request(:get, tracker)).to have_been_made.once # once, not once per retry of the advisory refresh
    end

    it "does not refresh the tracker when it is turned off, after a scheduled run, or when it cannot be started" do
      stub_feed
      DebianTriage.config.tracker_url = nil
      manual_refresh
      expect(TriageImport.count).to eq(0)
      expect(AuditEntry.where(action: "advisory.refresh_requested").sole.changeset).to include("triage_source" => nil)

      DebianTriage.config.tracker_url = tracker
      travel 10.minutes do
        refresh # the schedule runs the tracker as its own job
        expect(enqueued_jobs.map { |job| job["job_class"] }).not_to include("DebianTriageRefreshJob")
        expect(TriageImport.count).to eq(0)
      end

      travel 20.minutes do
        allow(DebianTriageRefreshJob).to receive(:perform_later).and_raise(ActiveJob::EnqueueError, "queue unavailable")
        expect(manual_refresh).to be_a(Advisories::ManualRefresh::Result) # nothing raised
        expect(AdvisoryImport.order(:id).last).to have_attributes(state: "succeeded", operator:)
      end
    end
  end
end
