require "rails_helper"

# P2-S15: two operators pressing "Refresh now" at the same moment start exactly one refresh job, because the
# cool-down check and the attempt it records run under one advisory lock. Runs outside the test transaction so
# each thread commits on its own connection.
RSpec.describe Advisories::ManualRefresh do
  self.use_transactional_tests = false

  around do |example|
    config = Advisories.config
    saved = config.to_h.slice(:feed_url, :refresh_cooldown)
    config.feed_url = "https://advisories.example.org/osv/Debian/all.zip"
    config.refresh_cooldown = 300.seconds
    example.run
  ensure
    config.feed_url, config.refresh_cooldown = saved.values_at(:feed_url, :refresh_cooldown)
  end

  before do
    @operators = Array.new(2) { |i| create(:operator, email: "refresh-race-#{i}@example.lan") }
    allow(AdvisoryFeedRefreshJob).to receive(:perform_later)
  end

  after do
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica") # audit entries are append-only
    AuditEntry.where(action: Audit::Actions::ALL.grep(/\Aadvisory\.refresh_/)).delete_all
    AdvisoryRefreshAttempt.delete_all
    Operator.where(id: @operators.map(&:id)).delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  it "starts exactly one job when two manual refreshes are requested at the same time" do
    now = Time.current.floor # microseconds, as stored
    ready = Concurrent::CountDownLatch.new(2)
    go = Concurrent::CountDownLatch.new(1)
    threads = @operators.map do |operator|
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          ready.count_down
          go.wait
          described_class.request!(actor: operator, now:)
        end
      end
    end
    ready.wait
    go.count_down
    results = threads.map(&:value)

    expect(results.map(&:accepted?)).to contain_exactly(true, false)
    expect(results.find(&:refused?).next_allowed_at).to eq(now + 5.minutes)
    attempt = AdvisoryRefreshAttempt.sole
    expect(AdvisoryFeedRefreshJob).to have_received(:perform_later).once.with(attempt_id: attempt.id)
    expect(AuditEntry.where(action: %w[advisory.refresh_requested advisory.refresh_refused]).pluck(:action))
      .to contain_exactly("advisory.refresh_requested", "advisory.refresh_refused")
  end

  it "makes a manual request wait for a scheduled run that holds the lock, then counts that run" do
    locked = Concurrent::CountDownLatch.new(1)
    scheduled = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        AdvisoryRefreshAttempt.transaction do
          described_class.record_start!(kind: "scheduled") # the inner transaction joins this one, so the lock is held until it ends
          locked.count_down
          sleep 0.3
        end
      end
    end
    locked.wait
    result = described_class.request!(actor: @operators.first)
    scheduled.join

    expect(result).to be_refused
    expect(AdvisoryRefreshAttempt.sole.kind).to eq("scheduled")
    expect(AdvisoryFeedRefreshJob).not_to have_received(:perform_later)
  end
end
