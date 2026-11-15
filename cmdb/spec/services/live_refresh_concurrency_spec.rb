require "rails_helper"

# Live refreshes under concurrency (#194, review of #212). Runs outside the test transaction so each thread commits on
# its own connection, as agent requests and job threads do.
RSpec.describe "Concurrent live refreshes" do
  self.use_transactional_tests = false

  def adapter = ActiveJob::Base.queue_adapter

  def flush_jobs = adapter.enqueued_jobs.count { |job| job["job_class"] == "LiveRefreshJob" }

  before do
    PendingRefresh.delete_all
    adapter.enqueued_jobs.clear
  end

  after do
    PendingRefresh.delete_all
    adapter.enqueued_jobs.clear
  end

  # Each block on its own connection, all released at once.
  def concurrently(*blocks)
    gate = Queue.new
    threads = blocks.map do |block|
      Thread.new { ActiveRecord::Base.connection_pool.with_connection { gate.pop && block.call } }
    end
    blocks.size.times { gate << true }
    threads.each { |thread| thread.join(30) or raise "a request did not finish: deadlocked or stuck" }
  end

  # Before streams were sorted, two such requests deadlocked in 50 of 50 rounds once "fleet" was pending (review of
  # #212). Each took the host rows in its own order.
  it "does not deadlock two requests that name the same streams in opposite orders" do
    allow(Rails.error).to receive(:report).and_call_original
    hosts = (1..2000).map { |id| FleetBroadcast.host_stream(id) }
    5.times do
      PendingRefresh.where.not(stream: [ FleetBroadcast::STREAM, LiveRefresh::SCHEDULED ]).delete_all
      LiveRefresh.request([ FleetBroadcast::STREAM ]) # pending, as mid-window
      concurrently(-> { LiveRefresh.request([ FleetBroadcast::STREAM, *hosts ]) },
                   -> { LiveRefresh.request([ FleetBroadcast::STREAM, *hosts.reverse ]) })
    end
    expect(Rails.error).not_to have_received(:report)
    expect(PendingRefresh.where("stream LIKE 'fleet:host:%'").count).to eq(2000)
  end

  it "schedules the next flush for a change made while a flush is sending, once the flush commits" do
    LiveRefresh.request([ TaskBroadcast::STREAM ])
    adapter.enqueued_jobs.clear
    sending = Queue.new
    go_on = Queue.new
    allow(Turbo::StreamsChannel).to receive(:broadcast_refresh_to) do
      sending << true
      go_on.pop
    end
    flush = Thread.new { ActiveRecord::Base.connection_pool.with_connection { LiveRefresh.flush } }
    sending.pop
    change = Thread.new { ActiveRecord::Base.connection_pool.with_connection { LiveRefresh.request([ TaskBroadcast.batch_stream(3) ]) } }
    expect(change.join(0.5)).to be_nil # waits on the marker row the flush deleted
    go_on << true
    flush.join(10)
    change.join(10) or raise "the change never finished"
    expect(flush_jobs).to eq(1) # the next flush
    expect(PendingRefresh.where.not(stream: LiveRefresh::SCHEDULED).pluck(:stream)).to eq([ TaskBroadcast.batch_stream(3) ])
  ensure
    go_on&.<< true
  end

  it "schedules nothing for a change made while a flush fails: its retry is the only next flush" do
    LiveRefresh.request([ TaskBroadcast::STREAM ])
    adapter.enqueued_jobs.clear
    sending = Queue.new
    go_on = Queue.new
    allow(Turbo::StreamsChannel).to receive(:broadcast_refresh_to) do
      sending << true
      go_on.pop
      raise "cable down"
    end
    flush = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection { LiveRefresh.flush }
    rescue RuntimeError => e
      e
    end
    sending.pop
    change = Thread.new { ActiveRecord::Base.connection_pool.with_connection { LiveRefresh.request([ TaskBroadcast.batch_stream(3) ]) } }
    go_on << true
    expect(flush.value.message).to eq("cable down")
    change.join(10) or raise "the change never finished"
    expect(flush_jobs).to eq(0)
    expect(PendingRefresh.pluck(:stream).sort).to eq([ LiveRefresh::SCHEDULED, TaskBroadcast::STREAM, TaskBroadcast.batch_stream(3) ])
  ensure
    go_on&.<< true
  end

  it "releases the liveness evaluation's lock even when requesting the refresh fails" do
    allow(FleetBroadcast).to receive(:hosts_changed).and_raise("refresh failed")
    expect { Liveness.evaluate! }.to raise_error("refresh failed")
    held = ActiveRecord::Base.connection.select_value(<<~SQL)
      SELECT count(*) FROM pg_locks
      WHERE locktype = 'advisory' AND objid = #{Liveness::EVALUATION_LOCK_KEY}
        AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
    SQL
    expect(held).to eq(0)
  end
end
