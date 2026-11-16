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

  # Follow-up to the review of #212: the flush held one transaction while it sent, so a change made meanwhile waited
  # on the marker row until the flush was done. Solid Cable's broadcast itself only queues the message in memory
  # (review of #218), so what makes a flush slow is anything else that holds it up mid-send: many streams, a
  # paused VM, a long collection. The stub stands in for that.
  it "lets a change made while a flush is held up mid-send return at once, and schedules its flush when it is done" do
    LiveRefresh.request([ TaskBroadcast::STREAM ])
    adapter.enqueued_jobs.clear
    sending = Queue.new
    allow(Turbo::StreamsChannel).to receive(:broadcast_refresh_to) do
      sending << true
      sleep 2 # the flush is held up for 2 s mid-send
    end
    flush = Thread.new { ActiveRecord::Base.connection_pool.with_connection { LiveRefresh.flush } }
    sending.pop
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    change = Thread.new { ActiveRecord::Base.connection_pool.with_connection { LiveRefresh.request([ TaskBroadcast.batch_stream(3) ]) } }
    change.join(5) or raise "the change never finished"
    waited = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    expect(waited).to be < 0.5 # REQUEST_LOCK_TIMEOUT, and in fact it waits for nothing
    expect(flush.join(10)&.value).to eq([ TaskBroadcast::STREAM ])
    expect(flush_jobs).to eq(1) # the next flush, for the change
    expect(PendingRefresh.where.not(stream: LiveRefresh::SCHEDULED).pluck(:stream)).to eq([ TaskBroadcast.batch_stream(3) ])
  end

  it "gives up after the lock timeout when something holds a row it needs, and reports it" do
    LiveRefresh.request([ FleetBroadcast::STREAM ])
    allow(Rails.error).to receive(:report).and_call_original
    holding = Queue.new
    done = Queue.new
    holder = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        PendingRefresh.transaction do
          PendingRefresh.where(stream: FleetBroadcast::STREAM).lock.load
          PendingRefresh.where(stream: FleetBroadcast::STREAM).delete_all # an INSERT of it now waits for this
          holding << true
          done.pop
        end
      end
    end
    holding.pop
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    # In a thread with a time limit, so a missing lock timeout fails this example instead of hanging it (review of #218).
    request = Thread.new { ActiveRecord::Base.connection_pool.with_connection { LiveRefresh.request([ FleetBroadcast::STREAM ]) } }
    expect(request.join(3)).to be_truthy, "the request was still waiting for the lock after 3 s"
    waited = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    expect(waited).to be_between(0.4, 1.5)
    expect(Rails.error).to have_received(:report).with(an_instance_of(ActiveRecord::LockWaitTimeout), hash_including(handled: true))
  ensure
    done&.<< true
    holder&.join(5)
    request&.join(5)
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
    ActiveRecord::Base.connection_pool.with_connection { LiveRefresh.request([ TaskBroadcast::STREAM, TaskBroadcast.batch_stream(3) ]) }
    go_on << true
    expect(flush.value.message).to eq("cable down")
    expect(flush_jobs).to eq(0)
    # The taken row's name came back; the change's own row for the same stream is kept, not doubled.
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
