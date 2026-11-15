require "rails_helper"

# Coalesced live refreshes (#194): a burst of changes is one job and one refresh per stream per window, the last
# change is never lost, a host's pages listen only to that host, and none of it needs the cache.
RSpec.describe LiveRefresh, type: :job do
  include ActiveJob::TestHelper

  def jobs = enqueued_jobs.select { |job| job["job_class"] == "LiveRefreshJob" }

  def broadcasts(stream) = ActionCable.server.pubsub.broadcasts(stream)

  def sent = ActionCable.server.pubsub.send(:channels_data).transform_values(&:size).reject { |_, count| count.zero? }

  def marker = PendingRefresh.find_by(stream: described_class::SCHEDULED)

  # Forgets the refreshes the examples' setup requested.
  def reset
    ActionCable.server.pubsub.clear
    clear_pending_refreshes
    clear_enqueued_jobs
  end

  before { reset }

  describe ".parse_window (FLEET_LIVE_REFRESH_SECONDS)" do
    it "is 2 seconds unless set, and takes a whole number of seconds from 1 to 15" do
      expect(described_class.parse_window(nil)).to eq(2.seconds)
      expect(described_class.parse_window("")).to eq(2.seconds)
      expect(described_class.parse_window("15")).to eq(15.seconds)
      expect(described_class.window).to eq(2.seconds)
    end

    it "refuses anything else, naming the setting, so the boot stops" do
      %w[0 16 1.5 two -1].each do |value|
        expect { described_class.parse_window(value) }.to raise_error(ArgumentError, /FLEET_LIVE_REFRESH_SECONDS must be a whole number of seconds from 1 to 15 \(got "#{Regexp.escape(value)}"\)/)
      end
    end
  end

  describe "a burst of changes" do
    it "is one job, one window later, and one refresh per stream, however many changes it has" do
      freeze_time do
        task = create_task(task_host)
        reset
        500.times { described_class.request([ TaskBroadcast::STREAM, TaskBroadcast.batch_stream(task.task_batch_id), FleetBroadcast.host_stream(task.host_id) ]) }
        500.times { FleetBroadcast.hosts_changed([ task.host_id ]) }
        expect(jobs.size).to eq(1)
        expect(jobs.sole).to include("queue_name" => "realtime", "priority" => ApplicationJob::BROADCAST_PRIORITY)
        expect(Time.iso8601(jobs.sole["scheduled_at"])).to eq(2.seconds.from_now)
        expect(sent).to be_empty # nothing reaches a browser before the window ends

        perform_enqueued_jobs
        expect(sent).to eq(TaskBroadcast::STREAM => 1, TaskBroadcast.batch_stream(task.task_batch_id) => 1,
                           FleetBroadcast.host_stream(task.host_id) => 1, FleetBroadcast::STREAM => 1)
        expect(pending_refreshes).to be_empty
        expect(marker).to be_nil
      end
    end

    it "sends about one refresh per window while changes keep coming" do
      task = create_task(task_host)
      reset
      windows = 5
      windows.times do
        100.times { TaskBroadcast.changed(task) } # the changes of one window
        perform_enqueued_jobs # its end
      end
      expect(broadcasts(TaskBroadcast::STREAM).size).to eq(windows)
      expect(broadcasts(FleetBroadcast.host_stream(task.host_id)).size).to eq(windows)
    end

    it "sends a refresh with no data in it, so nothing from a change reaches the stream" do
      host, = enrolled_host(name: HOSTILE)
      reset
      perform_enqueued_jobs { FleetBroadcast.hosts_changed([ host.id ]) }
      message = JSON.parse(broadcasts(FleetBroadcast.host_stream(host.id)).sole)
      expect(Nokogiri::HTML.fragment(message).css("turbo-stream").map { |stream| stream["action"] }).to eq([ "refresh" ])
      expect(message).not_to include("alert")
    end

    it "is one Solid Queue job for 1,000 changes, scheduled one window ahead (the real queue database)" do
      adapter = ActiveJob::QueueAdapters::SolidQueueAdapter.new
      allow(LiveRefreshJob).to receive(:queue_adapter).and_return(adapter)
      before = SolidQueue::Job.where(class_name: "LiveRefreshJob").count
      started = Time.current
      1000.times { |i| described_class.request([ TaskBroadcast::STREAM, FleetBroadcast.host_stream(i) ]) }
      queued = SolidQueue::Job.where(class_name: "LiveRefreshJob")
      expect(queued.count - before).to eq(1)
      expect(queued.last.scheduled_at).to be_within(1.second).of(started + 2.seconds)
      expect(PendingRefresh.count).to eq(1002) # 1,001 streams and the marker
    end
  end

  describe "the last change (trailing refresh)" do
    it "is in the flush when it commits while a flush is scheduled" do
      described_class.request([ TaskBroadcast::STREAM ])
      described_class.request([ TaskBroadcast.batch_stream(7) ]) # the marker is held: no second job
      expect(jobs.size).to eq(1)
      perform_enqueued_jobs
      expect(sent).to eq(TaskBroadcast::STREAM => 1, TaskBroadcast.batch_stream(7) => 1)
    end

    it "schedules the next flush when it commits while a flush is sending" do
      described_class.request([ TaskBroadcast::STREAM ])
      allow(Turbo::StreamsChannel).to receive(:broadcast_refresh_to).and_wrap_original do |original, stream|
        described_class.request([ TaskBroadcast.batch_stream(9) ]) if stream == TaskBroadcast::STREAM # a change mid-flush
        original.call(stream)
      end
      clear_enqueued_jobs
      LiveRefreshJob.perform_now # the scheduled flush
      expect(sent).to eq(TaskBroadcast::STREAM => 1)
      expect(pending_refreshes).to eq([ TaskBroadcast.batch_stream(9) ])
      expect(jobs.size).to eq(1) # the next flush
      perform_enqueued_jobs
      expect(sent).to eq(TaskBroadcast::STREAM => 1, TaskBroadcast.batch_stream(9) => 1)
    end

    it "is sent after a flush whose job was never enqueued or died: an old marker is taken over" do
      PendingRefresh.insert_all([ { stream: described_class::SCHEDULED, requested_at: 10.seconds.ago } ])
      described_class.request([ TaskBroadcast::STREAM ])
      expect(jobs).to be_empty # held by a flush that may still run

      PendingRefresh.where(stream: described_class::SCHEDULED).update_all(requested_at: 2.minutes.ago)
      described_class.request([ TaskBroadcast.batch_stream(1) ])
      expect(jobs.size).to eq(1)
      perform_enqueued_jobs
      expect(sent).to eq(TaskBroadcast::STREAM => 1, TaskBroadcast.batch_stream(1) => 1)
    end

    it "schedules the next flush for a change that commits just after the pending rows were taken (review of #212)" do
      described_class.request([ "tasks" ])
      clear_enqueued_jobs
      allow(described_class).to receive(:collapse).and_wrap_original do |original, streams|
        described_class.request([ "tasks:batch:9" ])
        original.call(streams)
      end
      described_class.flush
      expect(jobs.size).to eq(1)
    end

    it "reports a failed enqueue without failing the committed change, and the next change schedules the flush" do
      allow(LiveRefreshJob).to receive(:set).and_raise(ActiveRecord::ConnectionNotEstablished)
      allow(Rails.error).to receive(:report)
      expect { described_class.request([ TaskBroadcast::STREAM ]) }.not_to raise_error
      expect(Rails.error).to have_received(:report).with(an_instance_of(ActiveRecord::ConnectionNotEstablished), hash_including(handled: true))
      expect(marker).to be_nil
      expect(pending_refreshes).to eq([ TaskBroadcast::STREAM ])

      allow(LiveRefreshJob).to receive(:set).and_call_original
      described_class.request([ FleetBroadcast::STREAM ])
      perform_enqueued_jobs
      expect(sent).to eq(TaskBroadcast::STREAM => 1, FleetBroadcast::STREAM => 1)
    end

    it "keeps every stream pending and the marker held when a broadcast fails, and fails the flush for its retry" do
      described_class.request(%w[a b c])
      calls = 0
      allow(Turbo::StreamsChannel).to receive(:broadcast_refresh_to).and_wrap_original do |original, stream|
        raise "cable down" if (calls += 1) == 2

        original.call(stream)
      end
      expect { described_class.flush }.to raise_error("cable down")
      expect(sent).to eq("a" => 1) # sent before the failure; sent again by the retry, which is harmless
      expect(pending_refreshes).to eq(%w[a b c]) # the delete rolled back with the failed flush
      expect(marker).to be_present
    end

    # Review of #212: each failed flush both re-requested (a new job) and raised (a retry of the same job), so the
    # jobs doubled with every failure: 3, 9, 27, 79 ... runs per 5 s.
    it "runs a failing flush only as its own retries, however many changes arrive meanwhile, and then stops" do
      allow(Turbo::StreamsChannel).to receive(:broadcast_refresh_to).and_raise("cable down")
      described_class.request([ TaskBroadcast::STREAM ])
      runs = 0
      50.times do # due jobs in time order, retries included; far more than a bounded run needs
        job = enqueued_jobs.select { |j| j["job_class"] == "LiveRefreshJob" }.min_by { |j| j["scheduled_at"].to_s } or break
        enqueued_jobs.delete(job)
        runs += 1
        begin
          ActiveJob::Base.execute(job)
        rescue RuntimeError
          nil # the last attempt raises, so Solid Queue keeps it as failed
        end
        described_class.request([ FleetBroadcast::STREAM ]) # a change between attempts
      end
      expect(runs).to eq(LiveRefreshJob::ATTEMPTS)
      expect(jobs).to be_empty
      expect(pending_refreshes).to eq([ FleetBroadcast::STREAM, TaskBroadcast::STREAM ])
      expect(marker).to be_present # held until it is old, then the sweep or the next change takes it over
    end
  end

  # Review of #218: a flush stalled past the takeover age (a VM pause, a long collection) had its rows given back and
  # its marker taken over, and then its own release deleted the new owner's marker, so two flushes ran at once.
  it "lets a flush slower than the takeover finish without deleting the marker of the flush that took over" do
    described_class.request(%w[a b])
    clear_enqueued_jobs
    stalled = true
    allow(Turbo::StreamsChannel).to receive(:broadcast_refresh_to).and_wrap_original do |original, stream|
      if stalled
        stalled = false
        # Over a minute passes mid-send: the marker is abandoned, the sweep takes it over, and a change comes in.
        PendingRefresh.where(stream: described_class::SCHEDULED).update_all(requested_at: 2.minutes.ago)
        expect(described_class.sweep).to be(true)
        described_class.request(%w[c])
      end
      original.call(stream)
    end
    described_class.flush # the stalled flush carries on and finishes
    expect(marker).to be_present # the new owner's, which the stalled flush left alone
    expect(jobs.size).to eq(1) # the new owner's flush only
    expect(pending_refreshes).to eq(%w[a b c]) # given back, sent again by the new flush: harmless
    perform_enqueued_jobs
    expect(marker).to be_nil
    expect(pending_refreshes).to be_empty
  end

  describe ".sweep (LiveRefreshSweepJob, every minute)" do
    it "schedules a flush for streams left pending with no marker" do
      PendingRefresh.insert_all([ { stream: TaskBroadcast::STREAM } ])
      expect(described_class.sweep).to be(true)
      expect(jobs.size).to eq(1)
      perform_enqueued_jobs
      expect(sent).to eq(TaskBroadcast::STREAM => 1)
    end

    it "takes over a marker whose flush never came, and leaves a fresh one alone" do
      PendingRefresh.insert_all([ { stream: TaskBroadcast::STREAM }, { stream: described_class::SCHEDULED } ])
      expect(described_class.sweep).to be(false)
      PendingRefresh.where(stream: described_class::SCHEDULED).update_all(requested_at: 2.minutes.ago)
      expect(captured_log { LiveRefreshSweepJob.perform_now }).to include("[live_refresh] sweep scheduled a flush for streams left pending")
      expect(jobs.size).to eq(1)
    end

    it "gives back the rows a flush took only once that flush no longer owns a live marker, and schedules their flush" do
      described_class.request(%w[a b])
      clear_enqueued_jobs
      described_class.own_and_take("~0badf00d:") # a flush took them, and is still sending (or has died)
      expect(described_class.sweep).to be(false) # its marker is fresh: it may still be sending
      expect(PendingRefresh.where("stream LIKE '~%'").count).to eq(2)

      PendingRefresh.where(stream: described_class::SCHEDULED).update_all(requested_at: 2.minutes.ago) # it never finished
      expect(described_class.sweep).to be(true)
      expect(PendingRefresh.where("stream LIKE '~%'")).to be_empty
      perform_enqueued_jobs
      expect(sent).to eq("a" => 1, "b" => 1)
    end

    it "gives back the rows of a flush whose marker someone else now holds" do
      described_class.request(%w[a])
      described_class.own_and_take("~0badf00d:")
      PendingRefresh.where(stream: described_class::SCHEDULED).update_all(requested_at: 1.second.from_now) # another stamp
      described_class.sweep
      expect(pending_refreshes).to eq(%w[a])
    end

    it "does nothing when nothing is pending" do
      PendingRefresh.insert_all([ { stream: described_class::SCHEDULED, requested_at: 2.minutes.ago } ])
      expect(described_class.sweep).to be(false)
      expect(jobs).to be_empty
    end
  end

  it "refuses a stream name too long to take, and reports it, writing nothing" do
    allow(Rails.error).to receive(:report)
    expect(PendingRefresh.columns_hash["stream"].limit).to eq(described_class::MAX_STREAM_LENGTH + "~0badf00d:".length)
    described_class.request([ "tasks", "x" * (described_class::MAX_STREAM_LENGTH + 1) ])
    expect(Rails.error).to have_received(:report).with(an_instance_of(ArgumentError), hash_including(handled: true))
    expect(PendingRefresh.count).to eq(0)
    described_class.request([ "x" * described_class::MAX_STREAM_LENGTH ])
    expect(described_class.flush).to eq([ "x" * described_class::MAX_STREAM_LENGTH ])
  end

  it "retries a failed flush 5 s apart, so the whole chain ends inside the marker's takeover age" do
    allow(Turbo::StreamsChannel).to receive(:broadcast_refresh_to).and_raise("down")
    described_class.request(%w[a])
    clear_enqueued_jobs
    freeze_time do
      LiveRefreshJob.perform_later
      ActiveJob::Base.execute(enqueued_jobs.pop)
      retry_at = Time.iso8601(enqueued_jobs.sole["scheduled_at"])
      expect(retry_at - Time.current).to be_within(1).of(5) # jitter
      expect((LiveRefreshJob::ATTEMPTS - 1) * 6).to be < (described_class.window + described_class::ABANDONED_AFTER).to_i
    end
  end

  describe "many hosts at once" do
    it "writes two rows, not one per host, for a change to more than #{LiveRefresh::FAN_OUT_LIMIT} hosts (review of #212)" do
      FleetBroadcast.hosts_changed((1..100_000).to_a)
      expect(pending_refreshes).to eq([ FleetBroadcast::STREAM, FleetBroadcast::ALL_HOSTS_STREAM ])
      expect(described_class.flush).to eq([ FleetBroadcast::STREAM, FleetBroadcast::ALL_HOSTS_STREAM ])
      expect(sent).to eq(FleetBroadcast::STREAM => 1, FleetBroadcast::ALL_HOSTS_STREAM => 1)
    end

    it "refreshes every host page once in place of more than #{LiveRefresh::FAN_OUT_LIMIT} host streams from many changes" do
      (1..(LiveRefresh::FAN_OUT_LIMIT + 1)).each { |id| FleetBroadcast.hosts_changed([ id ]) }
      expect(pending_refreshes.size).to eq(LiveRefresh::FAN_OUT_LIMIT + 2)
      expect(described_class.flush).to eq([ FleetBroadcast::STREAM, FleetBroadcast::ALL_HOSTS_STREAM ])
      expect(sent).to eq(FleetBroadcast::STREAM => 1, FleetBroadcast::ALL_HOSTS_STREAM => 1)
    end

    it "sends each host its own up to the limit" do
      FleetBroadcast.hosts_changed((1..LiveRefresh::FAN_OUT_LIMIT).to_a)
      described_class.flush
      expect(sent.keys).to include(FleetBroadcast.host_stream(1), FleetBroadcast.host_stream(LiveRefresh::FAN_OUT_LIMIT))
      expect(sent.size).to eq(LiveRefresh::FAN_OUT_LIMIT + 1)
      expect(sent).not_to have_key(FleetBroadcast::ALL_HOSTS_STREAM)
    end
  end

  # The pending streams and the marker are rows in the primary database. The test environment's cache is a null
  # store and production's is the Solid Cache database; neither is read or written.
  it "works without the cache" do
    expect(Rails.cache).to be_a(ActiveSupport::Cache::NullStore)
    no_cache = Class.new { def method_missing(name, *) = raise("the cache was used: #{name}") }.new
    allow(Rails).to receive(:cache).and_return(no_cache)
    host, = enrolled_host
    reset
    3.times { FleetBroadcast.hosts_changed([ host.id ]) }
    expect(jobs.size).to eq(1)
    perform_enqueued_jobs
    expect(sent).to eq(FleetBroadcast::STREAM => 1, FleetBroadcast.host_stream(host.id) => 1)
  end

  it "logs what each flush refreshed" do
    described_class.request((1..12).map { |i| format("s%02d", i) })
    expect(captured_log { LiveRefreshJob.perform_now }).to include("[live_refresh] refreshed 12 streams: s01,s02,s03,s04,s05,s06,s07,s08,s09,s10,...")
  end
end
