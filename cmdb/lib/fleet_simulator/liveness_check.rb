module FleetSimulator
  # AC-1.2 scaled down, with the real timers: the thresholds are set to their minimum (online 1 minute, stale 2),
  # one simulated host goes silent, and the scheduled LivenessEvaluationJob must move it to stale and then to
  # offline; when it resumes, its next heartbeat must bring it back online. Each step has a deadline of its
  # threshold plus two evaluation periods. The previous thresholds are restored afterwards.
  #
  # Driven by #poll, every few seconds, while the runner keeps the rest of the fleet reporting.
  class LivenessCheck
    THRESHOLDS = { online_minutes: 1, stale_minutes: 2 }.freeze
    # One evaluation period (the job runs every minute) and a minute's margin for a busy machine.
    SLACK = 120

    attr_reader :host, :state, :log

    def initialize(host:)
      @host = host
      @state = :idle
      @log = []
    end

    def prepare!
      @previous = Setting.liveness_thresholds.transform_values { |value| (value / 60).to_i }
      Setting.update_liveness_thresholds!(**THRESHOLDS, actor: Audit::SYSTEM)
    end

    def restore!
      return unless @previous

      Setting.update_liveness_thresholds!(online_minutes: @previous[:online], stale_minutes: @previous[:stale], actor: Audit::SYSTEM)
    end

    def silence!(now)
      @host.silent_at = now
      @silenced_at = now
      step!(:awaiting_stale, now, "#{@host.name} stopped heartbeating")
    end

    # Advances when the transition it is waiting for has been recorded, and fails past its deadline. Returns the
    # state: :awaiting_stale, :awaiting_offline, :awaiting_online, :passed, or :failed.
    def poll(now)
      case @state
      when :awaiting_stale then await("stale", "evaluation", @silenced_at + 60 * THRESHOLDS[:online_minutes] + SLACK, now) { step!(:awaiting_offline, now, "turned stale") }
      when :awaiting_offline then await("offline", "evaluation", @silenced_at + 60 * THRESHOLDS[:stale_minutes] + SLACK, now) { resume!(now) }
      when :awaiting_online then await("online", "heartbeat", @resumed_at + 2 * @host.heartbeat_interval + 30, now) { step!(:passed, now, "back online") }
      end
      @state
    end

    def finished? = @state.in?(%i[passed failed])

    private

    def resume!(now)
      step!(:awaiting_online, now, "turned offline; resuming heartbeats")
      @resumed_at = now
      @host.resume!
      @host.next_heartbeat_at = now
    end

    def await(status, reason, deadline, now)
      since = @state == :awaiting_online ? @resumed_at : @silenced_at
      # Uncached: the job writes from another process, which never clears this process's query cache.
      event = HostStatusEvent.uncached do
        # Bounded by the deadline, so a late transition fails rather than passing on a later poll.
        HostStatusEvent.where(host_id: @host.host_id, to_status: status, reason:).where(occurred_at: since..deadline).order(:occurred_at).first
      end
      if event
        @log << "#{status} recorded at #{event.occurred_at.utc.iso8601} (#{(event.occurred_at - since).round}s after #{since == @silenced_at ? 'going silent' : 'resuming'})"
        yield
      elsif now > deadline
        step!(:failed, now, "no #{status} transition by #{deadline.utc.iso8601}: is the LivenessEvaluationJob running (bin/dev runs it)?")
      end
    end

    def step!(state, now, message)
      @state = state
      @log << "#{now.utc.iso8601} #{message}"
    end
  end
end
