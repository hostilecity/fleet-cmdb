module Advisories
  # The cool-down on an operator's "Refresh now" for the advisory feed (P2-S15, FR-2.4): a manual refresh is
  # refused while the last refresh attempt of any kind, manual, scheduled, or the rake task, started less than
  # Advisories.config.refresh_cooldown ago (FLEET_ADVISORY_REFRESH_COOLDOWN, 300 seconds by default).
  #
  # - request! is the action behind the dashboard button (P2-D06). Accepted, it records a manual attempt,
  #   audits advisory.refresh_requested with the operator as actor, and enqueues AdvisoryFeedRefreshJob, the
  #   job the schedule runs, once the transaction commits. Refused, it audits advisory.refresh_refused with the
  #   time a refresh is next allowed, and writes nothing else.
  # - next_allowed_at is when request! would next accept, or nil when it would now; the dashboard reads it to
  #   disable the button with the time left. last_attempt is the newest attempt, for "last refresh at".
  # - record_start! is called by AdvisoryFeedRefreshJob when a scheduled run or the rake task starts. Neither
  #   is ever refused, but each counts as the last attempt, so the next manual refresh waits for the cool-down.
  #
  # Concurrency: every read-then-write runs under one transaction-scoped advisory lock (LOCK_KEY). Two operators
  # clicking together are serialised: the second request reads the first one's attempt, committed, and is
  # refused, so exactly one job starts. An advisory lock rather than a row lock, because there may be no row to
  # lock yet (the first refresh ever) and a singleton row would need seeding; rather than a unique constraint,
  # because "younger than the cool-down" is a time window, not a value an index can make unique. Under READ
  # COMMITTED each statement sees what was committed before it began, and the lock is taken by a statement of
  # its own before the read, so the read always sees the attempt of whoever held the lock before.
  module ManualRefresh
    LOCK_KEY = "advisories.refresh_attempt".freeze

    # No feed is configured (FLEET_ADVISORY_FEED_URL is empty), so there is nothing to refresh. Nothing is
    # recorded or audited: the dashboard does not offer the button then.
    class NotConfigured < StandardError; end

    # accepted: whether a refresh was started. attempt: the manual attempt recorded (nil when refused).
    # next_allowed_at: when a manual refresh is next allowed (after this one, when accepted).
    Result = Data.define(:accepted, :attempt, :next_allowed_at) do
      def accepted? = accepted
      def refused? = !accepted
    end

    module_function

    def cooldown = Advisories.config.refresh_cooldown

    # actor: the Operator who clicked. Raises NotConfigured when no feed is configured.
    def request!(actor:, now: Time.current)
      raise NotConfigured, "no advisory feed is configured (FLEET_ADVISORY_FEED_URL)" if Advisories.config.feed_url.nil?

      AdvisoryRefreshAttempt.transaction do
        lock!
        if (next_at = next_allowed_at(now:))
          Audit.record(actor:, action: Audit::Actions::ADVISORY_REFRESH_REFUSED, changes: { "next_allowed_at" => next_at.utc.iso8601 })
          next Result.new(accepted: false, attempt: nil, next_allowed_at: next_at)
        end

        attempt = AdvisoryRefreshAttempt.create!(kind: "manual", operator: actor, started_at: now)
        next_at = now + cooldown
        Audit.record(actor:, action: Audit::Actions::ADVISORY_REFRESH_REQUESTED,
                     changes: { "source" => Feed.new.source, "next_allowed_at" => next_at.utc.iso8601 })
        ActiveRecord.after_all_transactions_commit { AdvisoryFeedRefreshJob.perform_later(attempt_id: attempt.id) }
        Result.new(accepted: true, attempt:, next_allowed_at: next_at)
      end
    end

    # An operator's confirmation of a feed refresh the withdrawal guard refused (review of #129): downloads the
    # feed again, as the same job, allowed to withdraw at most the refused counts per ecosystem. Not limited by
    # the cool-down, since it answers one refusal and can be used once: the refusal is marked confirmed under the
    # lock. Records a manual attempt (so the next "Refresh now" waits for the cool-down), audits
    # advisory.withdrawals_confirmed with the counts, and returns the attempt; nil when it was confirmed already.
    # The archive is downloaded again rather than kept (a full archive is larger than the upload store holds); the
    # new download is held to the confirmed counts, so an archive that would withdraw more is refused again.
    def confirm_withdrawals!(actor:, refused:, now: Time.current)
      raise NotConfigured, "no advisory feed is configured (FLEET_ADVISORY_FEED_URL)" if Advisories.config.feed_url.nil?

      AdvisoryRefreshAttempt.transaction do
        lock!
        refused.lock!
        withdrawals = refused.counts["would_withdraw"]
        next nil unless refused.origin == "feed" && refused.state == "failed" && withdrawals.is_a?(Hash) && withdrawals.any? && !refused.counts["confirmed_at"]

        allowed = withdrawals.transform_values { |w| w["withdraw"].to_i }
        refused.update!(counts: refused.counts.merge("confirmed_at" => now.utc.iso8601, "confirmed_by" => actor.id))
        attempt = AdvisoryRefreshAttempt.create!(kind: "manual", operator: actor, started_at: now)
        Audit.record(actor:, action: Audit::Actions::ADVISORY_WITHDRAWALS_CONFIRMED, target: refused,
                     changes: { "source" => refused.source, "refused_import_id" => refused.id, "withdrawals" => allowed })
        ActiveRecord.after_all_transactions_commit { AdvisoryFeedRefreshJob.perform_later(attempt_id: attempt.id, allowed_withdrawals: allowed) }
        attempt
      end
    end

    # When a manual refresh is next allowed, or nil when it is allowed now. Reads only.
    def next_allowed_at(now: Time.current)
      last = AdvisoryRefreshAttempt.maximum(:started_at)
      at = last && last + cooldown
      at if at && at > now
    end

    def last_attempt = AdvisoryRefreshAttempt.includes(:operator).order(started_at: :desc, id: :desc).first

    # Records that a scheduled run or the rake task started (kind "scheduled" or "task"). Never refused; taken
    # under the same lock so a manual request at the same moment sees it.
    def record_start!(kind:, now: Time.current)
      raise ArgumentError, "use request! for a manual refresh" if kind == "manual"

      AdvisoryRefreshAttempt.transaction do
        lock!
        AdvisoryRefreshAttempt.create!(kind:, started_at: now)
      end
    end

    def lock!
      connection = AdvisoryRefreshAttempt.connection
      connection.execute("SELECT pg_advisory_xact_lock(hashtext(#{connection.quote(LOCK_KEY)}))")
    end
    private_class_method :lock!
  end
end
