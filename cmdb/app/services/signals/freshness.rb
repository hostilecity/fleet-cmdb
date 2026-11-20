module Signals
  # How old each exploitation signal's stored data is (VT-S02, VT-S03), as P2-S16's freshness: stale past
  # FLEET_SIGNAL_MAX_AGE_HOURS (168). Staleness is only shown: rules keep using the stored data whatever its age, and
  # nothing is rewritten when a source goes stale or recovers (B1, S3).
  #
  # A source is as fresh as its last successful import, a "not modified" answer included. A held-back or failed import
  # stores nothing, so it does not refresh it. KEV data cleared by bin/rails signals:kev_clear reads as never imported
  # until an import stores it again. EPSS is also stale when the stored score date is older than the age limit, since a
  # source that stops publishing can still answer "not modified".
  module Freshness
    # updated_at: the last successful import (nil: never imported). version: KEV's catalog version or EPSS's model
    # version; score_date: EPSS's. configured: the URL setting is set (false: turned off, its last data kept).
    Status = Data.define(:signal, :updated_at, :stale, :version, :score_date, :configured) do
      def never? = updated_at.nil?
      def off? = !configured
    end

    module_function

    def status(signal, now: Time.current, max_age: Signals.config.max_age) = statuses(now:, max_age:).find { |status| status.signal == signal }

    # Both signals' Status, in one query (the freshness line is on every fleet and host page): each signal's newest
    # successful import after its last clear.
    def statuses(now: Time.current, max_age: Signals.config.max_age)
      rows = SignalImport.connection.select_rows(<<~SQL.squish).to_h { |signal, *rest| [ signal, rest ] }
        SELECT v.signal, l.finished_at, l.version, l.score_date
        FROM (VALUES ('#{KEV}'), ('#{EPSS}')) AS v(signal)
        CROSS JOIN LATERAL (
          SELECT s.finished_at, s.version, s.score_date FROM signal_imports s
          WHERE s.signal = v.signal AND s.state = 'succeeded'
            AND s.finished_at > coalesce((SELECT max(c.finished_at) FROM signal_imports c WHERE c.signal = v.signal AND c.state = 'cleared'), '-infinity')
          ORDER BY s.finished_at DESC, s.id DESC LIMIT 1) AS l
      SQL
      [ KEV, EPSS ].map { |signal| build(signal, *rows[signal], now:, max_age:) }
    end

    def build(signal, finished_at = nil, version = nil, score_date = nil, now:, max_age:)
      configured = !Signals.url_for(signal).nil?
      return Status.new(signal:, updated_at: nil, stale: true, version: nil, score_date: nil, configured:) unless finished_at

      finished_at = SignalImport.type_for_attribute(:finished_at).deserialize(finished_at)
      score_date = SignalImport.type_for_attribute(:score_date).deserialize(score_date)
      old_scores = score_date && score_date.end_of_day < now - max_age
      Status.new(signal:, updated_at: finished_at, stale: finished_at < now - max_age || old_scores || false, version:, score_date:, configured:)
    end
    private_class_method :build

    # The score date of the stored EPSS scores: the newest successful import's since the last reset, or nil. A file older
    # than it is refused (Signals::EpssImport::Older).
    def stored_score_date
      cleared = SignalImport.epss.where(state: "cleared").maximum(:finished_at)
      scope = SignalImport.epss.succeeded
      scope = scope.where(SignalImport.arel_table[:finished_at].gt(cleared)) if cleared
      scope.maximum(:score_date)
    end

    # Whether KEV data is stored (imported at least once and not cleared since), which rule I5 needs (VT-M1).
    def kev_imported? = KevEntry.exists?

    # The newest held-back import when no import has succeeded since, or nil.
    def held_import(signal)
      last_success = SignalImport.where(signal:).succeeded.maximum(:finished_at)
      held = SignalImport.where(signal:, state: "held_back")
      held = held.where(SignalImport.arel_table[:finished_at].gt(last_success)) if last_success
      held.order(finished_at: :desc, id: :desc).first
    end

    # Scheduled refreshes that failed since the last success.
    def failed_refreshes(signal)
      last = SignalImport.where(signal:).succeeded.maximum(:finished_at)
      scope = SignalImport.where(signal:, origin: "feed", state: "failed")
      (last ? scope.where(SignalImport.arel_table[:finished_at].gt(last)) : scope).count
    end
  end
end
