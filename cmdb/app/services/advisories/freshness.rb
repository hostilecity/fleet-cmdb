module Advisories
  # How old each ecosystem's advisory data is (P2-S13). Stale data fails silently, reporting no findings while
  # advisories are weeks old, so the dashboard warns when it is older than Advisories.config.max_age.
  #
  # Data is as fresh as the last successful full import with records for the ecosystem: the scheduled refresh,
  # including one the feed answered "not modified", or a complete archive imported by hand with FULL=1. A
  # partial import (one advisory file) adds data but does not make the rest current, so it does not count.
  module Freshness
    Status = Data.define(:ecosystem, :updated_at, :stale) do
      def never? = updated_at.nil?
    end

    module_function

    # One Status per fleet ecosystem, in one query.
    def statuses(now: Time.current, max_age: Advisories.config.max_age)
      updated = AdvisoryImport.succeeded.where(full: true)
                              .from("advisory_imports, unnest(advisory_imports.ecosystems) AS ecosystem")
                              .group("ecosystem").maximum(:finished_at)
      Ecosystems.supported.map do |ecosystem|
        at = updated[ecosystem]
        Status.new(ecosystem:, updated_at: at, stale: at.nil? || at < now - max_age)
      end
    end

    def stale?(**) = statuses(**).any?(&:stale)

    # The newest feed refresh the withdrawal guard refused, when no feed refresh has succeeded since and no
    # operator has confirmed it, or nil (review of #129). The data stays as it was, so it may be going stale:
    # the freshness notice says so on every page that shows it.
    def held_refresh
      last_success = AdvisoryImport.succeeded.where(origin: "feed").maximum(:finished_at)
      refused = AdvisoryImport.where(origin: "feed", state: "failed").where("counts ? 'would_withdraw'").where.not("counts ? 'confirmed_at'")
      refused = refused.where(AdvisoryImport.arel_table[:finished_at].gt(last_success)) if last_success
      refused.order(finished_at: :desc, id: :desc).first
    end
  end
end
