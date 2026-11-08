module DebianTriage
  # How old each release's Debian triage is (P2-S16), apart from OSV's freshness: its own last success, stale past
  # FLEET_ADVISORY_MAX_AGE_HOURS (Advisories.config.max_age), as OSV data is.
  #
  # A release is as fresh as the last import that stored its data: a successful one, a held-back one for the
  # releases it did store, or a refresh the tracker answered "not modified". A release a held-back import kept
  # back is not refreshed by it, so it goes stale if that continues. A release an import later dropped (no active
  # host reported it; removed_releases) is never imported again until an import stores it, so a host that starts
  # reporting it reads "not imported yet", not a stale or an empty result.
  module Freshness
    Status = Data.define(:release, :updated_at, :stale) do
      def never? = updated_at.nil?
    end

    module_function

    # One Status per release in the release table, in one query.
    def statuses(now: Time.current, max_age: Advisories.config.max_age)
      latest = TriageImport.debian.stored
                           .from("triage_imports CROSS JOIN LATERAL (SELECT unnest(triage_imports.releases) AS release, 'stored' AS kind " \
                                 "UNION ALL SELECT unnest(triage_imports.removed_releases), 'removed') AS r")
                           .group("r.release", "r.kind").maximum(:finished_at)
      updated = latest.filter_map { |(release, kind), at| [ release, at ] if kind == "stored" }.to_h
      removed = latest.filter_map { |(release, kind), at| [ release, at ] if kind == "removed" }.to_h
      Releases.names.map do |release|
        at = updated[release]
        at = nil if at && removed[release] && removed[release] >= at
        Status.new(release:, updated_at: at, stale: at.nil? || at < now - max_age)
      end
    end

    # The newest held-back import when no import has fully succeeded since, or nil: some release is keeping its
    # previous data, for the data sources page (P2-D08).
    def held_import
      last_success = TriageImport.debian.where(state: "succeeded").maximum(:finished_at)
      held = TriageImport.debian.where(state: "held_back")
      held = held.where(TriageImport.arel_table[:finished_at].gt(last_success)) if last_success
      held.order(finished_at: :desc, id: :desc).first
    end
  end
end
