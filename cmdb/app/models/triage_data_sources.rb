require "fugit" # Solid Queue's own parser for config/recurring.yml schedules

# What the Advisory data sources page shows of the Debian Security Tracker (P2-D08, ADR 0022; approved mockups
# data-sources.html#tracker, data-sources-stale.html, data-sources-held.html, owner decisions T2, T4, T8 on #134):
# the releases the fleet's active hosts use, with their freshness, entry counts, and host counts; the source as
# configured (host and path only); the newest held-back import while it is the latest; and the recent imports.
# Every count is aggregated in the database. It has no upload and no button of its own: the advisory feed's
# "Refresh now" refreshes it right after OSV (Advisories::ManualRefresh).
class TriageDataSources
  RECENT_IMPORTS = 10
  SCHEDULE_KEY = "debian_triage_refresh".freeze

  # status: DebianTriage::Freshness::Status. name: "Debian 13". ecosystem: the OSV ecosystem of the same release,
  # or nil. held: the latest held-back import kept this release's previous data.
  Release = Data.define(:status, :name, :ecosystem, :hosts, :entries, :open, :no_dsa, :postponed, :ignored, :held) do
    def release = status.release
  end

  def initialize(now: Time.current)
    @now = now
  end

  def configured? = !DebianTriage.config.tracker_url.nil?

  # The tracker's host and path, never a query string; nil when the refresh is off.
  def source = configured? ? DebianTriage.feed.source : nil

  def statuses = @statuses ||= DebianTriage::Freshness.statuses(now: @now)

  # The newest held-back import when no import has fully succeeded since (T4), or nil.
  def held_import = defined?(@held_import) ? @held_import : (@held_import = DebianTriage::Freshness.held_import)

  # The releases in the release table that active hosts use, by name.
  def releases
    @releases ||= begin
      hosts = host_counts
      used = statuses.select { |status| hosts[status.release].to_i.positive? }
      counts = entry_counts(used.map(&:release))
      held = held_import&.counts&.fetch("releases", {}) || {}
      used.map do |status|
        id, version_id = release_os(status.release)
        entries, open, no_dsa, postponed, ignored = counts.fetch(status.release, [ 0, 0, 0, 0, 0 ])
        Release.new(status:, name: [ id.to_s.capitalize, version_id ].compact.join(" "), ecosystem: Ecosystems::TABLE[[ id, version_id.to_s ]],
                    hosts: hosts[status.release], entries:, open:, no_dsa:, postponed:, ignored:,
                    held: held.dig(status.release, "outcome") == "held_back")
      end
    end
  end

  # Imports in the order they finished, newest first.
  def imports = TriageImport.debian.includes(:operator).order(finished_at: :desc, id: :desc).limit(RECENT_IMPORTS).to_a

  # How many scheduled refreshes in a row have failed since the last import that stored data, for the stale notice.
  def failed_refreshes
    last = TriageImport.debian.stored.maximum(:finished_at)
    scope = TriageImport.debian.where(origin: "feed", state: "failed")
    (last ? scope.where(TriageImport.arel_table[:finished_at].gt(last)) : scope).count
  end

  # [seconds between two scheduled runs, seconds after the advisory feed's run], or nil when this environment does
  # not schedule it.
  def self.schedule
    triage, osv = crons
    return nil unless triage

    first = triage.next_time(Time.utc(2026, 1, 1))
    interval = (triage.next_time(first).to_t - first.to_t).round
    after = osv && ((first.to_t - osv.next_time(Time.utc(2026, 1, 1)).to_t).round % interval)
    [ interval, after ]
  end

  # When the scheduled refresh runs next, for "Next refresh in about 4 hours" (#148), or nil when this environment
  # does not schedule it.
  def self.next_refresh(now = Time.current) = crons.first&.next_time(now)&.to_t

  # This environment's recurring jobs, from config/recurring.yml.
  def self.recurring_jobs = YAML.safe_load_file(Rails.root.join("config/recurring.yml")).fetch(Rails.env, nil) || {}

  # [the tracker refresh's schedule, the advisory feed's], each nil when this environment does not schedule it.
  def self.crons
    jobs = recurring_jobs
    [ SCHEDULE_KEY, "advisory_feed_refresh" ].map { |key| (cron = jobs.dig(key, "schedule")) && (Fugit.parse_cron(cron) || Fugit.parse_nat(cron)) }
  end
  private_class_method :crons

  private

  # Active hosts (the set Compliance lists) per release in the release table, counted in the database.
  def host_counts
    os_id = Arel.sql("lower(host_inventories.stable -> 'os' ->> 'id')")
    version = Arel.sql("host_inventories.stable -> 'os' ->> 'version_id'")
    HostInventory.joins(:host).merge(Host.active).group(os_id, version).count.each_with_object(Hash.new(0)) do |((id, version_id), count), hosts|
      release = DebianTriage::Releases.for_os("id" => id, "version_id" => version_id)
      hosts[release] += count if release
    end
  end

  # release => [entries, open, open with a plain no-DSA note, postponed, ignored], in one query.
  def entry_counts(releases)
    return {} if releases.empty?

    open = "status = 'open'"
    TriageEntry.where(tracker: DebianTriage::TRACKER, release: releases).group(:release)
               .pluck(:release, Arel.sql("count(*)"), Arel.sql("count(*) FILTER (WHERE #{open})"),
                      Arel.sql("count(*) FILTER (WHERE #{open} AND no_dsa AND coalesce(no_dsa_reason, '') NOT IN ('postponed', 'ignored'))"),
                      Arel.sql("count(*) FILTER (WHERE #{open} AND no_dsa_reason = 'postponed')"), Arel.sql("count(*) FILTER (WHERE #{open} AND no_dsa_reason = 'ignored')"))
               .to_h { |release, *counts| [ release, counts ] }
  end

  # The [os id, version_id] a release is mapped from (the first row of the release table that names it).
  def release_os(release) = DebianTriage::Releases.table.key(release) || [ nil, nil ]
end
