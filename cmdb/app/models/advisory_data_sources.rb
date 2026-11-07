require "fugit" # Solid Queue's own parser for config/recurring.yml schedules

# What the Advisory data sources page shows (P2-D06, FR-2.4; approved mockups data-sources.html and
# data-sources-stale.html): freshness and advisory counts per ecosystem, the scheduled feed as the server is
# configured (its host and path only: never the token, never a query string, which could carry a key), whether
# "Refresh now" can be used, and the recent imports. Every count is aggregated in the database.
class AdvisoryDataSources
  RECENT_IMPORTS = 10

  Ecosystem = Data.define(:status, :name, :current, :withdrawn, :hosts)
  # source: host and path, or nil when no feed is configured. schedule: the refresh interval in seconds, or nil
  # when this environment does not schedule it.
  FeedInfo = Data.define(:source, :schedule, :attempts, :max_age, :token)

  def initialize(now: Time.current)
    @now = now
  end

  def statuses = @statuses ||= Advisories::Freshness.statuses(now: @now)

  def ecosystems
    counts = AdvisoryPackage.joins(:advisory).group(:ecosystem, Arel.sql("advisories.withdrawn_at IS NULL")).distinct.count(:advisory_id)
    hosts = Ecosystems.host_counts
    statuses.map do |status|
      e = status.ecosystem
      Ecosystem.new(status:, name: Ecosystems.name(e), current: counts.fetch([ e, true ], 0), withdrawn: counts.fetch([ e, false ], 0), hosts: hosts.fetch(e, 0))
    end
  end

  def feed
    config = Advisories.config
    FeedInfo.new(source: config.feed_url && Advisories::Feed.new.source, schedule: self.class.schedule_interval,
                 attempts: ApplicationJob::ATTEMPTS, max_age: config.max_age, token: config.feed_token.present?)
  end

  def feed_configured? = !Advisories.config.feed_url.nil?

  # When "Refresh now" can next be used, or nil when it can now.
  def refresh_allowed_at = feed_configured? ? Advisories::ManualRefresh.next_allowed_at(now: @now) : nil

  def last_attempt = Advisories::ManualRefresh.last_attempt

  # Imports in progress first (no finished_at yet), then the newest.
  def imports = AdvisoryImport.includes(:operator).order(Arel.sql("finished_at DESC NULLS FIRST"), id: :desc).limit(RECENT_IMPORTS).to_a

  # How many feed refreshes in a row have failed since the last one that succeeded, for the stale notice.
  def failed_refreshes
    last_success = AdvisoryImport.succeeded.where(origin: "feed").maximum(:finished_at)
    scope = AdvisoryImport.where(origin: "feed", state: "failed")
    (last_success ? scope.where(AdvisoryImport.arel_table[:finished_at].gt(last_success)) : scope).count
  end

  # Seconds between two runs of the scheduled refresh in config/recurring.yml for this environment, or nil.
  def self.schedule_interval
    schedule = YAML.safe_load_file(Rails.root.join("config/recurring.yml")).dig(Rails.env, "advisory_feed_refresh", "schedule")
    cron = schedule && (Fugit.parse_cron(schedule) || Fugit.parse_nat(schedule))
    return nil unless cron

    first = cron.next_time(Time.utc(2026, 1, 1))
    (cron.next_time(first).to_t - first.to_t).round
  end
end
