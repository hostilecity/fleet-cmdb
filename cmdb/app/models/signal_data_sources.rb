require "fugit" # Solid Queue's own parser for config/recurring.yml schedules

# What the Data sources page shows of the exploitation signals (VT-D03, ADR 0032; approved mockup
# docs/mockups/vuln-triage/data-sources.html): one panel each for CISA KEV and FIRST EPSS with freshness, the entries
# kept and how many match open findings, the source as configured (host and path only), the held-back state, and the
# latest imports. Every count is aggregated in the database. No upload and no button of its own: the advisory feed's
# "Refresh now" refreshes both (Advisories::ManualRefresh).
class SignalDataSources
  RECENT_IMPORTS = 5
  SCHEDULE_KEYS = { Signals::KEV => "kev_refresh", Signals::EPSS => "epss_refresh" }.freeze

  # One panel. status: Signals::Freshness::Status. entries: stored rows; matching: KEV entries naming an open finding
  # (nil for EPSS, whose panel counts only the high band's); high: EPSS scores in the high band (nil for KEV);
  # high_matching: those naming an open finding. latest: the last
  # import that stored data (its counts say what changed). held: the newest held-back import while it is the latest.
  Panel = Data.define(:signal, :status, :source, :entries, :matching, :high, :high_matching, :latest, :held, :failed, :imports, :next_refresh) do
    def configured? = status.configured
    def kev? = signal == Signals::KEV
  end

  def initialize(now: Time.current)
    @now = now
  end

  def kev = @kev ||= panel(Signals::KEV, KevEntry)

  def epss = @epss ||= panel(Signals::EPSS, EpssScore)

  def panels = [ kev, epss ]

  # When the signal's scheduled refresh runs next, or nil when this environment does not schedule it.
  def self.next_refresh(signal, now = Time.current)
    cron = TriageDataSources.recurring_jobs.dig(SCHEDULE_KEYS.fetch(signal), "schedule")
    parsed = cron && (Fugit.parse_cron(cron) || Fugit.parse_nat(cron))
    parsed&.next_time(now)&.to_t
  end

  private

  def panel(signal, model)
    status = Signals::Freshness.status(signal, now: @now)
    kev = signal == Signals::KEV
    high = kev ? nil : EpssScore.where(band: "high").count
    Panel.new(signal:, status:, source: (Signals.feed_for(signal).source if status.configured), entries: model.count,
              matching: (Signals.matching_open_findings("SELECT cve_id FROM kev_entries") if kev),
              high:, high_matching: (Signals.matching_open_findings("SELECT cve_id FROM epss_scores WHERE band = 'high'") if high),
              latest: SignalImport.where(signal:).succeeded.where("counts ->> 'not_modified' IS NULL").order(finished_at: :desc, id: :desc).first,
              held: Signals::Freshness.held_import(signal), failed: Signals::Freshness.failed_refreshes(signal),
              imports: SignalImport.where(signal:).includes(:operator).order(finished_at: :desc, id: :desc).limit(RECENT_IMPORTS).to_a,
              next_refresh: self.class.next_refresh(signal, @now))
  end
end
