# The exploitation signals on the Data sources page and in the freshness line (VT-D03, ADR 0032; approved mockup
# docs/mockups/vuln-triage/data-sources.html). Stale or turned-off data is still used by the triage rules (B1), so the
# words say "out of date" or "turned off" and that the last data is kept, never that it is gone. Every value from a feed
# (catalog and model versions, sources, reasons) is text, escaped by Rails.
#
# Every method is prefixed signal_, since Rails includes every helper in every view.
module SignalsHelper
  SIGNAL_NAMES = { Signals::KEV => "Known exploited (CISA KEV)", Signals::EPSS => "Exploit prediction (FIRST EPSS)" }.freeze
  SIGNAL_LAMPS = { "succeeded" => [ "Imported", "online" ], "held_back" => [ "Held back", "stale" ], "failed" => [ "Failed", "fail" ],
                   "cleared" => [ "Cleared", "stale" ] }.freeze

  def signal_name(signal) = SIGNAL_NAMES.fetch(signal)

  # The age limit in words: "7 days" when it is a whole number of days, as the mockup says, otherwise hours.
  def signal_hours
    hours = (Signals.config.max_age / 1.hour).round
    (hours % 24).zero? ? pluralize(hours / 24, "day") : pluralize(hours, "hour")
  end

  # The freshness line on host, fleet, and Compliance pages and the data sources page: one sentence per signal.
  def signal_freshness_line(statuses = Signals::Freshness.statuses)
    safe_join(statuses.map { |status| tag.span(signal_freshness_text(status), class: ("stale-word" if status.stale && !status.never?)) }, " ")
  end

  # "Known exploited (CISA KEV): 5 hours ago." / "Exploit prediction (FIRST EPSS): scores of 2026-11-19."
  def signal_freshness_text(status)
    name = signal_name(status.signal)
    if status.off? && status.never? then "#{name}: turned off on this server, never imported."
    elsif status.off? && status.stale then "#{name}: turned off on this server; the last data, #{signal_when(status)}, is out of date and still used."
    elsif status.off? then "#{name}: turned off on this server; the last data, #{signal_when(status)}, is kept and still used."
    elsif status.never? then "#{name}: not imported yet."
    elsif status.stale then "#{name}: out of date (#{signal_when(status)}); still used until refreshed."
    else "#{name}: #{signal_when(status)}."
    end
  end

  # "5 hours ago", or EPSS's "scores of 2026-11-19".
  def signal_when(status) = status.score_date ? "scores of #{status.score_date.iso8601}" : seen_ago(status.updated_at)

  # The panel's freshness value: a lamp and the details.
  def signal_freshness_value(panel)
    status = panel.status
    lamp = if status.never? then tag.span("Never imported", class: "stale-word")
    elsif status.stale then tag.span("Out of date: older than #{signal_hours}", class: "stale-word")
    else tag.span("Up to date", class: "lamp online")
    end
    return lamp if status.never?

    version = status.version && (panel.kev? ? "catalog version #{status.version}" : "model #{status.version}")
    details = [ "last success #{seen_ago(status.updated_at)}", (status.score_date && "scores of #{status.score_date.iso8601}"), version ].compact
    safe_join([ lamp, " · ", details.join(", ") ])
  end

  # "of which 3 match open findings in this fleet (counted 5 hours ago, after the last import)", or why it is not known.
  def signal_matching_text(panel)
    matching = panel.matching
    return "none matching open findings" if panel.entries.zero?
    return "how many match open findings is not counted yet" if matching.nil?

    counted = panel.matching_at ? " (counted #{seen_ago(panel.matching_at)}, after the last import)" : ""
    "of which #{number_with_delimiter(matching)} #{matching == 1 ? 'matches' : 'match'} open findings in this fleet#{counted}"
  end

  # A CVSS v3 vector's parts in words (VT-S04, epic N7): "network, no login, no user action". nil without a vector. The
  # host tab (#260) shows it with the vector as secondary text.
  SIGNAL_VECTOR_WORDS = {
    av: { "N" => "network", "A" => "adjacent network", "L" => "local", "P" => "physical access" },
    pr: { "N" => "no login", "L" => "a low-privilege login", "H" => "an administrator login" },
    ui: { "N" => "no user action", "R" => "a user's action" }
  }.freeze

  def signal_vector_words(advisory)
    return nil unless advisory.cvss_av

    [ SIGNAL_VECTOR_WORDS[:av][advisory.cvss_av], SIGNAL_VECTOR_WORDS[:pr][advisory.cvss_pr], SIGNAL_VECTOR_WORDS[:ui][advisory.cvss_ui] ].join(", ")
  end

  def signal_import_lamp(import)
    word, lamp = import.not_modified? ? [ "Not modified", "online" ] : SIGNAL_LAMPS.fetch(import.state, [ import.state.humanize, "pending" ])
    tag.span(word, class: [ "lamp", lamp ])
  end

  def signal_import_how(import)
    if import.origin == "file" then "File import on the server"
    elsif import.origin == "task" then "bin/rails signals:kev_clear"
    elsif import.operator_id then "Refresh now, after the advisory feed"
    else "Scheduled refresh"
    end
  end

  def signal_import_by(import) = import.operator&.display_name || "System"

  # What an import changed, in a few words.
  def signal_import_summary(import)
    counts = import.counts
    return "Nothing imported: #{import.reason}" if import.state == "failed"
    return "Nothing downloaded" if import.not_modified?
    return "Entries deleted (#{number_with_delimiter(counts['deleted'].to_i)}): rules N1 and I5 stop applying until KEV is imported again" if import.state == "cleared"
    if import.state == "held_back"
      what = import.signal == Signals::KEV ? "entries" : "scores"
      return "Held back: it would remove #{number_with_delimiter(counts['removed'] || counts['dropped'])} of #{number_with_delimiter(counts['stored'])} stored #{what}"
    end

    parts = import.signal == Signals::KEV ? signal_kev_changes(counts) : signal_epss_changes(counts)
    parts << "#{number_with_delimiter(counts['malformed'])} malformed" if counts["malformed"].to_i.positive?
    parts.join("; ")
  end

  private

  def signal_kev_changes(counts)
    added = "#{number_with_delimiter(counts['added'].to_i)} added"
    added += " (#{counts['added_matching']} #{counts['added_matching'] == 1 ? 'matches' : 'match'} open findings: handed to triage)" if counts["added_matching"].to_i.positive?
    [ added, "#{number_with_delimiter(counts['removed'].to_i)} removed", "#{number_with_delimiter(counts['in_file'].to_i)} in the catalog" ]
  end

  def signal_epss_changes(counts)
    [ "#{number_with_delimiter(counts['kept'].to_i)} kept of #{number_with_delimiter(counts['rows'].to_i)} rows",
      "#{number_with_delimiter(counts['rose'].to_i)} rose to #{signal_percent(Signals.config.epss_enter)} or more",
      "#{number_with_delimiter(counts['fell'].to_i)} fell below #{signal_percent(Signals.config.epss_leave)}" ]
  end

  def signal_percent(share) = "#{(share * 100).round(1).to_s.delete_suffix('.0')}%"
end
