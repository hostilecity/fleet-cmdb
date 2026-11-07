# Display helpers for the Advisory data sources page and the import result (P2-D06, approved mockups
# data-sources.html and data-sources-import.html).
module DataSourcesHelper
  # "5 minutes": the manual refresh cool-down (P2-S15).
  def cooldown_words = human_duration(Advisories.config.refresh_cooldown.to_i)

  # "Available again in 4 minutes (last refresh 2026-11-07 08:01 UTC)." beside the disabled button.
  def refresh_available_text(at, last_attempt, now = Time.current)
    minutes = ((at - now) / 60.0).ceil
    left = minutes <= 1 ? "in less than a minute" : "in #{minutes} minutes"
    last = last_attempt ? " (last refresh #{utc(last_attempt.started_at)})" : ""
    "Available again #{left}#{last}."
  end

  # "Every 6 hours, up to 5 attempts with backoff".
  def feed_schedule_text(feed)
    return "Not scheduled in this environment; run bin/rails advisories:refresh" unless feed.schedule

    "Every #{human_duration(feed.schedule)}, up to #{feed.attempts} attempts with backoff"
  end

  def import_how(import) = import.origin == "file" ? "File upload" : "Feed refresh"

  def import_by(import) = import.operator&.display_name || "System"

  IMPORT_LAMPS = { "queued" => [ "Queued", "pending" ], "importing" => [ "Importing", "awaiting" ], "succeeded" => [ "Succeeded", "online" ],
                   "failed" => [ "Failed", "fail" ] }.freeze

  def import_result_lamp(import)
    word, lamp = IMPORT_LAMPS.fetch(import.state)
    tag.span(word, class: [ "lamp", lamp ])
  end

  # When an import finished, or, while it is in progress, when it was uploaded.
  def import_time(import) = import.finished_at || import.started_at

  # The counts that matter in one line: "38,412 records read: 6 new, 22 changed, 0 withdrawn", with a link to the
  # skipped records when some were malformed.
  def import_summary(import)
    counts = import.counts
    return link_to("Waiting to be imported", advisory_import_path(import)) if import.state == "queued"
    return link_to("Importing now", advisory_import_path(import)) if import.state == "importing"
    return "Nothing imported: #{import.reason}" if import.state == "failed"
    return "Not modified since the last download; nothing imported" if counts["not_modified"]

    read = "#{number_with_delimiter(counts['records'].to_i)} #{'record'.pluralize(counts['records'].to_i)} read: "
    malformed = counts["malformed"].to_i
    if malformed.positive?
      safe_join([ read, "#{number_with_delimiter(counts['records'].to_i - malformed)} imported, ",
                  link_to("#{number_with_delimiter(malformed)} malformed and skipped", advisory_import_path(import, anchor: "skipped")) ])
    else
      read + "#{number_with_delimiter(counts['created'].to_i)} new, #{number_with_delimiter(counts['updated'].to_i)} changed, " \
             "#{number_with_delimiter(import_withdrawn(import))} withdrawn"
    end
  end

  def import_withdrawn(import) = import.counts["withdrawn"].to_i + import.counts["absent"].to_i

  def import_type_text(import)
    import.full ? "Full import (advisories of its ecosystems that are not in the file are marked withdrawn)" : "Partial import (advisories not in the file are left alone)"
  end
end
