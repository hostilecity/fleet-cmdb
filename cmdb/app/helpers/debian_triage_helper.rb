# Debian's triage beside a finding (P2-D08, FR-2.4, FR-2.5, ADR 0022; approved mockups host-vulns.html,
# host-vuln-package.html, host-vuln-package-libc6.html, owner decisions T1 to T8 on #134), from FindingTriage.
#
# A line reads as Debian's note, never as a second severity or a state: it starts with "Debian:", the category is
# in our words, and Debian's own note text follows verbatim in quotation marks, at most TRIAGE_NOTE_MAX characters.
# Nothing here says a finding is fixed or not affected because of Debian's triage: an open finding stays open until
# the installed version is outside the advisory data's affected range. Every tracker value is text, escaped by
# Rails; the only link is DebianTriage.tracker_url_for, built from a validated CVE id.
#
# Every method is prefixed triage_, since Rails includes every helper in every view.
module DebianTriageHelper
  TRIAGE_NOTE_MAX = 200
  # The no-DSA reason in our words (T7); a reason the tracker adds later reads as a plain no-DSA.
  TRIAGE_NO_DSA = { nil => "no security update planned", "postponed" => "postponed to a later update or point release",
                    "ignored" => "ignored, no fix planned for this release" }.freeze

  # Whether the triage has a no-DSA note of any reason (none, postponed, or ignored) on an entry Debian has not
  # resolved: the "Debian: no security update planned" chip (T3). A resolved entry has a fix, whatever its note says.
  def triage_no_dsa?(triage) = triage.available? && triage.entries.any? { |entry| entry.no_dsa && entry.status != "resolved" }

  # Debian's note text as the tracker gives it, cut at TRIAGE_NOTE_MAX characters with an ellipsis (T7).
  def triage_note(note) = note.length > TRIAGE_NOTE_MAX ? "#{note[0, TRIAGE_NOTE_MAX]}…" : note

  # "Debian 13" for an inventory's os hash, as the host reports it.
  def triage_os_name(os)
    return "unknown" unless os.is_a?(Hash)

    [ os["id"].to_s.capitalize, os["version_id"] ].compact_blank.join(" ").presence || "unknown"
  end

  # The triage lines for one finding. page: :tab (under the advisory, T1) or :package (its own column, with the
  # explanation, the CVE's scope (T6), and the tracker's page). status: the host release's
  # DebianTriage::Freshness::Status, for the stale date (T8). os: the host's inventory os hash.
  def triage_lines(finding, triage, page:, status:, os:)
    return triage_unavailable(triage_unavailable_why(finding, triage, page:, status:, os:)) unless triage.available?

    found = triage.entries.map(&:cve_id)
    lines = triage.entries.map { |entry| triage_line(finding, entry, triage, page:) }
    lines += (triage.cve_ids - found).map { |cve_id| triage_unavailable("#{cve_id}: the tracker has no entry for it in #{triage.release}.") }
    safe_join(lines)
  end

  # What one tracker entry says, in our words with Debian's note quoted (T7). A no-DSA note on an entry that is not
  # open follows its status (review of #136): "not yet determined for trixie; ignored, no fix planned ...".
  def triage_summary(entry, release)
    summary = if entry.no_dsa
      category = TRIAGE_NO_DSA.fetch(entry.no_dsa_reason, TRIAGE_NO_DSA[nil])
      note = entry.no_dsa_note.presence
      no_dsa = safe_join([ category, (safe_join([ " (", tag.q(triage_note(note), class: "note"), ")" ]) if note), (", urgency #{entry.urgency}" if entry.urgency) ].compact)
      entry.status == "open" ? no_dsa : safe_join([ triage_status(entry, release), "; ", no_dsa ])
    else
      triage_status(entry, release)
    end
    entry.next_point_update && entry.status != "resolved" ? safe_join([ summary, "; fix planned for the next point release" ]) : summary
  end

  # An entry's status in our words, without its no-DSA note.
  def triage_status(entry, release)
    if entry.status == "resolved" && triage_fixed_version(entry)
      safe_join([ "fixed for #{release} in ", tag.span(entry.fixed_version, class: "mono") ])
    elsif entry.status == "resolved" then "marked resolved for #{release}"
    elsif entry.status == "undetermined" then "not yet determined for #{release}"
    elsif entry.urgency == "unimportant" then "unimportant"
    elsif entry.urgency then "urgency #{entry.urgency}"
    else "not triaged yet"
    end
  end

  # The host's release and its freshness for the line under the tab bar and on the data sources page: "Debian's
  # triage for trixie: about 3 hours ago." nil when the host has no release in the release table.
  def triage_freshness_text(release, status)
    return nil unless release && status

    if DebianTriage.config.tracker_url.nil? && status.stale then tag.span("Debian's triage: turned off on this server.", class: "muted")
    elsif status.never? then "Debian's triage for #{release}: not imported yet."
    else "Debian's triage for #{release}: #{seen_ago(status.updated_at)}."
    end
  end

  # Stale on the tab (T8): data was imported once but is older than the limit, and the source is on.
  def triage_stale?(status) = status.present? && status.stale && !status.never? && !DebianTriage.config.tracker_url.nil?

  def triage_hours = pluralize((Advisories.config.max_age / 1.hour).round, "hour")


  # The data sources page's tracker panel (P2-D08; data-sources.html#tracker, data-sources-held.html), trimmed to
  # status, problems, and the latest activity (#148). How it works is in docs/operations/health-and-jobs.md.

  def triage_import_how(import)
    if import.origin == "file" then "File import on the server"
    elsif import.operator_id then "Refresh now, after the advisory feed"
    else "Scheduled refresh"
    end
  end

  def triage_import_by(import) = import.operator&.display_name || "System"

  TRIAGE_IMPORT_LAMPS = { "succeeded" => [ "Succeeded", "online" ], "held_back" => [ "Held back", "stale" ], "failed" => [ "Failed", "fail" ] }.freeze

  def triage_import_lamp(import)
    word, lamp = TRIAGE_IMPORT_LAMPS.fetch(import.state, [ import.state.humanize, "pending" ])
    tag.span(word, class: [ "lamp", lamp ])
  end

  # A short summary of what an import did: "trixie: 41,250 kept, 3 removed; 79,646 entries read", with what was
  # held back, the malformed entries when there were any, or why nothing was imported. The full counts per release
  # are in the import's audit entry.
  def triage_import_summary(import)
    counts = import.counts
    return "Nothing imported: #{import.reason}" if import.state == "failed"
    return "Not modified since the last download; nothing imported" if counts["not_modified"]
    return "#{import.origin == 'file' ? 'Nothing imported' : 'Nothing downloaded'}: no active host uses a release in the release table" if counts["no_hosts"]

    releases = (counts["releases"].is_a?(Hash) ? counts["releases"] : {}).sort.select do |_, o|
      o.is_a?(Hash) && (o["outcome"] == "held_back" || o["stored"].to_i.positive? || o["in_file"].to_i.positive?)
    end
    parts = releases.map do |release, o|
      dropped = number_with_delimiter(o["dropped"].to_i)
      if o["outcome"] == "held_back" then "#{release}: held back (#{dropped} of #{number_with_delimiter(o['stored'].to_i)} would be removed)"
      else "#{release}: #{number_with_delimiter(o['in_file'].to_i)} kept#{", #{dropped} removed" if o['dropped'].to_i.positive?}"
      end
    end
    parts << "#{number_with_delimiter(counts['entries'].to_i)} #{'entry'.pluralize(counts['entries'].to_i)} read"
    parts << "#{number_with_delimiter(counts['malformed'].to_i)} malformed" if counts["malformed"].to_i.positive?
    parts.join("; ")
  end

  # "90%" of a release's stored entries.
  def triage_share(part, whole) = whole.to_i.positive? ? "#{(100.0 * part.to_i / whole.to_i).round}%" : "all"

  # "Next refresh in about 4 hours (every 6 hours, after the advisory feed)". schedule: TriageDataSources.schedule;
  # next_at: TriageDataSources.next_refresh.
  def triage_refresh_text(schedule, next_at, now = Time.current)
    return "Not scheduled in this environment" unless schedule && next_at

    interval, after = schedule
    "Next refresh in #{distance_of_time_in_words(now, next_at)} (every #{human_duration(interval)}#{', after the advisory feed' if after})"
  end

  private

  def triage_line(finding, entry, triage, page:)
    why = page == :package ? triage_package_why(finding, entry, triage) : triage_tab_why(finding, entry, triage)
    tag.span(class: "triage") do
      safe_join([ tag.span("Debian:", class: "who"), " ", triage_summary(entry, triage.release), (tag.span(safe_join(why, " "), class: "why") if why.any?) ].compact)
    end
  end

  def triage_unavailable(why) = tag.span(safe_join([ "Debian triage not available", tag.span(why, class: "why") ]), class: "triage na")

  def triage_unavailable_why(finding, triage, page:, status:, os:)
    case triage.reason
    when "unmapped_release" then "This host's release (#{triage_os_name(os)}) is not mapped to a tracker release yet."
    when "source_off" then "The Debian Security Tracker import is turned off on this server."
    when "never_imported" then "The tracker data has not been imported yet."
    when "stale" then "The tracker data is older than #{triage_hours} (last imported #{utc(status&.updated_at) || 'never'})."
    when "no_cve" then "#{page == :package ? finding.advisory.advisory_id : 'This advisory'} names no CVE, so there is nothing to look up."
    else "The tracker has no entry for #{triage.cve_ids.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')} in #{triage.release}."
    end
  end

  # Which CVE a line is for, when the advisory is not that CVE's own record (a DSA or DLA).
  def triage_cve_named?(finding, entry) = finding.advisory.advisory_id != "DEBIAN-#{entry.cve_id}"

  def triage_fixed_version(entry) = entry.fixed_version.presence && entry.fixed_version != "0" ? entry.fixed_version : nil

  def triage_active?(finding) = finding.state != "resolved"

  # Under the advisory on the tab, which shows open and reopened rows only (T5).
  def triage_tab_why(finding, entry, triage)
    why = []
    why << "For #{entry.cve_id}." if triage_cve_named?(finding, entry)
    if !entry.no_dsa && entry.status == "open" && entry.urgency == "unimportant"
      why << "Debian's urgency for this release. The installed version is still in the affected range."
    end
    why << triage_version_why(finding, entry) if entry.status == "resolved"
    why.compact
  end

  # The package page's column: the explanation, the scope (T6), and the tracker's page. Shown on every row as
  # today's note (T5); on a resolved row it never explains why the finding resolved.
  def triage_package_why(finding, entry, triage)
    release = triage.release
    why = []
    why << "#{entry.cve_id}." if triage_cve_named?(finding, entry)
    if entry.status == "resolved"
      why << triage_version_why(finding, entry)
    elsif entry.no_dsa
      why << case entry.no_dsa_reason
      when "postponed" then "Debian's security team has postponed the fix for this in #{release} to a later update or point release."
      when "ignored" then "Debian's security team does not plan to fix this in #{release}."
      else "Debian's security team plans no security update (DSA) for this in #{release}#{" and expects the fix in the next #{release} point release" if entry.next_point_update}."
      end
      if triage_active?(finding)
        why << (entry.next_point_update ? "Until then the installed version is still in the affected range." : "The installed version is still in the affected range.")
      end
    elsif entry.urgency == "unimportant"
      why << "Debian's urgency for #{release}; it does not say the package is unaffected."
    end
    why << "Scope: #{entry.scope}." if entry.scope.present?
    url = DebianTriage.tracker_url_for(entry.cve_id)
    why << link_to("Debian's page for #{entry.cve_id}", url, rel: "noopener noreferrer", target: "_blank") if url
    why.compact
  end

  # Why a finding Debian lists as resolved is still open: only for open and reopened findings.
  def triage_version_why(finding, entry)
    return nil unless triage_active?(finding)

    installed = tag.span(finding.installed_version, class: "mono")
    fixed = triage_fixed_version(entry)
    older = fixed && PackageVersions::SCHEMES.key?(Ecosystems::MANAGERS[finding.ecosystem]) &&
            PackageVersions.for(Ecosystems::MANAGERS[finding.ecosystem]).compare(finding.installed_version, fixed) == -1
    if older
      safe_join([ "This host has ", installed, ", so the finding stays open." ])
    else
      safe_join([ "This host has ", installed, "; the finding stays open while the advisory data's affected range includes it." ])
    end
  end
end
