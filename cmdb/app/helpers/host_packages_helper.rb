# Display helpers for the Packages tab and the package snapshot comparison (P2-D03, approved mockups host-packages.html,
# host-packages-diff.html). Every change is a word and a symbol as well as a colour.
module HostPackagesHelper
  # PackageDiff kinds: the label with its symbol, the CSS class, and the word used in a summary.
  KINDS = {
    installed: [ "+ Installed", "installed", "installed" ], removed: [ "− Removed", "removed", "removed" ],
    upgrade: [ "↑ Upgraded", "up", "upgraded" ], downgrade: [ "↓ Downgraded", "down", "downgraded" ],
    invalid: [ "? Cannot compare", "invalid", "not comparable" ], same: [ "∼ Source changed", "same", "source changed" ], equivalent: [ "≈ Equivalent version", "same", "equivalent version" ],
    skipped: [ "◌ Skipped / incomplete", "skipped", "skipped or incomplete" ],
    completed: [ "+ Install completed", "installed", "install completed" ], removed_skipped: [ "− Removed, was skipped", "removed", "removed while skipped" ]
  }.freeze
  # The comparison's filter chips, by ?kind=.
  KIND_FILTERS = { "installed" => :installed, "removed" => :removed, "upgraded" => :upgrade, "downgraded" => :downgrade, "invalid" => :invalid, "skipped" => :skipped, "equivalent" => :equivalent,
                   "completed" => :completed, "removed-skipped" => :removed_skipped }.freeze
  # Kinds the comparison shows a counter and a chip for only when there is one: the mockup has neither.
  OPTIONAL_KINDS = %i[skipped equivalent completed removed_skipped].freeze

  def change_kind(kind)
    label, css, = KINDS.fetch(kind)
    tag.span(label, class: [ "kind", css ])
  end

  # One change of a comparison, as the table shows it (review of #124). from and to are packages or nil; architecture
  # is nil for a package removed while it was skipped (a skipped name covers every architecture); reason is the
  # agent's, for the skip kinds.
  ChangeRow = Data.define(:kind, :name, :architecture, :from, :to, :reason)

  # Each change of a diff as a ChangeRow, in the order shown (PackageDiff::KINDS). A skipped package (named in the
  # later report's skipped list, P2-S08) is not a removal: it keeps its earlier version and carries the agent's
  # reason. A completed installation (skipped by the earlier report, installed now) carries the earlier reason, and a
  # package removed while it was skipped has no architecture or version known.
  def package_changes(diff)
    row = ->(kind, name, architecture, from: nil, to: nil, reason: nil) { ChangeRow.new(kind:, name:, architecture:, from:, to:, reason:) }
    diff.installed.map { |p| row.(:installed, p.name, p.architecture, to: p) } +
      diff.completed.map { |c| row.(:completed, c.name, c.architecture, to: c.package, reason: c.reason) } +
      diff.removed.map { |p| row.(:removed, p.name, p.architecture, from: p) } +
      diff.removed_skipped.map { |r| row.(:removed_skipped, r.name, nil, reason: r.reason) } +
      diff.skipped.map { |s| row.(:skipped, s.name, s.architecture, from: s.package, reason: s.reason) } +
      %i[upgrade downgrade invalid same].flat_map do |direction|
        diff.changed.select { |c| c.direction == direction }.map { |c| row.(c.kind, c.name, c.architecture, from: c.from, to: c.to) }
      end
  end

  # "2 installed, 1 removed, 3 upgraded", "No change", or why there is no diff, from a PackageDiff or its Summary.
  def package_change_summary(summary)
    unless summary.available?
      return tag.span(summary.unavailable_reason == PackageDiff::UNREADABLE ? "No diff: one side is a report whose package database could not be read" : "No diff: one side is from an unsupported package manager", class: "muted")
    end
    return tag.span("No change to the packages", class: "muted") if summary.empty?

    summary.counts.map { |kind, count| "#{count} #{KINDS.fetch(kind).last}" }.join(", ")
  end

  # The request box's texts for the Packages tab (P2-D03, Q6, Q7): the last report, what the button does, and what an
  # answered request did. "Unchanged since" names the latest snapshot, and is left out while the database is
  # unreadable, since the set is then unknown (review of #124).
  def package_request_texts(host, set, latest_snapshot, answered_new_snapshot:)
    ready = if set
      safe_join([ tag.strong("Package report received #{seen_ago(set.received_at).downcase_first}."),
                  " Collected #{utc(set.collected_at)}#{" by agent #{host.agent_version}" if host.agent_version}.",
                  (" Package set unchanged since snapshot #{utc(latest_snapshot.received_at)}." if latest_snapshot && !set.unreadable?) ].compact)
    else
      tag.strong("No package report yet.")
    end
    { ready:,
      ready_hint: "Package reports arrive every 6 hours, or when you ask. Each report type can be requested once every #{ReportRequests::COOLDOWN.in_minutes.to_i} minutes.",
      answered_hint: answered_new_snapshot ? "The package set changed, so a new snapshot was recorded." : "The package set had not changed, so no new snapshot was recorded. That still answers the request." }
  end

  # "2026-11-05 18:22 UTC (latest, 1,243 packages)" for a snapshot picker.
  def package_snapshot_label(snapshot, latest, oldest)
    size = if snapshot.unsupported? then "unsupported manager"
    elsif snapshot.unreadable? then "package database unreadable"
    else pluralize(number_with_delimiter(snapshot.package_count), "package")
    end
    "#{utc(snapshot.received_at)} (#{[ ('latest' if latest), ('oldest kept' if oldest), size ].compact.join(', ')})"
  end

  # What a snapshot holds, for the snapshot list: "unsupported package manager", "a package database that could not
  # be read", or "1,243 packages".
  def package_snapshot_contents(snapshot)
    return "unsupported package manager" if snapshot.unsupported?
    return "a package database that could not be read" if snapshot.unreadable?

    pluralize(number_with_delimiter(snapshot.package_count), "package")
  end
end
