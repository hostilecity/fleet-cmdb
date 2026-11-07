# Display helpers for the Packages tab and the package snapshot comparison (P2-D03, approved mockups host-packages.html,
# host-packages-diff.html). Every change is a word and a symbol as well as a colour.
module HostPackagesHelper
  # PackageDiff kinds: the label with its symbol, the CSS class, and the word used in a summary.
  KINDS = {
    installed: [ "+ Installed", "installed", "installed" ], removed: [ "− Removed", "removed", "removed" ],
    upgrade: [ "↑ Upgraded", "up", "upgraded" ], downgrade: [ "↓ Downgraded", "down", "downgraded" ],
    invalid: [ "? Cannot compare", "invalid", "not comparable" ], same: [ "∼ Source changed", "same", "source changed" ], equivalent: [ "≈ Equivalent version", "same", "equivalent version" ],
    skipped: [ "◌ Skipped / incomplete", "skipped", "skipped or incomplete" ]
  }.freeze
  # The comparison's filter chips, by ?kind=.
  KIND_FILTERS = { "installed" => :installed, "removed" => :removed, "upgraded" => :upgrade, "downgraded" => :downgrade, "invalid" => :invalid, "skipped" => :skipped, "equivalent" => :equivalent }.freeze
  # Kinds the comparison shows a counter and a chip for only when there is one: the mockup has neither.
  OPTIONAL_KINDS = %i[skipped equivalent].freeze

  def change_kind(kind)
    label, css, = KINDS.fetch(kind)
    tag.span(label, class: [ "kind", css ])
  end

  # :same is dpkg treating two versions as equal. When the strings are the same too, only the source package changed;
  # when they differ (`1.0` and `0:1.0`), the version is only spelled differently, whatever happened to the source
  # (review of #119).
  def change_kind_of(change)
    return change.direction unless change.direction == :same

    change.from.version == change.to.version ? :same : :equivalent
  end

  # Each change of a diff as [kind, name, architecture, from package or nil, to package or nil, reason or nil], in the
  # order shown. A skipped package (named in the later report's skipped list, P2-S08) is not a removal: it keeps its
  # earlier version and carries the agent's reason.
  def package_changes(diff)
    diff.installed.map { |p| [ :installed, p.name, p.architecture, nil, p, nil ] } +
      diff.removed.map { |p| [ :removed, p.name, p.architecture, p, nil, nil ] } +
      diff.skipped.map { |s| [ :skipped, s.name, s.architecture, s.package, nil, s.reason ] } +
      %i[upgrade downgrade invalid same].flat_map do |direction|
        diff.changed.select { |c| c.direction == direction }.map { |c| [ change_kind_of(c), c.name, c.architecture, c.from, c.to, nil ] }
      end
  end

  # { kind => count } for every kind with at least one change.
  def package_change_counts(diff) = package_changes(diff).map(&:first).tally

  # "2 installed, 1 removed, 3 upgraded", "No change", or why there is no diff.
  def package_change_summary(diff)
    unless diff.available?
      return tag.span(diff.unavailable_reason == PackageDiff::UNREADABLE ? "No diff: one side is a report whose package database could not be read" : "No diff: one side is from an unsupported package manager", class: "muted")
    end
    return tag.span("No change to the packages", class: "muted") if diff.empty?

    package_change_counts(diff).map { |kind, count| "#{count} #{KINDS.fetch(kind).last}" }.join(", ")
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
