# What the agent reports about applicability (FR-2.6, VT-APPLICABILITY, #258), for vulnerability triage (VT-BUCKETS,
# #277; VT-SCORES) and the reboot work item:
#
# - from the inventory: reboot_required (true when Debian's /run/reboot-required exists, NULL otherwise: never false,
#   Debian bug #1010699), the packages that asked for it, and the kernel build string;
# - from the package report: what is in use. in_use_reported is false when there is no in-use report: an agent that
#   does not send one, one that could not read it whole (in_use null), or a host whose package manager is not
#   supported, or one whose dpkg database could not be listed (unreadable: its in-use data cannot be confirmed, review
#   of #268). Then the lists are empty. With a report: the packages listening on the network and on loopback only, the
#   running services' packages, the sockets counted but not named, and the library scan's state (off, ran, failed)
#   with, when it ran, every package with mapped files, the stale ones, and the listening programs with the packages
#   they load (loaded_by_listeners: [{ listener, service, class, sockets, packages }], one per listener and unit; see
#   the migration), when it ran (library_scanned_at, the agent's clock; the agent reuses a scan for up to an hour), and
#   when the server first received a report carrying that scan (library_scan_received_at, the server's clock).
#
# Positive evidence only (owner decision 2026-11-21, replacing L1): nothing is ever demoted or called idle from these
# lists. A package a listening process loads is escalated instead (in_use_by_listener?) until ESCALATION_MAX_AGE
# after the server received the report that carried the scan (fifth review, S5: the server's clock, so a skewed agent
# clock changes nothing). A report with a failed scan, the scan off, or no in-use report clears the evidence at once.
#
# One narrow row per host, written only when what it holds changes (like hosts after #220, ADR 0029), so a steady
# fleet writes nothing here; the *_changed_at columns say when each half last changed. No row means nothing reported.
# Only the recorders write it, under the host row lock (AgentHostLock).
class HostApplicability < ApplicationRecord
  self.table_name = "host_applicability"
  self.primary_key = "host_id"

  LIBRARY_SCANS = %w[off ran failed].freeze
  IN_USE_DEFAULTS = { "in_use_reported" => false, "listening_network" => [], "listening_loopback" => [], "running_services" => [],
                      "unnamed_network" => 0, "unnamed_loopback" => 0, "library_scan" => nil, "libraries" => [],
                      "stale_libraries" => [], "loaded_by_listeners" => [], "library_scanned_at" => nil,
                      "library_scan_received_at" => nil }.freeze
  # An escalation expires this long after the server received the report that carried the host's latest scan (owner
  # decision 2026-11-21).
  ESCALATION_MAX_AGE = 24.hours

  belongs_to :host

  validates :library_scan, inclusion: { in: LIBRARY_SCANS }, allow_nil: true

  # Packages a running process is known to use: the running services' and, when the scan ran, every mapped one.
  def packages_in_use = (running_services + libraries).uniq.sort

  # Whether the latest scan ran and the report that carried it arrived at most ESCALATION_MAX_AGE before now, by the
  # server's clock.
  def scan_current?(now:) = library_scan == "ran" && !library_scan_received_at.nil? && now - library_scan_received_at <= ESCALATION_MAX_AGE

  # The listening processes that load package, by the latest current scan: [{ "listener" => package or nil,
  # "service" => unit or nil, "class" => "network" or "loopback", "sockets" => ["0.0.0.0:22/tcp", ...] (at most 4) }],
  # network ones first; [] when none, or when the scan is not current. For a reason that names them (#277).
  def listener_details(package, now:)
    return [] unless scan_current?(now:)

    loaded_by_package.fetch(package, []).map { |use| use.slice("listener", "service", "class", "sockets") }
                                      .sort_by { |use| [ use["class"] == "network" ? 0 : 1, use["listener"].to_s, use["service"].to_s ] }
  end

  # Whether a process holding a listening socket loads package (VT-BUCKETS' escalation, #277): it then cannot be
  # demoted by L2 to L5, counts toward Needs attention, and adds exposure points (VT-SCORES). network: true asks for a
  # socket on the network.
  def in_use_by_listener?(package, now:, network: false)
    listener_details(package, now:).any? { |use| !network || use["class"] == "network" }
  end

  # From an inventory report (AgentApi::InventoryReport#applicability). Returns whether anything changed.
  def self.record_inventory!(host_id:, report:, now:) = write!(host_id, report.applicability, :reboot_changed_at, now)

  # From a package report (AgentApi::PackageReport#in_use). Every report replaces it, and one without an in-use report
  # clears it: an unreadable or unsupported one too, so old use data never looks current (review of #268, S1).
  # Returns whether anything changed.
  def self.record_in_use!(host_id:, report:, now:) = write!(host_id, report.in_use || IN_USE_DEFAULTS, :in_use_changed_at, now)

  SCAN_TIMES = %w[library_scanned_at library_scan_received_at].freeze

  def self.write!(host_id, attributes, stamp, now)
    attributes = received(host_id, attributes, now)
    row = find_by(host_id:)
    if row.nil?
      return false if attributes.all? { |name, value| column_defaults[name] == value }

      create!(host_id:, **attributes, stamp => now)
      return true
    end
    row.assign_attributes(attributes)
    return false unless row.changed?

    # The scan's time moves with every scan; it is stored (and a new one restarts the expiry, by the server's clock)
    # but is not a change of what is in use (review of #268, N1), so triage reruns only when the lists change.
    changed = (row.changed - SCAN_TIMES).any?
    row[stamp] = now if changed
    row.save!
    changed
  end
  private_class_method :write!

  # library_scan_received_at: now when a report carries a scan the row does not have yet, else kept; nil without one.
  def self.received(host_id, attributes, now)
    return attributes unless attributes.key?("library_scanned_at")
    return attributes.merge("library_scan_received_at" => nil) if attributes["library_scanned_at"].nil?

    known = where(host_id:, library_scanned_at: attributes["library_scanned_at"]).pick(:library_scan_received_at)
    attributes.merge("library_scan_received_at" => known || now)
  end
  private_class_method :received

  private

  # Indexed once per value of the column (a reload or an assignment gives a new one).
  def loaded_by_package
    uses = loaded_by_listeners
    @loaded_by_package = nil unless @loaded_by_source.equal?(uses)
    @loaded_by_source = uses
    @loaded_by_package ||= uses.each_with_object(Hash.new { |h, k| h[k] = [] }) do |use, index|
      use["packages"].each { |package| index[package] << use }
    end
  end
end
