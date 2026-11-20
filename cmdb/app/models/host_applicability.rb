# What the agent reports about applicability (FR-2.6, VT-APPLICABILITY, #258), for the triage rules L1 and N4 and the
# reboot work item (#259):
#
# - from the inventory: reboot_required (true when Debian's /run/reboot-required exists, NULL otherwise: never false,
#   Debian bug #1010699), the packages that asked for it, and the kernel build string;
# - from the package report: what is in use. in_use_reported is false when there is no in-use report: an agent that
#   does not send one, one that could not read it whole (in_use null), or a host whose package manager is not
#   supported, or one whose dpkg database could not be listed (unreadable: its in-use data cannot be confirmed, review
#   of #268). Then the arrays are empty and nothing may be read as idle. With a report: the packages listening on the
#   network and on loopback only, the running services' packages, the sockets counted but not named, and the library
#   scan's state (off, ran, failed) with, when it ran, every package with mapped files, the stale ones, the packages
#   it can judge (native_packages: native code only), and when it ran (library_scanned_at, the agent's clock; the agent
#   reuses a scan for up to an hour).
#
# Every list is positive evidence only: a package missing from them is never idle on that account. Only a package in
# native_packages, absent from libraries, and neither listening nor a running service's is provably idle
# (provably_idle?, owner decision 2026-11-20); rule L1 (#259) applies to nothing else.
#
# One narrow row per host, written only when what it holds changes (like hosts after #220, ADR 0029), so a steady
# fleet writes nothing here; the *_changed_at columns say when each half last changed. No row means nothing reported.
# The report's freshness is the package set's and the inventory's received_at. Only the recorders write it, under the
# host row lock (AgentHostLock).
class HostApplicability < ApplicationRecord
  self.table_name = "host_applicability"
  self.primary_key = "host_id"

  LIBRARY_SCANS = %w[off ran failed].freeze
  IN_USE_DEFAULTS = { "in_use_reported" => false, "listening_network" => [], "listening_loopback" => [], "running_services" => [],
                      "unnamed_network" => 0, "unnamed_loopback" => 0, "library_scan" => nil, "libraries" => [],
                      "stale_libraries" => [], "native_packages" => [], "library_scanned_at" => nil }.freeze

  belongs_to :host

  validates :library_scan, inclusion: { in: LIBRARY_SCANS }, allow_nil: true

  # Packages a running process is known to use: the running services' and, when the scan ran, every mapped one.
  def packages_in_use = (running_services + libraries).uniq.sort

  # A package report older than this, by the server's clock, proves nothing idle: twice the agent's default package
  # report interval (6 hours, [config_report] interval_seconds). A host whose agent reports less often never gets L1.
  REPORT_MAX_AGE = 12.hours
  # How much older than its report's collected_at a scan may be (both the agent's clock): the agent reuses one for at
  # most an hour (scan::EVERY), plus an hour of slack. A scan time after collected_at is allowed a few minutes.
  SCAN_MAX_LAG = 2.hours
  SCAN_MAX_LEAD = 5.minutes

  # Whether the report proves the package idle: the scan ran, judged it (native code only), and found nothing of it
  # mapped, and no service of it runs or listens (owner decision 2026-11-20); and the scan is fresh (review of #268,
  # S5): the host's latest package report (package_set, its HostPackageSet) arrived within REPORT_MAX_AGE of now, and
  # the scan ran at most SCAN_MAX_LAG before that report was collected and not after it.
  def provably_idle?(package, package_set:, now:)
    library_scan == "ran" && scan_fresh?(package_set, now:) && native_packages.include?(package) &&
      !packages_in_use.include?(package) && !listening_network.include?(package) && !listening_loopback.include?(package)
  end

  def scan_fresh?(package_set, now:)
    return false if library_scanned_at.nil? || package_set&.received_at.nil? || package_set.collected_at.nil?
    return false if now - package_set.received_at > REPORT_MAX_AGE

    lag = package_set.collected_at - library_scanned_at
    lag <= SCAN_MAX_LAG && lag >= -SCAN_MAX_LEAD
  end

  # From an inventory report (AgentApi::InventoryReport#applicability). Returns whether anything changed.
  def self.record_inventory!(host_id:, report:, now:) = write!(host_id, report.applicability, :reboot_changed_at, now)

  # From a package report (AgentApi::PackageReport#in_use). Every report replaces it, and one without an in-use report
  # clears it: an unreadable or unsupported one too, so old use data never looks current (review of #268, S1).
  # Returns whether anything changed.
  def self.record_in_use!(host_id:, report:, now:) = write!(host_id, report.in_use || IN_USE_DEFAULTS, :in_use_changed_at, now)

  def self.write!(host_id, attributes, stamp, now)
    row = find_by(host_id:)
    if row.nil?
      return false if attributes.all? { |name, value| column_defaults[name] == value }

      create!(host_id:, **attributes, stamp => now)
      return true
    end
    row.assign_attributes(attributes)
    return false unless row.changed?

    # The scan's time moves with every scan; it is stored (scan_fresh? needs it) but is not a change of what is in use
    # (review of #268, N1), so #259 re-triages only when the lists change.
    changed = (row.changed - [ "library_scanned_at" ]).any?
    row[stamp] = now if changed
    row.save!
    changed
  end
  private_class_method :write!
end
