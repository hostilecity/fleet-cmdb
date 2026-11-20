# What the agent reports about applicability (FR-2.6, VT-APPLICABILITY, #258), for the triage rules L1 and N4 and the
# reboot work item (#259):
#
# - from the inventory: reboot_required (true when Debian's /run/reboot-required exists, NULL otherwise: never false,
#   Debian bug #1010699), the packages that asked for it, and the kernel build string;
# - from the package report: what is in use. in_use_reported is false when there is no in-use report: an agent that
#   does not send one, one that could not read it whole (in_use null), or a host whose package manager is not
#   supported. Then the arrays are empty and nothing may be read as idle. With a report: the packages listening on the
#   network and on loopback only, the running services' packages, the sockets counted but not named, and the library
#   scan's state (off, ran, failed) with, when it ran, every package in use and the stale ones.
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
                      "stale_libraries" => [] }.freeze

  belongs_to :host

  validates :library_scan, inclusion: { in: LIBRARY_SCANS }, allow_nil: true

  # Packages a running process is known to use: the running services' and, when the scan ran, every mapped one.
  def packages_in_use = (running_services + libraries).uniq.sort

  # From an inventory report (AgentApi::InventoryReport#applicability). Returns whether anything changed.
  def self.record_inventory!(host_id:, report:, now:) = write!(host_id, report.applicability, :reboot_changed_at, now)

  # From a package report (AgentApi::PackageReport#in_use). An unreadable one keeps what was known, as it keeps the
  # package set; any other report replaces it, and one without an in-use report clears it. Returns whether anything
  # changed.
  def self.record_in_use!(host_id:, report:, now:)
    return false if report.unreadable?

    write!(host_id, report.in_use || IN_USE_DEFAULTS, :in_use_changed_at, now)
  end

  def self.write!(host_id, attributes, stamp, now)
    row = find_by(host_id:)
    if row.nil?
      return false if attributes.all? { |name, value| column_defaults[name] == value }

      create!(host_id:, **attributes, stamp => now)
      return true
    end
    row.assign_attributes(attributes)
    return false unless row.changed?

    row[stamp] = now
    row.save!
    true
  end
  private_class_method :write!
end
