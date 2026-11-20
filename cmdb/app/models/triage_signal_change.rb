# The hand-off from the exploitation signals and the advisory import to the triage run (VT-SIGNALS, VT-S05, ADR 0032):
# what changed since the run last processed it, one row per kind and CVE or advisory, so changes coalesce.
#
# - kev: a CVE a KEV import added or removed. The triage run starts at once for these (VT-S05).
# - kev_all: KEV data appeared for the first time or was cleared, which turns rule I5 on or off for every finding.
# - epss: a CVE whose stored EPSS band changed between high and not high (or that gained or lost a high band).
#   Coalesced into the daily run.
# - advisory: an advisory whose CVSS vector parts or severity changed at import.
#
# Recorded in the transaction that made the change, so a rolled-back import hands nothing over. Nothing here changes
# a finding: the triage run (#259) reads and deletes these rows.
class TriageSignalChange < ApplicationRecord
  KINDS = %w[kev kev_all epss advisory].freeze

  validates :kind, inclusion: { in: KINDS }

  INSERT_ALL = "INSERT INTO triage_signal_changes (kind, created_at) VALUES (?, ?) ON CONFLICT DO NOTHING".freeze
  INSERT_CVES = "INSERT INTO triage_signal_changes (kind, cve_id, created_at) SELECT ?, v, ? FROM unnest(?::varchar[]) AS v ON CONFLICT DO NOTHING".freeze
  INSERT_ADVISORIES = "INSERT INTO triage_signal_changes (kind, advisory_id, created_at) SELECT ?, v, ? FROM unnest(?::bigint[]) AS v ON CONFLICT DO NOTHING".freeze

  # Records the changes, ignoring ones already pending. kind: :kev or :epss with cve_ids, :advisory with
  # advisory_ids, or :kev_all with neither.
  def self.record!(kind, cve_ids: [], advisory_ids: [])
    kind = kind.to_s
    raise ArgumentError, "unknown kind #{kind}" unless KINDS.include?(kind)

    now = Time.current
    if kind == "kev_all"
      connection.execute(sanitize_sql_array([ INSERT_ALL, kind, now ]))
    else
      sql, values = kind == "advisory" ? [ INSERT_ADVISORIES, advisory_ids.map { |id| Integer(id) } ] : [ INSERT_CVES, cve_ids.map(&:to_s) ]
      values.uniq.each_slice(5_000) { |slice| connection.execute(sanitize_sql_array([ sql, kind, now, PG::TextEncoder::Array.new.encode(slice) ])) }
    end
  end
end
