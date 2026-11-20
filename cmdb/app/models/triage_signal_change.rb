# The hand-off from the exploitation signals and the advisory import to the triage run (VT-SIGNALS, VT-S05, ADR 0032):
# dirty markers, one row per kind and CVE or advisory, which the triage run recomputes from the current data. They
# coalesce: recording a change already pending updates that row instead of adding one.
#
# - kev: a CVE a KEV import added or removed. The triage run starts at once for these (VT-S05).
# - kev_all: KEV data appeared for the first time or was cleared, which turns rule I5 on or off for every finding.
# - epss: a CVE whose stored EPSS band changed between high and not high (or that gained or lost a high band, an EPSS
#   reset included). Coalesced into the daily run.
# - advisory: an advisory whose CVSS vector parts or severity changed at import, or whose CVE set changed in a way that
#   touches rule N1 or N2 (it gained or lost a CVE that is in KEV or in the EPSS high band).
# Debian tracker changes are not here: VT-S05 gives them their own path (vt-buckets.md, "Hand-off").
#
# Recorded in the transaction that made the change, so a rolled-back import hands nothing over. Nothing here changes
# a finding.
#
# Claim protocol (race-free; review of #269). Every record! gives the row a new id from the table's sequence, also
# when the row was already pending, so a row's id names the version of the change a consumer saw:
#   1. claim(kinds:, limit:) reads up to limit rows, oldest id first, with a plain SELECT: no lock, so imports never
#      wait on a consumer.
#   2. The consumer recomputes from the current data and commits its work.
#   3. release!(ids) deletes exactly the claimed ids, in a short transaction of its own. A change recorded between 1 and
#      3 has a new id, so it is not deleted and is picked up by the next claim. A consumer that fails releases nothing,
#      and the rows stay.
# Never hold claimed rows in the run's transaction, and never delete by kind or key.
class TriageSignalChange < ApplicationRecord
  KINDS = %w[kev kev_all epss advisory].freeze
  NEXT_ID = "nextval(pg_get_serial_sequence('triage_signal_changes', 'id'))".freeze
  # What an upsert does with a change already pending: a new id (the claim protocol) and the new time.
  ON_CONFLICT_SET = "DO UPDATE SET id = #{NEXT_ID}, created_at = EXCLUDED.created_at".freeze
  # The conflict targets, matching the partial unique indexes.
  CVE_TARGET = "(kind, cve_id) WHERE cve_id IS NOT NULL".freeze
  INSERT = {
    "kev_all" => "INSERT INTO triage_signal_changes (id, kind, created_at) VALUES (#{NEXT_ID}, 'kev_all', now()) " \
                 "ON CONFLICT (kind) WHERE kind = 'kev_all' #{ON_CONFLICT_SET}",
    "advisory" => "INSERT INTO triage_signal_changes (id, kind, advisory_id, created_at) SELECT #{NEXT_ID}, 'advisory', v, now() " \
                  "FROM unnest(?::bigint[]) AS v ON CONFLICT (kind, advisory_id) WHERE advisory_id IS NOT NULL #{ON_CONFLICT_SET}",
    "cve" => "INSERT INTO triage_signal_changes (id, kind, cve_id, created_at) SELECT #{NEXT_ID}, ?, v, now() " \
             "FROM unnest(?::varchar[]) AS v ON CONFLICT #{CVE_TARGET} #{ON_CONFLICT_SET}"
  }.freeze

  validates :kind, inclusion: { in: KINDS }

  # Records the changes. kind: :kev or :epss with cve_ids, :advisory with advisory_ids, or :kev_all with neither. A
  # caller with the CVEs in a table writes the same upsert in SQL (Signals::EpssImport) with NEXT_ID, CVE_TARGET, and
  # ON_CONFLICT_SET.
  def self.record!(kind, cve_ids: [], advisory_ids: [])
    kind = kind.to_s
    raise ArgumentError, "unknown kind #{kind}" unless KINDS.include?(kind)
    return connection.execute(INSERT["kev_all"]) if kind == "kev_all"

    values = kind == "advisory" ? advisory_ids.map { |id| Integer(id) }.uniq : cve_ids.map(&:to_s).uniq
    values.each_slice(5_000) do |slice|
      array = PG::TextEncoder::Array.new.encode(slice)
      sql = kind == "advisory" ? sanitize_sql_array([ INSERT["advisory"], array ]) : sanitize_sql_array([ INSERT["cve"], kind, array ])
      connection.execute(sql)
    end
  end

  # Up to limit pending changes of the kinds, oldest first, read without locking (step 1 of the claim protocol).
  def self.claim(kinds: KINDS, limit: 1_000) = where(kind: kinds).order(:id).limit(limit).to_a

  # Deletes exactly the claimed rows (step 3); a row re-recorded since has a new id and stays. Returns how many went.
  def self.release!(ids) = transaction { where(id: ids).delete_all }
end
