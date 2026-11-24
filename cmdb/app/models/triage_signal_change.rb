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
# - tracker: a CVE whose Debian tracker entry for a stored release changed in a way the triage rules read (status,
#   urgency, fixed version, no-DSA, or scope; DebianTriage::Import, VT-BUCKETS #259). Coalesced into the daily run.
#
# Recorded in the transaction that made the change, so a rolled-back import hands nothing over. Nothing here changes
# a finding.
#
# Claim protocol (race-free; reviews of #269). Every record! gives the row a new id from the table's sequence, also
# when the row was already pending, so a row's id names the version of the change a consumer saw:
#   1. claim(kinds:, limit:) reads up to limit rows, oldest id first, with a plain SELECT: no lock. Pages after the
#      first read after the last id claimed, up to a bound fixed as the consumer started (after:, upto:, #312). An id
#      is taken before its import commits, so a row can appear below the cursor once its page was read: it is not
#      claimed, so not released, and the next consumer claims it.
#   2. The consumer recomputes from the current data and commits its work.
#   3. release!(ids) deletes the claimed ids in a transaction of its own, skipping any row an import has locked
#      (FOR UPDATE SKIP LOCKED). A change recorded between 1 and 3 has a new id, so it is not deleted and is picked up by
#      the next claim. A row locked by an import that is re-recording it is skipped: if that import commits, the row
#      has a new id and must stay; if it rolls back, the row is processed again, which is harmless. So release! never
#      waits on an import and can never deadlock with one (it deleted in id order while imports upsert in their own
#      order). It refuses to run inside an open transaction, where its delete would commit or roll back with the run.
#      A consumer that fails releases nothing, and the rows stay.
# Never hold claimed rows in the run's transaction, and never delete by kind or key. Within one run, process the
# advisory rows after the kev rows: an advisory import that adds an alias reads KEV before a concurrent KEV import
# commits that CVE, and the kev row then covers it.
class TriageSignalChange < ApplicationRecord
  KINDS = %w[kev kev_all epss advisory tracker].freeze
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

  # Records the changes. kind: :kev, :epss, or :tracker with cve_ids, :advisory with advisory_ids, or :kev_all with neither. A
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

  # Up to limit pending changes of the kinds, oldest first, read without locking (step 1 of the claim protocol). A
  # consumer that claims more than one page reads by keyset (#312): after the last id it claimed, and up to the newest
  # id when it started (last_id), so a change recorded since, which has a higher id, waits for the next consumer.
  def self.claim(kinds: KINDS, limit: 1_000, after: nil, upto: nil)
    rows = where(kind: kinds)
    rows = rows.where(id: (after + 1)..) if after
    rows = rows.where(id: ..upto) if upto
    rows.order(:id).limit(limit).to_a
  end

  # The newest pending change of the kinds, or 0 for none: the bound of a paged claim.
  def self.last_id(kinds: KINDS) = where(kind: kinds).maximum(:id) || 0

  # Deletes the claimed rows (step 3), skipping any an import has locked; a row re-recorded since has a new id and
  # stays. Returns how many went. Raises inside an open transaction.
  def self.release!(ids)
    raise ArgumentError, "TriageSignalChange.release! must run outside a transaction (the claim protocol)" if connection.transaction_open?

    transaction { where(id: where(id: ids).lock("FOR UPDATE SKIP LOCKED").select(:id)).delete_all }
  end
end
