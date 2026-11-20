module Signals
  # Stores a KEV catalog from a KevReader (VT-S02, ADR 0032) and audits the import.
  #
  # - The stored entries are replaced in one transaction, so readers see the old catalog or the new one, never a mix.
  #   The catalog's version and the counts are kept on the import (SignalImport).
  # - Truncation guard, as the tracker's (P2-S16): a catalog that would drop more than
  #   FLEET_ADVISORY_WITHDRAW_SHARE (10%) of the stored entries stores nothing and is held back with its counts.
  #   allowed_drops (ALLOW_DROPS=<count>, an operator's confirmation from the rake tasks) is a ceiling, not a bypass.
  # - The CVEs added or removed are handed to the triage run (TriageSignalChange kind kev), and KEV data appearing for
  #   the first time hands over every finding (kev_all), since rule I5 then applies. Nothing here touches a finding.
  class KevImport
    COLUMNS = %w[cve_id date_added due_date known_ransomware vendor product].freeze

    # origin: "feed" or "file". source: the feed's host and path, or the file name.
    def initialize(origin:, source:, operator: nil, etag: nil, last_modified: nil, allowed_drops: nil)
      @origin = origin
      @source = Advisories::Record.clean_text(source, 256) || "unknown"
      @operator = operator
      @validators = { etag:, last_modified: }
      @allowed_drops = allowed_drops
    end

    def call(catalog)
      started_at = Time.current
      added = []
      import = SignalImport.transaction do
        Signals.lock!(KEV)
        stored = KevEntry.pluck(:cve_id).to_set
        incoming = catalog.entries.map(&:cve_id)
        added = incoming.reject { |id| stored.include?(id) }
        removed = (stored - incoming).to_a.sort
        counts = { "in_file" => incoming.size, "stored" => stored.size, "added" => added.size, "removed" => removed.size,
                   "malformed" => catalog.malformed, "repeated" => catalog.repeated, "catalog_count" => catalog.count }.compact
        held = Signals.too_many_dropped?(dropped: removed.size, stored: stored.size, allowed: @allowed_drops)
        unless held
          replace(catalog.entries)
          TriageSignalChange.record!(:kev, cve_ids: added + removed)
          TriageSignalChange.record!(:kev_all) if stored.empty?
        end
        import = SignalImport.create!(signal: KEV, origin: @origin, source: @source, operator: @operator, state: held ? "held_back" : "succeeded",
                                      version: catalog.version, counts:, problems: catalog.problems, reason: (held_reason(counts) if held),
                                      **@validators, started_at:, finished_at: Time.current)
        Audit.record(actor: @operator || Audit::SYSTEM, action: held ? Audit::Actions::SIGNAL_KEV_IMPORT_HELD_BACK : Audit::Actions::SIGNAL_KEV_IMPORTED,
                     target: import, changes: { "origin" => @origin, "source" => @source, "version" => catalog.version, "counts" => counts, "reason" => import.reason }.compact)
        import
      end
      # How many entries, and how many of those added, match open findings: counted by a job after the commit.
      Signals.count_later(import, added:)
      import
    end

    private

    def replace(entries)
      KevEntry.delete_all
      entries.each_slice(1_000) do |slice|
        KevEntry.insert_all(slice.map { |e| COLUMNS.to_h { |column| [ column, e.public_send(column) ] } })
      end
    end

    def held_reason(counts)
      "the catalog would remove #{counts['removed']} of #{counts['stored']} stored entries, so the previous catalog is kept"
    end
  end
end
