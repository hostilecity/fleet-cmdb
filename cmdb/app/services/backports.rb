# What a server knows about backports beyond the static table (Ecosystems::BACKPORTS, #274, ADR 0011).
#
# - data?(ecosystem): whether the advisory data of the release the ecosystem's backports are built from (Debian:14)
#   is complete here: a succeeded full import kept it (its malformed Debian:14 entries are skipped and counted, never
#   its records' Debian:13 data; status says how many). Until then backports are matched on their own release's data
#   alone, as before #274: a partial upload of a few Debian:14 records cannot tell an advisory that does not name
#   forky from one not imported, so no verdict rests on its absence. The first full import that keeps it re-matches
#   every stored backport (Advisories::Import).
# - status(ecosystem): for Data sources and the host tab.
# - sources(ecosystem): the advisory sources the stored backports are matched as (SignedSources), for that re-match,
#   bin/rails vulnerabilities:rematch_backports, and EvaluationRun::Advisories.backports_scope.
module Backports
  module_function

  def data?(ecosystem)
    from = Ecosystems.backports_from(ecosystem)
    !from.nil? && full_imports(from).exists?
  end

  # The succeeded full imports that kept the ecosystem.
  def full_imports(from) = AdvisoryImport.succeeded.where(full: true).where("? = ANY (ecosystems)", from)

  # The release backports are built from, whether its data is complete, and the newest full import that kept it with
  # the entries and records it found malformed; nil when the ecosystem has no backports.
  Status = Data.define(:from, :complete, :import, :skipped_entries, :malformed)

  def status(ecosystem)
    from = Ecosystems.backports_from(ecosystem) or return nil
    import = full_imports(from).order(finished_at: :desc, id: :desc).first
    Status.new(from:, complete: !import.nil?, import:, skipped_entries: import&.counts&.fetch("skipped_entries", 0).to_i, malformed: import&.counts&.fetch("malformed", 0).to_i)
  end

  def sources(ecosystem)
    like = Ecosystems.backport_like_sql(ecosystem) or return []
    PackageChunkEntry.where(like).distinct.pluck(:name, :source).flat_map do |name, source|
      [ SignedSources.resolve(ecosystem, name, source, "").source, source || name ]
    end.uniq.sort
  end
end
