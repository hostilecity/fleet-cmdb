# What a server knows about backports beyond the static table (Ecosystems::BACKPORTS, #274, ADR 0011).
#
# - data?(ecosystem): whether the advisory data of the release the ecosystem's backports are built from (Debian:14)
#   is complete here: a succeeded full import with no malformed record kept it. Until then backports are matched on their own release's data
#   alone, as before #274: a partial upload of a few Debian:14 records cannot tell an advisory that does not name
#   forky from one not imported, so no verdict rests on its absence. The first full import that keeps it re-matches
#   every stored backport (Advisories::Import).
# - sources(ecosystem): the advisory sources the stored backports are matched as (SignedSources), for that re-match,
#   bin/rails vulnerabilities:rematch_backports, and EvaluationRun::Advisories.backports_scope.
module Backports
  module_function

  def data?(ecosystem)
    from = Ecosystems.backports_from(ecosystem)
    !from.nil? && AdvisoryImport.succeeded.where(full: true).where("? = ANY (ecosystems)", from).where("counts ->> 'malformed' = '0'").exists?
  end

  def sources(ecosystem)
    like = Ecosystems.backport_like_sql(ecosystem) or return []
    PackageChunkEntry.where(like).distinct.pluck(:name, :source).flat_map do |name, source|
      [ SignedSources.resolve(ecosystem, name, source, "").source, source || name ]
    end.uniq.sort
  end
end
