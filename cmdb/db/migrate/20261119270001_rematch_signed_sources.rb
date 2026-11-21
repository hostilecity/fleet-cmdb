# Signed-template source packages are now matched as the source Debian's advisories name (#270, SignedSources): the
# running kernel's signed image (source linux-signed-amd64) as linux, shim-signed as shim. Chunk verdicts are kept
# until the advisories of a chunk's sources change, so the chunks already matched still say these packages are not
# affected. This queues the same re-match an advisory import of linux and shim would (EvaluationRun::Advisories,
# after this migration commits): every evaluated chunk holding those sources, or a signed source built from them, is
# matched again, then the hosts on sets holding them move their findings. It runs in the background on the
# evaluation queue, shown on the Data sources page. Since this change, a routine import that changes a kernel advisory
# reaches every host with a signed kernel image too, so this run costs what each such import now costs (it opens the
# new findings as well). docs/operations/upgrades.md says what operators see and what it costs.
class RematchSignedSources < ActiveRecord::Migration[8.1]
  def up
    scope = EvaluationRun::Advisories.matching_scope(Ecosystems.supported.flat_map { |ecosystem| SignedSources.sources(ecosystem) })
    return if scope.nil? || !ChunkEvaluation.exists? # nothing matched yet: the first match uses the table

    EvaluationRun.after_commit_start("advisories", scope)
  end

  def down
    # Nothing to undo: matching again after a rollback is the next import's (or bin/rails vulnerabilities:match).
  end
end
