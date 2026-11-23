# Backports are now matched against the advisories of the release they are built from (#274, Ecosystems::BACKPORTS),
# and a fix in their own release's advisories no longer resolves their findings or clears them through Debian's triage
# for the release. Chunk verdicts are kept until an import changes their sources' advisories, so this queues the
# re-match a change to Debian:14's advisories of the stored backports' sources would (EvaluationRun::Advisories, after
# this migration commits): only the chunks holding a backport, then the hosts on sets holding them (the partial index
# from IndexBackportPackageEntries), not the fleet. Debian:14's advisories are stored by the next import, which writes
# again every advisory that names Debian:14 (Advisories::Import) and re-matches the same chunks; this run applies the
# rest now. docs/operations/upgrades.md says what operators see.
class RematchBackports < ActiveRecord::Migration[8.1]
  def up
    scope = EvaluationRun::Advisories.backports_scope
    return if scope.nil? || !ChunkEvaluation.exists? # nothing matched yet: the first match handles backports

    EvaluationRun.after_commit_start("advisories", scope)
  end

  def down
    # Nothing to undo: matching again after a rollback is the next import's (or bin/rails vulnerabilities:match).
  end
end
