# Signed-template source packages are now matched as the source Debian's advisories name (#270, SignedSources): the
# running kernel's signed image (source linux-signed-amd64) as linux, shim-signed as shim. Chunk verdicts are kept
# until the advisories of a chunk's sources change, so the chunks already matched still say these packages are not
# affected. This queues the same re-match an advisory import of linux and shim would (EvaluationRun::Advisories,
# after this migration commits): every evaluated chunk holding those sources, or a signed source built from them, is
# matched again, then the hosts on sets holding them move their findings. It runs in the background on the
# evaluation queue, shown on the Data sources page, at about the cost of a routine import that changes a kernel
# advisory (every Debian host has a kernel). docs/operations/upgrades.md says what operators see.
class RematchSignedSources < ActiveRecord::Migration[8.1]
  def up
    packages = Ecosystems.supported.to_h { |ecosystem| [ ecosystem, SignedSources.sources(ecosystem) ] }.reject { |_, sources| sources.empty? }
    return if packages.empty? || !ChunkEvaluation.exists? # nothing matched yet: the first match uses the table

    EvaluationRun.after_commit_start("advisories", "packages" => packages)
  end

  def down
    # Nothing to undo: matching again after a rollback is the next import's (or bin/rails vulnerabilities:match).
  end
end
