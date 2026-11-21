# Puts every open finding in its triage bucket after 20261121259001 added the columns (VT-BUCKETS #259): creates the
# work events' partitions, then queues a full re-triage (EvaluationRun::Triage, reason "all") once this commits. It
# recomputes every chunk verdict's base bucket, then runs every host's transitions, in the background on the
# evaluation queue, shown on the Data sources page like an advisory import's re-match. It costs about what
# bin/rails vulnerabilities:match costs (docs/operations/upgrades.md). Until it reaches a host, the host's bucket counts
# read 0 and do not yet add up to its open count; the open counts themselves are unchanged.
class TriageEveryFinding < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def up
    Partitions.ensure!(tables: [ "vulnerability_work_events" ])
    return unless ChunkEvaluation.exists? # nothing matched yet: every chunk is triaged as it is first matched

    EvaluationRun.after_commit_start("triage", { "reason" => "all" })
  end

  def down
    # Nothing to undo: the buckets go with 20261121259001's columns.
  end
end
