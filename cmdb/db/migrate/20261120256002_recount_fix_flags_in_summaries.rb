# Recounts every host's compliance summary after 20261120256001 added the fix counts (VT-FIXABLE #256), as
# bin/rails compliance_summaries:rebuild does: in batches of 1,000 hosts in id order, each its own short transaction
# that locks its summary rows in host order, as the flush does.
#
# Its own migration, outside a transaction, so the DDL before it is never undone by a failed recount, and a recount
# that stops partway (a timeout, a restarted container) is simply run again: a recount is idempotent, and rows already
# right are not rewritten (review of #267, S3). Until it has run, a host's summary says it has no open finding with a
# fix. It costs about 7 ms a host with 4,450 open findings (docs/operations/benchmark.md), so on a large fleet it is a
# long deploy step; agents' writes are not blocked, since each batch holds only its own summary rows.
class RecountFixFlagsInSummaries < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  BATCH = 1_000

  def up
    last = 0
    loop do
      ids = select_values("SELECT id FROM hosts WHERE id > #{last} ORDER BY id LIMIT #{BATCH}").map(&:to_i)
      break if ids.empty?

      transaction { execute "SELECT host_compliance_summaries_refresh(ARRAY[#{ids.join(',')}]::bigint[])" }
      last = ids.last
    end
  end

  def down
    # Nothing to undo: the counts go with 20261120256001's columns.
  end
end
