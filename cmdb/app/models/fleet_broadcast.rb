# Live fleet updates (P1-D05). Code that changes what the fleet list or a host header shows calls
# hosts_changed inside its transaction; the broadcast job is enqueued only after the outermost transaction
# commits, so browsers never see uncommitted state, and not at all if it rolls back.
module FleetBroadcast
  STREAM = "fleet".freeze

  module_function

  def hosts_changed(host_ids)
    ids = Array(host_ids).compact.uniq
    return if ids.empty?

    ActiveRecord.after_all_transactions_commit { FleetBroadcastJob.perform_later(ids) }
  end
end
