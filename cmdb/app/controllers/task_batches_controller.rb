# One batch, as the create flow leaves it (P3-S08): what was asked for, the tasks it created and their states, and
# the hosts left out. A minimal page that the create flow redirects to; P3-DASH-TASKS (#33) replaces it with batch
# progress (per-host counts updating live, problems first, cancel) at the same path.
class TaskBatchesController < ApplicationController
  def show
    @batch = TaskBatch.includes(:operator).find(params[:id])
    @tasks = @batch.tasks.includes(:host).order(:id)
    @excluded_hosts = Host.where(id: @batch.excluded_hosts.pluck("host_id")).index_by(&:id)
  end
end
