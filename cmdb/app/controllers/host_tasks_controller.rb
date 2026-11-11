# A host's Tasks tab (FR-3.4, P3-DASH-TASKS; mockup host-tasks.html, owner decision Q34): which task types its agent
# will run as it last reported them, what is waiting or running on it now, and its most recent tasks, with "Run a
# task on this host" in the header. Read-only.
class HostTasksController < ApplicationController
  include HostTab

  HISTORY = 20

  before_action :load_host_tab

  def show
    @open_tasks = @host.tasks.open_now.order(:created_at, :id).to_a
    @history = @host.tasks.includes(:task_batch).order(id: :desc).limit(HISTORY).to_a
    @batch_sizes = Task.where(task_batch_id: @history.map(&:task_batch_id).uniq).group(:task_batch_id).count
    # The newest package update whose agent reported whether a reboot is required, whatever its outcome (a failed or
    # timed-out update may have upgraded the kernel too). Updates that did not report it say nothing either way.
    @reboot_task = @host.tasks.where(task_type: "apply_package_updates").where("tasks.result_details -> 'reboot_required' IS NOT NULL")
                        .order(finished_at: :desc, id: :desc).first
  end
end
