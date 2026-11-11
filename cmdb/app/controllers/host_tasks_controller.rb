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
    @reboot_task = @host.tasks.where(task_type: "apply_package_updates", state: "succeeded").order(finished_at: :desc, id: :desc).first
  end
end
