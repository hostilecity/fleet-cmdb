# The Tasks page (FR-3.4, P3-DASH-TASKS; mockup tasks.html, owner decision Q2): one row per task, newest first,
# filterable by host (name or hostname), type, state, and batch. Built from query parameters so every view can be
# bookmarked. state is one task state or one of the chips' groups (GROUPS). Pages are keyset ranges on the task id,
# newest first, as on the audit log, so a page costs the same however many tasks there are. Read-only.
class TaskList
  PER_PAGE = 50
  PARAMS = %i[host type state batch before after].freeze
  HOST_MAX = 100
  ID_FORMAT = /\A[1-9]\d{0,17}\z/ # a positive bigint, without leading zeros
  # The chips (mockup tasks.html): group => [label, states].
  GROUPS = {
    "active" => [ "Waiting or running", %w[queued claimed running] ],
    "problem" => [ "Failed, timed out, refused, or expired", %w[failed timed_out refused expired] ],
    "succeeded" => [ "Succeeded", %w[succeeded] ],
    "cancelled" => [ "Cancelled", %w[cancelled] ]
  }.freeze

  # tasks: newest first. newer and older: the cursor parameters for the neighbouring pages, or nil.
  Page = Data.define(:tasks, :newer, :older)

  attr_reader :host, :type, :state, :batch

  def initialize(params = {})
    @host = params[:host].to_s.strip.first(HOST_MAX).presence
    @type = TaskCatalog.current.type?(params[:type].to_s) ? params[:type].to_s : nil
    @state = GROUPS.key?(params[:state].to_s) || Task::STATES.include?(params[:state].to_s) ? params[:state].to_s : nil
    @batch = params[:batch].to_s.strip.match?(ID_FORMAT) ? params[:batch].to_s.strip.to_i : nil
    @before = params[:before].to_s.match?(ID_FORMAT) ? params[:before].to_i : nil
    @after = params[:after].to_s.match?(ID_FORMAT) && @before.nil? ? params[:after].to_i : nil
  end

  def filtered? = filter_params.any?

  # The filters, without blanks, for links that keep them (pages, chips).
  def filter_params = { host:, type:, state:, batch: }.compact

  # The states a state filter stands for.
  def states = GROUPS.key?(state) ? GROUPS.fetch(state).last : [ state ]

  # Tasks per state for the host, type, and batch filters (not the state filter), for the chips' counts.
  def state_counts
    @state_counts ||= Task::STATES.index_with(0).merge(scope_without_state.group(:state).count)
  end

  # The chips' counts: "all" and every group.
  def chip_counts
    { "all" => state_counts.values.sum }.merge(GROUPS.transform_values { |(_, members)| state_counts.values_at(*members).sum })
  end

  def page
    @page ||= begin
      scope = filtered_scope.includes(:host, task_batch: :operator)
      rows = if @after
        scope.where("tasks.id > ?", @after).order(id: :asc).limit(PER_PAGE + 1).to_a.then { |list| [ list.first(PER_PAGE).reverse, list.size > PER_PAGE ] }
      else
        scope.where(@before ? [ "tasks.id < ?", @before ] : nil).order(id: :desc).limit(PER_PAGE + 1).to_a.then { |list| [ list.first(PER_PAGE), list.size > PER_PAGE ] }
      end
      tasks, more = rows
      newer = tasks.any? && (@before || (@after && more)) ? { after: tasks.first.id } : nil
      older = tasks.any? && (@after || more) ? { before: tasks.last.id } : nil
      Page.new(tasks:, newer:, older:)
    end
  end

  # Tasks in each batch shown on the page: { batch_id => size }.
  def batch_sizes
    @batch_sizes ||= Task.where(task_batch_id: page.tasks.map(&:task_batch_id).uniq).group(:task_batch_id).count
  end

  private

  def filtered_scope
    state ? scope_without_state.where(state: states) : scope_without_state
  end

  def scope_without_state
    scope = Task.all
    scope = scope.where(task_type: type) if type
    scope = scope.where(task_batch_id: batch) if batch
    if host
      pattern = "%#{ActiveRecord::Base.sanitize_sql_like(host)}%"
      scope = scope.where(host_id: Host.where("hosts.name ILIKE :pattern OR hosts.hostname ILIKE :pattern", pattern:).select(:id))
    end
    scope
  end
end
