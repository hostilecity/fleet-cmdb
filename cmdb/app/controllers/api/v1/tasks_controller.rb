module Api
  module V1
    # The task endpoints (FR-3.2, P3-S03, P3-S04; docs/api/README.md, "Tasks"):
    #
    #   POST /api/v1/tasks/poll           the host's next task, or null (task-poll.*)
    #   POST /api/v1/tasks/:id/start      the agent recorded it as started; may it run? (task-start.*)
    #   POST /api/v1/tasks/:id/progress   a running task's progress (task-progress.*)
    #   POST /api/v1/tasks/:id/result     the final result (task-result.*)
    #
    # Only active hosts, with the minimum agent version enforced. Each request locks the host row (AgentHostLock)
    # and runs in one transaction, so one host's task requests never interleave (AgentTasks). :id is the task's
    # uuid and is looked up only among the credential's host's tasks: another host's task is 404, exactly like
    # one that does not exist (FR-S.2, threat model V1).
    class TasksController < AuthenticatedController
      # Result bodies carry output (at most 131072 characters in the schema); the others are small.
      RESULT_MAX_BODY_BYTES = 1.megabyte
      # Why a result was refused (AgentTasks::Outcome#conflict). Either way the agent stops retrying it.
      CONFLICT_MESSAGES = {
        "different_result" => "This task already has a different result. Do not retry this one.",
        "state" => "This task's state cannot take that result. Do not retry it."
      }.freeze

      self.max_body_bytes = 4.kilobytes

      before_action :require_active_host!
      validates_body_with "task-poll.request", only: :poll
      validates_body_with "task-start.request", only: :start
      validates_body_with "task-progress.request", only: :progress
      validates_body_with "task-result.request", only: :result
      atomic :poll, :start, :progress, :result

      def poll
        task = AgentTasks.poll!(host: locked_host)
        render json: { task: task && AgentTasks.delivery(task) }
      end

      def start
        host = locked_host
        task = AgentTasks.start!(host:, task: host_task(host), agent_started_at: Time.iso8601(payload["started_at"]))
        render json: { id: task.uuid, state: task.state, run: task.state == "running" }
      end

      def progress
        task = host_task(locked_host).record_progress!(percent: payload["percent"])
        render json: { id: task.uuid, state: task.state }
      end

      def result
        host = locked_host
        outcome = AgentTasks.record_result!(host:, task: host_task(host), payload:)
        # Rendered, not raised, so the conflict's audit entry commits with the request.
        return render_api_error(AgentApi::TaskConflict.new(CONFLICT_MESSAGES.fetch(outcome.conflict))) if outcome.conflict

        render json: { id: outcome.task.uuid, report_id: payload["report_id"], duplicate: outcome.duplicate,
                       applied: outcome.applied, state: outcome.task.state }
      end

      private

      def max_body_bytes = action_name == "result" ? RESULT_MAX_BODY_BYTES : super

      def locked_host = AgentHostLock.lock!(host_id: current_host.id, credential_id: current_credential.id)

      def host_task(host) = host.tasks.find_by(uuid: params[:id]) || raise(AgentApi::TaskNotFound)
    end
  end
end
