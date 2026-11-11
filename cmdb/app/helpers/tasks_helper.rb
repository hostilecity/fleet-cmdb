# Words for tasks (FR-3.4, P3-DASH-TASKS; mockups tasks.html, task.html, task-states.html, batch.html,
# batch-partial.html): every state as a word beside its lamp, reasons in plain language with the code small beside
# them (owner decision Q21), and what a task did. Everything an agent reported is shown as text: values are passed to
# tag helpers or ERB, which escape them, and never marked safe.
module TasksHelper
  STATE_LABELS = {
    "queued" => "Queued", "claimed" => "Claimed", "running" => "Running", "succeeded" => "Succeeded", "failed" => "Failed",
    "timed_out" => "Timed out", "cancelled" => "Cancelled", "refused" => "Refused", "expired" => "Expired"
  }.freeze

  # reason => [headline, sentence]. Failed reasons first, then refused (Task::FAILED_REASONS, Task::REFUSED_REASONS).
  REASONS = {
    "nonzero_exit" => [ "the task exited with an error", "It ran and exited unsuccessfully. The output says why." ],
    "interrupted" => [ "interrupted", "The agent stopped while the task was running (the VM rebooted, or the agent was restarted or updated) and reported it when it started again. The task was not run again. Reports already sent before it stopped were kept." ],
    "lease_expired" => [ "the agent stopped reporting", "The agent said it started this task, then sent nothing before its lease ran out. The task may or may not have finished on the VM; check the host. It will not be run again." ],
    "lock_timeout" => [ "package manager busy", "Another program held the package manager's lock, so nothing was upgraded. Often an automatic update is running; wait and try again." ],
    "agent_error" => [ "the agent could not run it", "The agent hit an error of its own. The output may say more." ],
    "not_run" => [ "not run", "The agent had the task but never ran it: its start was not confirmed before the claim lapsed, and it closed the task when it was delivered again. Nothing ran." ],
    "unknown_type" => [ "the agent does not know this task type", "Its catalog is older than the server's. Nothing ran." ],
    "invalid_params" => [ "the parameters did not pass the checks", "The parameters did not pass the catalog's checks. Nothing ran." ],
    "not_supported" => [ "not supported by this agent", "The host no longer reports supporting this task type. Nothing ran." ],
    "not_enabled_locally" => [ "not enabled on this VM", "The task type is not turned on in the VM's agent configuration. Enabling it is an edit on the VM itself, never from the dashboard. Nothing ran." ],
    "not_allowed_locally" => [ "not in this VM's own allowlist", "The service is not listed in [tasks] allowed_services in /etc/fleet-agent/config.toml on the VM. Nothing ran." ],
    "not_allowed_on_server" => [ "no longer allowed", "The service is not on the server's restart allowlist for this host any more. Nothing ran." ],
    "protected_service" => [ "protected service", "The agent itself, SSH, systemd-*, networking, and D-Bus are never restarted remotely. Nothing ran." ]
  }.freeze

  # The batch counts strip (mockup batch.html, Q14): a cell for every state, Waiting being queued and claimed.
  STRIP = [ [ "Waiting", %w[queued claimed], "queued" ], [ "Running", %w[running], "running" ], [ "Succeeded", %w[succeeded], "succeeded" ],
            [ "Failed", %w[failed], "failed" ], [ "Timed out", %w[timed_out], "timed_out" ], [ "Refused", %w[refused], "refused" ],
            [ "Expired", %w[expired], "expired" ], [ "Cancelled", %w[cancelled], "cancelled" ] ].freeze
  # The bar under the strip, in this order, and the sentence under it.
  BAR = %w[succeeded failed timed_out refused expired cancelled running claimed queued].freeze
  # Batch rows, problems first (Q15), then running, waiting, cancelled, and succeeded.
  ROW_ORDER = %w[failed timed_out refused expired running claimed queued cancelled succeeded].freeze
  PROBLEM_STATES = %w[failed timed_out refused].freeze

  # /tasks with these query parameters. Built by hand because url_for treats a :host key as the URL's host, and the
  # filter is called host.
  def task_list_path(query = {})
    query = query.to_h.compact_blank
    query.empty? ? tasks_path : "#{tasks_path}?#{query.to_query}"
  end

  def task_state_label(state) = STATE_LABELS.fetch(state) { state.to_s.humanize }

  # The state as a lamp and a word. A running task an operator asked to cancel keeps its real state, with the request
  # beside it (Q17).
  def task_state_lamp(task)
    if task.state == "running" && task.cancel_requested?
      tag.span("Running, cancel requested", class: "lamp s-cancel-req")
    else
      tag.span(task_state_label(task.state), class: "lamp s-#{task.state}")
    end
  end

  def task_type_name(type) = TaskCatalog.current.type?(type) ? TaskCatalog.current.entry(type).name : type

  # "Restart a service: nginx.service", the parameter values as text in their own boxes.
  def task_what(task_or_batch)
    values = task_or_batch.parameters.to_h.values
    name = task_type_name(task_or_batch.task_type)
    return name if values.empty?

    safe_join([ "#{name}: ", safe_join(values.map { |value| tag.span(value.is_a?(String) ? value : value.to_json, class: "param") }, " ") ])
  end

  # "2026-11-08 14:02:11 UTC".
  def task_time(time) = time&.utc&.strftime("%Y-%m-%d %H:%M:%S UTC")

  # "14:02:11", for tables whose heading says UTC.
  def task_clock(time) = time&.utc&.strftime("%Y-%m-%d %H:%M:%S")

  # The reason as a headline and a sentence.
  def task_reason(reason) = REASONS.fetch(reason) { [ reason.to_s.humanize(capitalize: false), "" ] }

  def task_deadline(task) = task.started_at && (task.started_at + task.timeout)

  # How long the task took: the agent's own times when it reported both, otherwise the server's.
  def task_run_time(task)
    from, to = task.agent_started_at && task.agent_finished_at ? [ task.agent_started_at, task.agent_finished_at ] : [ task.started_at, task.finished_at ]
    return nil unless from && to

    seconds = (to - from).round(1)
    seconds < 60 ? "#{number_with_precision(seconds, precision: 1, strip_insignificant_zeros: true)} s" : "#{(seconds / 60).floor} min #{(seconds % 60).round} s"
  end

  # What a successful task reported, in words, or nil.
  def task_success_summary(task)
    details = task.result_details.to_h
    case task.task_type
    when "apply_package_updates"
      words = [ ("Reboot required." if details["reboot_required"]) ]
      services = Array(details["services_needing_restart"])
      words << "#{pluralize(services.size, 'service')} #{services.one? ? 'uses' : 'use'} old libraries." if services.any?
      words.compact.join(" ").presence
    when "restart_service"
      details["unit_active"] == false ? "Restarted, but not active afterwards." : "Restarted and active."
    when "refresh_reports"
      sent = Array(details["reports_sent"])
      "Sent: #{sent.join(', ')}." if sent.any?
    end
  end

  # The short line under a task's state in the list and on batch rows.
  def task_state_note(task, batch_size: 1)
    host = task.host.name
    case task.state
    when "queued" then "Waits for #{host} to poll. Expires #{task_time(task.expires_at)}."
    when "claimed" then "Delivered to #{host}, not started yet. Lease until #{task_time(task.lease_expires_at)}."
    when "running"
      if task.cancel_requested? && task.interruptible?
        "Stop requested; it ends when the agent stops."
      elsif task.cancel_requested?
        "Cannot be stopped safely; it runs to completion.#{" Nothing further in batch #{task.task_batch_id} starts." if batch_size > 1}"
      else
        "Started #{task_time(task.started_at)}. Times out at #{task_time(task_deadline(task))}."
      end
    when "succeeded" then task_success_summary(task)
    when "failed", "refused" then "#{task_reason(task.reason).first.upcase_first}."
    when "timed_out" then task.agent_result? ? "Stopped by the agent after #{task_duration(task.timeout)}." : "No result within #{task_duration(task.timeout)} and the grace period."
    when "cancelled" then task_cancelled_note(task)
    when "expired" then "#{host} did not poll within #{task_duration(task.expires_at - task.created_at)}. Never delivered."
    end
  end

  def task_cancelled_note(task)
    if task.agent_result? then "Stopped while running."
    elsif task.claimed_at then "Picked up by the agent but not started. Never ran."
    else "Cancelled before delivery. Never ran."
    end
  end

  # The batch counts strip: [label, count, lamp class] for each cell. The running cell says "cancel requested" when
  # every running task has one.
  def task_strip_cells(counts, tasks)
    STRIP.map do |label, states, lamp|
      count = counts.values_at(*states).sum
      if lamp == "running" && count.positive? && tasks.select { |task| task.state == "running" }.all?(&:cancel_requested?)
        [ "Running, cancel requested", count, "s-cancel-req" ]
      else
        [ label, count, "s-#{lamp}" ]
      end
    end
  end

  # The bar's segments: [state, count], in BAR order, leaving out states with none. Widths are grow classes, not
  # inline styles, so the CSP can forbid them; a batch has at most 25 tasks.
  def task_bar_segments(counts) = BAR.filter_map { |state| [ state, counts[state] ] if counts[state].to_i.positive? }

  # "5 succeeded, 1 failed, 1 running, 1 waiting."
  def task_bar_sentence(counts)
    waiting = counts.values_at("queued", "claimed").sum
    parts = (BAR - %w[claimed queued]).filter_map { |state| "#{counts[state]} #{task_state_label(state).downcase}" if counts[state].to_i.positive? }
    parts << "#{waiting} waiting" if waiting.positive?
    "#{parts.join(', ')}."
  end

  # Batch rows, problems first.
  def task_batch_rows(tasks) = tasks.sort_by { |task| [ ROW_ORDER.index(task.state), task.host.name.to_s, task.id ] }

  # The outcome notice over a finished batch: [css class, headline, sentence].
  def task_batch_outcome(counts)
    total = counts.values.sum
    succeeded = counts["succeeded"]
    return [ "info", "Finished: #{pluralize(succeeded, 'task')} succeeded.", nil ] if succeeded == total

    others = (BAR - %w[succeeded running claimed queued]).filter_map do |state|
      next unless counts[state].positive?

      "#{counts[state]} #{state == 'refused' ? 'refused by the VM or the server' : task_state_label(state).downcase}"
    end
    problems = counts.values_at(*PROBLEM_STATES).sum.positive?
    headline = "Finished: #{succeeded} succeeded, #{total - succeeded} did not."
    [ (problems ? "error" : nil), headline, "#{others.to_sentence.upcase_first}. Each host's row says why." ]
  end

  # One row of a task's timeline: the server's time, the agent's own time when it reported one, the state the task
  # entered (or nil), what happened, and the audit entry it comes from (nil for the last progress report).
  TimelineRow = Data.define(:at, :agent_at, :state, :words, :entry)

  # The task's timeline (mockup task.html#timeline, Q18): its audit entries, which are exactly its state changes and
  # cancel requests, plus the last progress report. Ordered by server time.
  def task_timeline(task, entries)
    rows = entries.filter_map { |entry| task_timeline_row(task, entry) }
    if task.progress_reported_at
      rows << TimelineRow.new(at: task.progress_reported_at, agent_at: nil, state: nil, words: "Last progress report#{": #{task.progress_percent}% done" if task.progress_percent}.", entry: nil)
    end
    rows.each_with_index.sort_by { |row, index| [ row.at, index ] }.map(&:first)
  end

  # "2 min 5 s" when the agent's clock and the server's differ by more than a minute, else nil.
  def task_clock_skew(server_at, agent_at)
    seconds = (server_at - agent_at).abs.round
    return nil if seconds <= 60

    human_duration(seconds) || "#{seconds} s"
  end

  # Hosts whose finished package update said a reboot is required.
  def task_reboot_hosts(tasks) = tasks.select { |task| task.state == "succeeded" && task.result_details.to_h["reboot_required"] }.map { |task| task.host.name }

  private

  def task_timeline_row(task, entry)
    to = entry.changeset.is_a?(Hash) && entry.changeset["state"].is_a?(Array) ? entry.changeset["state"].last : nil
    host = task.host.name
    by_host = entry.actor_type == "host"
    row = ->(words, state: to, agent_at: nil) { TimelineRow.new(at: entry.occurred_at, agent_at:, state:, words:, entry:) }
    case entry.action
    when Audit::Actions::TASK_CREATED then row.("Created#{" in batch #{task.task_batch_id}" if task.task_batch.tasks.size > 1}.", state: "queued")
    when Audit::Actions::TASK_CLAIMED then row.("Delivered to #{host} on its poll.")
    when Audit::Actions::TASK_REQUEUED then row.("Back in the queue: the agent did not start it before its lease lapsed.")
    when Audit::Actions::TASK_STARTED then row.("The agent recorded the task and started it.", agent_at: task.agent_started_at)
    when Audit::Actions::TASK_CANCEL_REQUESTED
      row.(task.interruptible? ? "Cancel requested: the agent is told to stop." : "Cancel requested: it cannot be stopped safely and runs to completion.", state: nil)
    when Audit::Actions::TASK_LATE_RESULT
      late = task.late_result
      row.("A result arrived after the server had ended the task: #{task_state_label(entry.changeset['outcome']).downcase}. Kept beside it; the state does not change.", state: nil, agent_at: late&.agent_finished_at)
    when Audit::Actions::TASK_RESULT_CONFLICT then row.("A result that did not match was refused and not applied.", state: nil)
    else
      task_finish_row(task, entry, to, by_host, row)
    end
  end

  def task_finish_row(task, entry, to, by_host, row)
    reason = entry.changeset["reason"] if entry.changeset.is_a?(Hash)
    words = if by_host
      exit_status = entry.changeset["exit_status"] if entry.changeset.is_a?(Hash)
      "Result received#{": exit status #{exit_status}" unless exit_status.nil?}#{", #{human_bytes(task.output.bytesize)} of output" if task.output && to == task.state}#{" (#{reason})" if reason}."
    else
      case to
      when "expired" then "Not picked up before its expiry. Never delivered."
      when "timed_out" then "No result within the time limit and the grace period."
      when "failed" then reason == "lease_expired" ? "The agent stopped reporting before its lease ran out." : "Failed (#{reason})."
      when "refused" then "Refused when the agent claimed it (#{reason}). Nothing ran."
      else entry.actor_type == "operator" ? "Cancelled by an operator." : "Cancelled." # the system cancels a revoked host's tasks with its event's actor
      end
    end
    row.(words, agent_at: (task.agent_finished_at if by_host && to == task.state))
  end
end
