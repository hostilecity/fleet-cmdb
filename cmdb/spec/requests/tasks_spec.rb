require "rails_helper"

# The task list, a task's page, its output download, batch progress, and a host's Tasks tab (FR-3.4, P3-DASH-TASKS;
# mockups tasks.html, task.html, task-states.html, batch.html, batch-partial.html, host-tasks.html).
RSpec.describe "Tasks pages", type: :request do
  include_context "signed in operator"

  before { enrol_second_factor(operator) }

  def run(task, at: Time.current)
    task.claim!(actor: task.host, lease_expires_at: at + 5.minutes, now: at)
    task.start!(actor: task.host, lease_expires_at: at + 1.hour, agent_started_at: at, now: at)
  end

  def report(details = nil) = { result_report_id: SecureRandom.uuid, result_digest: SecureRandom.hex(32), result_received_at: Time.current, result_details: details }

  def rows(selector) = page.css("#{selector} tbody tr")

  describe "the list" do
    it "shows every task newest first with its state in words, and filters by state, type, host, and batch" do
      web = task_host(name: "sim-001", hostname: "sim-001.example.lan")
      db = task_host(name: "sim-002", hostname: "sim-002.example.lan")
      allow_restart("nginx.service")
      batch = create_task_batch([ web, db ], type: "restart_service", parameters: { "service" => "nginx.service" })
      single = create_task(task_host(name: "sim-003"))
      run(batch.tasks.first).succeed!(actor: web, exit_status: 0, report: report("unit_active" => true))
      single.expire!(actor: Audit::SYSTEM)

      get "/tasks"
      expect(response).to have_http_status(:ok)
      expect(rows("#task_list").map { |row| row.at_css("td").text }).to eq([ "##{single.id}", "##{batch.tasks.last.id}", "##{batch.tasks.first.id}" ])
      expect(rows("#task_list").first.text).to include("Expired", "Single", "did not poll within 1 day")
      expect(rows("#task_list").last.text).to include("Restart a service: nginx.service", "Succeeded", "Restarted and active.", "(2 hosts)")
      expect(page.css(".chips a").map { |a| a.text.squish }).to eq([ "All 3", "Waiting or running 1", "Failed, timed out, refused, or expired 1", "Succeeded 1", "Cancelled 0" ])
      expect(page.at_css("a[href='/tasks/new']")).to be_present

      get "/tasks", params: { state: "problem" }
      expect(rows("#task_list").size).to eq(1)
      expect(page.at_css(".chips a[aria-current=true]").text).to start_with("Failed")
      get "/tasks", params: { state: "queued", type: "restart_service" }
      expect(rows("#task_list").map { |row| row.at_css("td").text }).to eq([ "##{batch.tasks.last.id}" ])
      get "/tasks", params: { host: "SIM-002.example" }
      expect(rows("#task_list").size).to eq(1)
      get "/tasks", params: { batch: batch.batch.id.to_s }
      expect(rows("#task_list").size).to eq(2)
      get "/tasks", params: { host: "nothing%here" }
      expect(page.at_css("#no_matches").text).to include("No tasks match these filters.")

      # The form sends every field; the address keeps only the ones in use. Unknown values are ignored.
      get "/tasks", params: { host: "", type: "restart_service", state: "", batch: "" }
      expect(response).to redirect_to("/tasks?type=restart_service")
      get "/tasks", params: { type: "run_shell", state: "nope", batch: "0x1" }
      expect(rows("#task_list").size).to eq(3)
    end

    it "pages newest first with keyset links" do
      host = task_host
      tasks = Array.new(3) { create_task(host) }
      stub_const("TaskList::PER_PAGE", 2)
      get "/tasks"
      expect(rows("#task_list").size).to eq(2)
      expect(page.at_css(".pager .off").text).to eq("Newer")
      get page.at_css(".pager a[rel=next]")["href"]
      expect(rows("#task_list").map { |row| row.at_css("td").text }).to eq([ "##{tasks.first.id}" ])
      get page.at_css(".pager a[rel=prev]")["href"]
      expect(rows("#task_list").map { |row| row.at_css("td").text }).to eq([ "##{tasks.last.id}", "##{tasks[1].id}" ])
      expect(page.at_css(".pager a[rel=next]")).to be_present
      expect(page.at_css(".pager a[rel=prev]")).to be_nil
    end

    it "has empty states, and explains create and cancel without a second factor (Q12)" do
      get "/tasks"
      expect(page.at_css("#no_tasks").text).to include("No tasks yet.")
      SecondFactor.where(operator:).delete_all
      get "/tasks"
      expect(page.at_css("#no_second_factor")).to be_present
      expect(page.css("a[href='/tasks/new']")).to be_empty
    end
  end

  describe "a task's page" do
    it "shows a finished package update: result, reboot, facts, timeline with both clocks, escaped output, and audit entries" do
      host = task_host(name: "sim-021", hostname: "sim-021.example.lan")
      batch = create_task_batch([ host, task_host ], type: "apply_package_updates")
      task = batch.tasks.first
      run(task)
      started = AuditEntry.where(action: Audit::Actions::TASK_STARTED, target_id: task.id).sole.occurred_at
      task.update_columns(agent_started_at: started - 3.minutes, progress_percent: 40, progress_reported_at: started) # the VM's clock is behind
      task.succeed!(actor: host, exit_status: 0, output: "$ apt-get upgrade\n<script>alert(1)</script>\n", agent_started_at: started - 3.minutes, agent_finished_at: started + 1.minute,
                    report: report("reboot_required" => true, "services_needing_restart" => %w[nginx.service cron.service]), now: started + 4.minutes)
      get "/tasks/#{task.id}"
      expect(response).to have_http_status(:ok)
      expect(page.at_css("h1").text).to eq("Task ##{task.id}: Apply package updates on sim-021")
      expect(page.at_css("#result h2").text).to start_with("Succeeded in 4 min 0 s: Reboot required. 2 services use old libraries.")
      expect(page.at_css("#task_details").text).to include("nginx.service, cron.service", "Exit status")
      expect(page.at_css("#task_facts").text).to include("apply_package_updates", "sim-021.example.lan", "Not once running")
      timeline = rows("#task_timeline").map { |row| row.text.squish }
      expect(timeline.size).to eq(5)
      expect(timeline[0]).to include("Queued Created in batch #{batch.batch.id}.")
      expect(timeline[2]).to include("Running The agent recorded", "Clock differs by 3 minutes")
      expect(timeline).to include(a_string_including("Last progress report: 40% done."), a_string_including("Succeeded Result received: exit status 0, 44 bytes of output."))
      expect(page.at_css("#task_output").inner_html).to include("&lt;script&gt;alert(1)&lt;/script&gt;")
      expect(page.css("#task_output script")).to be_empty
      expect(rows("#task_audit").size).to eq(4)
      expect(page.css("#cancel_link")).to be_empty

      get "/tasks/#{task.id}/output"
      expect(response.media_type).to eq("text/plain")
      expect(response.headers["Content-Disposition"]).to start_with("attachment;")
      expect(response.body).to eq(task.output)
      get "/tasks/#{batch.tasks.last.id}/output"
      expect(response).to have_http_status(:not_found)
    end

    it "says what each state means in plain words" do
      host = task_host(name: "sim-028")
      queued = create_task(host)
      get "/tasks/#{queued.id}"
      expect(page.at_css("#result h2").text).to eq("Queued: waiting for sim-028 to poll")
      expect(page.at_css("#cancel_link").text).to eq("Cancel task")
      expect(page.at_css("#no_output").text).to eq("Output appears when the task finishes.")

      claimed = create_task(task_host)
      claimed.claim!(actor: claimed.host, lease_expires_at: 5.minutes.from_now)
      claimed.requeue!(actor: Audit::SYSTEM)
      claimed.claim!(actor: claimed.host, lease_expires_at: 5.minutes.from_now)
      get "/tasks/#{claimed.id}"
      expect(page.at_css("#result h2").text).to start_with("Claimed: delivered to")
      expect(rows("#task_timeline").map(&:text).join).to include("Back in the queue: the agent did not start it before its lease lapsed.")
      get "/tasks", params: { state: "claimed" }
      expect(rows("#task_list").sole.text).to include("not started yet. Lease until")

      stoppable = run(create_task(task_host))
      get "/tasks/#{stoppable.id}"
      expect(page.at_css("#result h2").text).to start_with("Running for")
      expect(page.at_css("#cancel_link").text).to eq("Stop task")
      stoppable.request_cancel!(operator:)
      get "/tasks", params: { state: "running" }
      expect(page.at_css("#task_list").text).to include("Stop requested; it ends when the agent stops.")
      unstoppable = run(create_task(task_host, type: "apply_package_updates"))
      get "/tasks/#{unstoppable.id}"
      expect(page.at_css("#cancel_link").text).to eq("Request cancel")
      expect(page.at_css("#result .code-line").text).to eq("Cannot be cancelled once running")
      unstoppable.request_cancel!(operator:)
      get "/tasks/#{unstoppable.id}"
      expect(page.at_css("#result h2").text).to start_with("Running, cancel requested at")
      expect(page.at_css("#result").text).to include("cannot be stopped safely once started, so it runs to completion")
      expect(page.css("#cancel_link")).to be_empty
      unstoppable.fail!(actor: unstoppable.host, reason: "lock_timeout", exit_status: 100, report: report)
      get "/tasks/#{unstoppable.id}"
      expect(page.at_css("#result h2").text).to eq("Failed: package manager busy")
      expect(page.at_css("#result .code-line").text).to eq("Reason lock_timeout · exit status 100")
      expect(page.at_css("#cancel_was_requested").text).to include("it could not be stopped")

      lapsed = run(create_task(task_host))
      lapsed.fail!(actor: Audit::SYSTEM, reason: "lease_expired")
      get "/tasks/#{lapsed.id}"
      expect(page.at_css("#result h2").text).to eq("Failed: the agent stopped reporting")
      expect(page.at_css("#result .code-line").text).to eq("Reason lease_expired · set by the server")
      expect(rows("#task_timeline").last.text).to include("The agent stopped reporting before its lease ran out.")

      interrupted = run(create_task(task_host))
      interrupted.fail!(actor: interrupted.host, reason: "interrupted", report: report)
      get "/tasks/#{interrupted.id}"
      expect(page.at_css("#result").text).to include("The task was not run again.")

      refused = create_task(task_host)
      refused.refuse!(actor: Audit::SYSTEM, reason: "not_allowed_on_server")
      get "/tasks/#{refused.id}"
      expect(page.at_css("#result h2").text).to eq("Refused: no longer allowed")
      expect(page.at_css("#result .code-line").text).to include("refused by the server when the agent claimed it")
      agent_refused = run(create_task(task_host))
      agent_refused.refuse!(actor: agent_refused.host, reason: "not_enabled_locally", report: report)
      get "/tasks/#{agent_refused.id}"
      expect(page.at_css("#result .code-line").text).to include("refused by the agent")

      timed_out = run(create_task(task_host, type: "apply_package_updates"))
      timed_out.time_out!(actor: timed_out.host, agent_finished_at: Time.current, report: report)
      get "/tasks/#{timed_out.id}"
      expect(page.at_css("#result").text).to include("dpkg --configure -a")
      silent = run(create_task(task_host))
      silent.time_out!(actor: Audit::SYSTEM)
      get "/tasks/#{silent.id}"
      expect(page.at_css("#result h2").text).to eq("Timed out: no result from the agent")
      expect(rows("#task_timeline").last.text).to include("No result within the time limit")

      expired = create_task(task_host(name: "sim-004"))
      expired.expire!(actor: Audit::SYSTEM)
      get "/tasks/#{expired.id}"
      expect(page.at_css("#result h2").text).to eq("Expired: sim-004 did not poll within 1 day")
      expect(page.at_css("#no_output").text).to eq("No output was recorded.")
    end

    it "says how a task was cancelled, and keeps a late result beside it" do
      queued = create_task(task_host(name: "sim-002"))
      queued.cancel!(actor: operator)
      get "/tasks/#{queued.id}"
      expect(page.at_css("#result").text.squish).to include("Cancelled before it was delivered", "by operator@example.com. sim-002 never received it.")
      expect(rows("#task_timeline").last.text).to include("Cancelled by an operator.")

      claimed = create_task(task_host)
      claimed.claim!(actor: claimed.host, lease_expires_at: 5.minutes.from_now)
      claimed.cancel!(actor: operator)
      get "/tasks/#{claimed.id}"
      expect(page.at_css("#result h2").text).to eq("Cancelled after it was picked up, before it started")

      stopped = run(create_task(task_host))
      stopped.request_cancel!(operator:)
      stopped.cancel!(actor: stopped.host, agent_finished_at: Time.current, report: report)
      get "/tasks/#{stopped.id}"
      expect(page.at_css("#result h2").text).to eq("Cancelled while running")
      expect(rows("#task_timeline").map(&:text).join).to include("Cancel requested: the agent is told to stop.")

      late = run(create_task(task_host))
      late.time_out!(actor: Audit::SYSTEM)
      payload = { "report_id" => SecureRandom.uuid, "outcome" => "succeeded", "exit_status" => 0, "started_at" => Time.current.iso8601, "finished_at" => Time.current.iso8601, "output" => "<b>late</b>" }
      AgentTasks.record_result!(host: late.host, task: late, payload:)
      AgentTasks.record_result!(host: late.host, task: late, payload: payload.merge("report_id" => SecureRandom.uuid, "outcome" => "failed", "reason" => "agent_error"))
      get "/tasks/#{late.id}"
      expect(page.at_css("#late_result + p").text).to include("The agent reported succeeded", "after the server had ended the task as timed out")
      expect(page.at_css("#late_output").inner_html).to eq("&lt;b&gt;late&lt;/b&gt;")
      expect(rows("#task_timeline").map(&:text).join).to include("A result arrived after the server had ended the task: succeeded.", "A result that did not match was refused")
    end

    it "answers 404 for a task that does not exist" do
      get "/tasks/999999"
      expect(response).to have_http_status(:not_found)
    end
  end

  describe "batch progress" do
    it "counts every state from the task rows, lists problems first, and the hosts left out as recorded" do
      hosts = %w[sim-021 sim-026 sim-027 sim-028].map { |name| task_host(name:) }
      left_out = create(:host, :revoked, name: "sim-029")
      result = create_task_batch(hosts + [ left_out ], type: "apply_package_updates", confirm_host_count: 4)
      succeeded, failed, running, = result.tasks
      run(succeeded).succeed!(actor: succeeded.host, exit_status: 0, report: report("reboot_required" => true))
      run(failed).fail!(actor: failed.host, reason: "lock_timeout", exit_status: 100, report: report)
      run(running)

      get "/tasks/batches/#{result.batch.id}"
      expect(response).to have_http_status(:ok)
      expect(page.at_css("h1").text).to eq("Batch #{result.batch.id}: Apply package updates on 4 hosts")
      expect(page.at_css("#batch_outcome").text).to include("In progress: 2 of 4 finished.", "Queued tasks expire at")
      expect(page.css("#batch_counts a").map { |cell| cell.css("span").map(&:text).join(" ") }).to eq([ "1 Waiting", "1 Running", "1 Succeeded", "1 Failed", "0 Timed out", "0 Refused", "0 Expired", "0 Cancelled" ])
      expect(page.css(".bar-stack span").map { |span| span["class"] }).to eq([ "b-succeeded g-1", "b-failed g-1", "b-running g-1", "b-queued g-1" ])
      expect(page.at_css(".bar-legend").text).to eq("1 succeeded, 1 failed, 1 running, 1 waiting. 1 of the 1 that succeeded needs a reboot; the task never reboots.")
      expect(rows("#batch_tasks").map { |row| row.at_css("td").text }).to eq(%w[sim-026 sim-027 sim-028 sim-021])
      expect(rows("#batch_excluded").sole.css("td").map(&:text)).to eq([ "sim-029", "Not active when the batch was created." ])
      expect(page.at_css("#cancel_link").text).to eq("Cancel the rest of this batch")
      expect(page.at_css("turbo-cable-stream-source#tasks_stream")).to be_present
      expect(page.at_css("#run_again")).to be_nil

      running.request_cancel!(operator:)
      TaskCancellation.cancel_batch!(result.batch, operator:)
      get "/tasks/batches/#{result.batch.id}"
      expect(page.at_css("#batch_outcome").text).to include("Cancel requested. 1 task was already running and is finishing.", "Nothing further in this batch will start.")
      expect(page.css("#batch_counts a")[1].css("span").map(&:text)).to eq([ "1", "Running, cancel requested" ])
      expect(page.at_css(".host-head .sub").text).to include("Cancel requested")
      expect(page.css("#cancel_link")).to be_empty

      running.succeed!(actor: running.host, exit_status: 0, report: report)
      get "/tasks/batches/#{result.batch.id}"
      expect(page.at_css("#batch_outcome").text.squish).to include("Finished: 2 succeeded, 2 did not.", "1 failed and 1 cancelled. Each host's row says why.", "1 host needs a reboot (sim-021).")
      expect(page.at_css("#batch_outcome")["class"]).to include("error")
      again = page.at_css("#run_again")
      expect(again.text).to eq("Run again on the 2 hosts that did not succeed")
      expect(again["href"]).to start_with("/tasks/new/confirm?")
      expect(Rack::Utils.parse_nested_query(URI(again["href"]).query)).to eq("type" => "apply_package_updates", "target" => { "host_ids" => [ failed.host_id, result.tasks.last.host_id ].map(&:to_s) })
    end

    it "says plainly when every task succeeded" do
      result = create_task_batch([ task_host ])
      run(result.tasks.sole).succeed!(actor: result.tasks.sole.host, exit_status: 0, report: report("reports_sent" => %w[inventory]))
      get "/tasks/batches/#{result.batch.id}"
      expect(page.at_css("#batch_outcome").text.squish).to eq("Finished: 1 task succeeded.")
      expect(rows("#batch_tasks").sole.text).to include("Sent: inventory.")
    end
  end

  describe "a host's Tasks tab" do
    it "shows what the agent will run, what is open now, and its history" do
      host = task_host(name: "sim-021", types: %w[refresh_reports restart_service apply_package_updates], enabled: %w[refresh_reports apply_package_updates])
      done = run(create_task(host, type: "apply_package_updates"))
      done.succeed!(actor: host, exit_status: 0, report: report("reboot_required" => true))
      running = run(create_task(host))
      create_task(host)

      get "/hosts/#{host.id}/tasks"
      expect(response).to have_http_status(:ok)
      expect(page.at_css("nav.tabs a[aria-current=page]").text.squish).to eq("Tasks 1 running")
      expect(rows("#capabilities").map { |row| row.text.squish }).to eq([ "Refresh reports Enabled", "Restart a service Not enabledTurned off in the VM's configuration (the default).", "Apply package updates Enabled" ])
      expect(page.css("#now p.intro").size).to eq(2)
      expect(page.at_css("#now").text).to include("##{running.id}", "The agent runs one task at a time.")
      expect(page.at_css("#reboot_required").text).to include("##{done.id}")
      expect(rows("#host_task_history").size).to eq(3)
      expect(page.at_css("#run_task")["href"]).to eq("/tasks/new?target%5Bhost_ids%5D%5B%5D=#{host.id}")
      expect(page.at_css("a[href^='/tasks?host=']")["href"]).to eq("/tasks?host=#{host.hostname}")
    end

    it "says when the agent has not reported its task types or nothing has run" do
      host, = enrolled_host
      get "/hosts/#{host.id}/tasks"
      expect(page.at_css("#capabilities").text).to include("has not reported which tasks it runs")
      expect(page.at_css("#now").text).to include("Nothing is waiting or running.")
      expect(page.at_css("#no_history")).to be_present
      host2 = task_host(types: %w[refresh_reports])
      create_task(host2)
      get "/hosts/#{host2.id}/tasks"
      expect(page.at_css("nav.tabs a[aria-current=page]").text.squish).to eq("Tasks 1 waiting")
      expect(rows("#capabilities").map { |row| row.text.squish }).to include(a_string_starting_with("Restart a service Not supported"))
    end
  end
end
