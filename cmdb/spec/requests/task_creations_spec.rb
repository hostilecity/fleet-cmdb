require "rails_helper"

# The create-task flow (FR-3.4, P3-S08; mockups create-type.html, create-params.html, create-targets.html,
# create-confirm.html, create-blocked.html). Four GET steps, then one POST that needs a recent second factor and the
# confirmation page's token, re-checked on the server however the request was made (AC-3.1 through the dashboard).
RSpec.describe "Creating a task", type: :request do
  include_context "signed in operator"

  let(:secret) { @secret }

  before { @secret = enrol_second_factor(operator).first }

  def code = totp_code(secret)

  def refusals = AuditEntry.where(action: Audit::Actions::TASK_CREATION_REFUSED).order(:id)

  # The confirmation page for this request, and its form's fields as the browser would send them.
  def confirm(type:, target:, parameters: {})
    get "/tasks/new/confirm", params: { type:, parameters:, target: }
    expect(response).to have_http_status(:ok), response.body[/<div class="notice error".*?<\/div>/m]
    form_fields
  end

  def form_fields(form = "#create_task")
    page.css("#{form} input[type=hidden]").each_with_object({}) do |input, fields|
      name = input["name"]
      next if name == "authenticity_token"

      if name.end_with?("[]")
        (fields[name] ||= []) << input["value"]
      else
        fields[name] = input["value"]
      end
    end
  end

  def submit(fields, **extra) = post("/tasks", params: fields.merge(extra.transform_keys(&:to_s)))

  describe "without a second factor (Q12)" do
    before { SecondFactor.where(operator:).delete_all }

    it "replaces the flow with an explanation, and refuses a create request on the server with an audit entry" do
      host = task_host
      [ "/tasks/new", "/tasks/new/parameters?type=refresh_reports", "/tasks/new/targets?type=refresh_reports" ].each do |path|
        get path
        expect(response).to have_http_status(:ok)
        expect(page.at_css(".notice[role=alert]").text).to include("You cannot create or cancel tasks until you set up a second factor.")
        expect(page.at_css("a.btn")["href"]).to eq("/settings/second-factor")
      end
      get "/tasks"
      expect(page.at_css("#no_second_factor")).to be_present
      expect(page.css("a[href='/tasks/new']")).to be_empty

      post "/tasks", params: { type: "refresh_reports", target: { host_ids: [ host.id ] } }
      expect(response).to have_http_status(:forbidden)
      expect(TaskBatch.count).to eq(0)
      expect(refusals.sole.changeset).to eq("task_type" => "refresh_reports", "problems" => [ "/second_factor_code is not set up, so tasks cannot be created" ])
      expect(refusals.sole.actor_id).to eq(operator.id)
      expect(page.text).to include("You have no second factor")
    end
  end

  describe "step 1: the task type" do
    it "lists the catalog with exactly what each type does, its limits, and how many hosts will run it" do
      task_host
      task_host(types: %w[refresh_reports], enabled: %w[refresh_reports])
      create(:host, :active)
      allow_restart("nginx.service")
      get "/tasks/new"
      expect(response).to have_http_status(:ok)
      expect(page.at_css("nav a[aria-current=page]").text).to eq("Tasks")
      expect(page.at_css("ol.flow li[aria-current=step]").text).to eq("Task type")
      choices = page.css("form .catalog label.choice")
      expect(choices.map { |choice| choice.at_css("input[type=radio]")["value"] }).to eq(TaskCatalog.current.types)
      restart = choices[1]
      expect(restart.at_css("p").text).to eq(TaskCatalog.current.entry("restart_service").description)
      expect(restart.css(".props li").map(&:text)).to eq([ "Can be cancelled while running: no", "Time limit: 5 minutes", "Enabled on agents by default: no", "Hosts that will run it: 1 of 3" ])
      expect(choices[0].css(".props li").last.text).to eq("Hosts that will run it: 2 of 3")
      expect(choices[0].at_css("input")["checked"]).to eq("checked")
      expect(page.at_css("#no_agent_runs_tasks")).to be_nil
    end

    it "draws a type unavailable, with why, when nothing can run it, and says when no agent runs tasks at all" do
      create(:host, :active)
      get "/tasks/new"
      expect(page.at_css("#no_agent_runs_tasks").text).to include("No host can run tasks yet.")
      expect(page.css(".notice.error").map(&:text).join).to include("No task can be created now.")
      expect(page.css("form .catalog")).to be_empty
      expect(page.at_css("#unavailable_restart_service .why-off").text).to include("allowlist of restartable services is empty")
      expect(page.at_css("#unavailable_apply_package_updates .why-off").text).to include("No host will run this yet", "off by default on every VM")
      expect(page.at_css("#unavailable_refresh_reports .why-off").text).not_to include("off by default")
    end

    it "keeps a type chosen earlier, and a target carried from another page" do
      task_host
      host = task_host
      get "/tasks/new", params: { type: "apply_package_updates", target: { host_ids: [ host.id ] } }
      expect(page.at_css("#type_apply_package_updates")["checked"]).to eq("checked")
      expect(page.at_css("#type_refresh_reports")["checked"]).to be_nil
      expect(form_fields("form[action='/tasks/new/parameters']")).to eq("target[host_ids][]" => [ host.id.to_s ])
      # A link such as a host page's "Run a task on this host" (#33) carries the host through to the targets step.
      get "/tasks/new/parameters", params: { type: "apply_package_updates", target: { host_ids: [ host.id ] } }
      expect(form_fields("form[action='/tasks/new/targets']")).to eq("type" => "apply_package_updates", "target[host_ids][]" => [ host.id.to_s ])
      get "/tasks/new/targets", params: { type: "apply_package_updates", target: { host_ids: [ host.id ] } }
      expect(page.css("#pick input[checked]").map { |input| input["value"] }).to eq([ host.id.to_s ])
      expect(page.at_css("#targeted").text).to eq("1 host will get this task")
    end

    it "shows a type the dashboard has no control for as unavailable, never as a text box" do
      data = JSON.parse(TaskCatalog::PATH.read)
      data["tasks"] << data["tasks"][1].merge("type" => "rotate_logs", "name" => "Rotate logs", "since" => 1)
      allow(TaskCatalog).to receive(:current).and_return(TaskCatalog.send(:build, data, "0" * 64))
      task_host(types: TaskCatalog.current.types)
      get "/tasks/new"
      expect(page.at_css("#unavailable_rotate_logs .why-off").text).to include("no control for this type's parameters")
      get "/tasks/new/parameters", params: { type: "rotate_logs" }
      expect(page.at_css("#no_form").text).to include("cannot set this task's parameters")
      expect(page.css("form")).to be_empty.or(satisfy { |forms| forms.all? { |form| form["action"] == "/sign_out" } })
    end
  end

  describe "step 2: parameters" do
    it "offers the restart service only from the allowlist, naming the tags it is allowed for (Q5)" do
      allow_restart("nginx.service", tag: "web")
      allow_restart("nginx.service", tag: "db")
      allow_restart("chrony.service")
      get "/tasks/new/parameters", params: { type: "restart_service" }
      expect(response).to have_http_status(:ok)
      expect(page.css("#service option").map { |option| [ option["value"], option.text ] })
        .to eq([ [ "", "Choose a service" ], [ "chrony.service", "chrony.service" ], [ "nginx.service", "nginx.service (tags db, web only)" ] ])
      expect(page.at_css("#service_hint").text.squish).to include("2 services", "nginx.service is allowed only on hosts tagged db or web.")
      expect(page.css("main input[type=text], main textarea")).to be_empty
      expect(page.css("ol.flow li.done a").map { |a| a["href"] }).to eq([ "/tasks/new?type=restart_service" ])
    end

    it "says a type has no parameters, and refuses to go on with a restart when the allowlist is empty" do
      get "/tasks/new/parameters", params: { type: "apply_package_updates" }
      expect(page.text).to include("This task has no parameters.")
      expect(form_fields("form[action='/tasks/new/targets']")).to eq("type" => "apply_package_updates")

      get "/tasks/new/parameters", params: { type: "restart_service" }
      expect(page.at_css("#empty_allowlist").text).to include("There is no service you can restart.")
      expect(page.css("#service")).to be_empty
    end

    it "sends an unknown or missing type back to the first step" do
      get "/tasks/new/parameters", params: { type: "run_shell" }
      expect(response).to redirect_to("/tasks/new")
      expect(flash[:alert]).to eq("That is not a task type in the catalog. Choose one of these.")
      get "/tasks/new/targets"
      expect(flash[:alert]).to eq("Choose a task type.")
      get "/tasks/new/confirm", params: { type: [ "restart_service" ] }
      expect(response).to redirect_to("/tasks/new")
    end

    it "shows errors in place when the service is not allowed, however the request was made" do
      allow_restart("nginx.service")
      get "/tasks/new/targets", params: { type: "restart_service", parameters: { service: "postgresql.service" } }
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#parameter_errors").text).to include("Check the parameters.", "1 problem: the service is not on the server's restart allowlist.")
      expect(page.at_css(".field.invalid #service")["aria-invalid"]).to eq("true")
      expect(page.at_css("#service_error").text).to eq("postgresql.service is not on the server's restart allowlist.")

      get "/tasks/new/targets", params: { type: "restart_service" }
      expect(page.at_css("#service_error").text).to eq("Choose a service.")
      get "/tasks/new/confirm", params: { type: "refresh_reports", parameters: { command: "reboot" } }
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#parameter_errors").text).to include("the parameter command is not a parameter of refresh_reports")
    end
  end

  describe "step 3: targets" do
    it "resolves a tag to the hosts that get the task and those left out with why, warning about offline hosts (Q7, Q8)" do
      allow_restart("nginx.service", tag: "web")
      online = task_host(name: "sim-001", tags: %w[web])
      online.update_columns(liveness_status: "online", agent_version: "0.9.0", last_seen_at: 1.minute.ago)
      offline = task_host(name: "sim-004", tags: %w[web])
      offline.update_columns(liveness_status: "offline", last_seen_at: 3.hours.ago)
      task_host(name: "sim-006", tags: %w[web], enabled: %w[refresh_reports])
      task_host(name: "sim-007", tags: %w[web], services: %w[chrony.service])
      create(:host, :active, name: "sim-009", tags: %w[web], agent_version: "0.8.3")
      create(:host, :revoked, name: "sim-010", tags: %w[web])
      task_host(name: "sim-011", tags: %w[db])

      get "/tasks/new/targets", params: { type: "restart_service", parameters: { service: "nginx.service" } }
      expect(response).to have_http_status(:ok)
      expect(page.at_css("h1").text).to eq("New task: Restart nginx.service")
      expect(page.css("#tag option").map(&:text)).to eq([ "Choose a tag", "db (1 host)", "web (6 hosts)" ])
      expect(page.at_css("#targeted")).to be_nil

      get "/tasks/new/targets", params: { type: "restart_service", parameters: { service: "nginx.service" }, by: "tag", tag: "web" }
      expect(page.at_css("#targeted").text).to eq("2 hosts will get this task")
      rows = page.css("#targeted + .table-wrap tbody tr")
      expect(rows.map { |row| row.at_css("td").text }).to eq(%w[sim-001 sim-004])
      expect(rows[1].at_css(".state-sub.warn").text).to eq("Last seen about 3 hours ago. Its task waits for it and expires after 1 day if it does not ask for it.")
      expect(rows[0].at_css(".state-sub")).to be_nil
      expect(page.at_css("#excluded").text).to eq("4 hosts tagged web are left out")
      reasons = page.css("#excluded + .table-wrap tbody tr").to_h { |row| [ row.at_css("a").text, row.css("td")[1].text.squish ] }
      expect(reasons).to eq(
        "sim-006" => "Not enabled on this VM. Its agent reports that restart_service is not enabled in its configuration. Enabling it is an edit on the VM itself.",
        "sim-007" => "Not in this VM's own allowlist. Its agent does not list nginx.service in its own allowlist, so it would refuse the task.",
        "sim-009" => "Agent does not support tasks. Agent 0.8.3 has not reported which tasks it runs. Tasks need an agent that does (Agents).",
        "sim-010" => "Not active. Its credential was revoked. Only active hosts get tasks."
      )
      expect(page.text).to include("Each VM also has its own list of services it allows.")
      expect(form_fields("form[action='/tasks/new/confirm']")).to eq("type" => "restart_service", "parameters[service]" => "nginx.service", "target[tag]" => "web")
      expect(page.at_css("form[action='/tasks/new/confirm'] button").text).to eq("Next: confirm 2 hosts")
    end

    it "lets hosts be picked, saying which can run the task, and names every reason a host is left out" do
      allow_restart("nginx.service", tag: "web")
      web = task_host(name: "sim-001", tags: %w[web])
      db = task_host(name: "sim-011", tags: %w[db])
      old = task_host(name: "sim-012", tags: %w[web], types: %w[refresh_reports], agent_version: "0.8.3")
      moved = task_host(name: "sim-013", tags: %w[web])
      moved.update_columns(machine_id_mismatch_at: Time.current)
      pending = create(:host, name: "sim-014")
      retired = create(:host, :retired, name: "sim-015", tags: %w[web])
      params = { type: "restart_service", parameters: { service: "nginx.service" } }

      get "/tasks/new/targets", params: params.merge(by: "hosts", q: "sim-01")
      expect(page.css("#pick tbody tr").map { |row| row.css("td")[1].text.split.first }).to eq(%w[sim-011 sim-012 sim-013 sim-014])
      expect(page.css("#pick tbody tr").map { |row| row.css("td").last.text }).to eq([
        "No: service not allowed for this host.", "No: agent does not support this task.", "No: credential in use on another machine.", "No: not active (it has not enrolled yet)."
      ])
      expect(page.at_css("#q")["value"]).to eq("sim-01")

      get "/tasks/new/targets", params: params.merge(by: "hosts", host_ids: [ web, db, old, moved, pending, retired ].map { |host| host.id.to_s })
      expect(page.css("#pick input[type=checkbox][checked]").size).to eq(6)
      expect(page.at_css("#targeted").text).to eq("1 host will get this task")
      expect(page.at_css("#excluded").text).to eq("5 hosts you picked are left out")
      reasons = page.css("#excluded + .table-wrap tbody tr").to_h { |row| [ row.at_css("a").text, row.css("td")[1].text.squish ] }
      expect(reasons).to include(
        "sim-011" => "Service not allowed for this host. nginx.service is allowed only on hosts tagged web.",
        "sim-012" => "Agent does not support this task. Agent 0.8.3 does not run restart_service. A newer agent may (Agents).",
        "sim-013" => start_with("Credential in use on another machine."),
        "sim-014" => "Not active. It has not enrolled yet. Only active hosts get tasks.",
        "sim-015" => "Not active. It is retired. Only active hosts get tasks."
      )
      expect(form_fields("form[action='/tasks/new/confirm']")["target[host_ids][]"]).to eq([ web, db, old, moved, pending, retired ].map { |host| host.id.to_s })

      get "/tasks/new/targets", params: params.merge(by: "hosts", q: "nothing-matches")
      expect(page.text).to include("No host in the fleet matches.")
    end

    it "refuses more hosts than a batch can hold, and says when none of the selected hosts can run it" do
      TaskSettings.update_limits!({ "max_hosts_per_batch" => "2" }, actor: operator)
      hosts = Array.new(3) { task_host(tags: %w[lab]) }
      get "/tasks/new/targets", params: { type: "refresh_reports", by: "tag", tag: "lab" }
      expect(page.at_css("#target_errors").text).to include("That is more hosts than one batch can hold.", "at most 2 hosts")
      expect(page.css("form[action='/tasks/new/confirm']")).to be_empty

      get "/tasks/new/targets", params: { type: "refresh_reports", by: "tag", tag: "nothing" }
      expect(page.at_css("#target_errors").text).to include("The tag selects no host.")

      create(:host, :revoked, tags: %w[db])
      task_host(tags: %w[db], enabled: [])
      get "/tasks/new/targets", params: { type: "refresh_reports", by: "tag", tag: "db" }
      expect(page.at_css("#no_target").text.squish).to eq("None of the 2 hosts tagged db can run this task. 1 not active (its credential was revoked) and 1 not enabled on this VM. Nothing can be created.")

      get "/tasks/new/confirm", params: { type: "refresh_reports", target: { tag: "db" } }
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#no_target")).to be_present
      get "/tasks/new/confirm", params: { type: "refresh_reports", target: { host_ids: hosts.map(&:id) } }
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#target_errors").text).to include("more hosts than one batch can hold")
      expect(page.css("#pick input[checked]").size).to eq(3)
    end

    it "says when no host will run the type at all" do
      task_host(enabled: %w[refresh_reports])
      get "/tasks/new/targets", params: { type: "apply_package_updates" }
      expect(page.at_css("#no_host_runs_type").text).to include('No host will run "Apply package updates".', "off by default on every VM")
      expect(page.css("#selection")).to be_empty
      SecondFactor.none
      Host.update_all(task_types_enabled: [])
      get "/tasks/new/targets", params: { type: "refresh_reports" }
      expect(page.at_css("#no_host_runs_type").text).to include("No active host's agent supports it and has it enabled.")
    end
  end

  describe "step 4: confirm" do
    it "shows exactly what will run, on which hosts, with the typed count and the code box in one form (Q9 to Q11)" do
      allow_restart("nginx.service")
      hosts = Array.new(4) { |index| task_host(name: "sim-00#{index + 1}", tags: %w[web]) }
      hosts.last.update_columns(liveness_status: "offline", last_seen_at: 2.hours.ago)
      task_host(name: "sim-009", tags: %w[web], enabled: %w[refresh_reports])
      fields = confirm(type: "restart_service", parameters: { service: "nginx.service" }, target: { tag: "web" })

      expect(page.at_css("h1").text).to eq("Confirm: restart nginx.service on 4 hosts")
      expect(page.css(".confirm-sum .big").map(&:text)).to eq([ "Restart a service", "nginx.service", "4", "1 day" ])
      expect(page.css(".confirm-sum .detail")[2].text).to eq("Tag web; 1 left out")
      expect(page.at_css(".runs h2").text).to eq("What the agent does on each of the 4 hosts")
      expect(page.css(".runs ol li").size).to eq(3)
      expect(page.css(".runs pre.code").first.text).to eq("/usr/bin/systemctl restart -- nginx.service\n/usr/bin/systemctl is-active -- nginx.service")
      expect(JSON.parse(page.css(".runs pre.code").last.text)).to eq("type" => "restart_service", "parameters" => { "service" => "nginx.service" }, "timeout_seconds" => 300, "catalog_version" => 1)
      expect(page.at_css("#confirm_targeted").text.squish).to eq("4 get the task: sim-001, sim-002, sim-003, sim-004 (offline: runs when it returns, if within 1 day).")
      expect(page.at_css("#confirm_excluded").text).to include("sim-009 (not enabled on this VM)")
      expect(page.text).to include("All hosts run their task within about a minute of each other")
      expect(page.at_css("#confirm_host_count")).to be_present
      expect(page.at_css("#create_task input[name=second_factor_code]")).to be_present
      expect(page.at_css("#create_task button").text).to eq("Create 4 tasks")
      expect(fields.keys).to eq(%w[type parameters[service] target[tag] confirmation])
      # No field the operator types is sent as anything but the count and the code (P3-S08).
      expect(page.css("main input:not([type=hidden]):not([type=radio]):not([type=checkbox])").map { |input| input["name"] }).to eq(%w[confirm_host_count second_factor_code])
      expect(page.css("main textarea")).to be_empty
    end

    it "draws the other types' steps, no count field for 3 hosts or fewer, and an open window as passed" do
      host = task_host(name: "sim-012")
      operator_session = OperatorSession.order(:id).last
      operator_session.update!(second_factor_passed_at: 1.minute.ago)
      confirm(type: "refresh_reports", target: { host_ids: [ host.id ] })
      expect(page.at_css(".runs h2").text).to eq("What the agent does on sim-012")
      expect(page.css(".confirm-sum .big")[1].text).to eq("None")
      expect(page.text).to include("1 host: no number to type.")
      expect(page.css("#confirm_host_count")).to be_empty
      expect(page.at_css(".stepup.passed").text).to include("Checked.")
      expect(page.text).not_to include("All hosts run their task")

      confirm(type: "apply_package_updates", target: { host_ids: [ host.id ] })
      expect(page.css(".runs pre.code").first.text).to start_with("/usr/bin/apt-get update")
      expect(page.css(".runs .never").text).to include("It does not reboot")
    end
  end

  describe "creating the batch" do
    it "creates one task per host with a code and the typed count, audited, and goes to the batch" do
      hosts = Array.new(4) { task_host(tags: %w[lab]) }
      fields = confirm(type: "refresh_reports", target: { tag: "lab" })
      submit(fields, confirm_host_count: "4", second_factor_code: code)

      batch = TaskBatch.sole
      expect(response).to redirect_to("/tasks/batches/#{batch.id}")
      expect(batch.tasks.map(&:host_id)).to eq(hosts.map(&:id))
      expect(batch.attributes.slice("selection_method", "selection_tag", "confirmed_host_count")).to eq("selection_method" => "tag", "selection_tag" => "lab", "confirmed_host_count" => 4)
      expect(batch.confirmation_token).to be_present
      expect(AuditEntry.where(action: [ Audit::Actions::TASK_BATCH_CREATED, Audit::Actions::TASK_CREATED ]).pluck(:actor_id).uniq).to eq([ operator.id ])
      follow_redirect!
      expect(page.at_css(".notice.flash").text).to include("Created 4 tasks in batch #{batch.id}.")
      expect(page.at_css("h1").text).to eq("Batch #{batch.id}: Refresh reports")
      expect(page.css("table.stack tbody tr").size).to eq(4)
      expect(page.text).to include("4 queued")
      expect(refusals).to be_empty

      # The same page submitted again (a double click, a retry) creates nothing new (threat model H10).
      submit(fields, confirm_host_count: "4")
      expect(response).to redirect_to("/tasks/batches/#{batch.id}")
      expect(flash[:notice]).to include("Nothing new was created: this confirmation was already used for batch #{batch.id}")
      expect(TaskBatch.count).to eq(1)

      get "/tasks"
      expect(page.css("table.stack tbody tr td").map(&:text).first(3)).to eq([ "Batch #{batch.id}", "refresh_reports", "4" ])
    end

    it "lists the hosts left out on the batch page" do
      host = task_host
      left_out = create(:host, :revoked, name: "sim-020")
      submit(confirm(type: "refresh_reports", target: { host_ids: [ host.id, left_out.id ] }), second_factor_code: code)
      follow_redirect!
      expect(page.at_css("#excluded + ul").text.squish).to eq("sim-020: not active (its credential was revoked)")
      expect(page.text).to include("for picked hosts")
    end

    it "treats two submits of one confirmation at once as one batch" do
      host = task_host
      fields = confirm(type: "refresh_reports", target: { host_ids: [ host.id ] })
      submit(fields, second_factor_code: code)
      batch = TaskBatch.sole
      allow(TaskBatch).to receive(:find_by).and_return(nil)
      allow(TaskBatches).to receive(:create!).and_raise(ActiveRecord::RecordNotUnique)
      allow(TaskBatch).to receive(:find_by!).and_return(batch)
      submit(fields)
      expect(response).to redirect_to("/tasks/batches/#{batch.id}")
    end

    it "refuses a wrong typed count in place, audited, and keeps the page" do
      Array.new(4) { task_host(tags: %w[lab]) }
      fields = confirm(type: "refresh_reports", target: { tag: "lab" })
      submit(fields, confirm_host_count: "5", second_factor_code: code)
      expect(response).to have_http_status(:unprocessable_content)
      expect(TaskBatch.count).to eq(0)
      expect(page.at_css("#refused").text).to include("Nothing was created.", "The number typed must be 4")
      expect(page.at_css("#confirm_host_count_error").text).to eq("Type 4, the number of hosts in this batch.")
      expect(page.at_css("#confirm_host_count")["value"]).to eq("5")
      expect(form_fields["confirmation"]).not_to eq(fields["confirmation"]) # a new confirmation
      expect(refusals.sole.changeset).to eq("task_type" => "refresh_reports", "problems" => [ "/confirm_host_count must be 4, the number of hosts this batch will run on" ])

      submit(fields, confirm_host_count: "four")
      expect(page.at_css("#refused").text).to include("The number typed must be a whole number.")
      submit(fields, confirm_host_count: "")
      expect(page.at_css("#confirm_host_count_error")).to be_present
    end

    it "refuses a wrong code and a wrong count together, and a locked step-up with 429" do
      Array.new(4) { task_host(tags: %w[lab]) }
      fields = confirm(type: "refresh_reports", target: { tag: "lab" })
      submit(fields, confirm_host_count: "8", second_factor_code: "000000")
      expect(response).to have_http_status(:forbidden)
      expect(page.at_css("#refused").text).to include("2 problems", "The second factor code was not accepted.", "The number typed must be 4")
      expect(page.at_css("#second_factor_error").text).to include("That code was not accepted")
      expect(page.at_css("#confirm_host_count_error")).to be_present
      expect(refusals.sole.changeset["problems"]).to eq([ "/second_factor_code code was not accepted", "/confirm_host_count must be 4, the number of hosts this batch will run on" ])

      submit(fields, confirm_host_count: "4")
      expect(page.at_css("#refused").text).to include("The second factor is needed: type a code")
      4.times { submit(fields, confirm_host_count: "4", second_factor_code: "000000") }
      expect(response).to have_http_status(:too_many_requests)
      expect(page.at_css("#refused").text).to include("is locked after too many wrong codes")
      expect(TaskBatch.count).to eq(0)
    end

    it "refuses when the hosts changed since the page was drawn, and shows the new list to confirm again (Q13)" do
      hosts = Array.new(3) { |index| task_host(name: "sim-00#{index + 1}", tags: %w[lab]) }
      fields = confirm(type: "refresh_reports", target: { tag: "lab" })
      hosts[1].retire!(actor: operator)
      task_host(name: "sim-009", tags: %w[lab])
      submit(fields, second_factor_code: code)
      expect(response).to have_http_status(:unprocessable_content)
      expect(TaskBatch.count).to eq(0)
      expect(page.at_css("#refused").text.squish).to include("Nothing was created: the targets changed.",
                                                             "sim-002 is no longer in the list, and sim-009 is now in it, since the page was drawn. Check the new list of 3 hosts below")
      expect(page.at_css("#confirm_targeted").text).to include("sim-001, sim-003, sim-009")
      expect(refusals.sole.changeset["problems"]).to eq([ "/target now resolves to different hosts than the ones you confirmed" ])

      submit(form_fields, second_factor_code: code)
      expect(TaskBatch.sole.tasks.map { |task| task.host.name }).to eq(%w[sim-001 sim-003 sim-009])
    end

    it "refuses a confirmation over 30 minutes old (Q13), one for a different request, and one that is not genuine" do
      host = task_host
      other = task_host
      fields = confirm(type: "refresh_reports", target: { host_ids: [ host.id ] })
      travel(31.minutes) do
        submit(fields, second_factor_code: code)
        expect(response).to have_http_status(:unprocessable_content)
        expect(page.at_css("#refused").text).to include("this page was out of date", "More than 30 minutes passed")
      end
      submit(fields.merge("target[host_ids][]" => [ other.id.to_s ]), second_factor_code: code)
      expect(page.at_css("#refused").text).to include("The confirmation was drawn for a different request.")
      submit(fields.merge("confirmation" => "forged--token"))
      expect(page.at_css("#refused").text).to include("The confirmation is not valid")
      submit(fields.merge("confirmation" => [ "x" ]))
      expect(page.at_css("#refused").text).to include("The confirmation is not valid")
      expect(TaskBatch.count).to eq(0)
      expect(refusals.count).to eq(4)
      expect(refusals.map { |entry| entry.changeset["problems"].first }).to eq([ "/confirmation is over 30 minutes old", "/confirmation was drawn for a different request",
                                                                                 "/confirmation is not valid: confirm on the confirmation page again", "/confirmation is not valid: confirm on the confirmation page again" ])
    end

    it "refuses another operator's confirmation" do
      host = task_host
      fields = confirm(type: "refresh_reports", target: { host_ids: [ host.id ] })
      other = create(:operator)
      token = TaskConfirmation.issue({ "type" => "refresh_reports", "parameters" => {}, "target" => { "host_ids" => [ host.id ] } }, [ host.id ], operator: other)
      submit(fields.merge("confirmation" => token), second_factor_code: code)
      expect(page.at_css("#refused").text).to include("The confirmation is not valid")
    end

    it "gives a forged POST the same validation as the form, refuses it, and audits it (AC-3.1)" do
      allow_restart("nginx.service")
      host = task_host
      post "/tasks", params: { type: "run_shell", target: { host_ids: [ host.id.to_s ] } } # no code either, and no window yet
      expect(response).to have_http_status(:forbidden)
      expect(page.at_css("#refused").text).to include("The second factor is needed", "The task type is not a task type in the catalog.")

      post "/tasks", params: { type: "restart_service", parameters: { service: "nginx.service" }, target: { host_ids: [ host.id.to_s ] }, command: "rm -rf /", second_factor_code: code }
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#refused").text).to include("The confirmation is missing: create tasks from the confirmation page.", "The field command is not accepted.")
      expect(refusals.last.changeset["problems"]).to eq([ "/confirmation is missing: create tasks from the confirmation page", "/command is not accepted" ])

      post "/tasks", params: { type: "run_shell", parameters: { script: "x" }, target: { host_ids: [ "1x" ] } }
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("h1").text).to eq("Nothing was created")
      expect(page.at_css("#refused").text).to include("The task type is not a task type in the catalog.", "The selection must be a list of host ids.")
      expect(refusals.last.changeset).not_to have_key("task_type")

      post "/tasks", params: { type: "restart_service", parameters: { service: "ssh.service" }, target: { host_ids: [ host.id.to_s ] }, second_factor_code: code }
      expect(page.at_css("#refused").text).to include("The service is a protected service")
      post "/tasks", params: { type: "refresh_reports", target: { tag: "nothing" }, second_factor_code: code }
      expect(page.at_css("#refused").text).to include("The tag selects no host.")
      expect(TaskBatch.count).to eq(0)
      expect(Task.count).to eq(0)
    end

    it "refuses a confirmed request whose hosts can no longer run it at all" do
      host = task_host
      fields = confirm(type: "refresh_reports", target: { host_ids: [ host.id ] })
      host.revoke!(actor: operator)
      submit(fields, second_factor_code: code)
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("h1").text).to eq("Nothing was created")
      expect(page.at_css("#refused").text).to include("The selection now resolves to different hosts", "The selection selects no host that can run this task type now.")
    end
  end

  it "names refused creations in the audit log" do
    post "/tasks", params: { type: "refresh_reports", target: { tag: "web" }, second_factor_code: code }
    get "/audit", params: { action: Audit::Actions::TASK_CREATION_REFUSED }
    expect(page.css("select#action option").map(&:text)).to include("Task creation refused")
    row = page.at_css("table tbody tr")
    expect(row.text).to include("Task creation refused", "New task (nothing created)", "Why refused", "/confirmation is missing")
  end
end
