require "rails_helper"

# Adversarial tests for the server's half of Phase 3 (P3-X02, AC-3.1, AC-3.2, threat model section 8). What the
# other task specs already prove is not repeated here; docs/decisions/phase-3-security-review.md maps every check to
# its test. This file adds:
# - the task-changing dashboard routes, enumerated from the router, each refused without a step-up or a CSRF
#   token with nothing changed (H1, H8), so a new route cannot be added without these checks;
# - tasks written straight into the database with hostile types and parameters, past the application and its
#   step-up, which the claim-time check refuses with nothing delivered (C14);
# - malformed and hostile bodies and ids on every agent task endpoint, refused with nothing changed (V5);
# - a fuzz of the server's parameter validator (P3-X02);
# - a server that fails mid-claim, or loses its database, leaving no half-made claim (P3-X03).
RSpec.describe "Adversarial task traffic", type: :request do
  # Every non-GET dashboard route of the task controllers. A route added there must be added here, with its step-up.
  def task_changing_routes = %w[task_creations#create task_cancellations#task task_cancellations#batch task_settings#add_service
                                task_settings#remove_service task_settings#update_limits]

  def task_controllers = %w[task_creations task_cancellations task_settings tasks task_batches host_tasks]

  # What a refused request must leave as it was: every task's state, the batches, the allowlist, and the settings.
  def task_world
    { tasks: Task.order(:id).pluck(:id, :state, :cancel_requested_at), batches: TaskBatch.count,
      allowlist: TaskAllowedService.order(:id).pluck(:id, :service, :tag), settings: Setting.order(:key).pluck(:key, :value) }
  end

  describe "the task-changing dashboard routes" do
    include_context "signed in operator"

    let(:host) { task_host }
    let!(:queued) { create_task(host) }
    let!(:entry) { allow_restart("nginx.service", by: operator).first }

    # One request per route, as a forged form would send it: everything but a step-up code (and a CSRF token).
    def forge(route, **extra)
      case route
      when "task_creations#create" then post "/tasks", params: { type: "refresh_reports", target: { host_ids: [ host.id.to_s ] }, **extra }
      when "task_cancellations#task" then post "/tasks/#{queued.id}/cancel", params: extra
      when "task_cancellations#batch" then post "/tasks/batches/#{queued.task_batch_id}/cancel", params: extra
      when "task_settings#add_service" then post "/settings/tasks/services", params: { service: "redis-server.service", **extra }
      when "task_settings#remove_service" then post "/settings/tasks/services/#{entry.id}/remove", params: extra
      when "task_settings#update_limits" then patch "/settings/tasks/limits", params: { max_hosts_per_batch: "2", **extra }
      end
    end

    it "lists every non-GET route of the task controllers, so a new one cannot skip these checks" do
      routes = Rails.application.routes.routes.filter_map do |route|
        controller, action = route.defaults.values_at(:controller, :action)
        "#{controller}##{action}" if task_controllers.include?(controller) && route.verb != "GET"
      end
      expect(routes.uniq).to match_array(task_changing_routes)
    end

    it "refuses each one without a step-up code, with an enrolled factor, and changes nothing (H1)" do
      enrol_second_factor(operator)
      before = task_world
      task_changing_routes.each do |route|
        forge(route)
        expect(response).to have_http_status(:forbidden), "#{route}: #{response.status}"
      end
      # Wrong codes: refused, then locked after five (P3-S09).
      task_changing_routes.each do |route|
        forge(route, second_factor_code: "000000")
        expect(response.status).to be_in([ 403, 429 ]), "#{route}: #{response.status}"
      end
      expect(task_world).to eq(before)
    end

    it "refuses each one with no second factor enrolled at all, and changes nothing" do
      before = task_world
      task_changing_routes.each do |route|
        forge(route, second_factor_code: "123456")
        expect(response).to have_http_status(:forbidden), "#{route}: #{response.status}"
      end
      expect(task_world).to eq(before)
    end

    # The confirmation page's hidden fields for creating refresh_reports on host, as the browser would send them.
    def confirmation_fields
      get "/tasks/new/confirm", params: { type: "refresh_reports", target: { host_ids: [ host.id ] } }
      expect(response).to have_http_status(:ok)
      page.css("#create_task input[type=hidden]").each_with_object({}) do |input, fields|
        name = input["name"]
        next if name == "authenticity_token"

        name.end_with?("[]") ? (fields[name] ||= []) << input["value"] : fields[name] = input["value"]
      end
    end

    # A request that would succeed but for its missing CSRF token: a genuine confirmation for create.
    def complete(route, **extra)
      if route == "task_creations#create"
        post "/tasks", params: confirmation_fields.merge(extra.transform_keys(&:to_s))
      else
        forge(route, **extra)
      end
    end

    it "refuses each one without the CSRF token, even with a right code and a genuine confirmation, and changes nothing (H8)" do
      secret = enrol_second_factor(operator).first
      before = task_world
      ActionController::Base.allow_forgery_protection = true
      task_changing_routes.each do |route|
        complete(route, second_factor_code: totp_code(secret))
        expect(response).not_to have_http_status(:redirect), route
        expect(response).not_to have_http_status(:ok), route
      end
      expect(task_world).to eq(before)

      # The control: the same requests with CSRF checks off succeed, so the token was what stopped them. The first
      # code opens the step-up window; the rest pass inside it.
      ActionController::Base.allow_forgery_protection = false
      task_changing_routes.each_with_index do |route, i|
        complete(route, **(i.zero? ? { second_factor_code: totp_code(secret) } : {}))
        expect(response).to have_http_status(:redirect), "#{route}: #{response.status}"
      end
      expect(task_world).not_to eq(before)
    ensure
      ActionController::Base.allow_forgery_protection = false
    end
  end

  describe "tasks written straight into the database (threat model C14)", :agent_host do
    let(:operator) { create(:operator) }
    let!(:agent) { enrolled_host }
    let(:host) { agent.first }
    let(:credential) { agent.last }

    before do
      host.update_columns(task_catalog_version: TaskCatalog.current.version, task_types_supported: TaskCatalog.current.types,
                          task_types_enabled: TaskCatalog.current.types, task_services_allowed: %w[nginx.service],
                          task_capabilities_reported_at: Time.current)
      allow_restart("nginx.service", by: operator)
    end

    def versions = { "schema_version" => 1, "agent_version" => "0.3.0" }

    # A row inserted with SQL, as a database writer would, past the model, TaskBatches, the step-up, and the audit
    # log. The tasks_guard trigger lets a queued row in; nothing else checks it until a poll.
    def insert_task(batch, type, parameters, created_at)
      Task.connection.exec_insert(<<~SQL, "hostile insert", [ batch.id, host.id, type, JSON.generate(parameters), created_at, created_at ])
        INSERT INTO tasks (task_batch_id, host_id, task_type, parameters, timeout_seconds, expires_at, created_at, updated_at)
        VALUES ($1, $2, $3, $4::jsonb, 86400, now() + interval '1 day', $5, $6)
      SQL
      Task.order(:id).last
    end

    it "refuses every hostile row when it would be claimed, with the system as actor, and delivers only the valid task" do
      valid = TaskBatches.create!({ "type" => "refresh_reports", "parameters" => {}, "target" => { "host_ids" => [ host.id ] } }, operator:).tasks.sole
      batch = valid.task_batch
      hostile = {
        [ "run_shell", { "command" => "id" } ] => "unknown_type",
        [ "reboot", {} ] => "unknown_type",
        [ "refresh_reports", { "command" => "touch /tmp/pwned" } ] => "invalid_params",
        [ "refresh_reports", { "script" => "rm -rf /" } ] => "invalid_params",
        [ "apply_package_updates", { "packages" => "openssh-server=1:7.0" } ] => "invalid_params",
        [ "restart_service", { "service" => "nginx.service; reboot" } ] => "invalid_params",
        [ "restart_service", { "service" => "$(reboot).service" } ] => "invalid_params",
        [ "restart_service", { "service" => "`id`.service" } ] => "invalid_params",
        [ "restart_service", { "service" => "../../etc/systemd/system/x.service" } ] => "invalid_params",
        [ "restart_service", { "service" => "--now.service" } ] => "invalid_params",
        [ "restart_service", { "service" => "nginx‮.service" } ] => "invalid_params",
        [ "restart_service", { "service" => "nginx.service\n" } ] => "invalid_params",
        [ "restart_service", { "service" => "ssh*.service" } ] => "invalid_params",
        [ "restart_service", { "service" => "reboot.target" } ] => "invalid_params",
        [ "restart_service", { "service" => "nginx.service", "now" => true } ] => "invalid_params",
        [ "restart_service", { "service" => [ "nginx.service" ] } ] => "invalid_params",
        [ "restart_service", { "service" => "ssh.service" } ] => "protected_service",
        [ "restart_service", { "service" => "SSHD.service" } ] => "protected_service",
        [ "restart_service", { "service" => "fleet-agent-rollback.service" } ] => "protected_service",
        [ "restart_service", { "service" => "dbus-broker.service" } ] => "protected_service",
        [ "restart_service", { "service" => "postgresql.service" } ] => "not_allowed_on_server"
      }
      rows = hostile.keys.each_with_index.map { |(type, parameters), i| insert_task(batch, type, parameters, valid.created_at - (hostile.size - i).seconds) }
      expect(rows.map(&:state).uniq).to eq([ "queued" ])

      post_api("/api/v1/tasks/poll", versions, credential)
      expect(response).to have_http_status(:ok)
      expect(json["task"]).to include("id" => valid.uuid, "type" => "refresh_reports", "parameters" => {})
      expect(ApiContract.errors("task-poll.response", "v1", json)).to eq([])
      rows.zip(hostile.values).each do |row, reason|
        expect(row.reload).to have_attributes(state: "refused", reason:), "#{row.task_type} #{row.parameters}"
        refusal = AuditEntry.find_by!(action: Audit::Actions::TASK_REFUSED, target_type: "Task", target_id: row.id)
        expect(refusal.actor_type).to eq("system")
      end
      expect(AuditEntry.where(action: Audit::Actions::TASK_CLAIMED).pluck(:target_id)).to eq([ valid.id ])
    end

    it "refuses a hostile row swapped in under a claimed task's batch at start too, and never says run" do
      valid = TaskBatches.create!({ "type" => "refresh_reports", "parameters" => {}, "target" => { "host_ids" => [ host.id ] } }, operator:).tasks.sole
      row = insert_task(valid.task_batch, "restart_service", { "service" => "systemd-logind.service" }, 1.hour.ago)
      post_api("/api/v1/tasks/poll", versions, credential)
      expect(json["task"]["id"]).to eq(valid.uuid)
      expect(row.reload).to have_attributes(state: "refused", reason: "protected_service")
      post_api("/api/v1/tasks/#{row.uuid}/start", versions.merge("started_at" => "2026-01-01T12:00:05Z"), credential)
      expect(json).to include("run" => false, "state" => "refused")
    end
  end

  describe "hostile bodies and ids on the agent task endpoints (threat model V5)", :agent_host do
    let(:operator) { create(:operator) }
    let!(:agent) { enrolled_host }
    let(:host) { agent.first }
    let(:credential) { agent.last }
    let!(:task) do
      host.update_columns(task_catalog_version: TaskCatalog.current.version, task_types_supported: TaskCatalog.current.types,
                          task_types_enabled: TaskCatalog.current.types, task_services_allowed: [], task_capabilities_reported_at: Time.current)
      TaskBatches.create!({ "type" => "refresh_reports", "parameters" => {}, "target" => { "host_ids" => [ host.id ] } }, operator:).tasks.sole
    end

    def versions = { "schema_version" => 1, "agent_version" => "0.3.0" }

    def endpoints = [ "/api/v1/tasks/poll", "/api/v1/tasks/#{task.uuid}/start", "/api/v1/tasks/#{task.uuid}/progress", "/api/v1/tasks/#{task.uuid}/result" ]

    # The per-credential rate limit is not what these examples test, so each request starts with a fresh count.
    def raw(path, body, content_type: "application/json", headers: {})
      AgentApi.rate_limit_store.clear
      post path, params: body, headers: api_headers(credential).merge("Content-Type" => content_type, **headers)
    end

    def unchanged
      before = [ task.reload.attributes, AuditEntry.count ]
      yield
      expect([ task.reload.attributes, AuditEntry.count ]).to eq(before)
    end

    it "refuses bodies that are not JSON objects, too deep, too large, or compressed, on every endpoint, with nothing changed" do
      unchanged do
        endpoints.each do |path|
          {
            "{" => 400, "[]" => 400, "\"poll\"" => 400, "null" => 400, "{\"a\":\xff}" => 400,
            "#{'[' * 40}#{']' * 40}" => 400, JSON.generate(versions.merge("pad" => "x" * 2.megabytes)) => 413
          }.each do |body, status|
            raw(path, body)
            expect(response).to have_http_status(status), "#{path} #{body.truncate(20).inspect}: #{response.status}"
          end
          raw(path, JSON.generate(versions), content_type: "text/plain")
          expect(response).to have_http_status(:bad_request), path
          raw(path, ActiveSupport::Gzip.compress(JSON.generate(versions)), headers: { "Content-Encoding" => "gzip" })
          expect(response).to have_http_status(:bad_request), path
          expect(json.dig("error", "message")).not_to match(/backtrace|\.rb:\d|ActiveRecord|PG::/)
        end
      end
    end

    it "refuses wrong types and injection strings in declared fields, and never takes a command-like field as anything" do
      unchanged do
        post_api(endpoints[1], versions.merge("started_at" => "$(reboot)"), credential)
        expect_error(:bad_request, "validation_failed")
        post_api(endpoints[2], versions.merge("percent" => "100; rm -rf /"), credential)
        expect_error(:bad_request, "validation_failed")
        result = versions.merge("report_id" => SecureRandom.uuid, "outcome" => "succeeded; reboot", "reason" => nil, "exit_status" => 0,
                                "started_at" => nil, "finished_at" => "2026-01-01T12:00:09Z", "details" => {}, "output" => "", "output_truncated" => false)
        post_api(endpoints[3], result, credential)
        expect_error(:bad_request, "validation_failed")
        post_api(endpoints[3], result.merge("outcome" => "refused", "reason" => "../../etc/passwd"), credential)
        expect_error(:bad_request, "validation_failed")
      end
      # Fields no schema declares are ignored (DEC-08), never stored, and logged by their path only.
      log = captured_log do
        post_api(endpoints[0], versions.merge("command" => "touch /tmp/pwned", "task" => { "type" => "run_shell" }), credential)
      end
      expect(response).to have_http_status(:ok)
      expect(json["task"]).to include("id" => task.uuid, "type" => "refresh_reports", "parameters" => {})
      expect(log).to include("ignored unknown fields /command")
      expect(log).not_to include("touch /tmp/pwned")
      expect(task.reload.attributes.values.join).not_to include("pwned")
    end

    it "answers 404, and changes nothing, for ids that are not a task's uuid" do
      unchanged do
        [ "..%2F..%2Fetc%2Fpasswd", "#{task.id}", "#{task.uuid}%0A", "#{task.uuid.upcase}x", "%00", "#{task.uuid};id" ].each do |id|
          post_api("/api/v1/tasks/#{id}/start", versions.merge("started_at" => "2026-01-01T12:00:05Z"), credential)
          expect(response).to have_http_status(:not_found), "#{id}: #{response.status}"
        end
      end
    end
  end

  describe "a fuzz of the server's parameter validator (P3-X02)" do
    # The catalog's pattern written out by hand, so the fuzz does not trust the code it checks.
    def fits_the_catalog?(name) = name.match?(/\A[A-Za-z0-9][A-Za-z0-9_.@-]{0,247}\.service\z/) && name.length >= 9

    it "refuses every service name outside the catalog's pattern, never allows one the server has not listed, and refuses unknown keys" do
      pieces = [ "a", "Z", "0", "9", "_", ".", "@", "-", "--", "nginx", "ssh", "fleet-agent", ";", "|", "&", "$", "`", "(", ")", "$(", "<", ">",
                 "*", "?", "[", "]", "{", "}", "!", "~", "#", "'", "\"", "\\", "/", "../", "%2e", "%2F", " ", "\t", "\n", "\r", "\0", "\e[31m",
                 "\u007f", "\u0085", " ", "​", "‍", "‮", "⁦", "﻿", "ſ", "K", "с", "ｎ", ".service",
                 ".socket", ".target", ".service.d", "@.service" ]
      random = Random.new(38)
      outside = 0
      3_000.times do
        name = Array.new(random.rand(1..12)) { pieces.sample(random:) }.join
        name += ".service" if random.rand(2).zero?
        refusal = TaskPolicy.refusal("restart_service", { "service" => name })
        expect(refusal).not_to be_nil, name.inspect # the allowlist is empty: nothing is ever allowed
        if fits_the_catalog?(name)
          expect(refusal.reason).to be_in(%w[protected_service not_allowed_on_server]), name.inspect
        else
          outside += 1
          expect(refusal.reason).to eq("invalid_params"), name.inspect
        end
        key = Array.new(random.rand(1..4)) { pieces.sample(random:) }.join
        next if key == "service"

        expect(TaskPolicy.refusal("restart_service", { "service" => "nginx.service", key => name }).reason).to eq("invalid_params"), key.inspect
        expect(TaskPolicy.refusal("refresh_reports", { key => name }).reason).to eq("invalid_params"), key.inspect
      end
      expect(outside).to be > 1_000
    end
  end

  describe "a server that fails mid-claim (P3-X03)", :agent_host do
    let(:operator) { create(:operator) }
    let!(:agent) { enrolled_host }
    let(:host) { agent.first }
    let(:credential) { agent.last }
    let!(:task) do
      host.update_columns(task_catalog_version: TaskCatalog.current.version, task_types_supported: TaskCatalog.current.types,
                          task_types_enabled: TaskCatalog.current.types, task_services_allowed: [], task_capabilities_reported_at: Time.current)
      TaskBatches.create!({ "type" => "refresh_reports", "parameters" => {}, "target" => { "host_ids" => [ host.id ] } }, operator:).tasks.sole
    end

    def versions = { "schema_version" => 1, "agent_version" => "0.3.0" }

    it "leaves no claim when the request dies after claiming, so the next poll claims the task once" do
      calls = 0
      allow(AgentTasks).to receive(:delivery).and_wrap_original do |original, *args|
        calls += 1
        raise "the server stopped mid-claim" if calls == 1

        original.call(*args)
      end
      post_api("/api/v1/tasks/poll", versions, credential)
      expect_error(:internal_server_error, "internal_error")
      expect(response.body).not_to include("mid-claim")
      expect(task.reload).to have_attributes(state: "queued", claimed_at: nil, lease_expires_at: nil)
      expect(AuditEntry.where(action: Audit::Actions::TASK_CLAIMED)).to be_empty

      post_api("/api/v1/tasks/poll", versions, credential)
      expect(json["task"]["id"]).to eq(task.uuid)
      expect(task.reload.state).to eq("claimed")
      expect(AuditEntry.where(action: Audit::Actions::TASK_CLAIMED).count).to eq(1)
    end

    it "answers 500 without internals when the database is unavailable, which the agent retries (wire.rs final_or_retry)" do
      allow(AgentHostLock).to receive(:lock!).and_raise(ActiveRecord::ConnectionNotEstablished, "connection to server at 192.0.2.10 failed")
      post_api("/api/v1/tasks/poll", versions, credential)
      expect_error(:internal_server_error, "internal_error")
      expect(response.body).not_to include("192.0.2.10")
      expect(task.reload.state).to eq("queued")
    end
  end
end
