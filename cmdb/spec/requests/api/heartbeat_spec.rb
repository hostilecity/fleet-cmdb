require "rails_helper"

# POST /api/v1/heartbeat (P1-S07, FR-1.2, FR-1.4, AC-1.1, AC-1.2)
RSpec.describe "POST /api/v1/heartbeat", type: :request do
  let!(:enrolled) { enrolled_host }
  let(:host) { enrolled.first }
  let(:credential) { enrolled.last }

  def body(**overrides)
    { schema_version: 1, agent_version: "0.1.0", hostname: "vm-01.example.lan", uptime_seconds: 42, agent_time: "2026-01-01T12:00:00Z" }.merge(overrides)
  end

  def heartbeat(payload = body, as: credential) = post_api("/api/v1/heartbeat", payload, as)

  it "answers with the server time and an empty directives object (DEC-20)" do
    freeze_time do
      heartbeat
      expect(response).to have_http_status(:ok)
      expect(json).to eq("server_time" => Time.current.utc.iso8601, "directives" => {})
      expect(ApiContract.errors("heartbeat.response", "v1", json)).to eq([])
    end
  end

  it "records first contact and brings the host online at once (AC-1.1)" do
    expect(host.display_status).to eq("awaiting first contact")
    freeze_time do
      heartbeat(body(agent_version: "0.2.0"))
      expect(host.reload).to have_attributes(liveness_status: "online", last_seen_at: Time.current, first_seen_at: Time.current,
                                             agent_version: "0.2.0", agent_schema_version: 1)
    end
    expect(host.status_events.sole).to have_attributes(from_status: nil, to_status: "online", reason: "heartbeat")
  end

  it "keeps first_seen_at and writes no event while the host stays online" do
    heartbeat
    first_seen = host.reload.first_seen_at
    travel 1.minute
    expect { heartbeat }.not_to change(HostStatusEvent, :count)
    expect(host.reload.first_seen_at).to eq(first_seen)
    expect(host.last_seen_at).to be > first_seen
  end

  %w[stale offline].each do |status|
    it "returns a #{status} host to online and records the transition" do
      heartbeat
      set_liveness(host, liveness_status: status)
      heartbeat
      expect(host.reload.liveness_status).to eq("online")
      expect(host.status_events.chronological.last).to have_attributes(from_status: status, to_status: "online", reason: "heartbeat")
    end
  end

  it "never lets the agent's clock affect last_seen_at or liveness" do
    freeze_time do
      heartbeat(body(agent_time: "2001-01-01T00:00:00Z"))
      expect(host.reload).to have_attributes(last_seen_at: Time.current, agent_reported_at: Time.utc(2001, 1, 1), liveness_status: "online")
      Liveness.evaluate!
      expect(host.reload.liveness_status).to eq("online")
    end
    freeze_time { heartbeat(body(agent_time: "2099-12-31T23:59:59Z")) }
    seen_at = host.reload.last_seen_at
    expect(seen_at).to be <= Time.current
    travel_to(seen_at + 20.minutes) { Liveness.evaluate! }
    expect(host.reload.liveness_status).to eq("offline") # a future agent clock does not keep it online
  end

  it "writes no audit entries" do
    expect { heartbeat }.not_to change(AuditEntry, :count)
  end

  it "is one cheap write: a bounded number of queries and no other tables" do
    heartbeat # first contact writes an event; measure the steady state
    queries = []
    callback = ->(*, payload) { queries << payload[:sql] unless payload[:name] == "SCHEMA" || payload[:sql].match?(/\A(BEGIN|COMMIT|SAVEPOINT|RELEASE|ROLLBACK)/) }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { heartbeat }
    expect(response).to have_http_status(:ok)
    writes = queries.grep(/\A\s*(INSERT|UPDATE|DELETE|WITH\b.*\bUPDATE\b)/im)
    expect(writes.size).to eq(1), writes.inspect
    expect(writes.first).to match(/UPDATE host_liveness/) # not the hosts row (#192)
    # #189: the credential with its host (authentication), the host FOR UPDATE joined to the credential (the re-check
    # under the lock), the UPDATE, and one SELECT for the rollout offer (P1-UPDATES), outstanding report requests
    # (P2-S03), and a waiting task (P3-S03). The intervals setting comes from the per-process cache.
    expect(queries.size).to eq(4), queries.inspect
    expect(queries[0]).to match(/FROM "agent_credentials" LEFT OUTER JOIN "hosts"/)
    expect(queries[1]).to match(/FROM "hosts" INNER JOIN "agent_credentials".*FOR UPDATE OF hosts FOR SHARE OF agent_credentials/m)
    expect(queries[2]).to match(/\AWITH previous AS .*UPDATE host_liveness/m)
    expect(queries[3]).to match(/rollout_hosts.*report_requests.*EXISTS \(SELECT 1 FROM "tasks"/m)
    expect(queries[3]).not_to match(/FOR (SHARE|UPDATE)/) # no rollout row lock per heartbeat (#199)
    expect(queries.join).not_to match(/snapshot|audit_entries|host_status_events|settings/)
  end

  it "runs in one transaction, authentication included, and commits once (#189)" do
    heartbeat
    statements = []
    callback = ->(*, payload) { statements << payload[:sql] unless payload[:name] == "SCHEMA" }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { heartbeat }
    expect(response).to have_http_status(:ok)
    # In the test's own transaction, the request's transaction is a savepoint: every statement is inside it.
    expect(statements.first).to match(/\ASAVEPOINT/)
    expect(statements.last).to match(/\ARELEASE SAVEPOINT/)
    expect(statements.grep(/\A(SAVEPOINT|RELEASE|BEGIN|COMMIT)/).size).to eq(2), statements.inspect
  end

  it "reads the intervals setting at most once per process every few seconds, and at once after a change (#189)" do
    reads = 0
    callback = ->(*, payload) { reads += 1 if payload[:sql].include?('FROM "settings"') }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { 3.times { heartbeat } }
    expect(reads).to eq(1)
    Setting.update_agent_intervals!(heartbeat_seconds: 120, actor: Audit::SYSTEM)
    heartbeat
    expect(json.dig("directives", "intervals")).to eq("heartbeat_seconds" => 120)
    later = SettingsCache.clock + SettingsCache::TTL.to_f + 1
    allow(SettingsCache).to receive(:clock).and_return(later)
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { heartbeat }
    expect(reads).to eq(2)
  end

  it "stays one write after the credential last-use interval has passed (no agent_credentials write)" do
    heartbeat
    credential_record = host.agent_credentials.active.sole
    last_used = credential_record.reload.last_used_at
    travel(AgentCredential::LAST_USED_RESOLUTION + 1.minute) do
      writes = []
      callback = ->(*, payload) { writes << payload[:sql] if payload[:sql].match?(/\A\s*(INSERT|UPDATE|DELETE|WITH\b.*\bUPDATE\b)/im) }
      ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { heartbeat }
      expect(response).to have_http_status(:ok)
      expect(writes.size).to eq(1), writes.inspect
      expect(writes.first).to match(/UPDATE host_liveness/)
    end
    expect(credential_record.reload.last_used_at).to eq(last_used)
  end

  # #192: what a steady heartbeat changes lives in host_liveness, with no index but its key, so the update stays
  # heap-only (no index entry written) and the wide hosts row, with its seven indexes, is not written at all.
  it "keeps a steady heartbeat's update heap-only, and leaves the hosts row alone (#192)" do
    heartbeat
    counts = lambda do
      ActiveRecord::Base.connection.select_rows("SELECT relname, n_tup_upd, n_tup_hot_upd FROM pg_stat_xact_user_tables " \
                                                "WHERE relname IN ('hosts', 'host_liveness')").to_h { |name, *values| [ name, values.map(&:to_i) ] }
    end
    before = counts.call
    3.times { heartbeat }
    after = counts.call
    expect(after["host_liveness"].zip(before["host_liveness"]).map { |a, b| a - b }).to eq([ 3, 3 ]) # 3 updates, all HOT
    expect(after["hosts"]).to eq(before["hosts"])
  end

  it "reads the server clock only after locking the host row" do
    locked_at = nil
    callback = ->(*, payload) { locked_at ||= Time.current if payload[:sql].match?(/FROM "hosts".*FOR UPDATE/m) }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { heartbeat }
    expect(locked_at).to be_present
    expect(host.reload.last_seen_at).to be >= locked_at.floor(6)
    expect(Time.iso8601(json["server_time"])).to be >= locked_at.floor
  end

  it "never moves last_seen_at backwards behind a newer committed heartbeat" do
    heartbeat
    newer = 2.seconds.from_now.floor(6)
    set_liveness(host, last_seen_at: newer)
    heartbeat
    expect(host.reload.last_seen_at).to eq(newer)
    expect(host.first_seen_at).to be <= host.last_seen_at
  end

  describe "a state change between authentication and the write (review of #50)" do
    # Runs the transition after the request has authenticated and passed the active-host check, before
    # the heartbeat locks the host row.
    def after_authentication(&transition)
      allow_any_instance_of(Api::V1::HeartbeatsController).to receive(:require_active_host!).and_wrap_original do |original, *args|
        original.call(*args)
        transition.call
      end
    end

    it "refuses with 403 reenrollment_required when re-enrollment lands in between" do
      heartbeat
      after_authentication { Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM) }
      expect { heartbeat }.not_to(change { host.reload.last_seen_at })
      expect_error(:forbidden, "reenrollment_required")
      expect(response.headers["Fleet-Enrollment-State"]).to eq("pending")
    end

    it "refuses with 401 when revocation or retirement lands in between" do
      %i[revoke! retire!].each do |transition|
        target, target_credential = enrolled_host
        after_authentication { target.reload.public_send(transition, actor: Audit::SYSTEM) }
        expect { heartbeat(as: target_credential) }.not_to change(HostStatusEvent, :count)
        expect_error(:unauthorized, "unauthorized")
        expect(target.reload.last_seen_at).to be_nil
      end
    end
  end

  describe "directives (DEC-20, P1-UPDATES)" do
    let(:operator) { create(:operator) }

    it "sends the intervals the operator set, and only those" do
      Setting.update_agent_intervals!(heartbeat_seconds: 120, actor: operator)
      heartbeat
      expect(json["directives"]).to eq("intervals" => { "heartbeat_seconds" => 120 })
      Setting.update_agent_intervals!(inventory_seconds: 1800, actor: operator)
      heartbeat
      expect(json["directives"]).to eq("intervals" => { "heartbeat_seconds" => 120, "inventory_seconds" => 1800 })
      expect(ApiContract.errors("heartbeat.response", "v1", json)).to eq([])
    end

    it "sends the agent_update directive to a host in an open stage that runs an older version, and keeps sending it" do
      release = release_for_rollout("0.3.0")
      rollout = start_rollout(release:, canaries: [ host ].each { |h| h.update_columns(agent_version: "0.2.0") })
      2.times do
        heartbeat(body(agent_version: "0.2.0"))
        expect(json.dig("directives", "agent_update")).to include("rollout_id" => rollout.id, "version" => "0.3.0",
                                                                  "binary_url" => Releases.download_url("0.3.0", "binary"))
        expect(ApiContract.errors("heartbeat.response", "v1", json)).to eq([])
      end
      expect(rollout.rollout_hosts.sole.state).to eq("updating")
      heartbeat(body(agent_version: "0.3.0")) # now running the release: nothing more to say
      expect(json["directives"]).to eq({})
    end

    describe "tasks_available (P3-S03)" do
      def queued(now: Time.current)
        host.update_columns(task_catalog_version: TaskCatalog.current.version, task_types_supported: %w[refresh_reports],
                            task_types_enabled: %w[refresh_reports], task_capabilities_reported_at: Time.current)
        request = { "type" => "refresh_reports", "parameters" => {}, "target" => { "host_ids" => [ host.id ] } }
        TaskBatches.create!(request, operator:, now:).tasks.sole
      end

      it "is sent while the host has a queued or unstarted claimed task, so the agent polls at once" do
        task = queued
        heartbeat
        expect(json["directives"]).to eq("tasks_available" => {})
        expect(ApiContract.errors("heartbeat.response", "v1", json)).to eq([])
        task.claim!(actor: host, lease_expires_at: 5.minutes.from_now)
        heartbeat
        expect(json["directives"]).to eq("tasks_available" => {})
      end

      it "is not sent while a task is running, or for a task past its expiry" do
        task = queued
        waiting = queued
        task.claim!(actor: host, lease_expires_at: 5.minutes.from_now)
        task.start!(actor: host, lease_expires_at: 15.minutes.from_now)
        heartbeat
        expect(json["directives"]).to eq({}) # one task at a time: the poll would return nothing
        task.succeed!(actor: host)
        waiting.cancel!(actor: operator)
        queued(now: 25.hours.ago) # still queued, but past its expiry by the database clock
        heartbeat
        expect(json["directives"]).to eq({})
      end
    end

    it "sends no agent_update to a host outside the rollout" do
      release = release_for_rollout("0.3.0")
      canary, = host_running("0.2.0")
      start_rollout(release:, canaries: [ canary ])
      host.update_columns(agent_version: "0.2.0")
      heartbeat(body(agent_version: "0.2.0"))
      expect(json["directives"]).to eq({})
    end

    it "answers an agent below the minimum version with 200 (FR-S.5)" do
      allow(AgentApi.config).to receive(:minimum_agent_version).and_return("9.0.0")
      heartbeat
      expect(response).to have_http_status(:ok)
      expect(host.reload.agent_version).to eq("0.1.0")
    end
  end

  describe "task capabilities (FR-3.1, P3-A01)" do
    let(:tasks) do
      { catalog_version: 1, supported: %w[restart_service refresh_reports], enabled: %w[refresh_reports restart_service],
        allowed_services: %w[nginx.service cron.service], local_config: "valid" }
    end
    let(:restart) { TaskCatalog.current.entry("restart_service") }

    it "records what the agent supports and enables, in one UPDATE of the host row" do
      freeze_time do
        heartbeat(body(tasks: tasks.merge(future_field: true)))
        expect(response).to have_http_status(:ok)
        expect(host.reload).to have_attributes(task_catalog_version: 1, task_types_supported: %w[refresh_reports restart_service],
                                               task_types_enabled: %w[refresh_reports restart_service],
                                               task_services_allowed: %w[cron.service nginx.service],
                                               task_capabilities_reported_at: Time.current)
      end
      expect(host.task_exclusion_reason(restart, { "service" => "nginx.service" })).to be_nil
    end

    it "writes the host row only when the agent version or the capabilities change (#192)" do
      reported = Time.current.floor
      host_writes = []
      callback = ->(*, payload) { host_writes << payload[:sql] if payload[:sql].match?(/\AUPDATE "hosts"/) }
      travel_to(reported) { heartbeat(body(tasks:)) }
      travel_to(reported + 1.minute) { ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { heartbeat(body(tasks:)) } }
      expect(host_writes).to be_empty
      # The capabilities' time is when they were first reported as they are; the last report is the last heartbeat.
      expect(host.reload).to have_attributes(task_capabilities_reported_at: reported, last_seen_at: reported + 1.minute)

      travel_to(reported + 2.minutes) { heartbeat(body(tasks: tasks.merge(enabled: %w[refresh_reports]))) }
      expect(host.reload.task_capabilities_reported_at).to eq(reported + 2.minutes)
      travel_to(reported + 3.minutes) do
        ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { heartbeat(body(agent_version: "0.2.0", tasks: tasks.merge(enabled: %w[refresh_reports]))) }
      end
      expect(host_writes.size).to eq(1)
      expect(host.reload).to have_attributes(agent_version: "0.2.0", task_capabilities_reported_at: reported + 2.minutes)
    end

    it "sets or clears the capabilities' time when only it is out of step with the report (review of #220)" do
      heartbeat(body(tasks:))
      host.update_columns(task_capabilities_reported_at: nil) # the lists already as reported, but no time
      heartbeat(body(tasks:))
      expect(host.reload.task_capabilities_reported_at).to be_present
      # The lists already as a report without capabilities leaves them, but with a time.
      host.update_columns(task_catalog_version: nil, task_types_supported: [], task_types_enabled: [], task_services_allowed: [])
      heartbeat
      expect(host.reload.task_capabilities_reported_at).to be_nil
    end

    it "leaves out a restart of a service the VM's own allowlist does not name (P3-D01 Q7)" do
      heartbeat(body(tasks:))
      expect(host.reload.task_exclusion_reason(restart, { "service" => "postgresql.service" })).to eq("not_allowed_locally")
      heartbeat(body(tasks: tasks.merge(allowed_services: [])))
      expect(host.reload.task_exclusion_reason(restart, { "service" => "nginx.service" })).to eq("not_allowed_locally")
      expect(host.task_exclusion_reason(TaskCatalog.current.entry("refresh_reports"), {})).to be_nil
    end

    it "stops offering a type the host no longer enables, and everything when it reports none" do
      heartbeat(body(tasks:))
      heartbeat(body(tasks: tasks.merge(enabled: %w[refresh_reports])))
      expect(host.reload.task_exclusion_reason(restart, { "service" => "nginx.service" })).to eq("not_enabled")
      expect(host.task_exclusion_reason(TaskCatalog.current.entry("refresh_reports"))).to be_nil
      heartbeat(body(tasks: tasks.merge(supported: %w[refresh_reports])))
      expect(host.reload.task_exclusion_reason(restart, { "service" => "nginx.service" })).to eq("not_supported")
      heartbeat # an agent that sends no capabilities, such as one older than Phase 3
      expect(host.reload).to have_attributes(task_catalog_version: nil, task_types_supported: [], task_types_enabled: [],
                                             task_services_allowed: [], task_capabilities_reported_at: nil)
      expect(host.task_exclusion_reason(restart)).to eq("no_capability_report")
    end

    it "enables nothing when the agent refused its local task configuration" do
      heartbeat(body(tasks: tasks.merge(local_config: "invalid")))
      expect(host.reload).to have_attributes(task_types_enabled: [], task_services_allowed: [])
      expect(host.task_exclusion_reason(TaskCatalog.current.entry("refresh_reports"))).to eq("not_enabled")
    end

    it "rejects malformed capabilities without changing what was stored" do
      heartbeat(body(tasks:))
      heartbeat(body(tasks: tasks.merge(enabled: [ "Restart-Service" ])))
      expect_error(:bad_request, "validation_failed")
      expect(host.reload.task_types_enabled).to eq(%w[refresh_reports restart_service])
    end

    it "accepts the largest capabilities the contract allows" do
      ids = (1..64).map { |n| "task_type_#{n.to_s.rjust(3, '0')}_#{'x' * 50}" }
      services = (1..64).map { |n| "svc-#{n.to_s.rjust(3, '0')}-#{'x' * 240}.service" }
      heartbeat(body(tasks: tasks.merge(catalog_version: 1_000_000, supported: ids, enabled: ids, allowed_services: services)))
      expect(response).to have_http_status(:ok)
      expect(host.reload.task_types_supported.size).to eq(64)
    end
  end

  describe "recovery mode (#180, ADR 0030)" do
    let(:recovery) do
      { entered_at: "2026-01-01T11:00:00Z", reason: "a loop of the agent failed: panicked in fleet-agent-inventory",
        retry_at: "2026-01-01T12:00:00Z" }
    end

    it "records the episode in the heartbeat's one UPDATE, keeps when it began, and clears it in normal mode" do
      allow(FleetBroadcast).to receive(:hosts_changed)
      heartbeat
      expect(host.reload).not_to be_recovering
      started = 1.minute.from_now.change(usec: 0) # after the first heartbeat's last_seen_at, which never moves back
      travel_to(started) { heartbeat(body(recovery: recovery.merge(future_field: 1))) }
      expect(response).to have_http_status(:ok)
      expect(host.reload).to be_recovering
      expect(host).to have_attributes(agent_recovery_since: started, agent_recovery_reason: recovery[:reason],
                                      agent_recovery_entered_at: Time.utc(2026, 1, 1, 11), agent_recovery_retry_at: Time.utc(2026, 1, 1, 12),
                                      liveness_status: "online")
      # The agent's own times and reason are replaced; the server's start of the episode is kept.
      travel_to(started + 10.minutes) { heartbeat(body(recovery: recovery.merge(reason: "recovery mode failed: a panic"))) }
      expect(host.reload).to have_attributes(agent_recovery_since: started, agent_recovery_reason: "recovery mode failed: a panic")
      heartbeat
      expect(host.reload).to have_attributes(agent_recovery_since: nil, agent_recovery_reason: nil, agent_recovery_entered_at: nil,
                                             agent_recovery_retry_at: nil)
      expect(host).not_to be_recovering
      # Broadcast when it goes into recovery mode and when it leaves, not on every heartbeat in it.
      expect(FleetBroadcast).to have_received(:hosts_changed).with([ host.id ]).exactly(3).times
    end

    it "sends a host in recovery mode its agent_update directive like any other host" do
      release = release_for_rollout("0.3.0")
      rollout = start_rollout(release:, canaries: [ host ].each { |h| h.update_columns(agent_version: "0.2.0") })
      heartbeat(body(agent_version: "0.2.0", recovery:))
      expect(json.dig("directives", "agent_update")).to include("rollout_id" => rollout.id, "version" => "0.3.0")
    end

    it "rejects a malformed recovery object without changing what was stored" do
      heartbeat(body(recovery:))
      heartbeat(body(recovery: recovery.merge(reason: "two\nlines")))
      expect_error(:bad_request, "validation_failed")
      expect(host.reload.agent_recovery_reason).to eq(recovery[:reason])
    end
  end

  describe "unit coverage (#232)" do
    it "stores whether recovery mode is set up, writes the hosts row only when it changes, and clears it without the object" do
      allow(FleetBroadcast).to receive(:hosts_changed)
      heartbeat
      expect(host.reload.agent_recovery_coverage).to be_nil
      heartbeat(body(units: { recovery: false }))
      expect(host.reload.agent_recovery_coverage).to eq("not_set_up")
      # Steady: the hosts row is not written again (only host_liveness), and nothing is broadcast.
      writes = []
      callback = ->(*, payload) { writes << payload[:sql] if payload[:sql].match?(/\AUPDATE "hosts"/) }
      ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { heartbeat(body(units: { recovery: false, later_unit: true })) }
      expect(writes).to be_empty
      # The confirmed update refreshed the units: true, broadcast so the fleet list's filter and the host page follow.
      heartbeat(body(units: { recovery: true }))
      expect(host.reload.agent_recovery_coverage).to eq("set_up")
      # The agent could not check (re-review of #235): stored apart from "not set up".
      heartbeat(body(units: { recovery: nil }))
      expect(host.reload.agent_recovery_coverage).to eq("unchecked")
      heartbeat
      expect(host.reload.agent_recovery_coverage).to be_nil
      # The first heartbeat (online), then each change: false, true, not checked, not reported.
      expect(FleetBroadcast).to have_received(:hosts_changed).with([ host.id ]).exactly(5).times
    end

    it "rejects a malformed units object without changing what was stored" do
      heartbeat(body(units: { recovery: true }))
      heartbeat(body(units: { recovery: "yes" }))
      expect_error(:bad_request, "validation_failed")
      expect(host.reload.agent_recovery_coverage).to eq("set_up")
    end
  end

  describe "the agent process and its restarts (#251)" do
    let(:oom) { { result: "oom-kill", exit_code: "killed", exit_status: 9, stopped_at: "2026-01-01T11:59:49.512Z" } }

    def process(started_at: "2026-01-01T11:00:00.250Z", restarts: 0, last_stop: nil) = { started_at:, restarts:, last_stop: }

    # The heartbeat's agent_time is after every process start below: a start after it is refused as implausible.
    def beat(process) = heartbeat(body(agent_time: "2026-01-01T23:00:00Z", process:))

    def hosts_writes
      writes = []
      callback = ->(*, payload) { writes << payload[:sql] if payload[:sql].match?(/\AUPDATE "hosts"/) }
      ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { yield }
      writes
    end

    it "stores the process, writes the hosts row only when it changes, and counts restarts from systemd's count" do
      allow(FleetBroadcast).to receive(:hosts_changed)
      freeze_time do
        beat(process)
        expect(host.reload).to have_attributes(agent_process_started_at: Time.utc(2026, 1, 1, 11, 0, 0.25r), agent_restarts: 0,
                                               agent_recent_restarts: nil, agent_restarted_at: nil, agent_last_stop_result: nil)
        # Steady: nothing more is written to hosts, and nothing is broadcast, whatever the agent adds inside.
        expect(hosts_writes { beat(process.merge(pid: 42)) }).to be_empty
      end
      # Killed at its memory limit; systemd restarted it once. The new process says so, with how the last one stopped.
      first = Time.current.change(usec: 0)
      travel_to(first) { beat(process(started_at: "2026-01-01T12:00:00.000Z", restarts: 1, last_stop: oom)) }
      expect(host.reload).to have_attributes(agent_restarts: 1, agent_recent_restarts: [ first ], agent_restarted_at: first,
                                             agent_last_stop_result: "oom-kill", agent_last_stop_exit_code: "killed",
                                             agent_last_stop_exit_status: 9, agent_last_stop_at: Time.utc(2026, 1, 1, 11, 59, 49.512r))
      # Heartbeats failed meanwhile: a jump of 3 counts 3, at this heartbeat's time, newest first.
      second = first + 10.minutes
      travel_to(second) { beat(process(started_at: "2026-01-01T12:10:00.000Z", restarts: 4, last_stop: oom)) }
      expect(host.reload.agent_recent_restarts).to eq([ second, second, second, first ])
      expect(host.agent_restarts_within(1.day, now: second)).to eq(4)
      expect(host.restart_loop?(now: second)).to be(true)
      expect(host.restart_loop?(now: first + 25.hours)).to be(false)
      # A start by a person or an update resets systemd's count: no restart. One after it counts one.
      third = second + 1.hour
      travel_to(third) { beat(process(started_at: "2026-01-01T13:10:00.000Z", restarts: 0, last_stop: oom.merge(result: "success", exit_code: "exited", exit_status: 0))) }
      expect(host.reload).to have_attributes(agent_restarts: 0, agent_restarted_at: second, agent_last_stop_result: "success", agent_last_stop_exit_status: 0)
      travel_to(third + 1.minute) { beat(process(started_at: "2026-01-01T13:11:00.000Z", restarts: 1, last_stop: oom)) }
      expect(host.reload.agent_recent_restarts.size).to eq(5)
      # A lower count than the last one is a reset followed by that many restarts.
      travel_to(third + 2.minutes) { beat(process(started_at: "2026-01-01T13:12:00.000Z", restarts: 5, last_stop: oom)) }
      travel_to(third + 3.minutes) { beat(process(started_at: "2026-01-01T13:13:00.000Z", restarts: 2, last_stop: oom)) }
      expect(host.reload.agent_recent_restarts.size).to eq(11)
      # Changes broadcast: the first heartbeat (online), then each heartbeat that counted restarts (5).
      expect(FleetBroadcast).to have_received(:hosts_changed).with([ host.id ]).exactly(6).times
    end

    it "keeps at most 32 restarts, newest first" do
      beat(process)
      beat(process(started_at: "2026-01-01T12:00:00.000Z", restarts: 40))
      expect(host.reload.agent_recent_restarts.size).to eq(Liveness::RESTART_HISTORY)
      beat(process(started_at: "2026-01-01T12:01:00.000Z", restarts: 41))
      expect(host.reload.agent_recent_restarts.size).to eq(Liveness::RESTART_HISTORY)
    end

    it "counts nothing on the first report, or while the agent cannot read the count, and keeps the last known count" do
      beat(process(restarts: 7))
      expect(host.reload).to have_attributes(agent_restarts: 7, agent_recent_restarts: nil)
      beat(process(started_at: "2026-01-01T12:00:00.000Z", restarts: nil))
      expect(host.reload).to have_attributes(agent_restarts: 7, agent_process_started_at: Time.utc(2026, 1, 1, 12), agent_recent_restarts: nil)
      # Recovery mode reports the failed service's count, unchanged, from another process: no restart.
      beat(process(started_at: "2026-01-01T12:05:00.000Z", restarts: 7))
      expect(host.reload.agent_recent_restarts).to be_nil
    end

    it "keeps what it stored for a heartbeat without the object, such as the installer's" do
      beat(process(restarts: 2, last_stop: oom))
      expect(hosts_writes { heartbeat }).to be_empty
      expect(host.reload).to have_attributes(agent_restarts: 2, agent_last_stop_result: "oom-kill")
    end

    it "ignores, without refusing the heartbeat, a process object the agent could not have sent" do
      beat(process(restarts: 1))
      allow(Rails.logger).to receive(:warn)
      [ process(started_at: "2026-01-01T23:00:01.500Z", restarts: 9), # after the heartbeat's own agent_time
        process(restarts: 9, last_stop: oom.merge(exit_code: nil)), # a status without a code
        process(restarts: 9, last_stop: oom.merge(exit_code: "exited", exit_status: nil)),
        process(restarts: 9, last_stop: oom.merge(exit_status: 200)) ].each do |odd|
        beat(odd)
        expect(response).to have_http_status(:ok)
        expect(host.reload).to have_attributes(agent_restarts: 1, agent_recent_restarts: nil, agent_last_stop_result: nil)
      end
      expect(Rails.logger).to have_received(:warn).with(/could not have sent/).exactly(4).times
      beat(process(restarts: 1, last_stop: oom.merge(exit_status: nil)))
      expect(host.reload).to have_attributes(agent_last_stop_result: "oom-kill", agent_last_stop_exit_status: nil)
    end

    it "rejects a malformed process object without changing what was stored" do
      beat(process(restarts: 2))
      beat(process(restarts: -1))
      expect_error(:bad_request, "validation_failed")
      beat(process(restarts: 3, last_stop: oom.merge(result: "OOM KILL")))
      expect_error(:bad_request, "validation_failed")
      expect(host.reload.agent_restarts).to eq(2)
    end
  end

  it_behaves_like "the docs/api contract examples", "heartbeat.request", accepted: :ok do
    def submit_example(data, valid:) = heartbeat(data)
  end

  describe "hosts that may not send heartbeats" do
    it "tells a re-enrolling host to redeem its new token (403 with Fleet-Enrollment-State)" do
      Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM) # active -> pending; old credential still valid
      expect { heartbeat }.not_to(change { host.reload.attributes })
      expect_error(:forbidden, "reenrollment_required")
      expect(response.headers["Fleet-Enrollment-State"]).to eq("pending")
      expect(json.dig("error", "message")).to include("fleet-agent install --reenroll", "fleet-agent install --token")
    end

    it "refuses revoked and retired hosts with 401 (their credentials are revoked)" do
      %i[revoke! retire!].each do |transition|
        other_host, other_credential = enrolled_host
        other_host.public_send(transition, actor: Audit::SYSTEM)
        heartbeat(as: other_credential)
        expect_error(:unauthorized, "unauthorized")
        expect(other_host.reload.last_seen_at).to be_nil
      end
    end

    it "refuses a request without a credential" do
      heartbeat(as: nil)
      expect_error(:unauthorized, "unauthorized")
    end

    it "uses host_not_active for any other inactive state" do
      allow_any_instance_of(Host).to receive(:enrollment_state).and_return("revoked") # a credential that somehow outlived revocation
      heartbeat
      expect_error(:forbidden, "host_not_active")
      expect(response.headers).not_to have_key("Fleet-Enrollment-State")
    end
  end
end
