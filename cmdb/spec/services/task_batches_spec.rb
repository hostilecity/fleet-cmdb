require "rails_helper"

# P3-S02: bulk creation. AC-3.2: a request with any command-like field is refused with nothing written.
RSpec.describe TaskBatches do
  let(:operator) { create(:operator) }

  def request(hosts, type: "refresh_reports", parameters: {}, **extra)
    { "type" => type, "parameters" => parameters, "target" => { "host_ids" => Array(hosts).map(&:id) } }.merge(extra.stringify_keys)
  end

  def refused(request)
    described_class.create!(request, operator:)
    raise "expected TaskBatches::Refused"
  rescue TaskBatches::Refused => e
    e
  end

  def problems(request) = refused(request).errors.map { |error| error.values_at("pointer", "problem") }

  def records = [ TaskBatch.count, Task.count, AuditEntry.where(action: Audit::Actions::ALL.grep(/\Atask\./)).count ]

  describe "a bulk request" do
    it "creates one independent queued task per host, in one batch, audited with the operator" do
      hosts = Array.new(3) { task_host }
      result = nil
      freeze_time do
        result = described_class.create!(request(hosts), operator:)
        expect(result.tasks.map(&:host)).to eq(hosts)
        expect(result.tasks.map(&:state).uniq).to eq([ "queued" ])
        expect(result.tasks.map(&:expires_at).uniq).to eq([ 24.hours.from_now ]) # DEC-14
        expect(result.tasks.map(&:timeout_seconds).uniq).to eq([ 600 ])
        expect(result.tasks.map(&:uuid).uniq.size).to eq(3)
      end
      batch = result.batch.reload
      expect(batch.attributes.slice("task_type", "parameters", "selection_method", "selection_tag", "selected_host_ids", "excluded_hosts", "catalog_version", "catalog_digest"))
        .to eq("task_type" => "refresh_reports", "parameters" => {}, "selection_method" => "explicit", "selection_tag" => nil,
               "selected_host_ids" => hosts.map(&:id), "excluded_hosts" => [], "catalog_version" => 1, "catalog_digest" => TaskCatalog.current.digest)
      expect(batch.operator).to eq(operator)
      expect(result.excluded).to eq([])
      entries = AuditEntry.where(actor_type: "operator", actor_id: operator.id).order(:id)
      expect(entries.map(&:action)).to eq([ "task.batch_created" ] + [ "task.created" ] * 3)
      expect(entries.first.changeset).to eq("task_type" => "refresh_reports", "parameters" => {}, "selection_method" => "explicit",
                                            "host_ids" => hosts.map(&:id), "excluded" => [])
      expect(entries.second.changeset).to include("task_type" => "refresh_reports", "host_id" => hosts.first.id, "batch_id" => batch.id)
    end

    it "lets one task fail without touching the others" do
      tasks = described_class.create!(request(Array.new(3) { task_host }), operator:).tasks
      tasks.first.claim!(actor: tasks.first.host, lease_expires_at: 1.minute.from_now)
      tasks.first.start!(actor: tasks.first.host, lease_expires_at: 1.minute.from_now)
      tasks.first.fail!(actor: tasks.first.host, reason: "nonzero_exit", exit_status: 1)
      tasks.second.cancel!(actor: operator)
      expect(tasks.map { |task| task.reload.state }).to eq(%w[failed cancelled queued])
      expect(tasks.first.task_batch.state_counts).to include("failed" => 1, "cancelled" => 1, "queued" => 1, "running" => 0)
    end

    it "resolves a tag to the hosts in the fleet that have it, and records the selection" do
      web = Array.new(2) { task_host(tags: [ "web" ]) }
      task_host(tags: [ "db" ])
      retired = create(:host, :retired, tags: [ "web" ])
      result = described_class.create!(request([], "target" => { "tag" => "web" }), operator:)
      expect(result.tasks.map(&:host)).to eq(web)
      expect(result.batch.attributes.slice("selection_method", "selection_tag", "selected_host_ids"))
        .to eq("selection_method" => "tag", "selection_tag" => "web", "selected_host_ids" => web.map(&:id))
      expect(result.batch.selected_host_ids).not_to include(retired.id)
    end

    it "stores only the validated parameters" do
      allow(TaskPolicy).to receive(:restart_allowlist).and_return([ "nginx.service" ])
      task = described_class.create!(request(task_host, type: "restart_service", parameters: { "service" => "nginx.service" }), operator:).tasks.sole
      expect(task.reload.parameters).to eq("service" => "nginx.service")
      expect(task.timeout_seconds).to eq(300)
    end
  end

  describe "excluded hosts" do
    it "excludes hosts that are not active, or do not support or enable the type, and says why" do
      eligible = task_host
      pending = create(:host)
      revoked = create(:host, :revoked)
      unreported = create(:host, :active)
      old_catalog = task_host(catalog_version: 0)
      unsupported = task_host(types: %w[refresh_reports])
      disabled = task_host(enabled: %w[refresh_reports])
      cloned = task_host
      cloned.update_columns(machine_id_mismatch_at: Time.current)
      allow(TaskPolicy).to receive(:restart_allowlist).and_return([ "nginx.service" ])

      hosts = [ eligible, pending, revoked, unreported, old_catalog, unsupported, disabled, cloned ]
      result = described_class.create!(request(hosts, type: "restart_service", parameters: { "service" => "nginx.service" }, confirm_host_count: 1), operator:)
      expect(result.tasks.map(&:host)).to eq([ eligible ])
      expected = [ [ pending, "not_active" ], [ revoked, "not_active" ], [ unreported, "no_capability_report" ], [ old_catalog, "not_supported" ],
                   [ unsupported, "not_supported" ], [ disabled, "not_enabled" ], [ cloned, "machine_id_mismatch" ] ]
      expect(result.excluded.map { |e| [ e.host_id, e.reason ] }).to match_array(expected.map { |host, reason| [ host.id, reason ] })
      expect(result.batch.excluded_hosts).to match_array(expected.map { |host, reason| { "host_id" => host.id, "reason" => reason } })
      expect(result.batch.selected_host_ids).to match_array(hosts.map(&:id))
      expect(result.excluded.map(&:reason).uniq - TaskBatches::EXCLUSION_REASONS).to eq([])
    end

    it "creates nothing when no host is left, and reports the excluded hosts" do
      host = create(:host, :active)
      expect { refused(request(host)) }.not_to change { records }
      error = refused(request(host))
      expect(error.errors).to eq([ { "pointer" => "/target", "problem" => "selects no host that can run this task type" } ])
      expect(error.excluded).to eq([ TaskBatches::Exclusion.new(host_id: host.id, reason: "no_capability_report") ])
    end
  end

  describe "refused requests create nothing (AC-3.2)" do
    let(:host) { task_host }

    it "refuses a command-like field anywhere in the request" do
      [
        request(host).merge("command" => "/bin/sh -c 'reboot'"),
        request(host).merge("script" => "reboot"),
        request(host, parameters: { "command" => "reboot" }),
        request(host, type: "restart_service", parameters: { "service" => "nginx.service", "args" => [ "--force" ] }),
        request(host).merge("target" => { "host_ids" => [ host.id ], "shell" => "bash" })
      ].each do |req|
        expect { refused(req) }.not_to change { records }
      end
      expect(problems(request(host).merge("command" => "x"))).to eq([ [ "/command", "is not accepted" ] ])
      expect(problems(request(host, parameters: { "command" => "reboot" }))).to eq([ [ "/parameters/command", "is not a parameter of refresh_reports" ] ])
      expect(problems(request(host).merge("target" => { "host_ids" => [ host.id ], "a/b" => 1 }))).to eq([ [ "/target/a~1b", "is not accepted" ] ])
    end

    it "refuses an unknown type, missing fields, and invalid parameters, listing every problem" do
      expect(problems(request(host, type: "run_shell"))).to eq([ [ "/type", "is not a task type in the catalog" ] ])
      expect(problems(request(host, type: 7))).to eq([ [ "/type", "is not a task type in the catalog" ] ])
      expect(problems({ "target" => { "host_ids" => [ host.id ] } }))
        .to eq([ [ "/type", "is required" ], [ "/parameters", "is required; send {} for a type without parameters" ] ])
      expect(problems({ "type" => "restart_service", "target" => { "host_ids" => [ host.id ] } }))
        .to eq([ [ "/parameters", "is required; send {} for a type without parameters" ] ])
      expect(problems(request(host, type: "restart_service", parameters: { "service" => "nginx; reboot" }))).to eq([ [ "/parameters/service", "does not have the required form" ] ])
      expect(problems(request(host, type: "restart_service", parameters: {}))).to eq([ [ "/parameters/service", "is required" ] ])
      expect(problems(request(host, confirm_host_count: "1"))).to eq([ [ "/confirm_host_count", "must be a whole number" ] ])
      expect(problems([])).to eq([ [ "", "must be an object" ] ])
      expect(problems({ type: "refresh_reports" })).to eq([ [ "", "must be an object" ] ])
    end

    it "refuses what the server's policy does not allow (DEC-15)" do
      expect(problems(request(host, type: "restart_service", parameters: { "service" => "nginx.service" })))
        .to eq([ [ "/parameters/service", "is not on the server's restart allowlist" ] ])
      allow(TaskPolicy).to receive(:restart_allowlist).and_return([ "ssh.service" ])
      expect(problems(request(host, type: "restart_service", parameters: { "service" => "ssh.service" })))
        .to eq([ [ "/parameters/service", "is a protected service, which is never restarted remotely" ] ])
    end

    it "refuses a malformed target" do
      expect(problems(request(host).except("target"))).to eq([ [ "/target", "is required: host_ids or tag" ] ])
      expect(problems(request(host).merge("target" => [ host.id ]))).to eq([ [ "/target", "must be an object with host_ids or tag" ] ])
      expect(problems(request(host).merge("target" => {}))).to eq([ [ "/target", "must have exactly one of host_ids or tag" ] ])
      expect(problems(request(host).merge("target" => { "host_ids" => [ host.id ], "tag" => "web" }))).to eq([ [ "/target", "must have exactly one of host_ids or tag" ] ])
      expect(problems(request(host).merge("target" => { "tag" => "Web Servers" }))).to eq([ [ "/target/tag", "must be a tag such as web (1 to 32 lower-case letters, digits, - or _)" ] ])
      [ [], [ "1" ], [ 0 ], "1" ].each do |ids|
        expect(problems(request(host).merge("target" => { "host_ids" => ids }))).to eq([ [ "/target/host_ids", "must be a list of host ids" ] ]), ids.inspect
      end
      expect(problems(request(host).merge("target" => { "host_ids" => [ host.id, host.id ] }))).to eq([ [ "/target/host_ids", "lists a host more than once" ] ])
      expect(problems(request(host).merge("target" => { "host_ids" => [ host.id, host.id + 1000 ] }))).to eq([ [ "/target/host_ids/1", "is not a host" ] ])
      expect(problems(request(host).merge("target" => { "tag" => "nothing" }))).to eq([ [ "/target/tag", "selects no host" ] ])
    end
  end

  describe "batch limits (DEC-14)" do
    it "refuses a selection of more than 25 hosts, by ids or by tag" do
      ids = (1..26).to_a
      expect(problems({ "type" => "refresh_reports", "parameters" => {}, "target" => { "host_ids" => ids } }))
        .to eq([ [ "/target/host_ids", "has 26 hosts; a batch may target at most 25" ] ])
      26.times { create(:host, :active, tags: [ "wide" ]) }
      expect { refused(request([], "target" => { "tag" => "wide" })) }.not_to change { records }
      expect(problems(request([], "target" => { "tag" => "wide" }))).to eq([ [ "/target/tag", "selects more than 25 hosts; a batch may target at most 25" ] ])
    end

    it "requires the host count typed above 3 targeted hosts, counted after exclusions" do
      hosts = Array.new(4) { task_host }
      expect(problems(request(hosts))).to eq([ [ "/confirm_host_count", "must be 4, the number of hosts this batch will run on" ] ])
      expect(problems(request(hosts, confirm_host_count: 5))).to eq([ [ "/confirm_host_count", "must be 4, the number of hosts this batch will run on" ] ])
      expect(refused(request(hosts)).excluded).to eq([])
      expect(described_class.create!(request(hosts, confirm_host_count: 4), operator:).batch.confirmed_host_count).to eq(4)
      expect(described_class.create!(request(hosts.first(3) + [ create(:host) ]), operator:).tasks.size).to eq(3)
    end

    it "creates up to 25 tasks" do
      hosts = Array.new(25) { task_host }
      expect(described_class.create!(request(hosts, confirm_host_count: 25), operator:).tasks.size).to eq(25)
    end
  end
end
