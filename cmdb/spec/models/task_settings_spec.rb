require "rails_helper"

# P3-S06: the restart allowlist and the task limits (DEC-14, DEC-15, owner decisions Q31 to Q33). Every change is
# validated and audited with before and after.
RSpec.describe TaskSettings do
  let(:operator) { create(:operator) }

  def entries(action) = AuditEntry.where(action:).order(:id)

  describe "limits" do
    it "starts at the defaults: 25 hosts, 64 KiB, 30 seconds, and the catalog's 24 hours per type" do
      limits = described_class.limits
      expect(limits.to_h).to eq("max_hosts_per_batch" => 25, "output_limit_kib" => 64, "poll_seconds" => 30,
                                "expiry_hours" => TaskCatalog.current.types.index_with(24))
      expect(limits.output_limit_bytes).to eq(TaskOutput::LIMIT_BYTES)
      expect(limits.expiry("restart_service")).to eq(24.hours)
    end

    it "saves the changed values and audits them once, with before and after" do
      changes = described_class.update_limits!({ "max_hosts_per_batch" => "10", "output_limit_kib" => "64", "poll_seconds" => 60,
                                                 "expiry_hours" => { "restart_service" => "12", "refresh_reports" => "24" } }, actor: operator)
      expected = { "tasks.max_hosts_per_batch" => [ 25, 10 ], "tasks.poll_seconds" => [ 30, 60 ], "tasks.expiry_hours.restart_service" => [ 24, 12 ] }
      expect(changes).to eq(expected)
      expect(described_class.limits).to have_attributes(max_hosts_per_batch: 10, poll_seconds: 60, output_limit_kib: 64)
      expect(described_class.expiry("restart_service")).to eq(12.hours)
      entry = entries(Audit::Actions::TASK_SETTING_LIMITS_CHANGED).sole
      expect(entry).to have_attributes(actor_type: "operator", actor_id: operator.id, target_type: nil, changeset: expected)
    end

    it "audits nothing when nothing changed, and keeps an expiry set back to the default out of storage" do
      expect(described_class.update_limits!({ "poll_seconds" => "30" }, actor: operator)).to eq({})
      described_class.update_limits!({ "expiry_hours" => { "restart_service" => "12" } }, actor: operator)
      described_class.update_limits!({ "expiry_hours" => { "restart_service" => "24" } }, actor: operator)
      expect(Setting.find_by(key: "tasks.expiry_hours").value).to eq({})
      expect(entries(Audit::Actions::TASK_SETTING_LIMITS_CHANGED).map(&:changeset))
        .to eq([ { "tasks.expiry_hours.restart_service" => [ 24, 12 ] }, { "tasks.expiry_hours.restart_service" => [ 12, 24 ] } ])
    end

    it "refuses values outside the ranges, every one at once, and changes nothing (Q33)" do
      values = { "max_hosts_per_batch" => "50", "output_limit_kib" => "2", "poll_seconds" => "x", "expiry_hours" => { "apply_package_updates" => "169", "refresh_reports" => "0" } }
      expect { described_class.update_limits!(values, actor: operator) }.to raise_error(TaskSettings::Invalid) { |error|
        expect(error.errors).to eq(
          "max_hosts_per_batch" => "At most 25. The cap cannot be raised from the dashboard.",
          "output_limit_kib" => "Enter a whole number from 4 to 1024.", "poll_seconds" => "Enter a whole number from 10 to 300.",
          "expiry_hours.apply_package_updates" => "Enter a whole number of hours from 1 to 168.",
          "expiry_hours.refresh_reports" => "Enter a whole number of hours from 1 to 168."
        )
      }
      expect { described_class.update_limits!({ "max_hosts_per_batch" => "0" }, actor: operator) }.to raise_error(TaskSettings::Invalid, /from 1 to 25/)
      expect(Setting.where("key LIKE 'tasks.%'")).to be_empty
      expect(AuditEntry.count).to eq(0)
    end

    it "accepts the ends of each range, and ignores unknown fields and task types" do
      described_class.update_limits!({ "max_hosts_per_batch" => 1, "output_limit_kib" => 1024, "poll_seconds" => 10, "lease" => "1",
                                       "expiry_hours" => { "refresh_reports" => 168, "reboot" => 5 } }, actor: operator)
      expect(described_class.limits.to_h).to include("max_hosts_per_batch" => 1, "output_limit_kib" => 1024, "poll_seconds" => 10)
      expect(described_class.limits.expiry_hours).to eq("refresh_reports" => 168, "restart_service" => 24, "apply_package_updates" => 24)
      described_class.update_limits!({ "expiry_hours" => "not a hash" }, actor: operator)
    end
  end

  describe "the restart allowlist" do
    it "starts empty (DEC-15)" do
      expect(described_class.allowlist).to eq([])
    end

    it "adds a service for every host or one tag, audited with the list before and after" do
      described_class.add_service!(service: "nginx.service", tag: "web", actor: operator)
      chrony = described_class.add_service!(service: " chrony.service ", tag: "", actor: operator)
      expect(described_class.allowlist.map(&:label)).to eq([ "chrony.service (every host)", "nginx.service (tag web)" ])
      expect(chrony).to have_attributes(service: "chrony.service", tag: nil, added_by: operator)
      entry = entries(Audit::Actions::TASK_SETTING_SERVICE_ADDED).last
      expect(entry).to have_attributes(actor_type: "operator", target_type: "TaskAllowedService", target_id: chrony.id)
      expect(entry.changeset).to eq("service" => "chrony.service", "hosts" => "every host",
                                    "allowlist" => [ [ "nginx.service (tag web)" ], [ "chrony.service (every host)", "nginx.service (tag web)" ] ])
    end

    it "refuses protected services, instances, names that are not unit names, bad tags, repeats, and a full list (Q31, Q32)" do
      refusal = ->(service, tag = nil) { described_class.add_service!(service:, tag:, actor: operator) && nil rescue $!.errors } # rubocop:disable Style/RescueModifier
      expect(refusal.("ssh.service")).to eq("service" => "ssh.service is protected. Protected services are never restarted remotely, so they cannot be added.")
      %w[sshd.service systemd-journald.service fleet-agent.service dbus.service networking.service].each { |service| expect(refusal.(service)["service"]).to include("protected"), service }
      expect(refusal.("getty@tty1.service")["service"]).to start_with("Instances such as getty@tty1.service are not accepted")
      [ "nginx; reboot", "nginx", "Nginx.service", "/usr/sbin/nginx.service", "#{'a' * 57}.service", ".service" ].each do |service|
        expect(refusal.(service)["service"]).to start_with("Not a service unit name"), service
      end
      expect(refusal.("")["service"]).to start_with("Type a service name")
      expect(refusal.("nginx.service", "Web!")).to eq("tag" => "Choose every host or one tag.")
      described_class.add_service!(service: "nginx.service", tag: "web", actor: operator)
      expect(refusal.("nginx.service", "web")).to eq("service" => "nginx.service is already on the list for hosts tagged web.")
      expect(refusal.("nginx.service")).to be_nil # every host is another scope
      stub_const("TaskSettings::MAX_SERVICES", 2)
      expect(refusal.("chrony.service")["service"]).to start_with("The list holds at most 2 services")
      expect(entries(Audit::Actions::TASK_SETTING_SERVICE_ADDED).count).to eq(2)
    end

    it "removes a service, audited with the list before and after, and says which queued restarts it would leave without an entry" do
      web = task_host(tags: %w[web])
      other = task_host(tags: %w[db])
      nginx_web, nginx_all = [ "web", nil ].map { |tag| described_class.add_service!(service: "nginx.service", tag:, actor: operator) }
      tasks = [ web, other ].map { |host| create_task(host, type: "restart_service", parameters: { "service" => "nginx.service" }) }
      expect(described_class.tasks_refused_without(nginx_all)).to eq([ tasks.last ]) # the web host keeps its own entry
      expect(described_class.tasks_refused_without(nginx_web)).to eq([])

      expect(described_class.remove_service!(nginx_all.id, actor: operator)).to eq(nginx_all)
      expect(described_class.remove_service!(nginx_all.id, actor: operator)).to be_nil
      entry = entries(Audit::Actions::TASK_SETTING_SERVICE_REMOVED).sole
      expect(entry.changeset).to eq("service" => "nginx.service", "hosts" => "every host",
                                    "allowlist" => [ [ "nginx.service (every host)", "nginx.service (tag web)" ], [ "nginx.service (tag web)" ] ])
      expect(tasks.map { |task| task.reload.refusal_reason }).to eq([ nil, "not_allowed_on_server" ]) # rechecked at claim time
    end
  end
end
