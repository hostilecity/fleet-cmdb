require "rails_helper"

# POST /api/v1/reports/inventory (P1-INVENTORY, FR-1.3, DEC-07, FR-S.1, AC-1.4)
RSpec.describe "POST /api/v1/reports/inventory", type: :request do
  let(:machine_id) { "0123456789abcdef0123456789abcdef" }
  let!(:enrolled) do
    host, token = Enrollment::RegisterHost.call({ name: "VM 1", hostname: "vm-01.example.lan" }, actor: Audit::SYSTEM)
    [ host, Enrollment::Redeem.call(token:, machine_id:, agent_version: "0.1.0", schema_version: 1) ]
  end
  let(:host) { enrolled.first.reload }
  let(:credential) { enrolled.last }
  let(:full) { ApiContract.examples.find { |e| e.schema_name == "inventory.request" && e.kind == "valid" && e.name == "full" }.data }

  def report(**overrides) = full.merge("report_id" => SecureRandom.uuid).merge(overrides.transform_keys(&:to_s))

  def send_report(payload, as: credential)
    post "/api/v1/reports/inventory", params: payload.to_json, headers: api_headers(as)
  end

  it "stores the current inventory and the first snapshot, and audits the first inventory" do
    payload = report
    send_report(payload)
    expect(response).to have_http_status(:ok)
    expect(json).to eq("report_id" => payload["report_id"], "duplicate" => false)
    expect(ApiContract.errors("inventory.response", "v1", json)).to eq([])

    inventory = host.inventory
    expect(inventory.stable).to include("hostname" => "vm-01.example.lan", "architecture" => "x86_64", "cpu_cores" => 4,
                                        "boot_id" => payload["boot_id"], "machine_id" => machine_id)
    expect(inventory.stable["disks"]).to eq([ { "mount" => "/", "filesystem" => "ext4", "size_bytes" => 34_359_738_368 },
                                             { "mount" => "/srv/media files", "filesystem" => "xfs", "size_bytes" => 1_099_511_627_776 } ])
    expect(inventory.volatile).to include("memory_available_bytes" => 6_442_450_944, "uptime_seconds" => 86_400,
                                          "disk_free_bytes" => { "/" => 21_474_836_480, "/srv/media files" => 549_755_813_888 })
    expect(host.inventory_snapshots.count).to eq(1)
    expect(AuditEntry.for_target(host).where(action: Audit::Actions::HOST_FIRST_INVENTORY).count).to eq(1)
  end

  describe "idempotency (DEC-07)" do
    it "answers a retried report as a duplicate and changes nothing (AC-1.4)" do
      payload = report
      send_report(payload)
      before = [ host.inventory.reload.attributes, InventorySnapshot.count, InventoryReportReceipt.count, AuditEntry.count ]
      send_report(payload.merge("memory_available_bytes" => 1)) # same report id, even with different contents
      expect(response).to have_http_status(:ok)
      expect(json).to eq("report_id" => payload["report_id"], "duplicate" => true)
      expect([ host.inventory.reload.attributes, InventorySnapshot.count, InventoryReportReceipt.count, AuditEntry.count ]).to eq(before)
    end

    it "refreshes volatile fields but creates no snapshot when only volatile fields change" do
      send_report(report)
      disks = full["disks"].map { |d| d.merge("free_bytes" => 1024) }
      expect { send_report(report(memory_available_bytes: 1_000, uptime_seconds: 90_000, disks:)) }.not_to change(InventorySnapshot, :count)
      expect(host.inventory.volatile).to include("memory_available_bytes" => 1_000, "uptime_seconds" => 90_000,
                                                 "disk_free_bytes" => { "/" => 1024, "/srv/media files" => 1024 })
    end

    it "creates no snapshot when the agent lists the same disks, interfaces, and addresses in another order" do
      send_report(report)
      reordered = report(disks: full["disks"].reverse,
                         network_interfaces: full["network_interfaces"].reverse.map { |n| n.merge("addresses" => n["addresses"].reverse) })
      expect { send_report(reordered) }.not_to change(InventorySnapshot, :count)
    end

    {
      "kernel version" => { kernel_version: "6.12.1-example-amd64" },
      "boot id (a reboot)" => { boot_id: "00000000-0000-4000-8000-0000000000b2" },
      "mount list" => { disks: [ { "mount" => "/", "filesystem" => "ext4", "size_bytes" => 34_359_738_368, "free_bytes" => 1 } ] },
      "network addresses" => { network_interfaces: [ { "name" => "ens18", "primary" => true, "addresses" => [ "192.0.2.11/24" ] } ] },
      "agent version" => { agent_version: "0.2.0" }
    }.each do |label, change|
      it "creates a snapshot when the #{label} changes" do
        send_report(report)
        expect { send_report(report(**change)) }.to change(InventorySnapshot, :count).by(1)
        expect(host.inventory_snapshots.chronological.last.stable_hash).to eq(host.inventory.stable_hash)
      end
    end
  end

  it "stores a report with unreadable fields and its warnings" do
    payload = ApiContract.examples.find { |e| e.schema_name == "inventory.request" && e.name == "unreadable-facts" }.data
    send_report(payload)
    expect(response).to have_http_status(:ok)
    expect(host.inventory.stable).to include("machine_id" => nil, "disks" => nil)
    expect(host.inventory.warnings.pluck("field")).to contain_exactly("machine_id", "disks")
    expect(host.inventory_snapshots.sole.warnings).to eq(host.inventory.warnings)
  end

  describe "rejected reports write nothing" do
    def expect_rejected(payload, *pointers)
      expect { send_report(payload) }.not_to(change { [ InventorySnapshot.count, InventoryReportReceipt.count, HostInventory.count, AuditEntry.count ] })
      expect_error(:bad_request, "validation_failed")
      expect(json.dig("error", "details").pluck("pointer")).to include(*pointers) if pointers.any?
    end

    it "rejects wrong types and unknown enum values" do
      expect_rejected(report(cpu_cores: "4"), "/cpu_cores")
      expect_rejected(report(architecture: "aarch64"), "/architecture")
      expect_rejected(report(report_id: "not-a-uuid"), "/report_id")
    end

    it "rejects impossible values the schema cannot express" do
      expect_rejected(report(memory_available_bytes: full["memory_total_bytes"] + 1), "/memory_available_bytes")
      expect_rejected(report(disks: [ { "mount" => "/", "filesystem" => "ext4", "size_bytes" => 10, "free_bytes" => 11 } ]), "/disks/0/free_bytes")
      expect_rejected(report(disks: full["disks"] + [ full["disks"].first ]), "/disks/2/mount")
      expect_rejected(report(network_interfaces: full["network_interfaces"] + [ full["network_interfaces"].first ]), "/network_interfaces/2/name")
    end

    it "rejects an oversize report with 413" do
      big = report(cpu_model: "x" * 200).merge("padding" => "y" * 300.kilobytes)
      expect { send_report(big) }.not_to change(HostInventory, :count)
      expect_error(:payload_too_large, "payload_too_large")
    end

    ApiContract.examples.select { |e| e.version == "v1" && e.schema_name == "inventory.request" && e.kind == "invalid" }.each do |example|
      it "rejects the contract example #{example.name}" do
        expect_rejected(example.data)
      end
    end
  end

  it "accepts every valid contract example (NFR-5)" do
    allow(AgentApi.config).to receive(:minimum_agent_version).and_return("0.0.0")
    ApiContract.examples.select { |e| e.version == "v1" && e.schema_name == "inventory.request" && e.kind == "valid" }.each do |example|
      send_report(example.data.merge("report_id" => SecureRandom.uuid))
      expect(response).to have_http_status(:ok), "#{example.name}: #{response.body}"
    end
  end

  it "stores hostile strings safely: control characters stripped, markup kept as text" do
    send_report(report(cpu_model: "<script>alert(1)</script>\u0000Xeon\u001b[31m", kernel_version: "6.12\u0007-x"))
    expect(response).to have_http_status(:ok)
    expect(host.inventory.stable).to include("cpu_model" => "<script>alert(1)</script>Xeon[31m", "kernel_version" => "6.12-x")
  end

  describe "clone detection (FR-S.1)" do
    it "warns once when the credential is used from a different machine" do
      other = "fedcba9876543210fedcba9876543210"
      send_report(report)
      expect(host.machine_id_mismatch?).to be(false)
      2.times { send_report(report(machine_id: other)) }
      expect(host.reload).to have_attributes(machine_id_mismatch?: true, reported_machine_id: other)
      entries = AuditEntry.for_target(host).where(action: Audit::Actions::HOST_MACHINE_ID_MISMATCH)
      expect(entries.sole.changeset).to eq("machine_id" => [ machine_id, other ])
    end

    it "learns the machine id when it was unreadable at enrollment" do
      host2, token = Enrollment::RegisterHost.call(attributes_for(:host), actor: Audit::SYSTEM)
      credential2 = Enrollment::Redeem.call(token:, machine_id: nil, agent_version: "0.1.0", schema_version: 1)
      send_report(report, as: credential2)
      expect(host2.agent_credentials.active.sole.machine_id).to eq(machine_id)
      expect(host2.reload.machine_id_mismatch?).to be(false)
    end

    it "clears the warning when the host is re-enrolled" do
      send_report(report)
      send_report(report(machine_id: "fedcba9876543210fedcba9876543210"))
      token = Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM)
      Enrollment::Redeem.call(token:, machine_id: "fedcba9876543210fedcba9876543210", agent_version: "0.1.0", schema_version: 1)
      expect(host.reload.machine_id_mismatch?).to be(false)
    end
  end

  it "writes no audit entry for ordinary reports" do
    send_report(report)
    expect { send_report(report(kernel_version: "6.12.9-example-amd64")) }.not_to change(AuditEntry, :count)
  end

  describe "hosts that may not report" do
    it "tells a re-enrolling host to redeem its new token" do
      Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM)
      send_report(report)
      expect_error(:forbidden, "reenrollment_required")
      expect(HostInventory.count).to eq(0)
    end

    it "refuses a revocation that lands after authentication (checked under the host lock)" do
      allow_any_instance_of(Api::V1::InventoryReportsController).to receive(:require_active_host!).and_wrap_original do |original, *args|
        original.call(*args)
        host.revoke!(actor: Audit::SYSTEM)
      end
      send_report(report)
      expect_error(:unauthorized, "unauthorized")
      expect(InventoryReportReceipt.count).to eq(0)
    end
  end
end
