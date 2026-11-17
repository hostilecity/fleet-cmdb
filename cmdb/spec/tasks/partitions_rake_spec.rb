require "rails_helper"
require "rake"

# The partition tasks (ADR 0027, #195).
RSpec.describe "partitions rake tasks" do
  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "partitions:ensure" } }

  def run(task)
    Rake::Task[task].reenable
    output = StringIO.new
    $stdout = output
    Rake::Task[task].invoke
    output.string
  ensure
    $stdout = STDOUT
  end

  it "creates the partitions ahead, saying which, or that they all exist" do
    expect(run("partitions:ensure")).to eq("Every partition ahead exists.\n")
    allow(Partitions).to receive(:ensure!).and_return("audit_entries" => [ "audit_entries_p20270301" ], "inventory_snapshots" => [])
    expect(run("partitions:ensure")).to eq("audit_entries: created audit_entries_p20270301\n")
  end

  it "runs after db:prepare and db:schema:load" do
    %w[db:prepare db:schema:load db:schema:load:primary].each do |name|
      expect(Rake::Task[name].actions.size).to be >= 1, name
    end
    allow(Partitions).to receive(:ensure!).and_return({})
    Rake::Task["partitions:ensure"].reenable
    Rake::Task["db:schema:load:primary"].actions.last.call
    expect(Partitions).to have_received(:ensure!)
  end

  it "lists each table's partitions, the problems, and the audit guard" do
    output = run("partitions:status")
    expect(output).to include("audit_entries: ", "inventory_report_receipts: ", ", default", "No problems.",
                              "Audit guard (ops/postgres/audit-guard.sql): NOT installed: run it as the PostgreSQL superuser")
    first = Partitions.list("inventory_snapshots").reject(&:default?).first
    ApplicationRecord.connection.execute("CREATE TABLE inventory_snapshots_legacy PARTITION OF inventory_snapshots FOR VALUES FROM (MINVALUE) TO ('#{first.from.to_fs(:db)}')")
    InventoryReportReceipt.insert!({ host_id: create(:host).id, report_id: SecureRandom.uuid, received_at: 1.year.from_now })
    allow(Partitions).to receive(:audit_guard_installed?).and_return(true)
    output = run("partitions:status")
    expect(output).to include("inventory_snapshots: #{Partitions.list('inventory_snapshots').count { |p| !p.default? }} partitions, MINVALUE to",
                              ", legacy partition until #{first.from.to_date}",
                              "warning: inventory_report_receipts: the default partition has rows", "Audit guard (ops/postgres/audit-guard.sql): installed")
    allow(Partitions).to receive(:partitioned?).and_return(false)
    expect(run("partitions:status")).to include("audit_entries: not partitioned yet (run bin/rails db:migrate)")
  end

  it "checks for rows without their host, and fails when it finds any" do
    expect(run("partitions:check")).to eq("No rows without their host or rule.\n")
    InventoryReportReceipt.insert!({ host_id: 2_000_000_000, report_id: SecureRandom.uuid, received_at: Time.current })
    expect { expect { run("partitions:check") }.to output("inventory_report_receipts.host_id: 1 rows\n").to_stderr }.to raise_error(SystemExit)
  end
end
