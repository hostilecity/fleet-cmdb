require "rails_helper"
require "rake"
require Rails.root.join("db/migrate/20261123262001_add_exposure_scores")
require Rails.root.join("db/migrate/20261123262002_recount_exposure_scores")

# The recount after the exposure scores were added (VT-SCORES #262), as 20261120256002's: inline at container start
# when its estimate fits, otherwise refused with the upgrade step and done by the resumable rake task. The hosts with
# listener evidence are queued for their transitions first. The sort indexes are built CONCURRENTLY, which cannot run
# in the test's transaction, so this runs the migration's two other steps; db/schema.rb holds the indexes.
RSpec.describe RecountExposureScores do
  include ActiveJob::TestHelper

  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "compliance_summaries:recount_scores" } }

  let(:connection) { ActiveRecord::Base.connection }
  let!(:hosts) do
    Array.new(2) do
      enrolled_host.first.tap { |host| package_set!(host) && vulns_evaluated!(host) && findings!(host, "high", rule: "N4") && findings!(host, "low", rule: "F1") }
    end
  end

  def quiet(&) = ActiveRecord::Migration.suppress_messages(&)
  def unscored! = HostComplianceSummary.update_all(exposure_tier: nil, exposure_points: nil, work_items: nil, work_upgrades: nil) # as 20261123262001 leaves them
  def points = hosts.map { |host| HostComplianceSummary.find(host.id).exposure_points }
  def migration = @migration ||= described_class.new

  def rake
    Rake::Task["compliance_summaries:recount_scores"].reenable
    output = StringIO.new
    $stdout = output
    Rake::Task["compliance_summaries:recount_scores"].invoke
    output.string
  ensure
    $stdout = STDOUT
  end

  before do
    quiet { AddExposureScores.new.create_progress }
    unscored!
  end

  it "writes each finding's listener from the evidence in force before recounting, so no host is scored without its listener points" do
    host = hosts.last
    ssh = HostApplicability.create!(host:, in_use_reported: true, library_scan: "ran", library_scanned_at: Time.current, library_scan_received_at: Time.current,
                                    loaded_by_listeners: [ { "listener" => "cups", "service" => nil, "class" => "loopback", "sockets" => [], "packages" => %w[pkg-a pkg-b] },
                                                           { "listener" => "openssh-server", "service" => "ssh.service", "class" => "network", "sockets" => [], "packages" => %w[pkg-a] } ])
    findings = VulnerabilityFinding.where(host:).order(:id).to_a
    findings.first.update_columns(package: "pkg-a")
    findings.last.update_columns(package: "pkg-b")
    old = hosts.first # evidence received more than 24 hours ago is not in force: nothing written
    HostApplicability.create!(host: old, in_use_reported: true, library_scan: "ran", library_scanned_at: 2.days.ago, library_scan_received_at: 2.days.ago,
                              loaded_by_listeners: [ { "listener" => "x", "service" => nil, "class" => "network", "sockets" => [], "packages" => [ VulnerabilityFinding.where(host: old).pick(:package) ] } ])
    expect(quiet { migration.send(:write_listeners) }).to eq(2)
    expect(VulnerabilityFinding.where(host:).order(:id).pluck(:listener)).to eq([ 2, 1 ]) # the network listener wins
    expect(VulnerabilityFinding.where(host: old).pluck(:listener).uniq).to eq([ nil ])
    expect(quiet { migration.send(:write_listeners) }).to eq(0) # again: nothing left to write
    quiet { migration.send(:recount) }
    expect(points).to eq([ 21, 21 + 5 + 0 ]) # the high N4 on pkg-a: +5 for the network; the low F1 on pkg-b: +0 for loopback
    expect(ssh.reload.library_scan).to eq("ran")
    expect(connection.table_exists?(:compliance_score_recounts)).to be(false)
    expect(HostComplianceSummary.drift).to be_empty
  end

  it "validates the listener check on a table small enough, and leaves a larger one for the task" do
    name = VulnerabilityTriage::Checks::LISTENER[1]
    connection.execute("ALTER TABLE vulnerability_findings DROP CONSTRAINT #{name}")
    connection.execute("ALTER TABLE vulnerability_findings ADD CONSTRAINT #{name} CHECK (#{VulnerabilityTriage::Checks::LISTENER[2]}) NOT VALID")
    validated = -> { connection.select_value("SELECT convalidated FROM pg_constraint WHERE conname = '#{name}'") }
    stub_const("VulnerabilityTriage::Checks::INLINE_BYTES", -1)
    expect { quiet { migration.send(:validate_listener_check) } }.not_to(change { validated.call })
    stub_const("VulnerabilityTriage::Checks::INLINE_BYTES", 2.gigabytes)
    quiet { migration.send(:validate_listener_check) }
    expect(validated.call).to be(true)
    quiet { migration.send(:validate_listener_check) } # already validated: nothing to do
    expect { VulnerabilityFinding.where(host: hosts.first).update_all(listener: 3) }.to raise_error(ActiveRecord::StatementInvalid, /listener_valid/)
  end

  it "drops an index a failed concurrent build left INVALID, so it is built again, and keeps a valid one" do
    connection.execute("CREATE INDEX vt262_probe ON hosts (name)")
    sent = []
    allow(migration).to receive(:execute) { |sql| sent << sql }
    quiet { migration.send(:drop_invalid, "vt262_probe") }
    expect(sent).to eq([])
    connection.execute("UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'vt262_probe'::regclass") # as a stopped CONCURRENTLY build leaves it
    quiet { migration.send(:drop_invalid, "vt262_probe") }
    expect(sent).to eq([ %(DROP INDEX CONCURRENTLY IF EXISTS "vt262_probe") ])
  end

  it "refuses with the upgrade step when the estimate is too long, and the rake task recounts, resumably" do
    stub_const("#{described_class}::INLINE_SECONDS", 0.000001)
    expect { quiet { migration.send(:recount) } }.to raise_error(%r{fleet-cmdb upgrade step needed: recounting every host's exposure and work would take more than .* s.*compliance_summaries:recount_scores && docker restart}m)
    expect(points).to eq([ nil, nil ])
    expect(rake).to end_with("every host recounted (#{Host.count} in this run)\nDone. Start the server again: its migrations finish the upgrade.\n")
    expect(points).to eq([ 21, 21 ])
    stub_const("#{described_class}::INLINE_SECONDS", 90)
    quiet { migration.send(:recount) }
    expect(rake).to eq("Nothing to recount: the upgrade's recount is finished.\n")
    expect { ComplianceFixRecount.new(table: "users") }.to raise_error(ArgumentError, /unknown recount table/)
  end

  it "says how long when it counted everything" do
    expect(migration.send(:too_long, ComplianceFixRecount::Estimate.new(seconds: 150.0, hosts: 1, findings: 1, complete: true))).to eq("about 3 min")
  end
end
