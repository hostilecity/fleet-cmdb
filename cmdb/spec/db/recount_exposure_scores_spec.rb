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
  def migration = described_class.new

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

  it "recounts every host when it fits, drops its progress, and queues the hosts with listener evidence" do
    expect(points).to eq([ nil, nil ])
    HostApplicability.create!(host: hosts.last, in_use_reported: true, library_scan: "ran", library_scanned_at: Time.current, library_scan_received_at: Time.current,
                              loaded_by_listeners: [ { "listener" => "openssh-server", "service" => "ssh.service", "class" => "network", "sockets" => [], "packages" => [ "bash" ] } ])
    expect(points).to eq([ nil, 21 ]) # its row's insert recounts it (the reboot flag's trigger)
    quiet { migration.send(:queue_listener_hosts) }
    expect(enqueued_jobs.select { |job| job["job_class"] == "VulnerabilityMatchJob" }.map { |job| job["arguments"].first["host_ids"] }).to eq([ [ hosts.last.id ] ])
    quiet { migration.send(:recount) }
    expect(points).to eq([ 21, 21 ])
    expect(connection.table_exists?(:compliance_score_recounts)).to be(false)
    expect(HostComplianceSummary.drift).to be_empty
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
