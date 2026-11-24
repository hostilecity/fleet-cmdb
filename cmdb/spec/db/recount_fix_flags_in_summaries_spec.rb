require "rails_helper"
require "rake"
require Rails.root.join("db/migrate/20261120256001_add_fix_counts_to_compliance_summaries")
require Rails.root.join("db/migrate/20261120256002_recount_fix_flags_in_summaries")

# The recount after the fix counts were added (VT-FIXABLE #256; review of #267, S3 and N2): inline at container start
# when its estimate fits, otherwise refused with the upgrade step, done by the resumable rake task, and finished by
# the migration. The progress row is made for each example (inside its transaction), as 20261120256001 leaves it.
RSpec.describe RecountFixFlagsInSummaries do
  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "compliance_summaries:recount_fixes" } }

  let(:connection) { ActiveRecord::Base.connection }
  let!(:hosts) { Array.new(3) { enrolled_host.first.tap { |host| vulns_evaluated!(host) && findings!(host, "high", "low", fixed: "2.0-1") } } }

  def quiet(&) = ActiveRecord::Migration.suppress_messages(&)
  def progress! = quiet { AddFixCountsToComplianceSummaries.new.create_progress }
  # The fix counts' columns are gone since VT-SCORES (#262); the recount is the same refresh, so the open count stands in.
  def zero! = HostComplianceSummary.update_all(vuln_high: 0, vuln_low: 0)
  def fixable = hosts.map { |host| HostComplianceSummary.find(host.id).vuln_open }
  def migrate(direction = :up) = quiet { described_class.new.migrate(direction) }

  def rake
    Rake::Task["compliance_summaries:recount_fixes"].reenable
    output = StringIO.new
    $stdout = output
    Rake::Task["compliance_summaries:recount_fixes"].invoke
    output.string
  ensure
    $stdout = STDOUT
  end

  before do
    progress!
    zero! # as 20261120256001 leaves every row
  end

  it "recounts every host at container start when it fits, then drops its progress, and carries on from where a stopped run left off" do
    connection.execute("UPDATE compliance_fix_recounts SET last_host_id = #{hosts.first.id}") # a run stopped after the first host
    migrate
    expect(fixable).to eq([ 0, 2, 2 ]) # the first was recounted by the stopped run, which this one does not repeat
    expect(connection.table_exists?(:compliance_fix_recounts)).to be(false)
    expect(HostComplianceSummary.drift).to eq([ hosts.first.id ])
    expect([ ComplianceFixRecount.new.estimate.seconds, ComplianceFixRecount.new.run! ]).to eq([ 0.0, 0 ]) # nothing left to do

    migrate(:down) # the progress comes back at its start, so migrating up again recounts every host
    expect(ComplianceFixRecount.new.last_host_id).to eq(0)
    migrate
    expect(fixable).to eq([ 2, 2, 2 ])
    expect(HostComplianceSummary.drift).to be_empty
  end

  it "refuses with the upgrade step when the estimate is too long, recounting nothing, and the rake task does it, resumably" do
    stub_const("#{described_class}::INLINE_SECONDS", 0.000001)
    expect { migrate }.to raise_error(/fleet-cmdb upgrade step needed: recounting every host's vulnerability fix counts would take more than .* s \(it stopped counting there.*docker exec fleet-cmdb bin\/rails compliance_summaries:recount_fixes && docker restart fleet-cmdb/m)
    expect(fixable).to eq([ 0, 0, 0 ])

    out = rake
    expect(out).to start_with("To recount: #{Host.count} hosts with 6 open findings, about 1 min at the estimate's rates.\n")
    expect(out).to end_with("every host recounted (#{Host.count} in this run)\nDone. Start the server again: its migrations finish the upgrade.\n")
    expect(fixable).to eq([ 2, 2, 2 ])
    expect(rake).to include("every host recounted (0 in this run)") # nothing left: a second run does nothing

    stub_const("#{described_class}::INLINE_SECONDS", 90)
    migrate # the restart's migration finds nothing left and finishes
    expect(connection.table_exists?(:compliance_fix_recounts)).to be(false)
    expect(rake).to eq("Nothing to recount: the upgrade's recount is finished.\n")
  end

  it "says how long when it counted everything, and estimates from measured rates, stopping once past the limit" do
    recount = ComplianceFixRecount.new
    full = recount.estimate
    expect(full).to have_attributes(hosts: Host.count, findings: 6, complete?: true)
    expect(full.seconds).to be_within(1e-9).of(Host.count * ComplianceFixRecount::HOST_SECONDS + 6 * ComplianceFixRecount::FINDING_SECONDS)
    expect(recount.estimate(within: ComplianceFixRecount::HOST_SECONDS)).to have_attributes(hosts: 2, findings: 0, complete?: false) # past it on hosts alone
    expect(recount.estimate(within: (Host.count * ComplianceFixRecount::HOST_SECONDS) + (2 * ComplianceFixRecount::FINDING_SECONDS)))
      .to have_attributes(hosts: Host.count, findings: 3, complete?: false)
    expect(described_class.new.too_long(full)).to eq("about 1 min")

    connection.execute("DELETE FROM compliance_fix_recounts") # a lost row is made again, never looped on
    stub_const("ComplianceFixRecount::LOG_EVERY", 2)
    lines = []
    expect(ComplianceFixRecount.new(log: ->(message) { lines << message }).run!(batch: 1)).to eq(Host.count)
    expect(lines.first).to eq("2 hosts recounted, up to host #{Host.order(:id).second.id}")
    expect(fixable).to eq([ 2, 2, 2 ])
  end
end
