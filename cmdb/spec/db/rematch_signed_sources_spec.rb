require "rails_helper"
require Rails.root.join("db/migrate/20261119270001_rematch_signed_sources")

# After the upgrade that maps signed-template sources (#270), the chunks matched before it are matched again in the
# background, as an import of linux and shim would, so every host's running kernel gets its findings.
RSpec.describe RematchSignedSources do
  include ActiveJob::TestHelper

  def migrate = ActiveRecord::Migration.suppress_messages { described_class.new.migrate(:up) }

  it "queues one advisory re-match of the sources the table maps to, once chunks have been matched" do
    allow(VulnerabilityMatchJob).to receive(:perform_later)
    host = debian_host(packages: [ [ "linux-image-6.12.48+deb13-amd64", "6.12.48-1", "linux-signed-amd64" ] ])
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-91001", package: "linux", fixed: "6.12.88-1"))
    allow(SignedSources).to receive(:table).and_return({}) # matched before the upgrade
    VulnerabilityMatcher.match!([ host.id ])
    expect(VulnerabilityFinding.count).to eq(0)
    allow(SignedSources).to receive(:table).and_call_original

    expect { migrate }.to change(EvaluationRun, :count).by(1)
    run = EvaluationRun.last
    expect(run).to have_attributes(kind: "advisories", scope: { "packages" => { "Debian:13" => %w[linux shim] }, "reason" => "matching" })
    expect(EvaluationRunJob).to have_been_enqueued.with(run.id)
    perform_enqueued_jobs { EvaluationRunJob.perform_now(run.id) }
    expect(VulnerabilityFinding.with_details.pluck(:package, :source, :state)).to eq([ [ "linux-image-6.12.48+deb13-amd64", "linux", "open" ] ])
    expect(run.reload.state).to eq("finished")
  end

  it "queues nothing on a server that has matched nothing yet, or with no source to match, and rolls back without a change" do
    expect { migrate }.not_to change(EvaluationRun, :count)
    expect(EvaluationRun::Advisories.matching_scope([ "", nil ])).to be_nil
    allow(Ecosystems).to receive(:supported).and_return([])
    expect(EvaluationRun::Advisories.matching_scope(%w[linux])).to be_nil
    expect { ActiveRecord::Migration.suppress_messages { described_class.new.migrate(:down) } }.not_to change(EvaluationRun, :count)
  end
end
