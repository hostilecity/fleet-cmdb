require "rails_helper"
require Rails.root.join("db/migrate/20261122274002_rematch_backports")

# After the upgrade that matches backports against the release they are built from (#274), the chunks holding a
# backport are matched again in the background, and only those: the scope names the backports' sources under Debian:14.
RSpec.describe RematchBackports do
  include ActiveJob::TestHelper

  def migrate = ActiveRecord::Migration.suppress_messages { described_class.new.migrate(:up) }

  let(:bpo_image) { [ "linux-image-7.0.9+deb13-amd64", "7.0.9-1~bpo13+1", "linux-signed-amd64" ] }

  before { allow(VulnerabilityMatchJob).to receive(:perform_later) }

  it "queues one re-match of the stored backports' sources under Debian:14, which reaches only the hosts holding one" do
    bpo = debian_host(packages: [ bpo_image, [ "openssl", "3.5.0-1", "openssl" ] ])
    trixie = debian_host(packages: [ [ "linux-image-6.12.48+deb13-amd64", "6.12.48-1", "linux-signed-amd64" ] ])
    record = osv_record(id: "DEBIAN-CVE-2026-64253", package: "linux", fixed: "6.12.95-1")
    record["affected"] << osv_record(id: "x", package: "linux", fixed: "7.1.3-1", ecosystem: "Debian:14")["affected"].first
    import_advisories(record)
    allow(Ecosystems).to receive(:backports_from).and_return(nil) # matched before the upgrade
    VulnerabilityMatcher.match!([ bpo.id, trixie.id ])
    expect(VulnerabilityFinding.where(host: bpo).count).to eq(0)
    allow(Ecosystems).to receive(:backports_from).and_call_original

    expect { migrate }.to change(EvaluationRun, :count).by(1)
    run = EvaluationRun.last
    expect(run).to have_attributes(kind: "advisories", scope: { "packages" => { "Debian:14" => %w[linux linux-signed-amd64] }, "reason" => "matching" })
    expect(EvaluationRun::Advisories.new(run.scope).hosts.pluck(:id)).to eq([ bpo.id ])
    perform_enqueued_jobs { EvaluationRunJob.perform_now(run.id) }
    expect(VulnerabilityFinding.with_details.where(host: bpo).pluck(:package, :fixed_version)).to eq([ [ bpo_image[0], "7.1.3-1" ] ])
    expect(run.reload.state).to eq("finished")
  end

  it "queues nothing with no backport stored or nothing matched yet, and rolls back without a change" do
    expect { migrate }.not_to change(EvaluationRun, :count)
    debian_host(packages: [ [ "openssl", "3.5.0-1", "openssl" ] ])
    expect(EvaluationRun::Advisories.backports_scope).to be_nil
    debian_host(packages: [ bpo_image ])
    expect(EvaluationRun::Advisories.backports_scope).to eq("packages" => { "Debian:14" => %w[linux linux-signed-amd64] }, "reason" => "matching")
    expect { migrate }.not_to change(EvaluationRun, :count) # no chunk matched yet: the first match handles backports
    stub_const("Ecosystems::BACKPORTS", {})
    expect(EvaluationRun::Advisories.backports_scope).to be_nil
    expect { ActiveRecord::Migration.suppress_messages { described_class.new.migrate(:down) } }.not_to change(EvaluationRun, :count)
  end
end
