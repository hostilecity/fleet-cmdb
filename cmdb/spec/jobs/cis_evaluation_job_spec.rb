require "rails_helper"

# When rule evaluation runs (P2-S06, FR-2.2): after a new config snapshot or a change of operating system (that
# host), and after a rule is created, edited, enabled, or disabled (every host, that rule, as a fleet-wide EvaluationRun,
# #197). Agents are not involved.
RSpec.describe CisEvaluationJob, type: :job do
  include ActiveJob::TestHelper

  let(:host) { enrolled_host.first }

  it "is enqueued for the host after a new config snapshot commits, not for unchanged facts, and not on a rollback" do
    expect { record_config(host) }.to have_enqueued_job(described_class).with(host_ids: [ host.id ])
    expect { record_config(host) }.not_to have_enqueued_job(described_class)
    expect do
      Host.transaction do
        record_config(host, "sshd.permitrootlogin" => ok_fact("yes"))
        raise ActiveRecord::Rollback
      end
    end.not_to have_enqueued_job(described_class)
  end

  it "is enqueued for the host when its operating system is first known or changes, and not for other inventory changes" do
    expect { record_inventory(host) }.to have_enqueued_job(described_class).with(host_ids: [ host.id ])
    expect { record_inventory(host, hostname: "vm-02.example.lan") }.not_to have_enqueued_job(described_class)
    expect { record_inventory(host, os: { "id" => "debian", "version_id" => "14", "pretty_name" => "Debian 14" }) }
      .to have_enqueued_job(described_class).with(host_ids: [ host.id ])
  end

  it "starts a fleet-wide run for a rule when it is created, edited, enabled, or disabled, and not when it is unchanged" do
    runs = -> { EvaluationRun.order(:id).map { |run| run.scope["rule_ids"] } }
    rule, = define_cis_rules(cis_rule_hash)
    expect(runs.call).to eq([ [ rule.id ] ])
    expect(EvaluationRunJob).to have_been_enqueued.with(EvaluationRun.last.id)
    expect { define_cis_rules(cis_rule_hash) }.not_to change(EvaluationRun, :count)
    define_cis_rules(cis_rule_hash(condition: { "ne" => "yes" }))
    CisRule.transaction { rule.disable!(actor: Audit::SYSTEM) }
    expect { CisRule.transaction { rule.disable!(actor: Audit::SYSTEM) } }.not_to change(EvaluationRun, :count)
    CisRule.transaction { rule.enable!(actor: Audit::SYSTEM) }
    expect(runs.call).to eq([ [ rule.id ] ] * 4)
    expect(enqueued_jobs.map { |job| job["job_class"] }).not_to include("CisEvaluationJob")
  end

  it "evaluates a changed rule on every host in the fleet" do
    hosts = Array.new(2) { enrolled_host.first }
    hosts.each { |h| record_inventory(h) && record_config(h) }
    clear_enqueued_jobs
    perform_evaluation_jobs { define_cis_rules(cis_rule_hash) }
    expect(CisResult.where(host: hosts).pluck(:result)).to eq(%w[pass pass])
  end
end
