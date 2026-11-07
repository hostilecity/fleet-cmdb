require "rails_helper"

# When rule evaluation runs (P2-S06, FR-2.2): after a new config snapshot or a change of operating system (that
# host), and after a rule is created, edited, enabled, or disabled (every host, that rule). Agents are not involved.
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

  it "is enqueued for a rule when it is created, edited, enabled, or disabled, and not when it is unchanged" do
    rule = nil
    expect { rule, = define_cis_rules(cis_rule_hash) }.to have_enqueued_job(described_class).with(rule_ids: [ an_instance_of(Integer) ])
    expect { define_cis_rules(cis_rule_hash) }.not_to have_enqueued_job(described_class)
    expect { define_cis_rules(cis_rule_hash(condition: { "ne" => "yes" })) }.to have_enqueued_job(described_class).with(rule_ids: [ rule.id ])
    expect { CisRule.transaction { rule.disable!(actor: Audit::SYSTEM) } }.to have_enqueued_job(described_class).with(rule_ids: [ rule.id ])
    expect { CisRule.transaction { rule.disable!(actor: Audit::SYSTEM) } }.not_to have_enqueued_job(described_class)
    expect { CisRule.transaction { rule.enable!(actor: Audit::SYSTEM) } }.to have_enqueued_job(described_class).with(rule_ids: [ rule.id ])
  end

  it "evaluates a changed rule on every host in the fleet" do
    hosts = Array.new(2) { enrolled_host.first }
    hosts.each { |h| record_inventory(h) && record_config(h) }
    clear_enqueued_jobs
    perform_enqueued_jobs { define_cis_rules(cis_rule_hash) }
    expect(CisResult.where(host: hosts).pluck(:result)).to eq(%w[pass pass])
  end
end
