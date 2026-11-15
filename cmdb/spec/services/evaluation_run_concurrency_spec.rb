require "rails_helper"

# #197: two overlapping fleet-wide runs whose batches run at the same time on several workers lock hosts in id order,
# so they never deadlock, write each result change once, and each count every batch once. Runs outside the test
# transaction so each thread commits on its own connection.
RSpec.describe EvaluationRun do
  self.use_transactional_tests = false

  before do
    stub_const("EvaluationRun::BATCH_SIZE", 2)
    stub_const("CisEvaluation::LOCK_CHUNK", 1) # many short transactions, so the threads interleave
    allow(CisEvaluationJob).to receive(:perform_later)
    allow(EvaluationRunJob).to receive(:perform_later)
  end

  after do
    ids = @hosts.map(&:id)
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica") # hosts and audit are protected
    EvaluationRun.delete_all
    [ CisResultChange, CisResult, HostConfig, ConfigSnapshot, ConfigReportReceipt, InventorySnapshot, HostInventory, InventoryReportReceipt,
      AgentCredential, EnrollmentToken ].each { |model| model.where(host_id: ids).delete_all }
    CisRule.update_all(current_version_id: nil)
    CisRuleVersion.delete_all
    CisRule.delete_all
    AuditEntry.where(target_type: %w[Host CisRule]).delete_all
    Host.where(id: ids).delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  it "runs overlapping runs' batches at once without deadlock, writing each change once and counting each batch once" do
    @hosts = Array.new(6) { |i| enrolled_host(hostname: "eval-#{i}.example.lan").first.tap { |h| record_inventory(h) && record_config(h) } }
    rules = define_cis_rules(cis_rule_hash, cis_rule_hash(key: "ssh-max-auth-tries", fact: "sshd.maxauthtries", condition: { "lte" => 4 }))
    runs = [ described_class.start!("cis_rules", "rule_ids" => rules.map(&:id)), described_class.start!("cis_rules", "rule_ids" => [ rules.last.id ]) ]
    allow(ActiveJob).to receive(:perform_all_later) # the batches are run by the threads below
    runs.each(&:fan_out!)
    batches = EvaluationBatch.where(evaluation_run: runs).order(:position, :evaluation_run_id).to_a
    batches = batches.reverse + batches # every batch twice, in both orders: duplicates and overlaps at once

    queue = Queue.new
    batches.each { |batch| queue << batch.id }
    errors = Queue.new
    workers = Array.new(4) do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          while (id = begin queue.pop(true) rescue nil end)
            EvaluationBatchJob.perform_now(id)
          end
        rescue StandardError => e
          errors << e
        end
      end
    end
    workers.each(&:join)

    expect(errors).to be_empty
    expect(runs.map { |run| run.reload.attributes.slice("state", "batches_done", "hosts_done") })
      .to eq([ { "state" => "finished", "batches_done" => 3, "hosts_done" => 6 } ] * 2)
    expect(CisResult.where(host: @hosts).count).to eq(12)
    expect(CisResultChange.where(host: @hosts).group(:host_id, :cis_rule_id).count.values.uniq).to eq([ 1 ])
  end
end
