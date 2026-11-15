require "rails_helper"

# Fleet-wide CIS evaluation and advisory re-matching in batches (#197): the same results as the single job they
# replace, retry-safe, counted once, superseded by a later run that covers them, and safe when a host leaves the fleet
# part way.
RSpec.describe EvaluationRun do
  include ActiveJob::TestHelper

  before { stub_const("EvaluationRun::BATCH_SIZE", 2) }

  # What a result says, without its times and ids.
  def cis_state = CisResult.order(:host_id, :cis_rule_id).pluck(:host_id, :cis_rule_id, :cis_rule_version_id, :config_snapshot_id, :result, :observed, :reason)

  def cis_history = CisResultChange.order(:host_id, :cis_rule_id, :id).pluck(:host_id, :cis_rule_id, :cis_rule_version_id, :from_result, :to_result)

  def findings = VulnerabilityFinding.order(:host_id, :advisory_id, :package).pluck(:host_id, :advisory_id, :package, :state, :resolution, :installed_version, :fixed_version)

  def evaluations = HostVulnerabilityEvaluation.order(:host_id).pluck(:host_id, :state, :reason, :ecosystem, :not_evaluated_count)

  # Every job of the run's kind, in the order they were enqueued, one at a time.
  def batch_jobs = enqueued_jobs.select { |job| job["job_class"] == "EvaluationBatchJob" }

  def perform_batch(job)
    enqueued_jobs.delete(job)
    EvaluationBatchJob.perform_now(*ActiveJob::Arguments.deserialize(job["arguments"]))
  end

  describe "CIS evaluation on a mixed fleet" do
    let!(:rules) do
      define_cis_rules(cis_rule_hash,
                       cis_rule_hash(key: "ssh-max-auth-tries", fact: "sshd.maxauthtries", condition: { "lte" => 4 }),
                       cis_rule_hash(key: "ubuntu-only", applies_to: [ { "distribution" => "ubuntu" } ]))
    end
    let!(:hosts) do
      debian = Array.new(3) { enrolled_host.first.tap { |h| record_inventory(h) && record_config(h) } }
      failing = enrolled_host.first.tap { |h| record_inventory(h) && record_config(h, "sshd.permitrootlogin" => ok_fact("yes")) }
      ubuntu = enrolled_host.first.tap do |h|
        record_inventory(h, os: { "id" => "ubuntu", "version_id" => "24.04", "pretty_name" => "Ubuntu 24.04" })
        record_config(h)
      end
      no_os = enrolled_host.first.tap { |h| record_config(h) }
      no_report = enrolled_host.first.tap { |h| record_inventory(h) }
      retired = enrolled_host.first.tap { |h| record_inventory(h) && record_config(h) && h.retire!(actor: Audit::SYSTEM) }
      [ *debian, failing, ubuntu, no_os, no_report, retired ]
    end

    before do
      CisRule.transaction { rules.last.disable!(actor: Audit::SYSTEM) }
      clear_enqueued_jobs
    end

    it "writes the same results and history as the single job it replaces, in batches of keyset ranges" do
      CisEvaluation.evaluate!(Host.in_fleet.pluck(:id), rule_ids: rules.map(&:id)) # what CisEvaluationJob did for a rule change
      expected = [ cis_state, cis_history ]
      CisResultChange.delete_all
      CisResult.delete_all

      run = run_fleet_evaluation("cis_rules", "rule_ids" => rules.map(&:id))
      expect([ cis_state, cis_history ]).to eq(expected)
      expect(run.reload).to have_attributes(state: "finished", batch_count: 4, batches_done: 4, host_count: 7, hosts_done: 7, shown_changed: true)
      expect(run.batches).to be_empty
      expect(CisResult.where(host: hosts.last)).to be_empty
      expect(CisResult.distinct.pluck(:result)).to match_array(%w[pass fail not_applicable not_readable not_evaluated])
    end

    it "splits the fleet into consecutive ranges of host ids, the last one shorter" do
      run = described_class.start!("cis_rules", "rule_ids" => rules.map(&:id))
      perform_enqueued_jobs(only: EvaluationRunJob)
      ids = Host.in_fleet.order(:id).pluck(:id)
      expect(run.batches.order(:position).pluck(:first_host_id, :last_host_id, :host_count)).to eq(ids.each_slice(2).map { |s| [ s.first, s.last, s.size ] })
      expect(batch_jobs.size).to eq(4)
      expect(run.reload).to have_attributes(state: "running", batches_done: 0)
    end

    it "counts a retried batch once, and does nothing more for a duplicated fan-out or batch" do
      run = described_class.start!("cis_rules", "rule_ids" => rules.map(&:id))
      perform_enqueued_jobs(only: EvaluationRunJob)
      first = batch_jobs.first
      calls = 0
      allow(described_class).to receive(:batch_done!).and_wrap_original do |original, *args|
        calls += 1
        raise ActiveRecord::Deadlocked, "deadlock detected" if calls == 1 # the batch's work is done, its count is not

        original.call(*args)
      end
      expect { perform_batch(first) }.to have_enqueued_job(EvaluationBatchJob) # the retry
      expect(run.reload.batches_done).to eq(0)

      EvaluationRunJob.perform_now(run.id) # a duplicated fan-out enqueues the batches still waiting, adding none
      expect(run.batches.count).to eq(4)
      perform_evaluation_jobs
      expect(run.reload).to have_attributes(state: "finished", batches_done: 4, hosts_done: 7)
      expect(cis_history.size).to eq(CisResult.count) # one change per result, written once
      expect(cis_history.map(&:fourth).uniq).to eq([ nil ])

      expect { perform_batch(first) }.not_to(change { [ run.reload.attributes, cis_history ] }) # a duplicate after the end
    end

    it "lets the latest edit win: a run for the edited rule supersedes the unfinished one, whose remaining batches do nothing" do
      rule = rules.first
      older = described_class.start!("cis_rules", "rule_ids" => [ rule.id ])
      perform_enqueued_jobs(only: EvaluationRunJob)
      perform_batch(batch_jobs.first)

      define_cis_rules(cis_rule_hash(condition: { "eq" => "yes" })) # edited again mid-run: version 2
      newer = evaluation_runs.sole
      perform_enqueued_jobs(only: EvaluationRunJob)
      expect(older.reload).to have_attributes(state: "superseded", superseded_by: newer, batches_done: 1)
      expect(older.batches).to be_empty
      expect(newer.reload.shown_changed).to be(true) # the older run's finished batch changed results

      perform_evaluation_jobs
      version = rule.reload.current_version
      expect(CisResult.where(cis_rule: rule).where.not(result: "not_evaluated").pluck(:cis_rule_version_id).uniq).to eq([ version.id ])
      expect(CisResult.where(cis_rule: rule, host: hosts.first(3)).pluck(:result)).to eq(%w[fail fail fail])
      expect(newer.reload).to have_attributes(state: "finished", hosts_done: 7)
    end

    it "does not supersede a run it does not cover" do
      wide = described_class.start!("cis_rules", "rule_ids" => rules.map(&:id))
      narrow = described_class.start!("cis_rules", "rule_ids" => [ rules.first.id ])
      perform_evaluation_jobs
      expect([ wide.reload.state, narrow.reload.state ]).to eq(%w[finished finished])
    end

    it "skips a host retired after the run was split, and still finishes" do
      run = described_class.start!("cis_rules", "rule_ids" => rules.map(&:id))
      perform_enqueued_jobs(only: EvaluationRunJob)
      gone = hosts[5] # in the third batch
      gone.retire!(actor: Audit::SYSTEM)
      perform_evaluation_jobs
      expect(CisResult.where(host: gone)).to be_empty
      expect(CisResult.where(host: hosts[6])).to exist
      expect(run.reload).to have_attributes(state: "finished", batches_done: 4)
    end

    it "lets a batch still working when its run is superseded refresh the dashboard for what it changed itself" do
      older = described_class.start!("cis_rules", "rule_ids" => [ rules.first.id ])
      perform_enqueued_jobs(only: EvaluationRunJob)
      job = batch_jobs.first
      allow(CisEvaluation).to receive(:evaluate!).and_wrap_original do |original, *args, **options|
        RSpec::Mocks.space.proxy_for(CisEvaluation).reset
        outcome = original.call(*args, **options)
        perform_evaluation_jobs { described_class.start!("cis_rules", "rule_ids" => [ rules.first.id ]) } # meanwhile
        outcome
      end
      clear_enqueued_jobs
      perform_batch(job)
      expect(older.reload.state).to eq("superseded")
      broadcasts = enqueued_jobs.select { |j| j["job_class"] == "FleetBroadcastJob" }.map { |j| j["arguments"].first }
      expect(broadcasts).to include(hosts.first(2).map(&:id))
    end
  end

  describe "advisory re-matching on a mixed fleet" do
    let!(:hosts) do
      perform_enqueued_jobs do
        [ debian_host(packages: [ [ "curl", "8.14.1-1", "curl" ], [ "vim", "2:9.1-1", "vim" ] ]),
          debian_host(packages: [ [ "libcurl4", "8.14.1-1", "curl" ] ]),
          debian_host(packages: [ [ "vim", "2:9.1-1", "vim" ] ]),
          debian_host(packages: [ [ "curl", "8.14.1-1", "curl" ] ], os: { "id" => "debian", "version_id" => "12", "pretty_name" => "Debian 12" }),
          debian_host(packages: nil),
          debian_host(packages: [ [ "curl", "8.14.1-1", "curl" ] ]).tap { |h| h.retire!(actor: Audit::SYSTEM) } ]
      end
    end
    let(:packages) { { "Debian:13" => [ "curl" ] } }

    before do
      perform_enqueued_jobs { import_advisories(osv_record(id: "DSA-0-1", package: "vim", fixed: "2:9.1-2")) } # data for Debian 13
      import_advisories(osv_record(id: "DSA-1-1", package: "curl", fixed: "8.14.1-2"))
      clear_enqueued_jobs
    end

    # What VulnerabilityMatchJob did for an import before #197, in one job.
    def single_job_match(packages)
      evaluated = HostVulnerabilityEvaluation.where.not(reason: "no_advisory_data").or(HostVulnerabilityEvaluation.where(reason: nil)).select(:host_id)
      full = Host.in_fleet.where.not(id: evaluated).pluck(:id)
      targeted = packages.flat_map do |ecosystem, sources|
        HostPackage.where("COALESCE(source, name) IN (?)", sources).distinct.pluck(:host_id) |
          VulnerabilityFinding.where(ecosystem:, source: sources).distinct.pluck(:host_id)
      end.uniq - full
      VulnerabilityMatcher.match!(targeted, packages:) if targeted.any?
      VulnerabilityMatcher.match!(full)
    end

    def reset_matching
      VulnerabilityFinding.delete_all
      HostVulnerabilityEvaluation.delete_all
      perform_enqueued_jobs { VulnerabilityMatcher.match!(Host.in_fleet.pluck(:id)) }
      VulnerabilityFinding.where(source: "curl").delete_all # as before the curl advisory was matched
    end

    it "writes the same findings and evaluations as the single job it replaces, batching only the affected hosts" do
      reset_matching
      single_job_match(packages)
      expected = [ findings, evaluations ]
      reset_matching

      run = run_fleet_evaluation("advisories", "packages" => packages)
      expect([ findings, evaluations ]).to eq(expected)
      expect(findings.map(&:third)).to match_array(%w[curl libcurl4 vim vim])
      affected = hosts.values_at(0, 1, 3).map(&:id) # the curl hosts, on any release; not vim alone, no packages, nor the retired one
      expect(run.reload).to have_attributes(state: "finished", host_count: affected.size, batch_count: 2)
    end

    it "matches a host still without data in full, and lets a later import of the same sources supersede an unfinished run" do
      older = described_class.start!("advisories", "packages" => packages)
      perform_enqueued_jobs(only: EvaluationRunJob)
      newer = described_class.start!("advisories", "packages" => { "Debian:13" => %w[curl vim] })
      perform_enqueued_jobs(only: EvaluationRunJob) # the newer fan-out comes before the older batches
      perform_evaluation_jobs
      expect(older.reload).to have_attributes(state: "superseded", superseded_by: newer)
      expect(newer.reload.state).to eq("finished")
      expect(VulnerabilityFinding.where(host: hosts.first(2)).active.pluck(:package)).to match_array(%w[curl libcurl4 vim])
    end

    it "does not let an import of other sources supersede a run" do
      older = described_class.start!("advisories", "packages" => packages)
      described_class.start!("advisories", "packages" => { "Debian:13" => [ "vim" ] })
      perform_evaluation_jobs
      expect(older.reload.state).to eq("finished")
    end
  end

  it "finds the unfinished run for a rule's page and the data sources page, and deletes runs finished long ago" do
    rule, = define_cis_rules(cis_rule_hash)
    other, = define_cis_rules(cis_rule_hash(key: "other"))
    old = described_class.create!(kind: "advisories", state: "finished", finished_at: 31.days.ago)
    recent = described_class.create!(kind: "advisories", state: "finished", finished_at: 1.day.ago)
    expect(described_class.unfinished_for_rule(rule.id).scope).to eq("rule_ids" => [ rule.id ])
    expect(described_class.unfinished_for_rule(other.id).scope).to eq("rule_ids" => [ other.id ])
    expect(described_class.unfinished_advisories).to be_nil
    advisories = described_class.start!("advisories", "packages" => {})
    expect(described_class.unfinished_advisories).to eq(advisories)
    expect(described_class.where(id: [ old.id, recent.id ]).pluck(:id)).to eq([ recent.id ])
    perform_evaluation_jobs
    expect(described_class.unfinished_for_rule(rule.id)).to be_nil
  end

  it "refuses an unknown kind or state" do
    expect(described_class.new(kind: "other").tap(&:valid?).errors.attribute_names).to include(:kind)
    expect(described_class.new(kind: "advisories", state: "lost").tap(&:valid?).errors.attribute_names).to include(:state)
  end
end
