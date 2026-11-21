require "rails_helper"

# The exploitation signals' shared parts (VT-SIGNALS, ADR 0032): clearing KEV data, counting CVEs that match open
# findings, recording failures, and the truncation guard's rule.
RSpec.describe Signals do
  describe ".clear!" do
    it "deletes the stored entries, hands every finding to triage, audits what it means, and reads as never imported" do
      import_kev(kev_file("CVE-2026-0001", "CVE-2026-0002"))
      TriageSignalChange.delete_all
      operator = create(:operator)
      import = described_class.clear!("kev", operator:)
      expect(KevEntry.count).to eq(0)
      expect(import).to have_attributes(signal: "kev", origin: "task", state: "cleared", counts: { "deleted" => 2 }, operator:)
      expect(pending_changes("kev_all")).to eq(%w[kev_all])
      entry = AuditEntry.where(action: "signal.kev_cleared").sole
      expect(entry).to have_attributes(actor_type: "operator", actor_id: operator.id)
      expect(entry.changeset["reason"]).to include("rule N1", "rule I5", "stop applying")
      expect(Signals::Freshness.status("kev")).to be_never
      expect(Signals::Freshness).not_to be_kev_imported
    end

    # Review of #269: the way out of a wrong stored EPSS score date.
    it "resets EPSS: deletes the scores, hands the high CVEs to triage, and lets a file of any date import again" do
      advisory_for("CVE-2026-0001", "CVE-2026-0002")
      import_epss(epss_file([ %w[CVE-2026-0001 0.5 0.5], %w[CVE-2026-0002 0.01 0.5] ], date: Date.current.iso8601))
      expect { import_epss(epss_file([ %w[CVE-2026-0001 0.5 0.5] ], date: "2026-11-10")) }.to raise_error(Signals::EpssImport::Older)
      TriageSignalChange.delete_all
      import = described_class.clear!("epss")
      expect(import).to have_attributes(state: "cleared", source: "bin/rails signals:epss_reset", counts: { "deleted" => 2 })
      expect(EpssScore.count).to eq(0)
      expect(pending_changes("epss")).to eq(%w[CVE-2026-0001])
      expect(AuditEntry.where(action: "signal.epss_cleared").sole.changeset["reason"]).to include("rule N2 stops applying", "whatever its score date")
      expect(Signals::Freshness.status("epss")).to be_never
      expect(import_epss(epss_file([ %w[CVE-2026-0001 0.5 0.5] ], date: "2026-11-10")).state).to eq("succeeded")
    end
  end

  describe ".lock!" do
    it "limits the rest of the import's transaction with SET LOCAL timeouts" do
      SignalImport.transaction(requires_new: true) do
        described_class.lock!("epss")
        expect(SignalImport.connection.select_value("SHOW statement_timeout")).to eq("5min")
        expect(SignalImport.connection.select_value("SHOW idle_in_transaction_session_timeout")).to eq("1min")
      end
    end
  end

  describe "the matching count after an import (SignalMatchCountJob)" do
    include ActiveJob::TestHelper

    before { open_finding_for(advisory_for("CVE-2026-0001")) }

    it "counts in a job after the import commits and stores what it found, with when" do
      import = import_kev(kev_file("CVE-2026-0001", "CVE-2026-0002")).reload
      expect(import.counts).to include("matching" => 1, "added_matching" => 1, "matching_state" => "counted", "matching_at" => be_present)
    end

    it "stores a count that passed the time limit as timed out, and a failed one after the job's retries, never failing the import" do
      allow(described_class).to receive(:matching_open_findings).and_raise(ActiveRecord::QueryCanceled, "canceling statement due to statement timeout")
      import = import_kev(kev_file("CVE-2026-0001", "CVE-2026-0002")).reload
      expect(import).to have_attributes(state: "succeeded")
      expect(import.counts).to include("matching_state" => "timed_out").and(not_include("matching"))
      allow(described_class).to receive(:matching_open_findings).and_raise(ActiveRecord::StatementInvalid, "lost")
      import = perform_enqueued_jobs { import_kev(kev_file("CVE-2026-0001", "CVE-2026-0002")) }.reload # with the job's retries
      expect(import).to have_attributes(state: "succeeded")
      expect(import.counts).to include("matching_state" => "failed", "matching_error" => "ActiveRecord::StatementInvalid")
      allow(described_class).to receive(:matching_open_findings).and_call_original
      expect(described_class.recount_later.map(&:id)).to eq([ import.id ])
      expect(import.reload.counts).to include("matching_state" => "counted", "matching" => 1).and(not_include("matching_error"))
    end

    it "queues nothing for an import that stored nothing, and never raises when queueing fails" do
      expect(described_class.recount_later).to eq([]) # nothing stored yet
      held = SignalImport.create!(signal: "kev", origin: "file", source: "x", state: "held_back", started_at: Time.current, finished_at: Time.current)
      expect { described_class.count_later(held) }.not_to have_enqueued_job(SignalMatchCountJob)
      allow(SignalMatchCountJob).to receive(:perform_later).and_raise(ActiveJob::EnqueueError, "queue down")
      expect(import_kev(kev_file("CVE-2026-0001")).state).to eq("succeeded")
      expect(SignalMatchCountJob.perform_now(0)).to be_nil # an import gone meanwhile
    end
  end

  describe ".matching_open_findings" do
    it "counts the CVEs an advisory with an open or reopened finding names, by its id or an alias, each once" do
      open_finding_for(advisory_for("CVE-2026-0001", "CVE-2026-0002"))
      open_finding_for(Advisory.create!(advisory_id: "DSA-1-1", source: "t", aliases: %w[CVE-2026-0003 CVE-2026-0001], severity: "low", modified_at: Time.current),
                       state: "reopened")
      open_finding_for(advisory_for("CVE-2026-0004"), state: "resolved")
      advisory_for("CVE-2026-0005")
      expect(described_class.matching_open_findings(%w[CVE-2026-0001 CVE-2026-0002 CVE-2026-0003 CVE-2026-0004 CVE-2026-0005 CVE-2026-0006])).to eq(3)
      expect(described_class.matching_open_findings([])).to eq(0)
      import_kev(kev_file("CVE-2026-0003", "CVE-2026-0004"))
      expect(described_class.matching_open_findings("SELECT cve_id FROM kev_entries")).to eq(1)
    end
  end

  describe ".too_many_dropped?" do
    it "holds back past FLEET_ADVISORY_WITHDRAW_SHARE of the stored entries, or past an operator's ceiling once one is given" do
      expect(described_class.too_many_dropped?(dropped: 10, stored: 100, allowed: nil)).to be(false)
      expect(described_class.too_many_dropped?(dropped: 11, stored: 100, allowed: nil)).to be(true)
      expect(described_class.too_many_dropped?(dropped: 50, stored: 100, allowed: 50)).to be(false)
      expect(described_class.too_many_dropped?(dropped: 5, stored: 100, allowed: 4)).to be(true)
      expect(described_class.too_many_dropped?(dropped: 0, stored: 0, allowed: nil)).to be(false)
    end
  end

  it "records a failure with a cleaned source, audited, for either signal" do
    import = described_class.record_failure("epss", reason: "x" * 600, origin: "file", source: "bad\u0000name.csv")
    expect(import).to have_attributes(state: "failed", source: "bad name.csv", reason: have_attributes(length: 512))
    expect(AuditEntry.sole.action).to eq("signal.epss_import_failed")
    expect(described_class.record_failure("kev", reason: "r", origin: "feed", source: nil).source).to eq("unknown")
  end
end
