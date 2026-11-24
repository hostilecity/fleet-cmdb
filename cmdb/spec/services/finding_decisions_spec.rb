require "rails_helper"

# Finding decisions through the real paths (VT-OVERRIDES #261, VT-S06): a control moves the finding to Low risk (O1)
# and an acceptance moves nothing, both audited with their evidence and leaving the open count alone; a decision ends
# at expiry, when a fix appears, and when its findings resolve, and is suspended when its CVE is added to KEV, its
# EPSS band turns high, or its severity rises, each audited by the system; and the limits refuse what the spec
# refuses. Package names are a Debian 13 amd64 host's; advisory and CVE ids are made up.
RSpec.describe FindingDecisions do
  include ActiveJob::TestHelper

  let(:network) { [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } ] }
  let(:local) { [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" } ] }
  let(:packages) { [ [ "openssl", "3.5.0-1", "openssl" ], [ "libssl3t64", "3.5.0-1", "openssl" ], [ "bash", "5.2.37-2", "bash" ], [ "curl", "8.14.1-2", "curl" ] ] }
  let(:operator) { create(:operator) }
  let(:host) { debian_host(name: "Media server", packages:) }
  let(:tls) { Advisory.find_by!(advisory_id: "DEBIAN-CVE-2026-92002") }
  let(:shell) { Advisory.find_by!(advisory_id: "DEBIAN-CVE-2026-93001") }

  before do
    allow(VulnerabilityMatchJob).to receive(:perform_later)
    allow(CisEvaluationJob).to receive(:perform_later)
  end

  let(:low_network) { [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" } ] }

  def advisories(tls_fixed: nil, tls_severity: network, modified: "2026-10-20T08:00:00Z")
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-92001", package: "openssl", fixed: "3.5.1-1", severity: network),
                      osv_record(id: "DEBIAN-CVE-2026-92002", package: "openssl", fixed: tls_fixed, severity: tls_severity, modified:),
                      osv_record(id: "DEBIAN-CVE-2026-93001", package: "bash", fixed: nil, severity: local),
                      osv_record(id: "DEBIAN-CVE-2026-94001", package: "curl", fixed: nil, severity: local, modified: "2026-10-21T08:00:00Z"))
  end

  def match(*hosts) = VulnerabilityMatcher.match!((hosts.presence || [ host ]).map(&:id))

  def rules(advisory, on: host) = VulnerabilityFinding.active.where(host: on, advisory:).order(:package).pluck(:package, :bucket_rule).to_h.transform_values { |r| VulnerabilityTriage.rule_for(r) }

  def record(kind: "control", advisory: tls, hosts: [ host ], confirmed: hosts, reason: "smbd bound to the storage VLAN only; nftables drops 445/tcp", until_on: 30.days.from_now.to_date,
             stepped_up: false, operator_session: nil)
    described_class.record!(operator:, host: hosts.first, advisory:, stepped_up:, operator_session:,
                            params: { kind:, reason:, expires_on: until_on.iso8601, host_ids: hosts.map(&:id), confirmed_ids: confirmed.map(&:id) })
  end

  def summary(on = host) = HostComplianceSummary.find_by!(host_id: on.id)

  def audits(action) = AuditEntry.where(action: "vulnerability.#{action}").order(:id)

  before do
    host
    advisories
    match
  end

  describe "recording" do
    it "moves a controlled finding to Low risk (O1) for every package it matches, audited with its evidence, and leaves the open count alone" do
      expect(rules(tls)).to eq("libssl3t64" => "N4", "openssl" => "N4")
      open = summary.vuln_open
      outcome = record
      expect(outcome).to be_saved
      expect(rules(tls)).to eq("libssl3t64" => "O1", "openssl" => "O1")
      expect(summary).to have_attributes(vuln_open: open, vuln_attention: 0, vuln_low_risk: 4)
      expect(VulnerabilityFinding.where(host:, advisory: tls).pluck(:state).uniq).to eq([ "open" ])
      decision = outcome.decisions.sole
      expect(decision).to have_attributes(kind: "control", confirmed: true, created_by: operator, ended_at: nil)
      expect(decision.evidence).to include("bucket" => "attention", "rule" => "N4", "severity" => "critical", "kev" => false, "epss_band" => nil,
                                           "attack_vector" => "AV:N/PR:N/UI:N", "listening" => "none")
      entry = audits("decision_recorded").sole
      expect(entry).to have_attributes(actor_type: "operator", actor_id: operator.id, target_type: "Host", target_id: host.id)
      expect(entry.changeset).to include("advisory" => "DEBIAN-CVE-2026-92002", "decision_kind" => "control in place", "bucket" => [ "needs attention", "low risk" ],
                                         "evidence" => "critical; network, no login, no user action; not KEV; no EPSS score; no listener reported",
                                         "confirmed_for" => "Media server", "reason" => decision.reason)
    end

    it "keeps an accepted risk's bucket, rule, and counts" do
      before = summary.attributes.slice("vuln_open", "vuln_attention", "vuln_low_risk")
      expect(record(kind: "accepted", confirmed: [])).to be_saved
      expect(rules(tls)).to eq("libssl3t64" => "N4", "openssl" => "N4")
      expect(summary.attributes.slice("vuln_open", "vuln_attention", "vuln_low_risk")).to eq(before)
      expect(audits("decision_recorded").sole.changeset).not_to have_key("bucket")
      expect(HostDecisions.new(host.id).accepted_ids).to eq(Set[tls.id])
    end

    it "gives each host its own decision and audit entry, with the request's id" do
      other = debian_host(name: "File server", packages:)
      match(other)
      Current.request_id = "req-261"
      expect(record(hosts: [ host, other ])).to be_saved
      expect(FindingDecision.pluck(:host_id, :request_id)).to contain_exactly([ host.id, "req-261" ], [ other.id, "req-261" ])
      expect(audits("decision_recorded").pluck(:target_id, :request_id)).to contain_exactly([ host.id, "req-261" ], [ other.id, "req-261" ])
      expect(rules(tls, on: other)).to eq("libssl3t64" => "O1", "openssl" => "O1")
    ensure
      Current.reset
    end

    it "refuses with errors in place: a short reason, a date past the limit, an unconfirmed control, a Fix available or Ignorable finding" do
      other = debian_host(name: "File server", packages:)
      match(other)
      outcome = record(hosts: [ host, other ], confirmed: [ host ], reason: "ok", until_on: Date.current + 91)
      expect(outcome).not_to be_saved
      expect(outcome.errors).to include(reason: "Say what the control is or why the risk is acceptable, in at least 10 characters.",
                                        expires_on: "Pick a date no later than #{(Date.current + 90).iso8601} (90 days from today).",
                                        "confirm_#{other.id}": "Confirm the control on File server, or untick File server.")
      expect(record(advisory: Advisory.find_by!(advisory_id: "DEBIAN-CVE-2026-92001")).errors.values.sole).to eq("Media server: a fix is available for it on this host: upgrade instead.")
      expect(record(reason: "x" * 1001).errors[:reason]).to eq("Keep it to 1,000 characters (this is 1,001).")
      expect(record(until_on: Date.current - 1).errors[:expires_on]).to eq("Pick today or a later date.")
      expect(described_class.record!(operator:, host:, advisory: tls, params: { kind: "waive", reason: "a reason long enough", expires_on: "soon", host_ids: [] }).errors)
        .to eq(kind: "Choose whether a control is in place or the risk is accepted.", expires_on: "Pick the last day the decision applies, as a date.", hosts: "Choose at least one host.")
      record_config(other, "firewall.enabled" => ok_fact(false))
      expect(record(hosts: [ other ], confirmed: []).errors[:"confirm_#{other.id}"]).to eq("Confirm the control on File server, or untick File server. Its firewall is disabled.")
      expect(described_class.record!(operator:, host:, advisory: tls, params: { kind: "accepted", reason: "a reason long enough", expires_on: Date.current.iso8601,
                                                                             host_ids: (1..51).to_a }).errors[:hosts]).to eq("Choose at most 50 hosts in one action.")
      expect(FindingDecision.count).to eq(0)
    end

    it "allows at most 30 days on a KEV-listed advisory, and refuses a second active decision" do
      import_kev(kev_file("CVE-2026-93001"))
      perform_evaluation_jobs
      expect(rules(shell)).to eq("bash" => "N1")
      expect(record(advisory: shell, until_on: Date.current + 31).errors[:expires_on]).to eq("Pick a date no later than #{(Date.current + 30).iso8601} (30 days from today, since it is known exploited).")
      # A KEV-listed advisory needs the second factor every time (owner decision 2026-11-23, epic decision 37).
      expect(record(advisory: shell, until_on: Date.current + 30).errors[:second_factor_code])
        .to eq("A decision on a known exploited advisory needs a new code from your authenticator app every time. Nothing was saved.")
      # Passed only by an open window: not enough on a KEV-listed advisory.
      expect(record(advisory: shell, until_on: Date.current + 30, stepped_up: :window).errors[:second_factor_code]).to start_with("A decision on a known exploited advisory needs a new code")
      expect(record(advisory: shell, until_on: Date.current + 30, stepped_up: :fresh)).to be_saved
      expect(rules(shell)).to eq("bash" => "O1") # a control may cover a KEV finding; its kev flag stays
      expect(VulnerabilityFinding.find_by!(host:, advisory: shell).kev).to be(true)
      expect(record(advisory: shell, stepped_up: :fresh).errors.values.sole).to eq("Media server: it already has a decision for this advisory: change or end that one.")
    end

    it "refuses an advisory whose findings are only Ignorable, and a host with none" do
      import_triage(tracker_document("bash" => { "CVE-2026-93001" => { "trixie" => tracker_release(status: "resolved", fixed_version: "0") } }))
      perform_evaluation_jobs
      expect(rules(shell)).to eq("bash" => "I3")
      expect(record(advisory: shell).errors.values.sole).to eq("Media server: its findings are Ignorable here, so there is nothing to decide.")
      bare = debian_host(name: "Bare", packages: [ [ "bash", "5.2.36-1", "bash" ] ])
      expect(record(advisory: tls, hosts: [ bare ]).errors.values.sole).to eq("Bare: it has no open finding for this advisory.")
    end

    it "refuses an advisory added to the KEV list between the form's check and the save's lock, so its 30-day limit holds" do
      allow(Host).to receive(:lock).and_wrap_original do |original|
        KevEntry.create!(cve_id: "CVE-2026-92002", date_added: Date.current) unless KevEntry.exists?(cve_id: "CVE-2026-92002")
        original.call
      end
      outcome = record(until_on: Date.current + 80, stepped_up: :window)
      expect(outcome.errors[:hosts]).to eq("The advisory was added to CISA's KEV list meanwhile; check the date (at most 30 days) and save again.")
      expect(FindingDecision.count).to eq(0)
    end

    it "refuses findings not triaged yet, and a host retired between the form and the save" do
      VulnerabilityFinding.where(host:, advisory: tls).update_all(bucket: nil, bucket_rule: nil, kev: nil) # rubocop:disable Rails/SkipsModelValidations
      expect(record.errors.values.sole).to eq("Media server: its findings are not triaged yet; try again in a few minutes.")
      match
      allow(FindingDecisions::Candidates).to receive(:load).and_call_original
      allow(Host).to receive(:lock).and_wrap_original { |original| original.call.where.not(id: host.id) }
      expect(record.errors[:hosts]).to eq("A host chosen was retired meanwhile; nothing was saved.")
    end

    it "refuses when another decision is saved meanwhile" do
      allow(FindingDecision).to receive(:create!).and_raise(ActiveRecord::RecordNotUnique)
      expect(record.errors[:hosts]).to eq("A host chosen got a decision for this advisory meanwhile; nothing was saved.")
    end

    it "refuses a host that changed under the lock" do
      call = 0
      allow(FindingDecisions::Candidates).to receive(:load).and_wrap_original do |original, *args, **kw|
        list = original.call(*args, **kw)
        (call += 1) == 2 ? list.map { |c| c.with(problem: "it changed.") } : list
      end
      expect(record.errors[:hosts]).to eq("Media server: it changed. Nothing was saved.")
    end
  end

  describe "changing and ending" do
    it "changes the reason and date within the limit from the day it was recorded, and ends it" do
      decision = record.decisions.sole
      first_until = decision.expires_on
      travel 10.days
      outcome = described_class.change!(decision, operator:, params: { reason: "nftables drops 445/tcp from every network", expires_on: (decision.created_at.to_date + 90).iso8601 })
      expect(outcome).to be_saved
      expect(audits("decision_changed").sole.changeset).to include("reason" => [ "smbd bound to the storage VLAN only; nftables drops 445/tcp", "nftables drops 445/tcp from every network" ],
                                                                   "until" => [ first_until.iso8601, (decision.created_at.to_date + 90).iso8601 ])
      too_long = described_class.change!(decision, operator:, params: { reason: "nftables drops 445/tcp from every network", expires_on: (decision.created_at.to_date + 91).iso8601 })
      expect(too_long.errors[:expires_on]).to include("when it was recorded")
      same = described_class.change!(decision.reload, operator:, params: { reason: decision.reason, expires_on: decision.expires_on.iso8601 })
      expect(same.errors[:base]).to eq("Nothing changed: edit the reason or the date, or cancel.")

      expect(described_class.end!(decision, operator:)).to be_saved
      expect(decision.reload).to have_attributes(ended_why: "operator", ended_by: operator)
      expect(rules(tls)).to eq("libssl3t64" => "N4", "openssl" => "N4")
      expect(audits("decision_ended").sole.changeset).to include("ended_why" => "operator", "bucket" => [ "low risk", "needs attention" ])
      expect(described_class.end!(decision, operator:).errors[:base]).to eq("This decision has already ended.")
      expect(described_class.change!(decision, operator:, params: { reason: "a reason long enough", expires_on: Date.current.iso8601 }).errors[:base]).to eq("This decision has ended; record a new one.")
      expect(described_class.change!(decision, operator:, params: { reason: "", expires_on: "" }).errors.keys).to eq(%i[reason expires_on])
    end

    it "expires a decision past its last day when an operator changes or ends it, rather than reviving it" do
      decision = record(until_on: Date.current).decisions.sole
      other = record(advisory: shell, kind: "accepted", confirmed: [], until_on: Date.current).decisions.sole
      travel 1.day
      outcome = described_class.change!(decision, operator:, params: { reason: "a reason long enough", expires_on: (Date.current + 10).iso8601 })
      expect(outcome.errors[:base]).to start_with("It passed its last day, so it has now ended as expired")
      expect(decision.reload).to have_attributes(ended_why: "expired", expires_on: Date.current - 1)
      expect(rules(tls)).to eq("libssl3t64" => "N4", "openssl" => "N4")
      expect(described_class.end!(other, operator:).errors[:base]).to start_with("It passed its last day")
      expect(other.reload).to have_attributes(ended_why: "expired", ended_by: nil)
      expect(audits("decision_expired").pluck(:actor_type)).to eq(%w[system system])
      expect(audits("decision_changed")).to be_empty
    end

    it "suspends rather than changes a decision whose evidence got worse since it was recorded" do
      decision = record(kind: "accepted", confirmed: [], until_on: Date.current + 10).decisions.sole
      EpssScore.create!(cve_id: "CVE-2026-92002", score: 0.31, percentile: 0.97, band: "high", score_date: Date.current)
      outcome = described_class.change!(decision, operator:, params: { reason: decision.reason, expires_on: (Date.current + 80).iso8601 })
      expect(outcome.errors[:base]).to eq("The evidence got worse since it was recorded (EPSS band: none, now high), so it is now suspended and the finding is due a new decision. " \
                                          "Record a new one on today's evidence.")
      expect(decision.reload).to have_attributes(ended_why: "suspended", expires_on: Date.current + 10, ended_evidence: { "epss_band" => [ nil, "high" ] })
      expect(audits("decision_suspended").sole).to have_attributes(actor_type: "system")
      expect(audits("decision_changed")).to be_empty
    end

    it "caps the last day in the database too, written past the application" do
      decision = record(kind: "accepted", confirmed: []).decisions.sole
      expect { FindingDecision.where(id: decision.id).update_all(expires_on: Date.current + 367) }.to raise_error(ActiveRecord::StatementInvalid, /expires_within_limit/) # rubocop:disable Rails/SkipsModelValidations
    end

    it "never deletes a decision or changes one that ended" do
      decision = record(kind: "accepted", confirmed: []).decisions.sole
      expect { decision.destroy }.to raise_error(ActiveRecord::StatementInvalid, /never deleted/)
      expect { decision.update!(kind: "control", confirmed: true) }.to raise_error(ActiveRecord::StatementInvalid, /never change/)
      described_class.end!(decision.reload, operator:)
      expect { decision.reload.update!(reason: "another reason entirely") }.to raise_error(ActiveRecord::StatementInvalid, /cannot change/)
    end
  end

  describe "ending by itself" do
    it "suspends a control when its CVE is added to KEV, in the triage run, and the finding falls through to N1" do
      decision = record.decisions.sole
      import_kev(kev_file("CVE-2026-92002"))
      perform_evaluation_jobs
      expect(decision.reload).to have_attributes(ended_why: "suspended", ended_evidence: { "kev" => [ false, true ], "kev_cves" => [ [], [ "CVE-2026-92002" ] ] })
      expect(rules(tls)).to eq("libssl3t64" => "N1", "openssl" => "N1")
      entry = audits("decision_suspended").sole
      expect(entry).to have_attributes(actor_type: "system")
      expect(entry.changeset).to include("ended_why" => "suspended", "changed_evidence" => "known exploited: no, now yes; CVEs on the KEV list: none, now CVE-2026-92002")
      expect(HostDecisions.new(host.id).due_ids([ tls.id ])).to eq([ tls.id ])
      # A batch run again (EvaluationRun.retry!, or EvaluationRunWatchJob resuming a killed worker's run, #292) and the
      # hourly sweep after it end nothing twice: they act on active decisions only.
      VulnerabilityMatcher.retriage!([ host.id ], advisory_ids: [ tls.id ])
      match
      expect(FindingDecisionExpiryJob.perform_now).to eq(0)
      expect(audits("decision_suspended").count).to eq(1)
    end

    it "suspends a decision in the triage re-run itself, when the KEV list changed under it (review of #299, 2a)" do
      decision = record.decisions.sole
      KevEntry.create!(cve_id: "CVE-2026-92002", date_added: Date.current) # no triage run: only the re-run below sees it
      VulnerabilityMatcher.retriage!([ host.id ], advisory_ids: [ tls.id ])
      expect(decision.reload.ended_why).to eq("suspended")
      expect(rules(tls)).to eq("libssl3t64" => "N4", "openssl" => "N4") # the control no longer applies; the base is not refreshed here
    end

    it "suspends when another CVE of the advisory joins the KEV list, as the lists differ" do
      import_advisories(osv_record(id: "DEBIAN-CVE-2026-93001", package: "bash", fixed: nil, severity: local, aliases: [ "CVE-2026-93009" ], modified: "2026-11-01T08:00:00Z"))
      import_kev(kev_file("CVE-2026-93001"))
      perform_evaluation_jobs
      decision = record(kind: "accepted", advisory: shell, confirmed: [], until_on: Date.current + 20, stepped_up: :fresh).decisions.sole
      expect(decision.evidence).to include("kev" => true, "kev_cves" => [ "CVE-2026-93001" ])
      import_kev(kev_file("CVE-2026-93001", "CVE-2026-93009"))
      perform_evaluation_jobs
      FindingDecisionExpiryJob.perform_now
      expect(decision.reload).to have_attributes(ended_why: "suspended", ended_evidence: { "kev_cves" => [ [ "CVE-2026-93001" ], %w[CVE-2026-93001 CVE-2026-93009] ] })
      expect(audits("decision_suspended").sole.changeset["changed_evidence"]).to eq("CVEs on the KEV list: CVE-2026-93001, now CVE-2026-93001, CVE-2026-93009")
    end

    it "suspends an acceptance when the severity rises, and it is due again" do
      advisories(tls_severity: low_network, modified: "2026-10-25T08:00:00Z")
      match
      expect(rules(tls)).to eq("libssl3t64" => "L5", "openssl" => "L5") # low severity: an acceptance may cover Low risk too
      decision = record(kind: "accepted", confirmed: []).decisions.sole
      advisories(modified: "2026-11-01T08:00:00Z")
      match
      expect(decision.reload).to have_attributes(ended_why: "suspended", ended_evidence: { "severity" => %w[low critical] })
      expect(rules(tls)).to eq("libssl3t64" => "N4", "openssl" => "N4")
    end

    it "ends when a fix appears, and when every finding it covers resolves" do
      control = record.decisions.sole
      accepted = record(kind: "accepted", advisory: shell, confirmed: []).decisions.sole
      advisories(tls_fixed: "3.5.1-1", modified: "2026-11-01T08:00:00Z")
      match
      expect(control.reload.ended_why).to eq("fixed")
      expect(rules(tls)).to eq("libssl3t64" => "F1", "openssl" => "F1")
      report_packages(host, packages.reject { |p| p[0] == "bash" })
      match
      expect(accepted.reload.ended_why).to eq("resolved")
      expect(audits("decision_ended").pluck(:actor_type, Arel.sql("changeset->>'ended_why'"))).to contain_exactly(%w[system fixed], %w[system resolved])
    end

    it "stops applying a control after its last day, and the hourly job ends it and re-triages" do
      decision = record(until_on: Date.current + 1).decisions.sole
      travel 2.days
      expect(FindingDecisions::ControlSource.controls([ host.id ], now: Time.current)).to eq({})
      expect(HostDecisions.new(host.id).due_ids([])).to eq([ tls.id ]) # lapsed, not yet ended: due
      expect(rules(tls)).to eq("libssl3t64" => "O1", "openssl" => "O1")
      FindingDecisionExpiryJob.perform_now
      expect(decision.reload.ended_why).to eq("expired")
      expect(rules(tls)).to eq("libssl3t64" => "N4", "openssl" => "N4")
      expect(audits("decision_expired").sole).to have_attributes(actor_type: "system")
      expect(FindingDecisions::Lifecycle.sweep!).to eq(0)
    end

    it "catches in the hourly job an EPSS band turning high that moved no bucket" do
      import_kev(kev_file("CVE-2026-93001"))
      perform_evaluation_jobs
      decision = record(kind: "accepted", advisory: shell, confirmed: [], until_on: Date.current + 30, stepped_up: :fresh).decisions.sole
      EpssScore.create!(cve_id: "CVE-2026-93001", score: 0.31, percentile: 0.97, band: "high", score_date: Date.current)
      expect(FindingDecisionExpiryJob.perform_now).to eq(1)
      expect(decision.reload).to have_attributes(ended_why: "suspended", ended_evidence: { "epss_band" => [ nil, "high" ] })
      expect(FindingDecisions::Lifecycle.review!([ host.id ])).to eq([])
      expect(FindingDecisions::Lifecycle.settle!([])).to be_nil
    end
  end

  describe "the hourly job" do
    it "drops a run that would overlap a running one, rather than queueing it behind" do
      expect(FindingDecisionExpiryJob.concurrency_key).to eq("finding_decision_expiry")
      expect(FindingDecisionExpiryJob.concurrency_limit).to eq(1)
      expect(FindingDecisionExpiryJob.concurrency_on_conflict).to eq(:discard)
      expect(FindingDecisionExpiryJob.concurrency_duration).to be >= 3.hours
    end
  end

  describe "the sweep's slices" do
    it "keeps each slice to 100 hosts and 100 due decisions, splitting a host with more by advisory, in host id order" do
      due = { 3 => [ 7 ], 1 => (1..250).to_a, 2 => [ 1 ], **(10..120).to_h { |id| [ id, [ 5 ] ] } }
      slices = FindingDecisions::Lifecycle.send(:slices, due)
      expect(slices.first(2)).to eq([ [ [ 1 ], (1..100).to_a ], [ [ 1 ], (101..200).to_a ] ])
      expect(slices[2][0].first(3)).to eq([ 1, 2, 3 ])
      expect(slices[2][1]).to eq((201..250).to_a + [ 1, 7, 5 ]) # 50 + 1 + 1 + 48 hosts' one each: 100 decisions
      expect(slices[2][0].size).to eq(51)
      expect(slices.drop(2).map { |hosts, _| hosts.size }).to all(be <= 100)
      expect(slices.flat_map(&:first).uniq).to eq([ 1, 2, 3, *10..120 ])
      expect(slices.sum { |hosts, _| hosts.sum { |h| h == 1 ? 0 : 1 } }).to eq(due.size - 1)
    end
  end

  describe "helpers" do
    it "scores the epic's table, KEV doubled outside Ignorable, and words what got worse" do
      expect(described_class.points("attention", "critical", false)).to eq(40)
      expect(described_class.points("control", "critical", true)).to eq(20)
      expect(described_class.points("low_risk", "low", true)).to eq(0)
      expect(described_class.points("ignorable", "critical", true)).to eq(0)
      expect(described_class.changes_words("epss_band" => [ nil, "high" ], "severity" => %w[low high])).to eq("EPSS band: none, now high; severity: low, now high")
      expect(described_class.evidence_words("severity" => "low", "kev" => true, "epss_score" => "0.31", "listening" => "network"))
        .to eq("low; no CVSS vector; KEV; EPSS 0.31; listening on the network")
      expect(FindingDecision.sanitize_reason("a‮b​c\r\nd \xFF".dup.force_encoding("BINARY"))).to eq("a b c d")
    end
  end
end
