require "rails_helper"

# The decision flow (VT-OVERRIDES #261, VT-D05; approved mockup vuln-triage/override.html): the form with each host's
# evidence, errors in place, the saved notice with the points' change, the tab's decision column and O1 reason, the
# suspended and lapsed states, change and end, the second factor above 10 hosts, escaping of the operator's text
# everywhere it is shown (the audit log included), and refusals. Package names are a Debian 13 amd64 host's; advisory
# and CVE ids are made up.
RSpec.describe "Finding decisions", :signed_in, type: :request do
  include ActiveJob::TestHelper

  let(:network) { [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } ] }
  let(:local) { [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" } ] }
  let(:packages) { [ [ "openssl", "3.5.0-1", "openssl" ], [ "libssl3t64", "3.5.0-1", "openssl" ], [ "bash", "5.2.37-2", "bash" ] ] }
  let(:host) { debian_host(name: "Media server", packages:) }
  let(:tls) { Advisory.find_by!(advisory_id: "DEBIAN-CVE-2026-92002") }
  let(:shell) { Advisory.find_by!(advisory_id: "DEBIAN-CVE-2026-93001") }
  let(:tab) { "/hosts/#{host.id}/vulnerabilities" }
  let(:form) { "/hosts/#{host.id}/vulnerabilities/decisions/new?advisory_id=#{tls.id}" }
  let(:hostile) { "<script>alert(1)</script> ‮reversed <b>bold</b> nftables drops 445/tcp" }

  before do
    allow(VulnerabilityMatchJob).to receive(:perform_later)
    allow(CisEvaluationJob).to receive(:perform_later)
    host
    import_advisories(osv_record(id: "DEBIAN-CVE-2026-92001", package: "openssl", fixed: "3.5.1-1", severity: network),
                      osv_record(id: "DEBIAN-CVE-2026-92002", package: "openssl", fixed: nil, severity: network),
                      osv_record(id: "DEBIAN-CVE-2026-93001", package: "bash", fixed: nil, severity: local))
    match
  end

  def match(*hosts) = VulnerabilityMatcher.match!((hosts.presence || [ host ]).map(&:id))

  def words(node) = node&.xpath(".//text()")&.map(&:text)&.join(" ")&.squish

  def save(kind: "control", reason: "smbd bound to the storage VLAN only; nftables drops 445/tcp", until_on: Date.current + 30, hosts: [ host ], confirmed: hosts, advisory: tls, **extra)
    post "/hosts/#{host.id}/vulnerabilities/decisions",
         params: { advisory_id: advisory.id, kind:, reason:, expires_on: until_on.to_s, host_ids: hosts.map(&:id), confirmed_ids: confirmed.map(&:id), **extra }
  end

  def attention_row(id) = page.css("#attention_list > tbody > tr").find { |row| row.text.include?(id) }

  it "draws the form with the evidence now and each host's own evidence" do
    other = debian_host(name: "File server", hostname: "vm-07.example.lan", packages:)
    match(other)
    record_config(other, "firewall.enabled" => ok_fact(false))
    get tab
    expect(attention_row("DEBIAN-CVE-2026-92002").css("td.decision a").map { |a| [ a.text, a["href"] ] })
      .to eq([ [ "Record a control\u2026", "#{form}&kind=control" ], [ "Accept the risk\u2026", "#{form}&kind=accepted" ] ])
    get form
    expect(response).to have_http_status(:ok)
    expect(words(page.at_css("h1"))).to eq("Record a decision")
    expect(page.at_css("#kind_control")["checked"]).to eq("checked")
    expect(page.at_css("#expires_on")["value"]).to eq((Date.current + 90).iso8601)
    expect(page.at_css("#expires_on")["max"]).to eq((Date.current + 90).iso8601)
    expect(page.at_css("label[for=reason]")).not_to be_nil
    expect(page.css("#decision_hosts li").map { |li| words(li) }).to eq([
      "Media server (this host) #{host.hostname} Needs attention ( N4 ) · no listener reported · firewall not reported I confirm this control exists on Media server (for a control only)",
      "File server vm-07.example.lan Needs attention ( N4 ) · no listener reported · firewall disabled I confirm this control exists on File server (for a control only)"
    ])
    expect(page.css("#host_#{host.id}[checked]").size).to eq(1)
    expect(words(page.at_css("#evidence dl"))).to eq("Bucket Needs attention (rule N4 ) Severity Critical Reached Network, no login, no user action AV:N/PR:N/UI:N " \
                                                     "Fix None for this release Known exploited No (CISA's KEV list) EPSS No score On this host No listener reported")
    expect(page.at_css("#second_factor_code")).to be_nil # 2 hosts: no step-up
  end

  it "shows each host's listening class as its evidence, and records it" do
    loopback = VulnerabilityTriage::Listener.new(package: "nginx", network: false, unit: "nginx.service", addresses: [ "127.0.0.1:443/tcp" ], scanned_at: Time.current)
    source = Class.new do
      define_method(:listeners) { |ids, **| ids.to_h { |id| [ id, { "openssl" => loopback } ] } }
      define_method(:listener_hosts_expiring) { |**| [] }
    end.new
    allow(VulnerabilityTriage::HostFacts).to receive(:listener_source).and_return(source)
    get form
    expect(words(page.at_css("#decision_host_#{host.id} > .state-note"))).to eq("Needs attention ( N4 ) · Listening: loopback only · firewall not reported")
    expect(words(page.at_css("#evidence dd:last-of-type"))).to eq("Listening on loopback only")
    save(kind: "accepted", confirmed: [])
    expect(FindingDecision.sole.evidence["listening"]).to eq("loopback")
  end

  it "saves a control, says what changed, and shows it on the tab, in Low risk, with its reason escaped" do
    save(reason: hostile)
    expect(response).to redirect_to("#{tab}#attn")
    expect(flash[:notice]).to eq("Decision saved for Media server. DEBIAN-CVE-2026-92002 is now in Low risk with \"Control in place\" until #{(Date.current + 30).iso8601} on Media server. " \
                                 "Its points there go from 40 to 10 (a critical advisory in Needs attention is 40 points; under a control it is 10).")
    follow_redirect!
    expect(response.body).not_to include("<script>alert(1)</script>", "<b>bold</b>", "‮")
    expect(attention_row("DEBIAN-CVE-2026-92002")).to be_nil
    expect(words(page.at_css("#controlled_note"))).to start_with("2 findings under a recorded control are in Low risk (rule O1), not here.")
    expect(page.css("#low_rules > tbody > tr").map { |row| words(row) }).to include(start_with("A compensating control is recorded for it on this host. O1 2"))

    get tab, params: { rule: "O1" }
    reason = page.css("#rule_list .nested-findings td:last-child").map { |td| words(td) }.uniq.sole
    expect(reason).to eq("Control in place Example Operator recorded on #{Date.current.iso8601}, until #{(Date.current + 30).iso8601}: " \
                         "“<script>alert(1)</script> reversed <b>bold</b> nftables drops 445/tcp” Without it: Needs attention (N4). O1 Change or end")
    expect(response.body).to include("&lt;script&gt;alert(1)&lt;/script&gt;")

    get "/audit"
    entry = page.css("table tbody tr").find { |row| row.text.include?("Finding decision recorded") }
    expect(words(entry)).to include("Advisory DEBIAN-CVE-2026-92002", "Kind control in place", "Bucket needs attention low risk",
                                    "Evidence critical; network, no login, no user action; not KEV; no EPSS score; no listener reported", "Confirmed for Media server")
    expect(response.body).not_to include("<script>alert(1)</script>", "<b>bold</b>")
  end

  it "saves an acceptance: no bucket moves, it is marked on the row, and it is no longer due" do
    get tab
    expect(words(page.at_css("#decisions_due"))).to start_with("1 advisory needs a decision .")
    save(kind: "accepted", confirmed: [])
    expect(flash[:notice]).to eq("Decision saved for Media server. DEBIAN-CVE-2026-92002 is marked \"Risk accepted\" until #{(Date.current + 30).iso8601} and is no longer listed as due. " \
                                 "No change to its bucket, points (40), or tier: accepting a risk changes nothing about exposure.")
    get tab
    row = attention_row("DEBIAN-CVE-2026-92002")
    expect(words(row.at_css("td.decision"))).to eq("Risk accepted Until #{(Date.current + 30).iso8601}. Still counted here, with its points; not due. " \
                                                   "Accepted by Example Operator on #{Date.current.iso8601}: “smbd bound to the storage VLAN only; nftables drops 445/tcp” Change or end")
    expect(words(page.at_css("#decisions_due"))).to start_with("No decision is due; 1 advisory in Needs attention has an accepted risk.")
    expect(words(page.at_css("#bucket_strip a.attn .act"))).to eq("0 need a decision")
    expect(words(page.at_css("#bucket_strip a.attn .what"))).to eq("1 advisory, no fix yet")

    travel 25.days
    sign_in_operator # the session's absolute timeout
    get tab
    expect(words(attention_row("DEBIAN-CVE-2026-92002").at_css("td.decision"))).to include("It ends within 7 days, so it is listed as due.")
    expect(words(page.at_css("#decisions_due"))).to start_with("1 advisory needs a decision .")
  end

  it "refuses with every problem in place, announced, and saves nothing" do
    other = debian_host(name: "File server", hostname: "vm-07.example.lan", packages:)
    match(other)
    save(reason: "ok", until_on: Date.current + 120, hosts: [ host, other ], confirmed: [ host ])
    expect(response).to have_http_status(:unprocessable_content)
    expect(words(page.at_css("#decision_errors"))).to start_with("The decision was not saved. 3 problems: fix them and save again.")
    expect(page.at_css("#reason")["aria-invalid"]).to eq("true")
    expect(page.at_css("#reason")["aria-describedby"]).to eq("reason_error reason_hint")
    expect(words(page.at_css("#reason_error"))).to eq("Say what the control is or why the risk is acceptable, in at least 10 characters.")
    expect(words(page.at_css("#expires_on_error"))).to eq("Pick a date no later than #{(Date.current + 90).iso8601} (90 days from today).")
    expect(page.at_css("#confirm_#{other.id}")["aria-describedby"]).to eq("confirm_#{other.id}_error")
    expect(words(page.at_css("#confirm_#{other.id}_error"))).to eq("Confirm the control on File server, or untick File server.")
    expect(page.at_css("#reason").text.strip).to eq("ok") # what was typed is kept
    expect(page.css("input[name='host_ids[]'][checked]").map { |i| i["value"].to_i }).to contain_exactly(host.id, other.id)
    expect(FindingDecision.count).to eq(0)

    save(advisory: Advisory.find_by!(advisory_id: "DEBIAN-CVE-2026-92001"))
    expect(response).to have_http_status(:unprocessable_content)
    expect(words(page.at_css("#host_#{host.id}_error"))).to eq("Media server: a fix is available for it on this host: upgrade instead.")
    get "/hosts/#{host.id}/vulnerabilities/decisions/new?advisory_id=#{Advisory.find_by!(advisory_id: 'DEBIAN-CVE-2026-92001').id}"
    expect(words(page.at_css("#decision_unavailable"))).to eq("No decision can be recorded on Media server now. A fix is available for it on this host: upgrade instead.")
  end

  it "needs the second factor for more than 10 hosts, checked on the server" do
    others = Array.new(10) { |i| debian_host(name: "Host #{i}", hostname: "vm-#{format('%02d', i + 10)}.example.lan", packages:) }
    match(*others)
    secret = enrol_second_factor(operator).first
    get form
    expect(page.at_css("#second_factor_code")["required"]).to be_nil # needed only above 10 hosts
    save(kind: "accepted", hosts: [ host, *others ], confirmed: [])
    expect(response).to have_http_status(:forbidden)
    expect(words(page.at_css("#decision_errors li"))).to eq("You have recorded 0 host decisions in the last 15 minutes, in any session, and 11 more would pass 10: that needs a code from your authenticator app: type a code.")
    expect(FindingDecision.count).to eq(0)
    save(kind: "accepted", hosts: [ host, *others ], confirmed: [], second_factor_code: totp_code(secret))
    expect(response).to redirect_to("#{tab}#attn")
    expect(flash[:notice]).to start_with("Decision saved for 11 hosts (each with its own decision and audit entry).")
    expect(FindingDecision.distinct.count(:request_id)).to eq(1)
    expect(second_factor_audits.last.changeset).to include("purpose" => "record_decisions")
  end

  it "counts the step-up per operator over 15 minutes, so splitting an action into smaller ones does not avoid it" do
    others = Array.new(11) { |i| debian_host(name: "Host #{i}", hostname: "vm-#{format('%02d', i + 10)}.example.lan", packages:) }
    match(*others)
    secret = enrol_second_factor(operator).first
    save(kind: "accepted", hosts: others.first(6), confirmed: [])
    expect(response).to redirect_to("#{tab}#attn") # 6: no code
    save(kind: "accepted", hosts: others.last(5), confirmed: [])
    expect(response).to have_http_status(:forbidden) # 6 + 5 = 11 in 15 minutes
    expect(words(page.at_css("#decision_errors li"))).to eq("You have recorded 6 host decisions in the last 15 minutes, in any session, and 5 more would pass 10: that needs a code from your authenticator app: type a code.")
    expect(FindingDecision.count).to eq(6)
    get form
    expect(page.at_css("#second_factor_code")).not_to be_nil # 6 so far and 12 listed
    travel 16.minutes
    sign_in_operator
    save(kind: "accepted", hosts: others.last(5), confirmed: [])
    expect(response).to redirect_to("#{tab}#attn") # the window moved on
    expect(FindingDecision.count).to eq(11)
    save(kind: "accepted", hosts: [ host ], confirmed: [])
    expect(response).to have_http_status(:redirect) # 5 + 1 in this window
    expect(FindingDecision.count).to eq(12)
    save(kind: "control", hosts: others.first(5), confirmed: others.first(5), advisory: shell, second_factor_code: totp_code(secret))
    expect(response).to redirect_to("#{tab}#attn") # 6 + 5 = 11 again: with a code
  end

  it "refuses an operator's count that passes 10 under the lock, though the form's check passed" do
    others = Array.new(3) { |i| debian_host(name: "Host #{i}", hostname: "vm-#{format('%02d', i + 30)}.example.lan", packages:) }
    match(*others)
    # The form's check sees none; by the time the hosts and the operator are locked, another request of the operator has
    # recorded 9 (simulated; the real race is spec/services/finding_decisions_concurrency_spec.rb): 9 + 3 passes 10.
    calls = 0
    allow(FindingDecisions).to receive(:recent_count).and_wrap_original { |original, *args, **kw| (calls += 1) == 1 ? original.call(*args, **kw) : original.call(*args, **kw) + 9 }
    save(kind: "accepted", hosts: others, confirmed: [])
    expect(response).to have_http_status(:forbidden)
    expect(words(page.at_css("#decision_errors li"))).to eq("You have recorded 9 host decisions in the last 15 minutes, in any session; more than 10 need a code from your authenticator app. Nothing was saved.")
    expect(FindingDecision.count).to eq(0)
  end

  it "counts every session of the operator: signing in again starts no new count (clarified, review of #299)" do
    others = Array.new(11) { |i| debian_host(name: "Host #{i}", hostname: "vm-#{format('%02d', i + 50)}.example.lan", packages:) }
    match(*others)
    enrol_second_factor(operator)
    sessions = []
    [ others.first(4), others[4, 3], others[7, 3] ].each do |hosts|
      sign_in_operator # a new Google round trip: a new session each time
      sessions << OperatorSession.where(operator:).maximum(:id)
      save(kind: "accepted", hosts:, confirmed: [])
      expect(response).to redirect_to("#{tab}#attn") # 4, 7, then 10: exactly 10 needs no code
    end
    expect(sessions.uniq.size).to eq(3)
    expect(FindingDecision.where(created_by: operator).distinct.count(:operator_session_id)).to eq(3)
    sign_in_operator
    save(kind: "accepted", hosts: [ others.last ], confirmed: [])
    expect(response).to have_http_status(:forbidden) # the 11th, from a fourth session
    expect(words(page.at_css("#decision_errors li"))).to start_with("You have recorded 10 host decisions in the last 15 minutes, in any session, and 1 more would pass 10")
    expect(FindingDecision.count).to eq(10)
  end

  it "asks for a new code on a KEV-listed advisory even while a step-up window is open" do
    others = Array.new(11) { |i| debian_host(name: "Host #{i}", hostname: "vm-#{format('%02d', i + 70)}.example.lan", packages:) }
    match(*others)
    secret = enrol_second_factor(operator).first
    save(kind: "accepted", hosts: others, confirmed: [], second_factor_code: totp_code(secret)) # 11: a code, so the window is open
    expect(response).to redirect_to("#{tab}#attn")
    import_kev(kev_file("CVE-2026-93001"))
    perform_evaluation_jobs
    save(advisory: shell, kind: "accepted", confirmed: [])
    expect(response).to have_http_status(:forbidden)
    expect(words(page.at_css("#decision_errors li"))).to eq("A decision on a known exploited advisory needs a code from your authenticator app every time: type a code.")
    expect(FindingDecision.where(advisory: shell)).to be_empty
  end

  it "needs a fresh code every time for a KEV-listed advisory, to record or to change" do
    import_kev(kev_file("CVE-2026-93001"))
    perform_evaluation_jobs
    secret = enrol_second_factor(operator).first
    get "/hosts/#{host.id}/vulnerabilities/decisions/new?advisory_id=#{shell.id}"
    expect(page.at_css("#second_factor_code")["required"]).to eq("required")
    save(advisory: shell, kind: "accepted", confirmed: [])
    expect(response).to have_http_status(:forbidden)
    expect(words(page.at_css("#decision_errors li"))).to eq("A decision on a known exploited advisory needs a code from your authenticator app every time: type a code.")
    save(advisory: shell, kind: "accepted", confirmed: [], second_factor_code: totp_code(secret))
    expect(response).to redirect_to("#{tab}#attn")
    decision = FindingDecision.sole
    # The window is open, but a KEV-listed advisory still needs a new code.
    path = "/hosts/#{host.id}/vulnerabilities/decisions/#{decision.id}"
    get path
    expect(page.at_css("#second_factor_code")).not_to be_nil
    post path, params: { reason: "Only reachable from the admin VLAN", expires_on: (Date.current + 20).iso8601 }
    expect(response).to have_http_status(:forbidden)
    expect(words(page.at_css("#decision_errors"))).to include("Changing a decision on a known exploited advisory needs a code from your authenticator app every time")
    expect(decision.reload.reason).not_to eq("Only reachable from the admin VLAN")
    post path, params: { reason: "Only reachable from the admin VLAN", expires_on: (Date.current + 20).iso8601, second_factor_code: totp_code(secret, offset: 1) }
    expect(response).to redirect_to("#{tab}#attn")
    expect(decision.reload.reason).to eq("Only reachable from the admin VLAN")
  end

  it "says so when the decision was suspended in the same save, by a KEV listing that raced it" do
    allow(VulnerabilityMatcher).to receive(:retriage!).and_wrap_original do |original, *args, **kw|
      KevEntry.create!(cve_id: "CVE-2026-92002", date_added: Date.current) unless KevEntry.exists?(cve_id: "CVE-2026-92002")
      original.call(*args, **kw)
    end
    save
    expect(flash[:notice]).to eq("Decision saved for Media server. It was suspended at once, since the evidence got worse while it was saved " \
                                 "(known exploited: no, now yes; CVEs on the KEV list: none, now CVE-2026-92002). DEBIAN-CVE-2026-92002 is due a new decision.")
    expect(FindingDecision.sole.ended_why).to eq("suspended")
  end

  it "shows a decision on a Low risk finding on its row, and lists it when it is due" do
    save(advisory: shell, kind: "accepted", confirmed: [], until_on: Date.current + 3)
    get tab, params: { rule: "L2" }
    note = page.css("#rule_list .nested-findings td:last-child .decision-note").map { |n| words(n) }.uniq.sole
    expect(note).to eq("Risk accepted Until #{(Date.current + 3).iso8601}. Change or end")
    expect(page.at_css("#rule_list .decision-note a")["href"]).to eq("/hosts/#{host.id}/vulnerabilities/decisions/#{FindingDecision.sole.id}")
    expect(words(page.at_css("#due_elsewhere tbody tr"))).to start_with("DEBIAN-CVE-2026-93001 Risk accepted Until #{(Date.current + 3).iso8601}.")
    expect(words(page.at_css("#decisions_due"))).to start_with("2 advisories need a decision .")

    note = -> { get(tab, params: { rule: "L2" }) && page.css("#rule_list .decision-note").map { |n| words(n) }.uniq.sole }
    travel 4.days
    sign_in_operator # the session's absolute timeout
    expect(note.call).to eq("Decision expired Its last day was #{(Date.current - 1).iso8601}. Change or end")
    FindingDecision.sole.update!(ended_at: Time.current, ended_why: "suspended", ended_evidence: { "severity" => %w[high critical] })
    expect(note.call).to eq("Decision suspended The evidence got worse (severity: high, now critical). Change or end")
    expect(words(page.at_css("#due_elsewhere tbody tr"))).to start_with("DEBIAN-CVE-2026-93001 Decision suspended")
  end

  it "shows a suspended decision with what got worse, and a decision past its last day" do
    save(kind: "accepted", confirmed: [], until_on: Date.current + 1)
    save(advisory: shell)
    import_kev(kev_file("CVE-2026-93001"))
    perform_evaluation_jobs
    get tab
    expect(words(attention_row("DEBIAN-CVE-2026-93001").at_css("td.decision"))).to eq(
      "Decision suspended Control in place by Example Operator on #{Date.current.iso8601} (“smbd bound to the storage VLAN only; nftables drops 445/tcp”), " \
      "but on #{Date.current.iso8601} the evidence got worse (known exploited: no, now yes; CVEs on the KEV list: none, now CVE-2026-93001). It no longer applies; the finding is due a new decision. Record a new decision…"
    )
    travel 2.days
    sign_in_operator # the session's absolute timeout
    get tab
    expect(words(attention_row("DEBIAN-CVE-2026-92002").at_css("td.decision"))).to eq(
      "Decision expired Its last day was #{(Date.current - 1).iso8601}; it ends within the hour and the finding is due a new decision."
    )
    FindingDecisionExpiryJob.perform_now
    get tab
    expect(words(attention_row("DEBIAN-CVE-2026-92002").at_css("td.decision"))).to eq("Record a control… Accept the risk… The last decision expired on #{Date.current.iso8601}.")
  end

  it "changes and ends a decision from its page, and shows an ended one without a form" do
    save(kind: "accepted", confirmed: [])
    decision = FindingDecision.sole
    page_path = "/hosts/#{host.id}/vulnerabilities/decisions/#{decision.id}"
    get page_path
    expect(words(page.at_css("h1"))).to eq("Risk accepted")
    expect(words(page.at_css("#decision dl"))).to include("Evidence Needs attention (rule N4 ); critical; network, no login, no user action; not KEV")
    post page_path, params: { reason: "ok", expires_on: "" }
    expect(response).to have_http_status(:unprocessable_content)
    expect(words(page.at_css("#reason_error"))).to start_with("Say what the control is")
    post page_path, params: { reason: "Only reachable from the admin VLAN", expires_on: (Date.current + 60).iso8601 }
    expect(flash[:notice]).to eq("Decision changed for Media server: DEBIAN-CVE-2026-92002 until #{(Date.current + 60).iso8601}. Its bucket, points, and tier are unchanged.")
    post "#{page_path}/end"
    expect(flash[:notice]).to eq("Decision ended for Media server on DEBIAN-CVE-2026-92002. The finding is due a decision again; its bucket, points, and tier are unchanged.")
    get page_path
    expect(page.at_css("#change_form")).to be_nil
    expect(words(page.at_css("#decision_ended"))).to end_with("by Example Operator")
    post "#{page_path}/end"
    expect(response).to have_http_status(:unprocessable_content)
    expect(words(page.at_css("#decision_errors"))).to eq("Nothing was changed. This decision has already ended.")

    save(advisory: shell)
    control = FindingDecision.find_by!(advisory: shell)
    post "/hosts/#{host.id}/vulnerabilities/decisions/#{control.id}/end"
    expect(flash[:notice]).to end_with("It no longer counts as a control: the finding is back in the bucket the rules give it.")
    get "/hosts/#{host.id}/vulnerabilities/decisions/#{control.id}"
    expect(words(page.at_css("#decision dl"))).to include("Confirmed for Media server")
  end

  it "shows a suspended decision's page, and refuses another host's decision, a retired host, and an unknown advisory" do
    save(advisory: shell)
    decision = FindingDecision.sole
    import_kev(kev_file("CVE-2026-93001"))
    perform_evaluation_jobs
    get "/hosts/#{host.id}/vulnerabilities/decisions/#{decision.id}"
    expect(words(page.at_css("#decision_ended"))).to end_with("suspended: the evidence got worse (known exploited: no, now yes; CVEs on the KEV list: none, now CVE-2026-93001)")
    other = debian_host(name: "File server", hostname: "vm-07.example.lan", packages:)
    get "/hosts/#{other.id}/vulnerabilities/decisions/#{decision.id}"
    expect(response).to have_http_status(:not_found)
    get "/hosts/#{host.id}/vulnerabilities/decisions/new?advisory_id=abc"
    expect(response).to have_http_status(:not_found)
    other.retire!(actor: operator)
    get "/hosts/#{other.id}/vulnerabilities/decisions/new?advisory_id=#{tls.id}"
    expect(response).to have_http_status(:not_found)
    save(hosts: [ host, other ])
    expect(words(page.at_css("#host_#{other.id}_error"))).to be_nil
    expect(words(page.at_css("#decision_errors"))).to include("This host cannot be chosen.")
  end
end
