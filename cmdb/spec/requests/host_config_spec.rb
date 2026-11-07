require "rails_helper"

# The host tabs and summary, the Configuration tab, and the config snapshot comparison (P2-D02, FR-2.2, FR-2.5;
# approved mockups host-overview.html, host-config.html, host-config-diff.html, report-requests.html, states-host.html).
RSpec.describe "Host configuration", :signed_in, type: :request do
  let(:start) { Time.utc(2026, 11, 6, 9, 0, 0) }
  let!(:host) { enrolled_host(name: "Media server").first }

  before do
    allow(CisEvaluationJob).to receive(:perform_later) # evaluation is run by hand, at known times
    travel_to(start)
    record_heartbeat(host)
    record_inventory(host) # Debian 13
  end

  def evaluate(at = Time.current) = CisEvaluation.evaluate!([ host.id ], now: at)

  # A config report at `at`, evaluated a second later, as the job would.
  def report(facts = {}, at:)
    travel_to(at) { record_config(host, facts) }
    evaluate(at + 1.second)
  end

  # Text with a space between elements, as a reader hears it.
  def words(node) = node.xpath(".//text()").map(&:text).join(" ").squish

  def unreadable(reason) = { "state" => "unreadable", "value" => nil, "reason" => reason }

  def check_row(key) = page.at_css("tr#check_#{key}")

  def check_cells(key) = check_row(key)&.css("td")&.map { |td| words(td) }

  def fact_row(key) = page.css("#facts_section tr").find { |row| row.at_css("td .mono")&.text == key }

  let(:root_login) { cis_rule_hash } # sshd.permitrootlogin eq "no", high
  let(:max_auth) { cis_rule_hash(key: "ssh-max-auth-tries", title: "SSH limits authentication attempts", reference: "CIS Debian Linux 13 v1.0.0 5.1.16", severity: "medium", fact: "sshd.maxauthtries", condition: { "lte" => 4 }) }
  let(:min_length) { cis_rule_hash(key: "password-min-length", title: "Passwords have a minimum length", reference: "CIS Debian Linux 13 v1.0.0 5.4.1.4", severity: "medium", fact: "pwquality.minlen", condition: { "gte" => 14 }) }
  let(:ubuntu) { cis_rule_hash(key: "ubuntu-crash-reports-off", title: "Crash reports are not sent", severity: "low", applies_to: [ { "distribution" => "ubuntu", "versions" => [ "24.04" ] } ]) }
  let(:shadow) { cis_rule_hash(key: "shadow-file-mode", title: "The password hash file is not readable by everyone", fact: "file:/etc/shadow", condition: { "all" => [ { "mode_at_most" => "0640" }, { "field" => "owner", "eq" => "root" }, { "field" => "group", "in" => [ "root", "shadow" ] } ] }) }

  describe "the tab bar and summary tiles on every tab (Q1)" do
    before do
      define_cis_rules(root_login, max_auth, min_length, ubuntu)
      report({ "sshd.maxauthtries" => ok_fact(6), "pwquality.minlen" => unreadable("/etc/security/pwquality.conf: permission denied") }, at: start + 1.minute)
    end

    it "shows the same header, summary, and tabs on the Overview and Configuration tabs, with the current tab marked" do
      %W[/hosts/#{host.id} /hosts/#{host.id}/config].each_with_index do |path, i|
        get path
        expect(response).to have_http_status(:ok)
        expect(page.at_css(".host-head h1").text).to eq("Media server")
        expect(page.css("nav.tabs a").map { |a| [ a.text, a["href"], a["aria-current"] ] }.first(2))
          .to eq([ [ "Overview", "/hosts/#{host.id}", ("page" if i.zero?) ], [ "Configuration", "/hosts/#{host.id}/config", ("page" if i == 1) ] ])
        expect(page.css("#host_summary > *").map { |tile| tile.at_css(".label").text })
          .to eq([ "CIS-aligned checks", "Open vulnerabilities", "Packages", "Last reports received" ])
      end
      expect(page.at_css("title").text).to eq("Media server: configuration · Fleet CMDB")
    end

    it "counts not readable against the pass rate and leaves not applicable out (Q3)" do
      get "/hosts/#{host.id}/config"
      tile = page.at_css("#glance_cis")
      expect(tile["href"]).to eq("/hosts/#{host.id}/config#results")
      expect(tile.at_css(".big").text.squish).to eq("33.3% pass")
      expect(tile.at_css(".detail").text).to eq("1 of 3 pass · 1 fail · 1 not readable")
      expect(page.at_css("#results_section > p").text.squish).to start_with("This host passes 1 of 3 checks (33.3%).")
      expect(response.body).not_to match(/CIS[- ]compliant/i)
    end

    it "says not evaluated, not 0 or 100%, for vulnerabilities and packages it knows nothing about, and when reports arrived" do
      get "/hosts/#{host.id}"
      expect(words(page.at_css("#glance_vulns"))).to eq("Open vulnerabilities Not evaluated Packages have not been matched against advisories yet")
      expect(words(page.at_css("#glance_packages"))).to eq("Packages Not known No package report yet")
      expect(words(page.at_css("#glance_reports"))).to eq("Last reports received 1 minute ago Config and inventory; no package report yet")
      expect(page.at_css("#glance_reports")["href"]).to eq("/hosts/#{host.id}#report_requests")
    end

    it "says so when no check counts towards the pass rate" do
      other = enrolled_host.first
      get "/hosts/#{other.id}/config"
      expect(words(page.at_css("#glance_cis"))).to eq("CIS-aligned checks Not evaluated No check has a pass or fail result yet")
      expect(page.at_css("#results_section > p").text.squish).to start_with("Not evaluated. No check on this host has passed, failed, or been unreadable yet, because the host has not sent a config report.")
      expect(words(page.at_css("#glance_reports"))).to eq("Last reports received None yet The agent has sent no report")
    end
  end

  it "says there are no rules, and that there is no config report yet" do
    get "/hosts/#{host.id}/config"
    expect(page.at_css("#glance_cis .detail").text).to eq("No rules are defined")
    expect(page.at_css("#results_section .empty").text.squish).to start_with("No CIS-aligned rules are defined.")
    expect(page.at_css("#facts_section .empty").text.squish).to start_with("No config report yet.")
    expect(page.at_css("#snapshots_section").text).to include("No snapshots yet.")
    expect(page.at_css("#history_section").text).to include("No changes yet.")
    expect(page.at_css("#request").text.squish).to start_with("No config report yet.")
  end

  describe "CIS-aligned results" do
    before do
      define_cis_rules(root_login, max_auth, min_length, ubuntu, shadow, cis_rule_hash(key: "ssh-later", title: "Not yet evaluated rule", fact: "sshd.banner"))
      CisRule.transaction { CisRule.find_by!(key: "ssh-later").disable!(actor: Audit::SYSTEM) }
      report({ "sshd.maxauthtries" => ok_fact(6), "pwquality.minlen" => unreadable("/etc/security/pwquality.conf: permission denied") }, at: start + 1.minute)
    end

    it "opens on Needs attention, grouped by area, with severity, observed and expected values, and remediation (Q4)" do
      get "/hosts/#{host.id}/config"
      expect(page.css(".chips a").map { |a| [ a.text.squish, a["aria-current"] ] }).to eq(
        [ [ "Needs attention 2", "true" ], [ "Fail 1", nil ], [ "Not readable 1", nil ], [ "Pass 2", nil ], [ "Not applicable 1", nil ], [ "Not evaluated 1", nil ], [ "All 6", nil ] ]
      )
      expect(page.css("#results_section .group-head").map { |head| words(head) }).to eq([ "SSH server 1 of 4 checks needs attention", "Login and password policy 1 of 1 check needs attention" ])
      expect(check_cells("ssh-max-auth-tries")).to eq([ "Fail", "Medium", "SSH limits authentication attempts CIS Debian Linux 13 v1.0.0 5.1.16 · ssh-max-auth-tries · rule v1 Remediation Set PermitRootLogin to no.", "Observed 6 Expected at most 4" ])
      expect(check_row("ssh-root-login-off")).to be_nil
      expect(words(page.at_css("#checks_pager"))).to eq("2 checks need attention. The other 4 are filtered out. Show all 6")
    end

    it "shows an unreadable fact's reason in the facts list and, naming the fact, in the check that depends on it (AC-2.5)" do
      get "/hosts/#{host.id}/config"
      expect(check_cells("password-min-length")).to include("Not readable", "pwquality.minlen: /etc/security/pwquality.conf: permission denied Expected at least 14")
      expect(fact_row("pwquality.minlen").css("td").map { |td| words(td) })
        .to eq([ "pwquality.minlen #{ConfigManifest.current.fact('pwquality.minlen').description}", "Unreadable", "No value", "/etc/security/pwquality.conf: permission denied" ])
    end

    it "filters by result, severity, and text, keeping the filter in the URL" do
      get "/hosts/#{host.id}/config", params: { result: "all" }
      expect(page.css("tr.check").map { |row| row["id"] }).to eq(%w[check_ssh-max-auth-tries check_ssh-root-login-off check_ubuntu-crash-reports-off check_ssh-later check_password-min-length check_shadow-file-mode])
      expect(check_cells("ubuntu-crash-reports-off").last).to eq("Applies to ubuntu 24.04; this host runs debian 13.")
      expect(check_cells("ssh-later").last).to eq(CisEvaluation::DISABLED)
      expect(check_cells("shadow-file-mode").last).to eq(%(Observed {"mode":"0640","group":"shadow","owner":"root"} Expected mode at most 0640, owner equals "root", group is one of "root", "shadow"))
      expect(page.at_css("#checks_pager")).to be_nil

      get "/hosts/#{host.id}/config", params: { result: "pass", severity: "high", q: "SHADOW" }
      expect(page.css("tr.check").map { |row| row["id"] }).to eq(%w[check_shadow-file-mode])
      expect(page.at_css("#check_filters input[name=result]")["value"]).to eq("pass")
      expect(page.at_css("#check_filters select[name=severity] option[selected]")["value"]).to eq("high")
      expect(page.at_css("#check_filters input[name=q]")["value"]).to eq("SHADOW")
      expect(words(page.at_css("#checks_pager"))).to eq("1 check shown. The other 5 are filtered out. Show all 6")
      chip = page.css(".chips a").find { |a| a.text.start_with?("Fail") }["href"]
      expect(Rack::Utils.parse_query(URI(chip).query)).to eq("result" => "fail", "severity" => "high", "q" => "SHADOW")

      get "/hosts/#{host.id}/config", params: { q: "nothing like this", result: "bogus", severity: "bogus" }
      expect(words(page.at_css("#no_checks"))).to eq("No checks match. Show all 6 checks")
      expect(page.at_css(".chips a[aria-current]").text).to start_with("Needs attention")
    end

    it "lists facts a rule checks or that are not OK by default, and every fact on request, in words" do
      get "/hosts/#{host.id}/config"
      keys = page.css("#facts_section td .mono").map(&:text)
      expect(keys).to include("sshd.permitrootlogin", "pwquality.minlen", "file:/etc/sudoers", "pwquality.retry", "sshd.banner")
      expect(keys).not_to include("firewall.backend")
      expect(fact_row("pwquality.retry").css("td")[1..].map { |td| words(td) }).to eq([ "Unsupported", "No value", "libpwquality is not installed." ])
      total = ConfigManifest.current.facts.size
      expect(words(page.at_css("#facts_pager"))).to eq("Showing #{keys.size} of #{total} facts: the ones a rule checks or that are not OK. Show all #{total}")
      expect(page.at_css("#facts_section > p.muted").text).to start_with("#{total} facts in the latest snapshot: ")

      get page.at_css("#facts_pager a")["href"]
      expect(page.css("#facts_section td .mono").size).to eq(total)
      values = %w[sshd.permitrootlogin sshd.passwordauthentication sshd.ciphers file:/etc/shadow file:/etc/issue.net service:ssh.service service:telnet.socket].to_h { |key| [ key, words(fact_row(key).css("td")[2]) ] }
      expect(values).to eq("sshd.permitrootlogin" => %("no"), "sshd.passwordauthentication" => "false", "sshd.ciphers" => %("aes256-gcm" "aes256-ctr" 2 entries, order matters),
                           "file:/etc/shadow" => "mode 0640, owner root, group shadow", "file:/etc/issue.net" => "File does not exist",
                           "service:ssh.service" => "active, enabled", "service:telnet.socket" => "Not installed")
      expect(words(page.at_css("#facts_pager"))).to eq("Showing all #{total} facts. Show the ones with a rule or a problem")
    end
  end

  describe "snapshots, comparison, and result changes" do
    let(:editor) { create(:operator, email: "editor@example.com", name: "Example Editor") }

    before do
      define_cis_rules(root_login, max_auth, min_length)
      report({ "sshd.permitrootlogin" => ok_fact("yes") }, at: start + 1.minute)                                  # root login fails
      report({ "pwquality.minlen" => unreadable("/etc/security/pwquality.conf: permission denied") }, at: start + 1.hour) # root login passes, minlen not readable
      travel_to(start + 2.hours) do
        CisRule.transaction { CisRule.define!(CisRules::Definition.from_h(max_auth.merge("condition" => { "lte" => 3 })), actor: editor) }
        evaluate
      end
      travel_to(start + 3.hours)
    end

    def snapshots = ConfigSnapshot.where(host:).order(:received_at).to_a

    it "calls the oldest snapshot still kept that, not the first config report, once older ones are pruned (review of #124)" do
      ConfigSnapshot.where(id: snapshots.first.id).delete_all # what Retention does to snapshots past the window
      get "/hosts/#{host.id}/config"
      cells = page.css("#snapshot_list tbody tr").map { |row| row.css("td").map { |td| words(td) } }
      expect(cells.map { |row| [ row[1], row[3] ] }).to eq([ [ "Oldest config snapshot kept", "No earlier snapshot kept" ] ])
      expect(page.at_css("#snapshot_list").text).not_to include("First config report", "Nothing before it")
    end

    it "lists each snapshot with what changed, the results it flipped, and comparison links" do
      get "/hosts/#{host.id}/config"
      rows = page.css("#snapshot_list tbody tr")
      expect(rows.map { |row| row.css("td").map { |td| words(td) } }).to eq([
        [ "2026-11-06 10:00 UTC Latest", "2 facts changed", "Fail → Pass: ssh-root-login-off Pass → Not readable: password-min-length", "With the one before" ],
        [ "2026-11-06 09:01 UTC", "Oldest config snapshot kept", "First results recorded", "No earlier snapshot kept" ]
      ])
      first, latest = snapshots
      expect(rows.first.at_css("a")["href"]).to eq("/hosts/#{host.id}/config/compare?from=#{first.id}&to=#{latest.id}")
    end

    it "explains each result change, newest first: a rule edit by its editor, and new reports with the fact before and after" do
      get "/hosts/#{host.id}/config"
      expect(page.css("#result_changes tbody tr").map { |row| row.css("td").map { |td| words(td) } }).to eq([
        [ "2026-11-06 11:00 UTC", "ssh-max-auth-tries", "Pass → Fail", "Rule edited to version 2 by Example Editor; no new report" ],
        [ "2026-11-06 10:00 UTC", "password-min-length", "Pass → Not readable", "New config report: pwquality.minlen became unreadable" ],
        [ "2026-11-06 10:00 UTC", "ssh-root-login-off", "Fail → Pass", %(New config report: sshd.permitrootlogin "yes" → "no") ],
        [ "2026-11-06 09:01 UTC", "password-min-length", "Pass", "First result for this check" ],
        [ "2026-11-06 09:01 UTC", "ssh-max-auth-tries", "Pass", "First result for this check" ]
      ])
      expect(words(page.at_css("#history_section .pager"))).to eq("Showing the latest 5 changes. Older changes")
      get "/hosts/#{host.id}/config", params: { history: "all" }
      expect(page.css("#result_changes tbody tr").size).to eq(6)
      expect(words(page.at_css("#history_section .pager"))).to eq("Showing the latest 6 changes.")
    end

    it "shows a changed SSH setting in the diff and the rule result it flipped, by default the latest against the one before (AC-2.1)" do
      get "/hosts/#{host.id}/config/compare"
      expect(response).to have_http_status(:ok)
      first, latest = snapshots
      expect(page.at_css("#snapshot_picker select[name=from] option[selected]")["value"]).to eq(first.id.to_s)
      expect(page.at_css("#snapshot_picker select[name=to] option[selected]").text).to eq("2026-11-06 10:00 UTC (latest, 2 facts changed)")
      expect(page.css("#snapshot_picker select[name=from] option").map(&:text)).to eq([ "2026-11-06 10:00 UTC (latest, 2 facts changed)", "2026-11-06 09:01 UTC (oldest kept)" ])
      expect(words(page.at_css("#diff_summary"))).to eq("1 fact changed value 1 fact changed state or reason 0 facts added 0 facts removed 2 checks changed result: 1 to Pass, 1 to Not readable")
      expect(page.at_css("#change_sshd-permitrootlogin").css("td").map { |td| words(td) }).to eq([ "sshd.permitrootlogin", "Changed", %("yes"), %("no"), "ssh-root-login-off Fail → Pass" ])
      expect(page.at_css("#change_sshd-permitrootlogin del")).to be_present
      expect(page.at_css("#change_pwquality-minlen").css("td").map { |td| words(td) })
        .to eq([ "pwquality.minlen", "State changed", "OK 14", "Unreadable /etc/security/pwquality.conf: permission denied", "password-min-length Pass → Not readable" ])
      expect(page.at_css("title").text).to eq("Media server: compare config snapshots · Fleet CMDB")
      expect(page.css("nav.tabs a[aria-current]").map(&:text)).to eq([ "Configuration" ])
    end

    it "compares any two snapshots by a bookmarkable address, reversed with Swap, and lists result changes with no new snapshot" do
      report({ "sshd.permitrootlogin" => ok_fact("yes") }, at: start + 4.hours)
      first, _, last = snapshots
      get "/hosts/#{host.id}/config/compare", params: { from: first.id, to: last.id }
      expect(words(page.at_css("#diff_summary"))).to start_with("0 facts changed value 0 facts changed state or reason")
      expect(words(page.at_css("#diff_summary"))).to end_with("0 checks changed result") # the same facts: the rule edit is listed apart
      expect(words(page.at_css("#rule_changes"))).to eq("ssh-max-auth-tries went from Pass to Fail on 2026-11-06 11:00 UTC: Rule edited to version 2 by Example Editor; no new report.")
      get page.at_css("#snapshot_picker a.btn")["href"]
      expect(request.query_parameters).to eq("from" => last.id.to_s, "to" => first.id.to_s)
      expect(page.at_css("#reversed_note")).to be_present
      expect(page.at_css("#value_changes")).to be_nil
      get "/hosts/#{host.id}/config/compare", params: { from: snapshots[1].id, to: last.id }
      expect(words(page.at_css("#change_sshd-permitrootlogin td:last-child"))).to eq("ssh-root-login-off Pass → Fail")
      expect(words(page.at_css("#change_pwquality-minlen td:last-child"))).to eq("password-min-length Not readable → Pass")
      expect(words(page.at_css("#diff_summary"))).to end_with("2 checks changed result: 1 to Pass, 1 to Fail")
    end

    it "refuses a snapshot of another host" do
      other = enrolled_host.first
      travel_to(start) { record_config(other) }
      get "/hosts/#{host.id}/config/compare", params: { from: ConfigSnapshot.find_by!(host: other).id, to: snapshots.last.id }
      expect(response).to have_http_status(:not_found)
    end

    it "explains a disabled and re-enabled rule, and a result changed by the host's operating system" do
      rule = CisRule.find_by!(key: "ssh-root-login-off")
      travel_to(start + 4.hours) { CisRule.transaction { rule.disable!(actor: editor) } && evaluate }
      travel_to(start + 5.hours) { CisRule.transaction { rule.enable!(actor: Audit::SYSTEM) } && evaluate }
      travel_to(start + 6.hours) { record_inventory(host, os: { "id" => "ubuntu", "version_id" => "24.04", "pretty_name" => "Ubuntu 24.04" }) && evaluate }
      get "/hosts/#{host.id}/config"
      causes = page.css("#result_changes tbody tr").map { |row| [ row.css("td")[1].text, row.css("td")[3].text.squish ] }
      expect(causes.first(5)).to eq([
        [ "password-min-length", "Re-evaluated with no new config report" ],
        [ "ssh-max-auth-tries", "Re-evaluated with no new config report" ],
        [ "ssh-root-login-off", "Re-evaluated with no new config report" ],
        [ "ssh-root-login-off", "Rule enabled; no new report" ],
        [ "ssh-root-login-off", "Rule disabled by Example Editor" ]
      ])
    end
  end

  it "says there is nothing to compare with one snapshot or none" do
    get "/hosts/#{host.id}/config/compare"
    expect(words(page.at_css("#nothing_to_compare"))).to start_with("No config report yet.")
    travel_to(start) { record_config(host) }
    get "/hosts/#{host.id}/config/compare"
    expect(words(page.at_css("#nothing_to_compare"))).to start_with("Only one config snapshot.")
  end

  it "shows a long observed value in a scrolling box and a cut one as cut, pointing at the fact" do
    many = Array.new(200) { |i| "unit-#{i}.service" }
    define_cis_rules(cis_rule_hash(key: "no-telnet-running", fact: "services.running", condition: { "not_in" => [ "telnet.socket" ] }),
                     cis_rule_hash(key: "few-logins", fact: "users.login", condition: { "in" => [ "root" ] }))
    report({ "services.running" => ok_fact(many + [ "telnet.socket" ]), "users.login" => ok_fact(Array.new(10) { |i| "user-number-#{i}" }) }, at: start + 1.minute)
    get "/hosts/#{host.id}/config"
    cut = check_row("no-telnet-running").at_css("pre.value")
    expect(cut["tabindex"]).to eq("0")
    expect(cut.text).to match(/… \(truncated from [\d,]+ bytes\)\z/)
    expect(check_row("no-telnet-running").at_css(".trunc").text.squish).to eq("Cut at 1 KiB. The whole value is in the facts as services.running.")
    expect(check_row("no-telnet-running").at_css(".state-note:last-child").text).to eq(%(Expected contains none of "telnet.socket"))
    long = check_row("few-logins")
    expect(long.at_css("pre.value")["aria-label"]).to eq("Observed value")
    expect(long.at_css(".trunc")).to be_nil
    expect(long.at_css(".state-note:last-child").text).to eq(%(Expected contains only "root"))
  end

  it "escapes agent-supplied fact values, reasons, and observed values (NFR-1)" do
    define_cis_rules(cis_rule_hash(key: "ssh-banner", fact: "sshd.banner", condition: { "eq" => "/etc/issue.net" }),
                     cis_rule_hash(key: "ssh-max-auth-tries", fact: "sshd.maxauthtries", condition: { "lte" => 4 }))
    report({ "sshd.banner" => ok_fact(HOSTILE), "sshd.maxauthtries" => unreadable(HOSTILE) }, at: start + 1.minute)
    report({ "sshd.banner" => ok_fact("#{HOSTILE} again"), "sshd.maxauthtries" => ok_fact(9) }, at: start + 2.minutes)
    [ "/hosts/#{host.id}/config?result=all&facts=all&history=all", "/hosts/#{host.id}/config/compare" ].each do |path|
      get path
      expect(page.css("script:not([type])").map(&:text).grep(/alert/)).to eq([])
      expect(page.css("img[onerror]")).to be_empty
      expect(response.body).to include("&lt;script&gt;alert(")
    end
  end

  describe "the Configuration tab's request button (Q6, Q7)" do
    def box = page.at_css("#request")
    def button = box.at_css("button")

    before { travel_to(start) { record_config(host) } }

    it "asks for a config report only, and comes back to the Configuration tab" do
      get "/hosts/#{host.id}/config"
      expect(words(box)).to start_with("Config report received less than 5 seconds ago. Collected 2026-01-01 12:00 UTC by agent 0.1.0, manifest version 1.")
      expect(box.at_css("form")["action"]).to eq("/hosts/#{host.id}/request_reports")
      expect(box.css("input[type=hidden]").to_h { |input| [ input["name"], input["value"] ] }).to include("report_types[]" => "config", "return_to" => "config")
      expect([ button.text, button["disabled"] ]).to eq([ "Request fresh config report", nil ])
      post "/hosts/#{host.id}/request_reports", params: { report_types: %w[config], return_to: "config" }
      expect(response).to redirect_to("/hosts/#{host.id}/config#request")
      expect(host.report_requests.pluck(:report_type)).to eq(%w[config])
    end

    it "shows the request pending, before and after the agent was asked, with the button off" do
      ReportRequests.request!(host:, types: %w[config], actor: operator)
      get "/hosts/#{host.id}/config"
      expect(words(box)).to eq("Requested. Config report requested. The agent is asked on its next heartbeat. Requested by Example Operator, 09:00:00 UTC. " \
                                    "The agent checks in about once a minute. The button is not offered again while a request is pending. Request pending")
      expect(button["disabled"]).to eq("disabled")
      travel_to(start + 6.minutes) do
        Host.transaction { ReportRequests.directive_for(host_id: host.id, agent_time: Time.current) }
        get "/hosts/#{host.id}/config"
      end
      expect(words(box)).to start_with("Agent asked 09:06:00 UTC, waiting for the report. Expires 10:00:00 UTC if no report arrives.")
      expect([ button.text, button["disabled"] ]).to eq([ "Request pending", "disabled" ])
    end

    it "is disabled with the time it can be used again when rate limited, and refreshes the page then" do
      ReportRequests.request!(host:, types: %w[config], actor: operator)
      Host.transaction { ReportRequests.directive_for(host_id: host.id, agent_time: Time.current) }
      travel_to(start + 1.minute) { record_config(host, {}, Time.current) }
      travel_to(start + 2.minutes) { get "/hosts/#{host.id}/config" }
      expect(words(box)).to start_with("Config report requested less than 5 minutes ago. Try again after 09:05:00 UTC.")
      expect([ button.text, button["disabled"], button["aria-describedby"] ]).to eq([ "Request fresh config report", "disabled", "request_retry" ])
      expect(box.at_css("#request_retry").text).to eq("Try again after 09:05:00 UTC.")
      expect([ box["data-controller"], box["data-refresh-after-seconds-value"] ]).to eq([ "refresh-after", "180" ])
    end

    it "says the request was answered, then later just when the report arrived" do
      ReportRequests.request!(host:, types: %w[config], actor: operator)
      Host.transaction { ReportRequests.directive_for(host_id: host.id, agent_time: Time.current) }
      travel_to(start + 1.minute) { record_config(host, {}, Time.current) }
      travel_to(start + 10.minutes) { get "/hosts/#{host.id}/config" }
      expect(words(box)).to start_with("Received 09:01:00 UTC. Config report requested by Example Operator, 09:00:00 UTC. The new report showed no change, so no new snapshot was recorded.")
      expect(button["disabled"]).to be_nil
      expect(box["data-controller"]).to be_nil
      travel_to(start + 2.hours) { get "/hosts/#{host.id}/config" }
      expect(words(box)).to start_with("Config report received about 2 hours ago.")
    end

    it "says an answered request recorded a new snapshot when the report changed something" do
      ReportRequests.request!(host:, types: %w[config], actor: operator)
      Host.transaction { ReportRequests.directive_for(host_id: host.id, agent_time: Time.current) }
      travel_to(start + 1.minute) { record_config(host, { "sshd.maxauthtries" => ok_fact(5) }, Time.current) }
      travel_to(start + 10.minutes) { get "/hosts/#{host.id}/config" }
      expect(box.at_css(".hint").text).to eq("The new report changed some facts, so a new snapshot was recorded.")
    end

    it "says a request expired with no report" do
      ReportRequests.request!(host:, types: %w[config], actor: operator)
      travel_to(start + 61.minutes) { get "/hosts/#{host.id}/config" }
      expect(words(box)).to start_with("Expired 10:00:00 UTC: no report arrived within 60 minutes. Requested by Example Operator, 09:00:00 UTC. The agent may be offline")
      expect(button["disabled"]).to be_nil
    end

    it "draws no button for a host that cannot be asked, and still shows a retired host's configuration" do
      host.revoke!(actor: Audit::SYSTEM)
      get "/hosts/#{host.id}/config"
      expect(words(box)).to include("Only an active host's agent can be asked for a report.")
      expect(box.at_css("button")).to be_nil
      host.retire!(actor: Audit::SYSTEM)
      get "/hosts/#{host.id}/config"
      expect(response).to have_http_status(:ok)
      expect(page.at_css(".notice:not(.flash):not([data-live-status-target])").text).to include("This host is retired.")
    end
  end

  describe "the Overview's three-way form (Q6, Q7)" do
    it "disables a type that is pending or rate limited, saying until when, and the button when none is left" do
      ReportRequests.request!(host:, types: %w[config], actor: operator)
      get "/hosts/#{host.id}"
      boxes = page.css("#report_request_form input[type=checkbox]").to_h { |box| [ box["value"], [ box["checked"].present?, box["disabled"].present? ] ] }
      expect(boxes).to eq("config" => [ false, true ], "inventory" => [ true, false ], "packages" => [ true, false ])
      expect(page.at_css("#report_type_config_note").text).to eq("(pending)")
      ReportRequests.request!(host:, types: %w[inventory packages], actor: operator)
      ReportRequests.expire!(now: start + 2.hours, host_id: host.id)
      travel_to(start + 2.hours) { ReportRequests.request!(host:, types: %w[packages inventory config], actor: operator) }
      travel_to(start + 2.hours + 1.minute) do
        ReportRequests.expire!(now: start + 3.hours, host_id: host.id)
        get "/hosts/#{host.id}"
      end
      expect(page.at_css("#report_type_packages_note").text).to eq("(requested less than 5 minutes ago. Try again after 11:05:00 UTC.)")
      expect(page.at_css("#report_request_form button")["disabled"]).to eq("disabled")
      expect(page.at_css("#report_requests")["data-refresh-after-seconds-value"]).to eq("240")
    end
  end

  describe "review of #118" do
    def flips = words(page.at_css("#diff_summary")).sub(/.*removed /, "")

    it "refuses another host's snapshot even when this host has nothing to compare" do
      other = enrolled_host.first
      travel_to(start) { record_config(other) }
      foreign = ConfigSnapshot.find_by!(host: other).id
      get "/hosts/#{host.id}/config/compare", params: { from: foreign }
      expect(response).to have_http_status(:not_found)
      travel_to(start) { record_config(host) }
      get "/hosts/#{host.id}/config/compare", params: { to: foreign }
      expect(response).to have_http_status(:not_found)
    end

    it "offers every snapshot kept in the pickers, labelling only the newest with their changes" do
      27.times { |i| travel_to(start + i.minutes) { record_config(host, "sshd.maxauthtries" => ok_fact(i)) } }
      get "/hosts/#{host.id}/config/compare"
      options = page.css("#snapshot_picker select[name=from] option").map(&:text)
      expect(options.size).to eq(27)
      expect(options.first).to eq("2026-11-06 09:26 UTC (latest, 1 fact changed)")
      expect(options[25]).to eq("2026-11-06 09:01 UTC")
      expect(options.last).to eq("2026-11-06 09:00 UTC (oldest kept)")
      expect(page.at_css("#snapshot_picker")["data-controller"]).to eq("keep-edits") # a live refresh keeps an unsubmitted choice
    end

    it "does not join report changes across a rule edit into a report effect" do
      define_cis_rules(root_login)
      report({}, at: start + 1.minute)                                              # "no": pass
      report({ "sshd.permitrootlogin" => ok_fact("yes") }, at: start + 1.hour)      # fail
      travel_to(start + 2.hours) do                                                  # the rule now wants "yes": pass
        CisRule.transaction { CisRule.define!(CisRules::Definition.from_h(root_login.merge("condition" => { "eq" => "yes" })), actor: Audit::SYSTEM) }
        evaluate
      end
      report({}, at: start + 3.hours)                                                # "no" again: fail
      first, second, _, last = ConfigSnapshot.where(host:).order(:received_at).to_a.then { |s| [ s[0], s[1], s[1], s[2] ] }
      get "/hosts/#{host.id}/config/compare", params: { from: first.id, to: last.id }
      expect(flips).to eq("0 checks changed result") # the same facts; the rule edit is listed apart
      expect(page.at_css("#rule_changes").text).to include("Rule edited")
      get "/hosts/#{host.id}/config/compare", params: { from: second.id, to: last.id }
      expect(words(page.at_css("#change_sshd-permitrootlogin td:last-child"))).to eq("ssh-root-login-off Pass → Fail")
      expect(flips).to eq("1 check changed result: 1 to Fail")
    end

    it "names a rule enabled after a report arrived while it was disabled as enabled, not as the report" do
      define_cis_rules(root_login)
      report({}, at: start + 1.minute)
      rule = CisRule.find_by!(key: "ssh-root-login-off")
      travel_to(start + 1.hour) { CisRule.transaction { rule.disable!(actor: Audit::SYSTEM) } && evaluate }
      report({ "sshd.maxauthtries" => ok_fact(5) }, at: start + 2.hours)
      travel_to(start + 3.hours) { CisRule.transaction { rule.enable!(actor: Audit::SYSTEM) } && evaluate }
      get "/hosts/#{host.id}/config"
      expect(page.css("#result_changes tbody tr").first.css("td").map { |td| td.text.squish }.values_at(2, 3)).to eq([ "Not evaluated → Pass", "Rule enabled; no new report" ])
    end

    it "shows a change of reason alone with both reasons, and the effect of a fact added to the manifest" do
      define_cis_rules(cis_rule_hash(key: "ssh-banner", fact: "sshd.banner", condition: { "eq" => "/etc/issue.net" }))
      report({ "pwquality.minlen" => unreadable("busy") }, at: start + 1.minute)
      first = ConfigSnapshot.find_by!(host:)
      first.update_columns(facts: first.facts.except("sshd.banner")) # taken before the manifest had the fact
      evaluate(start + 2.minutes)
      report({ "pwquality.minlen" => unreadable("permission denied"), "sshd.banner" => ok_fact("/etc/issue.net") }, at: start + 1.hour)
      get "/hosts/#{host.id}/config/compare"
      expect(page.at_css("#change_pwquality-minlen").css("td").map { |td| words(td) }.first(4)).to eq([ "pwquality.minlen", "Reason changed", "Unreadable busy", "Unreadable permission denied" ])
      expect(page.at_css("#value_changes")).to be_nil
      expect(words(page.at_css("#change_sshd-banner"))).to eq(%(sshd.banner OK "/etc/issue.net" ssh-banner Not readable → Pass))
      expect(flips).to eq("1 check changed result: 1 to Pass")
    end

    it "says an answered request recorded a snapshot when a later report has come since" do
      travel_to(start) { record_config(host) }
      ReportRequests.request!(host:, types: %w[config], actor: operator)
      Host.transaction { ReportRequests.directive_for(host_id: host.id, agent_time: Time.current) }
      travel_to(start + 1.minute) { record_config(host, { "sshd.maxauthtries" => ok_fact(5) }, Time.current) }
      travel_to(start + 2.minutes) { record_config(host, { "sshd.maxauthtries" => ok_fact(6) }, Time.current) }
      travel_to(start + 10.minutes) { get "/hosts/#{host.id}/config" }
      expect(page.at_css("#request .hint").text).to eq("The new report changed some facts, so a new snapshot was recorded.")
    end
  end
end
