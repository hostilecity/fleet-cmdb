require "rails_helper"

# The rules pages (P2-D06, FR-2.2; approved mockups rules.html, rule.html, rule-version.html, rule-create.html,
# rule-create-preview.html, rule-edit.html, rule-edit-preview.html, rule-edit-errors.html, dialogs.html): the list,
# a rule's results, versions, and change log, adding and editing with a preview that writes nothing, and enabling and
# disabling, every change through CisRule.define! (the import's path), audited with the operator, and re-evaluated
# with no agent contact (AC-2.2).
RSpec.describe "Rules", :signed_in, type: :request do
  include ActiveJob::TestHelper

  let!(:web) { enrolled_host(name: "Web A", hostname: "web-a.example.lan").first }
  let!(:media) { enrolled_host(name: "Media server", hostname: "media.example.lan").first }
  let!(:dns) { enrolled_host(name: "DNS resolver", hostname: "dns.example.lan").first } # never reports config

  let(:max_auth) do
    cis_rule_hash(key: "ssh-max-auth-tries", title: "SSH limits authentication attempts per connection", reference: "CIS Debian 13 5.1.18", severity: "medium",
                  fact: "sshd.maxauthtries", condition: { "lte" => 4 }, remediation: "Set MaxAuthTries to 4 or lower.")
  end
  let(:root_login) { cis_rule_hash } # sshd.permitrootlogin eq "no", high
  let(:shadow) do
    cis_rule_hash(key: "shadow-file-mode", title: "The password hash file is not readable by everyone", reference: "CIS Debian 13 7.1.3", fact: "file:/etc/shadow",
                  condition: { "all" => [ { "mode_at_most" => "0640" }, { "field" => "owner", "eq" => "root" }, { "field" => "group", "in" => [ "root", "shadow" ] } ] })
  end

  before do
    [ web, media, dns ].each { |host| record_inventory(host) } # Debian 13
    record_config(web, "sshd.maxauthtries" => ok_fact(5), "sshd.permitrootlogin" => ok_fact("no"))
    record_config(media, "sshd.maxauthtries" => ok_fact(3), "sshd.permitrootlogin" => ok_fact("yes"))
  end

  def define(*rules) = perform_enqueued_jobs { define_cis_rules(*rules) }

  def result(host, key) = CisResult.joins(:cis_rule).find_by!(host:, cis_rules: { key: }).result

  def words(node) = node.xpath(".//text()").map(&:text).join(" ").squish

  # The edit form's fields, with the signature a preview of exactly that rule would carry (RulePreviewSignature).
  def form_params(rule = CisRule.find_by!(key: "ssh-max-auth-tries"), **overrides)
    fields = RuleForm.for_rule(rule).to_params.merge(overrides.transform_keys(&:to_s))
    { rule: fields, base_version_id: rule.current_version_id, preview_signature: signature(fields, rule:, base_version_id: rule.current_version_id) }
  end

  def new_rule_params(**overrides)
    fields = { "key" => "ssh-ignore-rhosts", "title" => "SSH ignores per-user trust files", "reference" => "CIS Debian 13 5.1.9", "severity" => "medium",
               "platforms" => { "0" => { "distribution" => "debian", "versions" => "13" } }, "fact" => "sshd.permitrootlogin", "operator" => "eq", "expected" => "no",
               "remediation" => "Set it.", "enabled" => "1" }.merge(overrides.transform_keys(&:to_s))
    { rule: fields, preview_signature: signature(fields) }
  end

  def signature(fields, rule: nil, base_version_id: nil)
    form = RuleForm.new(attributes: fields, rule:)
    form.valid?
    RulePreviewSignature.generate(form.rule_hash, base_version_id:, operator:)
  end

  # The fields of the form whose action is path, as the browser would send them.
  def form_fields(path) = page.at_css("form[action='#{path}']").css("input").reject { |input| input["name"].nil? }.map { |input| [ input["name"], input["value"].to_s ] }

  # Every row count and enqueued job, to show a preview writes nothing.
  def table_counts = [ CisRule, CisRuleVersion, CisResult, CisResultChange, AuditEntry, ReportRequest ].to_h { |model| [ model.name, model.count ] }

  describe "the list (rules.html)" do
    it "shows the empty state, with the one import button in the page head, when there are no rules (#144)" do
      get "/rules"
      expect(page.at_css("#no_rules").text).to include("No rules yet.")
      expect(page.at_css("#no_rules a")).to be_nil
      expect(page.css("a[href='/rules/import']").map { |a| [ a.text, a.ancestors(".page-head").any? ] }).to eq([ [ "Import rules file", true ] ])
      expect(page.at_css("nav[aria-label='Main'] a[aria-current='page']").text).to eq("Rules")
    end

    it "lists each rule with severity, applies to, fact and expected value, version, status, and fleet result" do
      define(max_auth, root_login, cis_rule_hash(key: "ubuntu-crash", title: "Crash reports are not sent", severity: "low", applies_to: [ { "distribution" => "ubuntu", "versions" => [ "24.04" ] } ]))
      CisRule.transaction { CisRule.find_by!(key: "ssh-root-login-off").update!(enabled: true) }

      get "/rules"
      expect(response).to have_http_status(:ok)
      expect(page.at_css(".page-head p").text).to include("3 rules: 3 enabled, 0 disabled").and include("CIS-aligned")
      rows = page.css("#rules tbody tr").map { |row| row.css("td").map { |td| words(td) } }
      expect(rows.map(&:first)).to eq([ "Crash reports are not sent ubuntu-crash · CIS Debian 13 5.1.20", "SSH does not let root log in ssh-root-login-off · CIS Debian 13 5.1.20",
                                        "SSH limits authentication attempts per connection ssh-max-auth-tries · CIS Debian 13 5.1.18" ])
      expect(rows[2].drop(1)).to eq([ "Medium", "debian 13", "sshd.maxauthtries at most 4", "v1", "Enabled", "Fails on 1 of 2 hosts" ])
      expect(rows[1].last).to eq("Fails on 1 of 2 hosts")
      expect(rows[0].last).to eq("Not applicable on all 2 hosts")
      expect(response.body).not_to match(/CIS compliant/i)
    end

    it "filters by text, severity, status, applies to, and fleet result, and sorts" do
      define(max_auth, root_login, cis_rule_hash(key: "x11-off", title: "SSH does not forward graphical sessions", severity: "low", fact: "sshd.x11forwarding", condition: { "eq" => false },
                                                 applies_to: [ { "distribution" => "debian" } ]))
      CisRule.transaction { CisRule.find_by!(key: "x11-off").disable!(actor: Audit::SYSTEM) }
      keys = -> { page.css("#rules tbody tr td:first-child code").map(&:text) }

      get "/rules", params: { q: "MAX-AUTH" }
      expect(keys.call).to eq([ "ssh-max-auth-tries" ])
      get "/rules", params: { severity: "high" }
      expect(keys.call).to eq([ "ssh-root-login-off" ])
      get "/rules", params: { status: "disabled" }
      expect(keys.call).to eq([ "x11-off" ])
      expect(page.css("#rules tbody tr td").last.text).to eq("Not evaluated: rule disabled")
      get "/rules", params: { applies: "debian:12" }
      expect(keys.call).to eq([ "x11-off" ]) # every release
      get "/rules", params: { applies: "debian" }
      expect(keys.call).to contain_exactly("ssh-max-auth-tries", "ssh-root-login-off", "x11-off")
      expect(page.css("#applies option").map { |o| [ o.text, o["value"] ] }).to eq([ [ "Any distribution", "" ], [ "debian", "debian" ], [ "debian 13", "debian:13" ] ])
      get "/rules", params: { result: "fail" }
      expect(keys.call).to contain_exactly("ssh-max-auth-tries", "ssh-root-login-off")

      record_config(web, "sshd.maxauthtries" => ok_fact(2))
      perform_enqueued_jobs { CisEvaluation.evaluate!([ web.id ]) }
      get "/rules", params: { result: "pass" }
      expect(keys.call).to eq([ "ssh-max-auth-tries" ])
      expect(page.css("#rules tbody tr td").last.text).to eq("Passes on all 2 hosts")
      get "/rules", params: { result: "not_readable" }
      expect(page.at_css("#no_matches").text).to include(%(No rules match fleet result "Not readable on a host".))
      expect(page.at_css("#no_matches a")["href"]).to eq("/rules")

      get "/rules", params: { sort: "severity" }
      expect(keys.call).to eq(%w[ssh-root-login-off ssh-max-auth-tries x11-off])
      expect(page.at_css("th[aria-sort='ascending'] a").text).to eq("Severity")
      get "/rules", params: { sort: "status", dir: "desc" }
      expect(keys.call.first).to eq("x11-off")
      get "/rules", params: { sort: "name", dir: "desc", q: "zzz", severity: "critical" }
      expect(page.at_css("#no_matches").text).to include(%(No rules match "zzz" with severity "critical".))
    end

    it "pages 50 rules at a time, and ignores filter values it does not know" do
      define(*Array.new(51) { |i| cis_rule_hash(key: "rule-#{format('%02d', i)}", title: "Rule #{format('%02d', i)}") })

      get "/rules", params: { severity: "nope", status: "nope", applies: "Bad Value", result: "nope", sort: "nope", page: "x" }
      expect(page.css("#rules tbody tr").size).to eq(50)
      expect(page.at_css(".pager").text.squish).to start_with("Rules 1–50 of 51, sorted by name")
      get page.at_css(".pager a[rel='next']")["href"]
      expect(page.css("#rules tbody tr td:first-child code").map(&:text)).to eq([ "rule-50" ])
      expect(page.at_css(".pager a[rel='prev']")["href"]).to eq("/rules")
    end

    it "says a rule passes on every host it applies to when some hosts are another distribution" do
      ubuntu = enrolled_host(name: "Ubuntu box").first
      record_inventory(ubuntu, os: { "id" => "ubuntu", "version_id" => "24.04", "pretty_name" => "Ubuntu 24.04" })
      record_config(ubuntu)
      define(max_auth.merge("condition" => { "lte" => 9 }))
      get "/rules"
      expect(page.css("#rules tbody tr td").last.text).to eq("Passes on all 2 hosts it applies to")
    end

    it "says when a rule has no result yet because no host has sent a config report" do
      ConfigSnapshot.delete_all
      HostConfig.delete_all
      define(max_auth)
      get "/rules"
      expect(page.css("#rules tbody tr td").last.text).to eq("Not evaluated: no config report yet")
    end
  end

  describe "a rule (rule.html, rule-version.html)" do
    let!(:rule) { travel_to(Time.utc(2026, 11, 1, 9, 0)) { define(max_auth).first } }

    # These changes are made without a source, as audit entries were recorded before sources were (P2-D06), so the
    # change log uses the plain wording ("Created, version 1").
    it "shows the definition, results on every host, versions, change log, the fact, and the fleet effect" do
      perform_enqueued_jobs { CisRule.transaction { CisRule.define!(CisRules::Definition.from_h(max_auth.merge("condition" => { "lte" => 3 }, "severity" => "high")), actor: operator) } }
      CisRule.transaction { rule.reload.disable!(actor: operator) }
      CisRule.transaction { rule.reload.enable!(actor: operator) }
      perform_enqueued_jobs

      get "/rules/#{rule.id}"
      expect(response).to have_http_status(:ok)
      expect(page.at_css("h1").text).to eq("SSH limits authentication attempts per connection")
      expect(words(page.at_css(".host-head .sub"))).to eq("ssh-max-auth-tries CIS Debian 13 5.1.18 High Enabled Version 2, current")
      definition = page.css("dl.facts").first.css("dt").map(&:text).zip(page.css("dl.facts").first.css("dd").map { |dd| words(dd) })
      expect(definition).to include([ "Fact", "sshd.maxauthtries (integer, 0 to 1000)" ], [ "Expected value", "At most 3" ], [ "Condition", "lte: 3" ])
      expect(page.css("#rule_results tbody tr").map { |row| row.css("td").first(4).map { |td| words(td) } })
        .to eq([ [ "Web A", "Fail", "5", "v2" ], [ "Media server", "Pass", "3", "v2" ], [ "DNS resolver", "Not evaluated", "The host has not sent a config report.", "—" ] ])
      expect(page.css("#rule_versions tbody tr").map { |row| row.css("td").first(5).map { |td| words(td) }.values_at(0, 2, 3, 4) })
        .to eq([ [ "v2 Current", "Example Operator", "High", "at most 3" ], [ "v1", "System", "Medium", "at most 4" ] ])
      expect(page.css("#rule_versions a").map { |a| a["href"] }).to eq([ "/rules/#{rule.id}/versions/2", "/rules/#{rule.id}/versions/1" ])
      log = page.css("#rule_log tbody tr").map { |row| row.css("td").drop(1).map { |td| words(td) } }
      expect(log).to eq([ [ "Example Operator", "Enabled", "Enabled no yes" ], [ "Example Operator", "Disabled", "Enabled yes no" ],
                          [ "Example Operator", "Edited, version 1 → 2", "Severity medium high Condition lte: 4 lte: 3" ],
                          [ "System", "Created, version 1", "All fields set, enabled" ] ])
      expect(page.at_css("#rule_log del.mono").text).to eq("lte: 4")
      expect(words(page.at_css("#fleet_effect"))).to include("Fails on 1 of 2 hosts evaluated. 1 host has no config report yet.").and include("No agent is contacted.")
      expect(page.css(".actions a").map(&:text)).to eq([ "Edit", "Disable", "Audit log" ])
    end

    it "says in the change log where each change was made: the dashboard, a rules file import, or rules:import" do
      perform_enqueued_jobs { patch "/rules/#{rule.id}", params: form_params(rule, expected: "3") }
      post "/rules/#{rule.id}/disable"
      post "/rules/#{rule.id}/enable"
      file = JSON.generate({ "format_version" => 1, "rules" => [ max_auth.merge("condition" => { "lte" => 2 }) ] })
      perform_enqueued_jobs { CisRule.transaction { CisRules::Import.call(file, actor: Audit::SYSTEM, source: "rules_import") } }
      perform_enqueued_jobs { post "/rules", params: new_rule_params }
      upload = Rack::Test::UploadedFile.new(StringIO.new(JSON.generate({ "format_version" => 1, "rules" => [ root_login ] })), "application/json", original_filename: "r.json")
      post "/rules/import", params: { file: upload }
      perform_enqueued_jobs { post "/rules/import/#{RuleImportPreview.sole.token}/apply" }

      get "/rules/#{rule.id}"
      expect(page.css("#rule_log tbody tr td:nth-child(3)").map(&:text))
        .to eq([ "Edited by rules:import, version 2 → 3", "Enabled in the dashboard", "Disabled in the dashboard", "Edited in the dashboard, version 1 → 2", "Created, version 1" ])
      expect(page.at_css("#rule_log tbody tr td:nth-child(4)").text.squish).to eq("Condition lte: 3 lte: 2") # the source is not listed as a changed field
      get "/rules/#{CisRule.find_by!(key: 'ssh-ignore-rhosts').id}"
      expect(page.css("#rule_log tbody tr td:nth-child(3)").map(&:text)).to eq([ "Created in the dashboard, version 1" ])
      get "/rules/#{CisRule.find_by!(key: 'ssh-root-login-off').id}"
      expect(page.css("#rule_log tbody tr td:nth-child(3)").map(&:text)).to eq([ "Created from a rules file import, version 1" ])
      expect(AuditEntry.where(target_type: "CisRule").map { |entry| entry.changeset["source"] }.tally)
        .to eq(nil => 1, "dashboard" => 4, "rules_import" => 1, "file_upload" => 1)
      expect { CisRule.transaction { rule.reload.disable!(actor: Audit::SYSTEM, source: "elsewhere") } }.to raise_error(ArgumentError, /unknown rule change source/)
    end

    it "says a disabled rule is not evaluated and offers Enable" do
      CisRule.transaction { rule.disable!(actor: operator) }
      perform_enqueued_jobs
      get "/rules/#{rule.id}"
      expect(page.at_css("#fleet_effect").text).to include("Disabled: not evaluated on any host")
      expect(page.css(".actions a").map(&:text)).to include("Enable")
      expect(page.css("#rule_results tbody tr td:nth-child(3)").map(&:text).uniq).to eq([ CisEvaluation::DISABLED ])
    end

    it "shows an old version read-only, with what differs now and when it was current" do
      travel_to(Time.utc(2026, 11, 2, 10, 0)) do
        perform_enqueued_jobs { CisRule.transaction { CisRule.define!(CisRules::Definition.from_h(max_auth.merge("condition" => { "lte" => 3 }, "severity" => "high")), actor: operator) } }
      end

      get "/rules/#{rule.id}/versions/1"
      expect(response).to have_http_status(:ok)
      expect(words(page.at_css(".host-head .sub"))).to eq("ssh-max-auth-tries Version 1 Read-only Created 2026-11-01 09:00 UTC by System")
      expect(page.at_css(".notice.info:not(.flash)").text).to include("This is an old version of the rule.").and include("Version 2 is current")
      definition = page.css("dl.facts dt").map(&:text).zip(page.css("dl.facts dd").map { |dd| words(dd) }).to_h
      expect(definition).to include("Severity" => "Medium (high in version 2)", "Expected value" => "At most 4 (at most 3 in version 2)", "Condition" => "lte: 4")
      expect(words(page.at_css("section[aria-labelledby='used']"))).to include("Version 1 was current from 2026-11-01 09:00 to 2026-11-02 10:00 UTC.")
        .and include("No host's current result uses it now.")

      get "/rules/#{rule.id}/versions/2"
      expect(page.at_css(".notice.info:not(.flash)").text).to include("This is the current version of the rule.")
      expect(words(page.at_css("section[aria-labelledby='used']"))).to include("has been current from 2026-11-02 10:00 UTC and still is.").and include("2 hosts' current results use it.")
      expect(words(page.at_css(".host-head .sub"))).to include("by Example Operator")

      get "/rules/#{rule.id}/versions/3"
      expect(response).to have_http_status(:not_found)
    end
  end

  describe "editing (rule-edit.html, rule-edit-preview.html, rule-edit-errors.html)" do
    let!(:rule) { define(max_auth, root_login).first }

    it "opens a single comparison as an operator and an expected value" do
      get "/rules/#{rule.id}/edit"
      expect(response).to have_http_status(:ok)
      expect(page.at_css("h1").text).to eq("Edit rule")
      expect(page.at_css(".page-head p").text).to eq("Saving creates version 2. Version 1 stays as it is.")
      expect(page.at_css("#rule_key")["readonly"]).to eq("readonly")
      expect(page.at_css("#rule_operator option[selected]").text).to eq("at most")
      expect(page.at_css("#rule_condition")).to have_attributes(name: "input")
      expect(page.at_css("#rule_condition")["type"]).to eq("text") # so "one of" can take "3, 4" (review of #130)
      expect(page.at_css("#rule_condition")["value"]).to eq("4")
      expect(page.at_css("#rule_fact option[selected]").text).to eq("sshd.maxauthtries (integer)")
      expect(page.css("#rule_fact option").map(&:text)).not_to include(a_string_starting_with("file:"))
      expect(page.css("input[name^='rule[platforms]']").map { |i| i["value"].to_s }).to eq([ "debian", "13", "", "" ])
    end

    it "previews the hosts whose result would change, with before and after, and writes nothing" do
      before = table_counts
      expect do
        post "/rules/#{rule.id}/preview", params: form_params(expected: "3")
      end.not_to have_enqueued_job

      expect(response).to have_http_status(:ok)
      expect(table_counts).to eq(before)
      expect(page.at_css(".page-head p").text).to eq("Version 2 would replace version 1. Nothing has been saved yet.")
      expect(page.at_css("#preview_summary strong").text).to eq("0 of 3 hosts would change result: .").or eq("No host would change result.")

      post "/rules/#{rule.id}/preview", params: form_params(expected: "5")
      expect(table_counts).to eq(before)
      expect(page.at_css("#preview_summary strong").text).to eq("1 of 3 hosts would change result: 1 fail → pass.")
      expect(page.at_css("#preview_summary p").text).to include("1 host has no config report").and include("No agent is contacted.")
      expect(page.css("#preview_changes thead th").map(&:text)).to eq([ "Host", "Observed", "Now (version 1, at most 4)", "After (version 2, at most 5)" ])
      expect(page.css("#preview_changes tbody tr").map { |row| row.css("td").map { |td| words(td) } }).to eq([ [ "Web A", "5", "Fail", "Pass" ] ])
      expect(page.text).to include("The change on Web A is only because the condition changed")
      expect(page.at_css("form[action='/rules/#{rule.id}'] input[name='_method']")["value"]).to eq("patch")
      expect(page.at_css("form[action='/rules/#{rule.id}'] button").text).to eq("Save as version 2")
      expect(page.at_css("form[action='/rules/#{rule.id}'] input[name='rule[expected]']")["value"]).to eq("5")
    end

    it "lists a host that would drop out to not applicable" do
      post "/rules/#{rule.id}/preview", params: form_params(platforms: { "0" => { "distribution" => "ubuntu", "versions" => "24.04" } })
      expect(page.at_css("#preview_summary strong").text).to eq("2 of 3 hosts would change result: 2 → not applicable.")
      expect(page.css("#preview_changes tbody tr td:last-child").map(&:text)).to eq([ "Not applicable", "Not applicable" ])
    end

    it "previews an unchanged definition as no change and offers no Save" do
      post "/rules/#{rule.id}/preview", params: form_params
      expect(page.at_css("#preview_summary strong").text).to eq("No change: saving makes no new version.")
      expect(page.at_css("form[action='/rules/#{rule.id}']")).to be_nil
      expect(page.at_css("form[action='/rules/#{rule.id}/preview'] button").text).to eq("Back to editing")
    end

    it "goes back to editing with what was typed" do
      post "/rules/#{rule.id}/preview", params: form_params(expected: "7", title: "Typed title").merge(back: "1")
      expect(response).to have_http_status(:ok)
      expect(page.at_css("#rule_condition")["value"]).to eq("7")
      expect(page.at_css("#rule_title")["value"]).to eq("Typed title")
    end

    it "saves a new version through the import's checks, audits it, and re-evaluates every host with no agent contact (AC-2.2)" do
      expect(result(web, "ssh-max-auth-tries")).to eq("fail")
      snapshots = ConfigSnapshot.count
      perform_enqueued_jobs do
        patch "/rules/#{rule.id}", params: form_params(expected: "5")
      end

      expect(response).to redirect_to("/rules/#{rule.id}")
      follow_redirect!
      expect(page.at_css(".flash").text).to include("Saved as version 2").and include("no agent is contacted")
      expect(rule.reload.current_version).to have_attributes(version: 2, condition: { "lte" => 5 })
      expect(rule.versions.first.condition).to eq({ "lte" => 4 }) # version 1 is kept as it was
      expect(result(web, "ssh-max-auth-tries")).to eq("pass")
      expect(CisResult.joins(:cis_rule).find_by!(host: web, cis_rules: { key: "ssh-max-auth-tries" }).cis_rule_version.version).to eq(2)
      expect(ConfigSnapshot.count).to eq(snapshots) # evaluated from the stored snapshots
      expect(ReportRequest.count).to eq(0) # no agent was asked for anything
      entry = AuditEntry.where(action: Audit::Actions::RULE_EDITED).sole
      expect(entry).to have_attributes(actor_type: "operator", actor_id: operator.id, target_type: "CisRule", target_id: rule.id)
      expect(entry.changeset).to eq("condition" => [ { "lte" => 4 }, { "lte" => 5 } ], "version" => [ 1, 2 ], "source" => "dashboard")
    end

    it "refuses to save an edit that is not the one previewed, and previews it instead (review S1 of #130)" do
      before = table_counts
      patch "/rules/#{rule.id}", params: form_params(expected: "5").merge(preview_signature: form_params(expected: "6")[:preview_signature])
      expect(response).to have_http_status(:conflict)
      expect(page.at_css("#unconfirmed")).to be_present
      expect(page.at_css("#preview_changes thead th:last-child").text).to eq("After (version 2, at most 5)")
      expect(table_counts).to eq(before)

      other = enrolled_host(name: "Other").first
      record_inventory(other)
      perform_enqueued_jobs { CisRule.transaction { CisRule.define!(CisRules::Definition.from_h(max_auth.merge("condition" => { "lte" => 2 })), actor: Audit::SYSTEM) } }
      patch "/rules/#{rule.id}", params: form_params(rule, expected: "5").merge(base_version_id: rule.versions.first.id)
      expect(response).to have_http_status(:conflict)
      expect(page.at_css("#rule_problems").text).to include("version 2 was saved meanwhile")
      expect(rule.reload.current_version.condition).to eq({ "lte" => 2 })
    end

    it "saves the edit the preview page's form carries" do
      post "/rules/#{rule.id}/preview", params: form_params(expected: "5").except(:preview_signature)
      fields = form_fields("/rules/#{rule.id}")
      perform_enqueued_jobs { post "/rules/#{rule.id}", params: URI.encode_www_form(fields), headers: { "CONTENT_TYPE" => "application/x-www-form-urlencoded" } }
      expect(response).to redirect_to("/rules/#{rule.id}")
      expect(rule.reload.current_version.condition).to eq({ "lte" => 5 })
    end

    it "makes no new version when nothing changed" do
      patch "/rules/#{rule.id}", params: form_params
      expect(response).to redirect_to("/rules/#{rule.id}")
      expect(flash[:notice]).to eq("No change: saving made no new version.")
      expect(rule.reload.versions.size).to eq(1)
    end

    it "rejects an invalid edit with every problem at the top and beside its field, keeping what was typed" do
      before = table_counts
      post "/rules/#{rule.id}/preview", params: form_params(reference: "", expected: "four", severity: "urgent", platforms: { "0" => { "distribution" => "Debian!", "versions" => "13" } })

      expect(response).to have_http_status(:unprocessable_content)
      expect(table_counts).to eq(before)
      expect(page.at_css("#rule_problems strong").text).to eq("The rule was not saved. 4 problems:")
      lines = page.css("#rule_problems li").map { |li| li.text.squish }
      expect(lines).to contain_exactly("Reference: is required", "Severity: is not one of: [\"low\", \"medium\", \"high\", \"critical\"]",
                                       "Applies to: /applies_to/0/distribution does not match pattern: ^[a-z0-9][a-z0-9._-]{0,63}$", "Condition: /condition/lte is not an integer")
      expect(page.at_css("#rule_problems a[href='#rule_reference']")).to be_present
      expect(page.at_css("#rule_reference")["aria-invalid"]).to eq("true")
      expect(page.at_css("#rule_reference")["aria-describedby"]).to eq("rule_reference_error rule_reference_hint")
      expect(page.at_css("#rule_reference_error").text).to eq("is required")
      expect(page.at_css("#rule_condition_error").text).to eq("/condition/lte: is not an integer")
      expect(page.at_css("#rule_applies_to")["class"]).to include("invalid")
      expect(page.at_css("#rule_condition")["value"]).to eq("four")

      patch "/rules/#{rule.id}", params: form_params(title: "")
      expect(response).to have_http_status(:unprocessable_content)
      expect(table_counts).to eq(before)
    end

    it "edits a composite condition as text, with errors in place and their JSON Pointers" do
      shadow_rule = define(shadow).first
      get "/rules/#{shadow_rule.id}/edit"
      expect(page.at_css("textarea#rule_condition").text.delete_prefix("\n")).to eq("all:\n- mode_at_most: '0640'\n- field: owner\n  eq: root\n- field: group\n  in:\n  - root\n  - shadow\n")
      expect(page.at_css("label[for='rule_condition']").text).to eq("Condition (YAML or JSON)")
      expect(page.at_css("#rule_operator")).to be_nil

      text = "all:\n  - mode_at_most: rw-r-----\n  - field: owner\n    eq: root\n"
      post "/rules/#{shadow_rule.id}/preview", params: form_params(shadow_rule, condition_text: text, reference: "")
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.css("#rule_problems li").map { |li| li.text.squish })
        .to contain_exactly("Reference: is required", "Condition: /condition/all/0/mode_at_most does not match pattern: ^[0-7]{3,4}$")
      expect(page.at_css("#rule_condition_error code").text).to eq("/condition/all/0/mode_at_most")
      expect(page.at_css("textarea#rule_condition").text.delete_prefix("\n")).to eq(text)

      post "/rules/#{shadow_rule.id}/preview", params: form_params(shadow_rule, condition_text: "all: [unclosed")
      expect(page.at_css("#rule_condition_error").text).to start_with("is not plain YAML or JSON")
      post "/rules/#{shadow_rule.id}/preview", params: form_params(shadow_rule, condition_text: "  ")
      expect(page.at_css("#rule_condition_error").text).to eq("is required")
      post "/rules/#{shadow_rule.id}/preview", params: form_params(shadow_rule, condition_text: "a" * (RuleForm::CONDITION_TEXT_MAX + 1))
      expect(page.at_css("#rule_condition_error").text).to eq("is longer than 64 KiB")
      post "/rules/#{shadow_rule.id}/preview", params: form_params(shadow_rule, condition_text: "#{'[' * 30_000}#{']' * 30_000}") # review S2 of #130
      expect(page.at_css("#rule_condition_error").text).to eq("is nested more than 64 levels deep")

      post "/rules/#{shadow_rule.id}/preview", params: form_params(shadow_rule, condition_text: "all:\n  - mode_at_most: '0600'\n")
      expect(response).to have_http_status(:ok)
      expect(page.at_css("#preview_changes thead th:nth-child(4)").text).to eq("After (version 2, mode at most 0600)")
    end

    it "refuses to save over a version someone else saved since the edit began, keeping what was typed" do
      params = form_params(expected: "5")
      perform_enqueued_jobs { CisRule.transaction { CisRule.define!(CisRules::Definition.from_h(max_auth.merge("condition" => { "lte" => 2 })), actor: Audit::SYSTEM) } }

      post "/rules/#{rule.id}/preview", params: params
      expect(response).to have_http_status(:conflict)
      expect(page.at_css("#rule_problems").text).to include("version 2 was saved meanwhile")
      expect(page.at_css("input[name='base_version_id']")["value"]).to eq(rule.reload.current_version_id.to_s)

      patch "/rules/#{rule.id}", params: params
      expect(response).to have_http_status(:conflict)
      expect(rule.reload.current_version).to have_attributes(version: 2, condition: { "lte" => 2 })
      expect(page.at_css("#rule_condition")["value"]).to eq("5")
    end

    it "keeps the operator choices to the fact's type and reads booleans and lists by type" do
      x11 = define(cis_rule_hash(key: "x11-off", fact: "sshd.x11forwarding", condition: { "eq" => false })).first
      get "/rules/#{x11.id}/edit"
      expect(page.css("#rule_operator option").map(&:text)).to eq([ "equal to", "not equal to", "one of", "not one of" ])
      expect(page.at_css("#rule_condition")["type"]).to eq("text")
      expect(page.at_css("#rule_condition")["value"]).to eq("false")
      expect(page.at_css("#rule_condition_hint").text).to start_with("true or false")

      perform_enqueued_jobs { patch "/rules/#{x11.id}", params: form_params(x11, expected: "yes") }
      expect(x11.reload.current_version.condition).to eq({ "eq" => true })

      perform_enqueued_jobs { patch "/rules/#{rule.id}", params: form_params(operator: "in", expected: "3, 4") }
      expect(rule.reload.current_version.condition).to eq({ "in" => [ 3, 4 ] })
      get "/rules/#{rule.id}/edit"
      expect(page.at_css("#rule_condition")["value"]).to eq("3, 4")
      expect(page.at_css("#rule_condition")["type"]).to eq("text")
    end

    it "reads a list fact's entries, refuses a word that is not a boolean, and logs composite and platform changes" do
      services = define(cis_rule_hash(key: "no-telnet", fact: "services.running", condition: { "not_in" => [ "telnet.socket" ] })).first
      get "/rules/#{services.id}/edit"
      expect(page.at_css("#rule_condition_hint").text).to eq("Entries separated by commas, because the fact is a list.")

      x11 = define(cis_rule_hash(key: "x11-off", fact: "sshd.x11forwarding", condition: { "eq" => false })).first
      post "/rules/#{x11.id}/preview", params: form_params(x11, expected: "maybe")
      expect(page.at_css("#rule_condition_error").text).to eq("eq needs a boolean")

      shadow_rule = define(shadow).first
      perform_enqueued_jobs do
        patch "/rules/#{shadow_rule.id}", params: form_params(shadow_rule, condition_text: "all:\n  - mode_at_most: '0600'\n", platforms: { "0" => { "distribution" => "debian", "versions" => "" } })
      end
      get "/rules/#{shadow_rule.id}"
      change = page.css("#rule_log tbody tr").first.css("li").map { |li| li.text.squish }
      expect(change).to eq([ %(Applies to debian 13 debian (every release)), %(Condition {"all":[{"mode_at_most":"0640"},{"eq":"root","field":"owner"},{"in":["root","shadow"],"field":"group"}]} {"all":[{"mode_at_most":"0600"}]}) ])
    end

    it "is not found for a rule that does not exist" do
      get "/rules/0/edit"
      expect(response).to have_http_status(:not_found)
    end
  end

  describe "adding (rule-create.html, rule-create-preview.html)" do
    before { define(root_login) }

    it "shows the form for one single comparison" do
      get "/rules/new"
      expect(response).to have_http_status(:ok)
      expect(page.at_css("h1").text).to eq("Add rule")
      expect(page.at_css("#rule_fact option").text).to eq("Choose a fact…")
      expect(page.at_css("#rule_enabled")["checked"]).to eq("checked")
      expect(page.at_css("#rule_severity option[selected]").text).to eq("Medium")
      expect(page.css("#rule_operator option").map(&:text)).to eq(RuleForm::OPERATORS.values)
      expect(page.at_css("#rule_condition_hint").text).to include("A rule with several conditions can be added by importing a file.")
    end

    it "previews pass, fail, not readable, and the hosts it does not apply to or with no report, and writes nothing" do
      record_config(web, "sshd.ignorerhosts" => { "state" => "unreadable", "value" => nil, "reason" => "Permission denied reading /etc/ssh/sshd_config." })
      record_config(media, "sshd.ignorerhosts" => ok_fact(false))
      extra = enrolled_host(name: "Ubuntu box").first
      record_inventory(extra, os: { "id" => "ubuntu", "version_id" => "24.04", "pretty_name" => "Ubuntu 24.04" })
      record_config(extra)
      before = table_counts

      expect do
        post "/rules/preview", params: new_rule_params(fact: "sshd.ignorerhosts", expected: "yes")
      end.not_to have_enqueued_job

      expect(response).to have_http_status(:ok)
      expect(table_counts).to eq(before)
      expect(page.at_css("h1").text).to eq("Preview: ssh-ignore-rhosts")
      expect(page.at_css("#preview_summary strong").text).to eq("On 2 of 4 hosts: 0 would pass, 1 would fail, 1 not readable.")
      expect(page.at_css("#preview_summary p").text).to eq("Calculated now from each host's latest config snapshot; 1 host has no config report and 1 host is not debian 13, so the rule does not apply to it. No agent is contacted.")
      expect(page.css("#preview_changes thead th").last.text).to eq("Result (version 1, equals true)")
      expect(page.css("#preview_changes tbody tr").map { |row| row.css("td").map { |td| words(td) } })
        .to eq([ [ "Media server", "false", "Fail" ], [ "Web A", "Permission denied reading /etc/ssh/sshd_config.", "Not readable" ] ])
      expect(page.at_css("form[action='/rules'] button").text).to eq("Add rule")
      expect(page.at_css("form[action='/rules/preview'] button").text).to eq("Back to editing")
    end

    it "lists the hosts that would pass" do
      post "/rules/preview", params: new_rule_params(operator: "in", expected: "no, yes")
      expect(page.at_css("#preview_summary strong").text).to eq("On 2 of 3 hosts: 2 would pass, 0 would fail, 0 not readable.")
      expect(page.at_css("#would_pass").text.squish).to eq("Would pass 2 Media server, Web A.")
      expect(page.css("#preview_changes")).to be_empty
    end

    it "previews a disabled rule as checking no host" do
      post "/rules/preview", params: new_rule_params(enabled: "0")
      expect(page.at_css("#preview_summary strong").text).to eq("The rule would be added disabled, so no host is checked against it.")
    end

    it "creates version 1 through the import's checks, re-evaluates every host, and audits it with the operator" do
      perform_enqueued_jobs { post "/rules", params: new_rule_params }

      rule = CisRule.find_by!(key: "ssh-ignore-rhosts")
      expect(response).to redirect_to("/rules/#{rule.id}")
      expect(flash[:notice]).to eq("Added ssh-ignore-rhosts, version 1. Every host is checked against it now; no agent is contacted.")
      expect(rule).to have_attributes(enabled: true)
      expect(rule.current_version).to have_attributes(version: 1, fact: "sshd.permitrootlogin", condition: { "eq" => "no" }, applies_to: [ { "distribution" => "debian", "versions" => [ "13" ] } ])
      expect([ result(web, "ssh-ignore-rhosts"), result(media, "ssh-ignore-rhosts"), result(dns, "ssh-ignore-rhosts") ]).to eq(%w[pass fail not_evaluated])
      entry = AuditEntry.where(action: Audit::Actions::RULE_CREATED, target_id: rule.id).sole
      expect(entry).to have_attributes(actor_type: "operator", actor_id: operator.id)
      expect(entry.changeset).to include("version" => [ nil, 1 ], "enabled" => [ nil, true ], "condition" => [ nil, { "eq" => "no" } ])
      expect(ReportRequest.count).to eq(0)
    end

    it "creates a disabled rule when Enabled is off" do
      post "/rules", params: new_rule_params(enabled: "0", platforms: { "0" => { "distribution" => "debian", "versions" => "" }, "1" => { "distribution" => "ubuntu", "versions" => "24.04, 22.04" } })
      rule = CisRule.find_by!(key: "ssh-ignore-rhosts")
      expect(rule.enabled).to be(false)
      expect(rule.current_version.applies_to).to eq([ { "distribution" => "debian" }, { "distribution" => "ubuntu", "versions" => [ "24.04", "22.04" ] } ])
      expect(flash[:notice]).to include("It is disabled")
    end

    it "refuses a key already in use, and an invalid rule, writing nothing" do
      before = table_counts
      post "/rules/preview", params: new_rule_params(key: "ssh-root-login-off")
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#rule_key_error").text).to eq("ssh-root-login-off is already used by another rule; a key is never reused")
      expect(page.at_css("#rule_problems strong").text).to eq("The rule was not added. 1 problem:")

      post "/rules", params: new_rule_params(key: "Bad Key", fact: "nope.fact", title: "")
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.css("#rule_problems li").map { |li| li.text.squish }).to include("Key: does not match pattern: ^[a-z0-9][a-z0-9-]{0,63}$", "Title: is required")
      expect(table_counts).to eq(before)

      post "/rules/preview", params: new_rule_params(fact: "nope.fact")
      expect(page.at_css("#rule_fact_error").text).to eq("nope.fact is not in the fact manifest")
      post "/rules/preview", params: { rule: { "key" => "x" } }
      expect(page.at_css("#rule_applies_to_error").text).to eq("is required")
    end

    it "refuses a key someone else added between the check and the save" do
      params = new_rule_params
      allow(CisRule).to receive(:exists?).and_call_original
      allow(CisRule).to receive(:exists?).with(key: "ssh-ignore-rhosts").and_return(false, true)
      post "/rules", params: params
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#rule_key_error").text).to include("was added by someone else since your preview")
      expect(CisRule.where(key: "ssh-ignore-rhosts")).to be_empty
    end

    it "saves the rule the preview page's form carries, signed by the preview" do
      post "/rules/preview", params: new_rule_params.except(:preview_signature)
      fields = form_fields("/rules")
      expect(fields.map(&:first)).to include("preview_signature", "rule[key]", "rule[expected]")
      perform_enqueued_jobs { post "/rules", params: URI.encode_www_form(fields), headers: { "CONTENT_TYPE" => "application/x-www-form-urlencoded" } }
      expect(response).to redirect_to("/rules/#{CisRule.find_by!(key: 'ssh-ignore-rhosts').id}")
    end

    it "refuses to save a rule that is not the one previewed, or whose preview expired, and previews it instead (review S1 of #130)" do
      before = table_counts
      post "/rules", params: new_rule_params.merge(preview_signature: new_rule_params(expected: "yes")[:preview_signature]) # an edited hidden field
      expect(response).to have_http_status(:conflict)
      expect(page.at_css("#unconfirmed strong").text).to eq("Nothing was saved: this rule is not the one that was previewed, or its preview expired.")
      expect(page.at_css("form[action='/rules'] input[name='rule[expected]']")["value"]).to eq("no")
      expect(table_counts).to eq(before)

      post "/rules", params: new_rule_params.except(:preview_signature)
      expect(response).to have_http_status(:conflict)
      params = new_rule_params
      travel(RulePreviewSignature::TTL + 1.second) { post "/rules", params: }
      expect(response).to have_http_status(:conflict)
      expect(table_counts).to eq(before)

      post "/rules", params: { rule: params[:rule], preview_signature: page.at_css("form[action='/rules'] input[name='preview_signature']")["value"] }
      expect(response).to have_http_status(:redirect) # the new preview's signature saves it
    end

    it "goes back to editing with what was typed" do
      post "/rules/preview", params: new_rule_params(title: "Kept").merge(back: "1")
      expect(response).to have_http_status(:ok)
      expect(page.at_css("#rule_title")["value"]).to eq("Kept")
      expect(page.at_css("#rule_problems")).to be_nil
    end
  end

  describe "enabling and disabling (dialogs.html)" do
    let!(:rule) { define(max_auth).first }

    it "confirms disabling with its effect in numbers, then disables, audits, and re-evaluates" do
      get "/rules/#{rule.id}/disable"
      expect(response).to have_http_status(:ok)
      expect(page.at_css(".dialog h2").text).to eq("Disable ssh-max-auth-tries?")
      expect(page.at_css(".dialog p").text.squish).to include(%(Its result on all 3 hosts becomes "Not evaluated")).and include("Fleet failure counts fall by 1 (Web A).")
      expect(page.at_css(".dialog form")["action"]).to eq("/rules/#{rule.id}/disable")

      perform_enqueued_jobs { post "/rules/#{rule.id}/disable" }
      expect(response).to redirect_to("/rules/#{rule.id}")
      expect(flash[:notice]).to eq("Disabled ssh-max-auth-tries. Its results become not evaluated; its history and versions are kept.")
      expect(rule.reload.enabled).to be(false)
      expect(result(web, "ssh-max-auth-tries")).to eq("not_evaluated")
      expect(AuditEntry.where(action: Audit::Actions::RULE_DISABLED).sole).to have_attributes(actor_type: "operator", actor_id: operator.id, changeset: { "enabled" => [ true, false ], "source" => "dashboard" })

      get "/rules/#{rule.id}/disable"
      expect(page.at_css(".dialog").text).to include("already disabled")
      post "/rules/#{rule.id}/disable"
      expect(flash[:notice]).to eq("ssh-max-auth-tries was already disabled.")

      get "/rules/#{rule.id}/enable"
      expect(page.at_css(".dialog h2").text).to eq("Enable ssh-max-auth-tries?")
      expect(page.at_css(".dialog p").text).to include("No agent is contacted.")
      perform_enqueued_jobs { post "/rules/#{rule.id}/enable" }
      expect(flash[:notice]).to start_with("Enabled ssh-max-auth-tries.")
      expect(result(web, "ssh-max-auth-tries")).to eq("fail")
      get "/rules/#{rule.id}/enable"
      expect(page.at_css(".dialog").text).to include("already enabled")
    end

    it "says when the rule fails nowhere, and lists at most five failing hosts" do
      6.times do |i|
        host = enrolled_host(name: "Host #{i}").first
        record_inventory(host)
        record_config(host, "sshd.maxauthtries" => ok_fact(9))
      end
      perform_enqueued_jobs { CisEvaluation.evaluate!(Host.pluck(:id)) }
      get "/rules/#{rule.id}/disable"
      expect(page.at_css(".dialog p").text.squish).to include("Fleet failure counts fall by 7 (Host 0, Host 1, Host 2, Host 3, Host 4, and 2 more).")

      ok = define(root_login.merge("key" => "nothing-fails", "condition" => { "ne" => "maybe" })).first
      get "/rules/#{ok.id}/disable"
      expect(page.at_css(".dialog p").text).to include("It fails on no host now")
    end

    it "accepts the change only as a CSRF-protected POST" do
      ActionController::Base.allow_forgery_protection = true
      post "/rules/#{rule.id}/disable"
      expect(response).to have_http_status(:unprocessable_content).or have_http_status(:forbidden)
      expect(rule.reload.enabled).to be(true)
    ensure
      ActionController::Base.allow_forgery_protection = false
    end
  end
end
