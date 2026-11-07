require "rails_helper"

# Importing a rules file from the dashboard (P2-D06, FR-2.2; approved mockups rules-import.html, rules-import-preview.html,
# rules-import-errors.html; owner decision Q13): the file is checked as a whole, previewed without writing anything,
# kept for 15 minutes for its operator only, and applied exactly as previewed, or refused if the rules changed.
RSpec.describe "Rule imports", :signed_in, type: :request do
  include ActiveJob::TestHelper

  let(:max_auth) { cis_rule_hash(key: "ssh-max-auth-tries", title: "SSH limits authentication attempts", severity: "medium", fact: "sshd.maxauthtries", condition: { "lte" => 4 }) }
  let(:root_login) { cis_rule_hash } # ssh-root-login-off
  let(:ciphers) { cis_rule_hash(key: "ssh-strong-ciphers", title: "SSH offers only modern ciphers", fact: "sshd.ciphers", condition: { "matches" => "[a-z0-9@.-]+" }) }
  let(:banner) { cis_rule_hash(key: "login-banner-set", title: "A login banner is set", fact: "sshd.banner", condition: { "ne" => "none" }) }

  let!(:host) { enrolled_host(name: "Web A").first }

  before do
    record_inventory(host)
    record_config(host, "sshd.maxauthtries" => ok_fact(4))
    perform_enqueued_jobs { define_cis_rules(max_auth, root_login, ciphers, banner) }
    CisRule.transaction { CisRule.find_by!(key: "ssh-strong-ciphers").disable!(actor: Audit::SYSTEM) }
  end

  # JSON, which is YAML too (to_yaml would write aliases for shared values, which the import refuses).
  def rules_file(*rules) = JSON.pretty_generate({ "format_version" => 1, "rules" => rules })

  def words(node) = node.xpath(".//text()").map(&:text).join(" ").squish

  # The file of the mockup: one rule added, one changed, one enabled, one unchanged, and login-banner-set not listed.
  def mockup_file
    rules_file(cis_rule_hash(key: "ssh-ignore-rhosts", title: "SSH ignores per-user trust files", fact: "sshd.ignorerhosts", condition: { "eq" => true }),
               max_auth.merge("condition" => { "lte" => 3 }, "severity" => "high"), ciphers.merge("enabled" => true), root_login)
  end

  def upload(text, filename: "rules-2026-11.yml", disable_missing: false)
    file = Rack::Test::UploadedFile.new(StringIO.new(text), "application/yaml", original_filename: filename)
    post "/rules/import", params: { file:, disable_missing: (disable_missing ? "1" : "0") }
  end

  def preview = RuleImportPreview.sole

  def written = [ CisRule.count, CisRuleVersion.count, AuditEntry.count, CisRule.enabled.count ]

  def section(id) = page.at_css(id)

  it "shows the upload form" do
    get "/rules/import"
    expect(response).to have_http_status(:ok)
    expect(page.at_css("h1").text).to eq("Import rules file")
    expect(page.at_css("#import_form")["enctype"]).to eq("multipart/form-data")
    expect(page.at_css("#file")["accept"]).to eq(".yml,.yaml,.json")
    expect(page.at_css("#disable_missing")["checked"]).to be_nil
    expect(page.at_css("nav[aria-label='Main'] a[aria-current='page']").text).to eq("Rules")
  end

  it "previews adds, changes, enables, unchanged, and rules not listed, before anything is written" do
    before = written
    expect { upload(mockup_file) }.not_to have_enqueued_job

    expect(response).to redirect_to("/rules/import/#{preview.token}")
    expect(written).to eq(before)
    expect(preview).to have_attributes(operator:, filename: "rules-2026-11.yml", body: mockup_file, sha256: Digest::SHA256.hexdigest(mockup_file), disable_missing: false,
                                       rules_digest: CisRule.state_digest)
    expect(preview.expires_at).to be_within(5.seconds).of(15.minutes.from_now)

    follow_redirect!
    expect(response).to have_http_status(:ok)
    expect(page.at_css("h1").text).to eq("Preview: rules-2026-11.yml")
    expect(page.at_css(".page-head p").text).to include("format version 1, 4 rules. Checksum #{preview.sha256.first(16).upcase}. Nothing has been written yet.")
    expect(page.at_css("#import_summary strong").text).to eq("The file is valid: 1 to add, 1 to change, 1 to enable, 1 unchanged.")
    expect(page.at_css("#import_summary p").text).to include("After, 5 rules in total.").and include("No agent is contacted.")
    expect(section("#import_added").css("tbody tr").map { |row| row.css("td").map { |td| words(td) } })
      .to eq([ [ "+ Add ssh-ignore-rhosts SSH ignores per-user trust files · CIS Debian 13 5.1.20", "High", "debian 13", "sshd.ignorerhosts equals true", "Yes" ] ])
    expect(section("#import_changed").css("tbody tr").map { |row| row.css("td").map { |td| words(td) } })
      .to eq([ [ "~ Change ssh-max-auth-tries", "Severity medium high Condition lte: 4 lte: 3", "1 → 2" ] ])
    expect(section("#import_flags").text.squish).to include("~ Enable ssh-strong-ciphers").and include("Enabled no yes (the file says enabled: true). No new version.")
    expect(section("#import_unchanged").text.squish).to include("Show the 1 rule the file lists unchanged").and include("ssh-root-login-off")
    expect(section("#import_not_listed").text.squish).to include("These 1 rule are left as they are").or include("These 1 rules")
    expect(section("#import_not_listed").text).to include("login-banner-set")
    expect(page.at_css("form[action='/rules/import/#{preview.token}/apply'] button").text).to eq("Apply import")
    expect(written).to eq(before)
    expect(response.body).not_to match(/CIS compliant/i)
  end

  it "applies exactly the previewed file with the operator as actor, re-evaluates, and discards the file" do
    upload(mockup_file)
    token = preview.token
    perform_enqueued_jobs { post "/rules/import/#{token}/apply" }

    expect(response).to redirect_to("/rules")
    expect(flash[:notice]).to eq("Imported rules-2026-11.yml: 1 added, 1 changed, 1 enabled, 0 disabled, and 1 unchanged. Every host is checked against the added and changed rules now; no agent is contacted.")
    expect(RuleImportPreview.count).to eq(0)
    expect(CisRule.find_by!(key: "ssh-max-auth-tries").current_version).to have_attributes(version: 2, condition: { "lte" => 3 })
    expect(CisRule.find_by!(key: "ssh-strong-ciphers").enabled).to be(true)
    expect(CisRule.find_by!(key: "login-banner-set").enabled).to be(true) # not listed, option off: left as it is
    entries = AuditEntry.where(action: Audit::Actions.constants.map { |c| Audit::Actions.const_get(c) }.grep(/\Arule\./), actor_type: "operator")
    expect(entries.pluck(:action, :actor_id)).to contain_exactly([ "rule.created", operator.id ], [ "rule.edited", operator.id ], [ "rule.enabled", operator.id ])
    expect(entries.map { |entry| entry.changeset["source"] }.uniq).to eq([ "file_upload" ])
    expect(CisResult.joins(:cis_rule).find_by!(host:, cis_rules: { key: "ssh-max-auth-tries" }).result).to eq("fail") # 4 > 3, from the stored snapshot
    expect(ReportRequest.count).to eq(0)

    post "/rules/import/#{token}/apply" # applied once only
    expect(response).to redirect_to("/rules/import")
    expect(flash[:alert]).to include("expired, was already applied or cancelled")
  end

  it "disables the rules the file does not list when asked, and says so in the preview" do
    upload(mockup_file, disable_missing: true)
    follow_redirect!
    expect(page.at_css("#import_summary strong").text).to eq("The file is valid: 1 to add, 1 to change, 1 to enable, 1 to disable, 1 unchanged.")
    expect(section("#import_flags").text.squish).to include("− Disable login-banner-set")
    expect(section("#import_not_listed").text).to include("The enabled ones are disabled above")

    perform_enqueued_jobs { post "/rules/import/#{preview.token}/apply" }
    expect(CisRule.find_by!(key: "login-banner-set").enabled).to be(false)
    expect(flash[:notice]).to include("1 disabled")
  end

  it "says when a file changes nothing, and offers no Apply" do
    CisRule.transaction { CisRule.find_by!(key: "ssh-strong-ciphers").enable!(actor: Audit::SYSTEM) }
    upload(rules_file(max_auth, root_login, ciphers, banner.merge("enabled" => true)), disable_missing: true)
    follow_redirect!
    expect(page.at_css("#import_summary").text).to include("4 unchanged").and include("applying it would change nothing")
    expect(page.at_css("form[action$='/apply']")).to be_nil
    expect(section("#import_not_listed").text).to include("None: the file lists every rule.")
  end

  it "lists already disabled rules the file does not list as left alone when disabling missing rules" do
    upload(rules_file(max_auth, root_login, banner), disable_missing: true)
    follow_redirect!
    expect(section("#import_not_listed").text.squish).to include("Already disabled, left as they are: ssh-strong-ciphers.")
    expect(section("#import_added")).to be_nil
    expect(page.text).to include("None.")
  end

  it "disables a listed rule the file says is off" do
    upload(rules_file(max_auth.merge("enabled" => false)))
    follow_redirect!
    expect(section("#import_flags").text.squish).to include("− Disable ssh-max-auth-tries").and include("Enabled yes no")
    expect(page.at_css("#import_summary strong").text).to eq("The file is valid: 1 to disable, 0 unchanged.")
  end

  it "lists every problem with its JSON Pointer and writes and keeps nothing for a file with any problem" do
    before = written
    bad = rules_file(max_auth.merge("severity" => "urgent"), root_login, root_login, cis_rule_hash(key: "nope", fact: "nope.fact"),
                     max_auth.merge("key" => "matches-int", "condition" => { "matches" => "x" }), root_login.merge("key" => "yaml-no", "condition" => { "eq" => false }))
    upload(bad, filename: "bad.yml")

    expect(response).to have_http_status(:unprocessable_content)
    expect(written).to eq(before)
    expect(RuleImportPreview.count).to eq(0)
    expect(page.at_css("#import_problems_summary strong").text.squish).to eq("Nothing was imported. bad.yml has 5 problems.")
    rows = page.css("#import_problems tbody tr").map { |row| row.css("td").map { |td| td.text.squish } }
    expect(rows).to include([ "/rules/0/severity", %(is not one of: ["low", "medium", "high", "critical"]) ], [ "/rules/2/key", "ssh-root-login-off is already used by /rules/1" ],
                            [ "/rules/3/fact", "nope.fact is not in the fact manifest" ],
                            [ "/rules/4/condition", "matches works only on a string or list fact, and sshd.maxauthtries is integer" ])
    expect(rows.last.last).to include("eq needs a string (quote yes, no, on, and off in YAML")
    expect(page.at_css("#import_form")).to be_present

    upload("format_version: 1\nrules: [\n", filename: "broken.yml")
    expect(page.css("#import_problems tbody tr td").first.text).to eq("/")
    expect(page.css("#import_problems tbody tr td").last.text).to start_with("is not a plain YAML or JSON document")
    expect(written).to eq(before)
  end

  it "asks for a file when none is chosen, and refuses an upload too large or without a length" do
    post "/rules/import", params: { disable_missing: "1" }
    expect(response).to have_http_status(:unprocessable_content)
    expect(page.at_css("#file_error").text).to eq("Choose a YAML or JSON rules file to check.")
    expect(page.at_css("#file")["aria-invalid"]).to eq("true")

    upload("#{"x" * (CisRules::RuleFile::MAX_BYTES + 1)}\n")
    expect(response).to have_http_status(:unprocessable_content)
    expect(page.css("#import_problems tbody tr td").map(&:text)).to eq([ "/", "is larger than 1 MiB" ])

    post "/rules/import", headers: { "CONTENT_LENGTH" => (RuleImportsController::MAX_UPLOAD_BYTES + 1).to_s }
    expect(response).to have_http_status(:content_too_large)
    post "/rules/import", headers: { "CONTENT_LENGTH" => "chunked" }
    expect(response).to have_http_status(:length_required)
    expect(RuleImportPreview.count).to eq(0)
  end

  it "keeps one preview per operator: a later upload replaces it, and the earlier tab cannot apply the later file" do
    upload(rules_file(max_auth.merge("condition" => { "lte" => 3 })))
    first = preview.token
    upload(rules_file(max_auth.merge("condition" => { "lte" => 2 })), filename: "second.yml")
    expect(RuleImportPreview.count).to eq(1)

    post "/rules/import/#{first}/apply"
    expect(response).to redirect_to("/rules/import")
    expect(CisRule.find_by!(key: "ssh-max-auth-tries").current_version.version).to eq(1)
    expect(preview.filename).to eq("second.yml")
  end

  it "is tied to the operator who uploaded it" do
    upload(mockup_file)
    token = preview.token
    other = create(:operator, email: "other@example.com")
    RuleImportPreview.where(token:).update_all(operator_id: other.id)

    get "/rules/import/#{token}"
    expect(response).to redirect_to("/rules/import")
    post "/rules/import/#{token}/apply"
    expect(response).to redirect_to("/rules/import")
    delete "/rules/import/#{token}"
    expect(RuleImportPreview.where(token:)).to exist
    expect(CisRule.where(key: "ssh-ignore-rhosts")).to be_empty
  end

  it "refuses an expired preview, which the prune job then deletes" do
    upload(mockup_file)
    token = preview.token
    travel 15.minutes + 1.second do
      get "/rules/import/#{token}"
      expect(response).to redirect_to("/rules/import")
      post "/rules/import/#{token}/apply"
      expect(CisRule.where(key: "ssh-ignore-rhosts")).to be_empty
      expect(RuleImportPreviewPruneJob.perform_now).to eq(1)
    end
    expect(RuleImportPreview.count).to eq(0)
  end

  it "cancels, discarding the file" do
    upload(mockup_file)
    delete "/rules/import/#{preview.token}"
    expect(response).to redirect_to("/rules/import")
    expect(flash[:notice]).to eq("Import cancelled. The uploaded file was discarded; nothing was imported.")
    expect(RuleImportPreview.count).to eq(0)
  end

  it "applies nothing when the rules changed since the preview, and previews the same file again against them" do
    upload(mockup_file)
    token = preview.token
    perform_enqueued_jobs { CisRule.transaction { CisRule.define!(CisRules::Definition.from_h(max_auth.merge("condition" => { "lte" => 5 })), actor: Audit::SYSTEM) } }
    before = written

    post "/rules/import/#{token}/apply"
    expect(response).to have_http_status(:conflict)
    expect(written).to eq(before)
    expect(page.at_css("#rules_changed strong").text).to eq("Nothing was applied: the rules changed since you previewed this file.")
    expect(section("#import_changed").text.squish).to include("lte: 5 lte: 3").and include("2 → 3")
    expect(preview.reload.rules_digest).to eq(CisRule.state_digest)

    perform_enqueued_jobs { post "/rules/import/#{token}/apply" }
    expect(response).to redirect_to("/rules")
    expect(CisRule.find_by!(key: "ssh-max-auth-tries").current_version).to have_attributes(version: 3, condition: { "lte" => 3 })
  end

  it "refuses at apply a file the checks no longer accept, and lists why" do
    upload(mockup_file)
    allow(CisRules::Import).to receive(:call).and_return(CisRules::Import::Result.new(errors: [ "/rules/0/fact: sshd.ignorerhosts is not in the fact manifest" ],
                                                                                       created: [], versioned: [], unchanged: [], enabled: [], disabled: []))
    post "/rules/import/#{preview.token}/apply"
    expect(response).to have_http_status(:unprocessable_content)
    expect(page.css("#import_problems tbody tr td").map(&:text)).to eq([ "/rules/0/fact", "sshd.ignorerhosts is not in the fact manifest" ])
    expect(RuleImportPreview.count).to eq(0)
  end

  it "shows the file's name as text" do
    upload(mockup_file, filename: "règles <b>2026<i>.yml")
    follow_redirect!
    expect(page.at_css("h1").text).to eq("Preview: règles <b>2026<i>.yml")
    expect(page.at_css("h1 b")).to be_nil
  end

  describe RuleImportPreview do
    it "keeps a file name as valid text that fits its column, without NUL" do
      expect(described_class.display_filename("#{'ä' * 300}.yml")).to eq("ä" * 255)
      expect(described_class.display_filename("a\u0000b\xFF.yml".b)).to eq("ab?.yml")
      expect(described_class.display_filename(" ")).to eq("rules file")
      expect(described_class.display_filename(nil)).to eq("rules file")
    end
  end
end
