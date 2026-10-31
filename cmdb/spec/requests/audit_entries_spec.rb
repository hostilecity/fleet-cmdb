require "rails_helper"

# The fleet-wide audit log page (FR-S.3, FR-S.4, NFR-1, P1-AUDIT-PAGE).
RSpec.describe "Audit log", type: :request do
  hostile = %(<script>alert("x")</script><img src=x onerror=alert(1)>).freeze
  base = Time.utc(2026, 10, 14, 10, 0, 0)
  let(:hostile) { hostile }

  let(:operator) { Operator.find_by!(email: "operator@example.com") }

  # Signing in writes "Operator allowed" and "Operator signed in", and factories write "Host created", all at
  # the database clock. The log is append-only, so examples filter or pick the entries they check.
  before { sign_in_operator }

  def page = Nokogiri::HTML(response.body)

  def rows = page.css("table.audit tbody tr")

  def row_ids = rows.map { |tr| tr["id"].delete_prefix("audit_entry_").to_i }

  def cells(row) = row.css("td").map { |td| td.text.squish }

  def row(entry) = page.at_css("#audit_entry_#{entry.id}")

  def link(rel) = page.at_css(%(.pager a[rel="#{rel}"]))&.[]("href")

  def query(href) = Rack::Utils.parse_query(URI(href).query)

  # An entry at a chosen time. The app writes entries only through Audit.record, which takes the time
  # from the database clock; specs need fixed times.
  define_method(:base) { base }

  def entry(action: Audit::Actions::HOST_EDITED, at: base, actor: nil, target: nil, changes: {}, request_id: nil)
    actor_type, actor_id = actor ? Audit.actor_columns(actor) : [ "system", nil ]
    AuditEntry.create!(actor_type:, actor_id:, action:, target_type: target&.class&.name, target_id: target&.id,
                       changeset: changes, request_id:, occurred_at: at)
  end

  describe "access" do
    it "redirects anonymous requests to sign-in and returns there afterwards" do
      delete "/sign_out"
      get "/audit", params: { action: "host.edited" }
      expect(response).to redirect_to(sign_in_path)
      sign_in_with_google
      expect(response).to redirect_to("/audit?action=host.edited")
    end

    it "is served on the dashboard hostname only" do
      host! agent_host
      get "/audit"
      expect(response).to have_http_status(:not_found)
    end

    it "is in the main navigation, marked as the current page" do
      get "/audit"
      expect(response).to have_http_status(:ok)
      expect(page.at_css('nav[aria-label="Main"] a[aria-current="page"]').text).to eq("Audit log")
      expect(page.at_css("title").text).to eq("Audit log · Fleet CMDB")
    end
  end

  describe "read-only" do
    it "has no route to create, edit, or delete an entry" do
      routes = Rails.application.routes.routes.select { |r| r.defaults[:controller] == "audit_entries" }
      expect(routes.map { |r| [ r.verb, r.defaults[:action] ] }).to eq([ %w[GET index] ])
      %i[post put patch delete].each do |verb|
        public_send(verb, "/audit")
        expect(response).to have_http_status(:not_found), "#{verb.upcase} /audit"
        public_send(verb, "/audit/#{AuditEntry.last.id}")
        expect(response).to have_http_status(:not_found), "#{verb.upcase} /audit/:id"
      end
    end

    it "offers no control that changes an entry: one GET form, and links only to hosts and other views" do
      host = create(:host, name: "Media server")
      entry(target: host, changes: { "name" => %w[Old New] })
      get "/audit"
      forms = page.css("main form")
      expect(forms.size).to eq(1)
      expect(forms.first["method"]).to eq("get")
      expect(forms.first.css("input[name=authenticity_token], input[name=_method]")).to be_empty
      expect(page.css("main button").map(&:text)).to eq([ "Apply" ])
      expect(page.css("table.audit a").map { |a| a["href"] }.uniq).to eq([ "/hosts/#{host.id}" ])
      expect(page.css("table.audit input, table.audit button")).to be_empty
    end

    it "never writes to the audit log" do
      entry
      writes = []
      counter = ->(*, payload) { writes << payload[:sql] if payload[:sql].match?(/\A\s*(INSERT|UPDATE|DELETE)/i) && payload[:sql].include?("audit_entries") }
      ActiveSupport::Notifications.subscribed(counter, "sql.active_record") do
        get "/audit"
        get "/audit", params: { target: "vm", before: "2026-10-14T10:00:00.000000Z,1" }
      end
      expect(writes).to eq([])
    end
  end

  describe "entries" do
    it "lists entries newest first with time, actor, action, target, and before and after values (FR-S.3)" do
      host = create(:host, name: "Backup target", hostname: "vm-02.example.lan")
      old = entry(at: base - 1.day, actor: operator, target: host, changes: { "description" => [ "Nightly restic target.", "Weekly" ], "tags" => [ %w[storage], %w[storage backup] ] })
      new = entry(action: Audit::Actions::HOST_FIRST_INVENTORY, at: base, actor: host, target: host, changes: { "stable_hash" => [ nil, "a1b2" ] }, request_id: "4f1c2d3e-0000-4000-8000-00000000abcd")
      get "/audit", params: { target: "Backup" }
      created = AuditEntry.find_by!(action: Audit::Actions::HOST_CREATED, target_id: host.id)
      expect(row_ids).to eq([ created.id, new.id, old.id ]) # "Host created" was written at the database clock, after base
      expect(cells(row(new))).to eq([ "2026-10-14 10:00:00 4f1c2d3e-0000-4000-8000-00000000abcd", "Backup target Host", "First inventory received", "Backup target", "Inventory fingerprint a1b2" ])
      expect(cells(row(old)).first(4)).to eq([ "2026-10-13 10:00:00", "operator@example.com Operator", "Host edited", "Backup target" ])
      expect(row(old).css(".change-list li").map { |li| li.text.squish }).to eq([ "Tags storage storage, backup", "Description Nightly restic target. Weekly" ])
      expect(row(old).css("del").map(&:text)).to eq([ "storage", "Nightly restic target." ])
      expect(row(old).css("ins").map(&:text)).to eq([ "storage, backup", "Weekly" ])
      expect(row(new).at_css("time")["datetime"]).to eq("2026-10-14T10:00:00.000000Z")
    end

    it "shows each kind of actor and target" do
      retired = create(:host, :retired, name: "Old web")
      Setting.update_liveness_thresholds!(online_minutes: 5, stale_minutes: 15, actor: operator)
      online = Setting.find_by!(key: "liveness.online_threshold_minutes")
      setting_entry = AuditEntry.find_by!(action: Audit::Actions::SETTING_CHANGED, target_id: online.id)
      removed = AuditEntry.where(action: Audit::Actions::OPERATOR_ALLOWED).last
      OperatorAllowlistEntry.allow!("lee@example.com", actor: Audit::SYSTEM)
      OperatorAllowlistEntry.disallow!("lee@example.com", actor: Audit::SYSTEM)
      get "/audit"
      by_id = rows.to_h { |tr| [ tr["id"], cells(tr) ] }
      expect(by_id["audit_entry_#{setting_entry.id}"][1..]).to eq([ "operator@example.com Operator", "Setting changed", "Online threshold liveness.online_threshold_minutes", "Minutes 3 5" ])
      retire = AuditEntry.find_by!(action: Audit::Actions::HOST_RETIRED, target_id: retired.id)
      expect(by_id["audit_entry_#{retire.id}"][1..]).to eq([ "System", "Retired", "Old web Retired host", "Enrollment state pending retired" ])
      expect(page.at_css("#audit_entry_#{retire.id} a")["href"]).to eq("/hosts/#{retired.id}")
      sign_in = AuditEntry.where(action: Audit::Actions::OPERATOR_SIGNED_IN).last
      expect(by_id["audit_entry_#{sign_in.id}"][1..]).to eq([ "operator@example.com Operator", "Operator signed in", "operator@example.com", "No values recorded" ])
      gone = AuditEntry.where(action: Audit::Actions::OPERATOR_DISALLOWED).last
      expect(by_id["audit_entry_#{gone.id}"][1..]).to eq([ "System", "Operator removed", "lee@example.com", "Email lee@example.com none" ])
      expect(by_id["audit_entry_#{removed.id}"][2..3]).to eq([ "Operator allowed", "operator@example.com" ])
    end

    it "shows a value the server filtered as recorded, and unknown fields by their recorded name" do
      host = create(:host)
      entry(target: host, changes: { "recovery_hint" => Audit::Scrubber::FILTERED, "kernel_flags" => [ "a", "b" ] })
      get "/audit", params: { target: host.hostname }
      edited = AuditEntry.find_by!(action: Audit::Actions::HOST_EDITED)
      expect(row(edited).css(".change-list li").map { |li| li.text.squish }).to eq([ "kernel_flags a b", "recovery_hint [FILTERED]" ])
      expect(row(edited).css(".change-list .key.mono").size).to eq(2)
      expect(row(edited).css(".change-list span.mono:not(.key)").map(&:text)).to eq([ "[FILTERED]" ])
    end

    it "renders markup in recorded values as text (NFR-1)" do
      host = create(:host, name: hostile)
      entry(actor: operator, target: host, changes: { "description" => [ hostile, "<b>Do not reboot</b> & scrub" ], hostile => [ nil, hostile ] },
            request_id: "<script>alert(2)</script>")
      get "/audit", params: { target: "script", actor: hostile }
      get "/audit", params: { target: "script" }
      table = page.at_css("table.audit")
      expect(table.css("script, img, b")).to be_empty
      expect(table.text).to include(hostile, "<b>Do not reboot</b> & scrub", "<script>alert(2)</script>")
      expect(response.body).to include("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;")
      expect(page.css("script:not([type])").map(&:text).grep(/alert/)).to eq([])
      get "/audit", params: { from: "<script>alert(3)</script>" }
      expect(page.at_css("#from_error").text).to include("<script>alert(3")
      expect(page.css("script:not([type])").map(&:text).grep(/alert/)).to eq([])
    end

    it "shows every action by its label, grouped in the action filter" do
      get "/audit"
      groups = page.css("select[name=action] optgroup").to_h { |g| [ g["label"], g.css("option").map { |o| o["value"] } ] }
      expect(groups.keys).to eq(%w[Hosts Onboarding Operators Settings])
      expect(groups.values.flatten).to match_array(Audit::Actions::ALL)
      expect(AuditEntriesHelper::AUDIT_LABELS.keys).to match_array(Audit::Actions::ALL)
    end

    it "runs a fixed number of queries whatever is on the page" do
      hosts = create_list(:host, 2)
      entry(actor: hosts.first, target: hosts.last)
      get "/audit"
      few = count_queries { get "/audit" }
      more = create_list(:host, 10)
      more.each_with_index do |host, i|
        entry(actor: host, target: host, at: base + i)
        entry(actor: operator, target: host, at: base + i)
      end
      started = start_onboarding(hostname: "vm-30.example.lan")
      Onboarding::Reject.call(request: started.record, operator:)
      Setting.update_liveness_thresholds!(online_minutes: 4, stale_minutes: 15, actor: operator)
      many = count_queries { get "/audit" }
      expect(rows.size).to be > 25
      expect(many).to be <= few + 4 # each kind of target adds at most one lookup: requests, links, settings, allowlist
      many_more = count_queries { 5.times { |i| entry(actor: operator, target: more.first, at: base + 100 + i) } && get("/audit") }
      expect(many_more).to eq(many + 5) # the five inserts, and no more lookups for more entries
    end
  end

  describe "request id (owner answer 6)" do
    it "shows each entry's request id, so it can be matched to a server log line" do
      host = create(:host, name: "Media server")
      get "/hosts/#{host.id}/edit"
      patch "/hosts/#{host.id}", params: { host: { name: "Media server 2", hostname: host.hostname, tags: "", description: "", notes: "" } }
      edited = AuditEntry.where(action: Audit::Actions::HOST_EDITED).last
      expect(edited.request_id).to be_present
      get "/audit", params: { action: "host.edited" }
      expect(rows.first.at_css(".request-id").text).to eq(edited.request_id)
    end
  end

  describe "filters" do
    let!(:media) { create(:host, name: "Media server", hostname: "vm-01.example.lan") }
    let!(:backup) { create(:host, :retired, name: "Backup target", hostname: "vm-02.example.lan") }
    let!(:other) { Operator.create!(email: "sam@example.com", google_uid: "3000000000001") }
    let!(:e1) { entry(at: base - 3.days, actor: operator, target: media, changes: { "name" => %w[A B] }) }
    let!(:e2) { entry(action: Audit::Actions::HOST_RETIRED, at: base - 2.days, actor: other, target: backup) }
    let!(:e3) { entry(action: Audit::Actions::HOST_FIRST_INVENTORY, at: base - 1.day, actor: media, target: media) }
    let!(:e4) { entry(action: Audit::Actions::HOST_CREATED, at: base, target: backup) }
    let!(:e5) { entry(action: Audit::Actions::OPERATOR_SIGNED_IN, at: base + 1.hour, actor: other, target: other) }

    def ids_for(params)
      get "/audit", params: params
      expect(response).to have_http_status(:ok)
      row_ids & [ e1, e2, e3, e4, e5 ].map(&:id)
    end

    it "filters by actor type" do
      expect(ids_for(actor_type: "operator")).to eq([ e5, e2, e1 ].map(&:id))
      expect(ids_for(actor_type: "host")).to eq([ e3.id ])
      expect(ids_for(actor_type: "system")).to eq([ e4.id ])
      expect(row_ids).not_to include(e1.id)
    end

    it "filters by actor: an operator's email or a host's name or hostname, case-insensitively, with or without a type" do
      expect(ids_for(actor: "SAM@example")).to eq([ e5, e2 ].map(&:id))
      expect(ids_for(actor: "media")).to eq([ e3.id ])
      expect(ids_for(actor: "vm-01.example.lan", actor_type: "host")).to eq([ e3.id ])
      expect(ids_for(actor: "vm-01", actor_type: "operator")).to eq([])
      expect(ids_for(actor: "sam", actor_type: "system")).to eq([ e4.id ]) # the system has no name to match
    end

    it "filters by action, from Audit::Actions::ALL only" do
      expect(ids_for(action: "host.retired")).to eq([ e2.id ])
      expect(page.at_css("select[name=action] option[selected]")["value"]).to eq("host.retired")
      expect(ids_for(action: "host.deleted")).to eq([ e5, e4, e3, e2, e1 ].map(&:id)) # not an action: ignored
    end

    it "filters by target host name or hostname, retired hosts included (owner answer 2)" do
      expect(ids_for(target: "backup TARGET")).to eq([ e4, e2 ].map(&:id))
      expect(ids_for(target: "vm-02.example")).to eq([ e4, e2 ].map(&:id))
      expect(ids_for(target: "example.lan")).to eq([ e4, e3, e2, e1 ].map(&:id))
    end

    it "covers hosts only as targets (owner answer 3)" do
      expect(ids_for(target: "sam@example.com")).to eq([])
    end

    it "filters by exact host id from the host page, ignoring hosts with similar names (owner answer 2)" do
      twin = create(:host, name: "Media server", hostname: "vm-03.example.lan")
      e6 = entry(at: base - 4.days, target: twin)
      expect(ids_for(host_id: media.id)).to eq([ e3, e1 ].map(&:id))
      expect(ids_for(target: "Media server")).to eq([ e3, e1 ].map(&:id) + [])
      expect(row_ids).to include(e6.id)
      get "/audit", params: { host_id: media.id }
      expect(page.at_css("#applied_filters").text.squish).to start_with("All actions on Media server")
      expect(page.at_css("input[type=hidden][name=host_id]")["value"]).to eq(media.id.to_s)
      get "/hosts/#{media.id}"
      expect(page.at_css("#host_audit_link")["href"]).to eq("/audit?host_id=#{media.id}")
    end

    it "filters by date range: whole UTC days, both included" do
      expect(ids_for(from: "2026-10-12", to: "2026-10-13")).to eq([ e3, e2 ].map(&:id))
      expect(ids_for(from: "2026-10-14")).to eq([ e5, e4 ].map(&:id))
      expect(ids_for(to: "2026-10-11")).to eq([ e1.id ])
      edge = entry(at: Time.utc(2026, 10, 13, 23, 59, 59, 999_999))
      after = entry(at: Time.utc(2026, 10, 14))
      get "/audit", params: { to: "2026-10-13" }
      expect(row_ids).to include(edge.id)
      expect(row_ids).not_to include(after.id)
      expect(page.at_css("input[name=to]")["value"]).to eq("2026-10-13")
    end

    it "composes filters, keeps them in the URL, and describes them in words" do
      get "/audit", params: { actor_type: "operator", actor: "sam@example.com", action: "host.retired", from: "2026-10-01", to: "2026-10-28" }
      expect(row_ids).to eq([ e2.id ])
      expect(page.at_css("#applied_filters span").text.squish).to eq("Host retired by sam@example.com (operator), 1 to 28 Oct 2026".sub("Host retired", "Retired"))
      expect(page.at_css("#applied_filters a")["href"]).to eq("/audit")
      expect(page.at_css("select[name=actor_type] option[selected]")["value"]).to eq("operator")
      expect(page.at_css("input[name=actor]")["value"]).to eq("sam@example.com")
    end

    it "leaves empty filters out of the URL" do
      get "/audit", params: { actor_type: "", actor: " ", action: "host.retired", target: "", from: "", to: "" }
      expect(response).to redirect_to("/audit?action=host.retired")
      get "/audit", params: { actor: "" }
      expect(response).to redirect_to("/audit")
    end

    it "hides sign-ins with one click, keeping the other filters (owner answer 5)" do
      expect(ids_for(actor_type: "operator")).to eq([ e5, e2, e1 ].map(&:id))
      toggle = page.at_css("#sign_ins_toggle")
      expect(toggle.text).to eq("Hide sign-ins")
      expect(query(toggle["href"])).to eq("actor_type" => "operator", "hide_sign_ins" => "1")
      get toggle["href"]
      expect(row_ids & [ e5, e2, e1 ].map(&:id)).to eq([ e2, e1 ].map(&:id))
      expect(page.at_css("#sign_ins_toggle").text).to eq("Show sign-ins")
      expect(query(page.at_css("#sign_ins_toggle")["href"])).to eq("actor_type" => "operator")
      expect(page.at_css("input[type=hidden][name=hide_sign_ins]")["value"]).to eq("1")
      expect(page.at_css("#applied_filters span").text.squish).to eq("All actions by any operator, sign-ins hidden")
    end

    it "keeps sign-ins in the default view, and shows them when the action is chosen even if hidden" do
      expect(ids_for({})).to include(e5.id)
      expect(ids_for(action: "operator.signed_in", hide_sign_ins: "1")).to eq([ e5.id ])
      expect(page.at_css("#sign_ins_toggle")).to be_nil
    end

    it "explains when nothing matches, with a way back" do
      get "/audit", params: { action: "host.retired", target: "Lab sandbox", from: "2026-10-01", to: "2026-10-28" }
      expect(page.at_css("table.audit")).to be_nil
      expect(page.at_css("#no_entries strong").text).to eq("No entries match these filters.")
      expect(page.at_css("#no_entries").text.squish).to include("Retired on Lab sandbox, 1 to 28 Oct 2026. Clear the filters or widen the dates.")
      expect(page.at_css("#no_entries a")["href"]).to eq("/audit")
    end

    it "matches nothing for an unknown host, by text or by id" do
      expect(ids_for(target: "no-such-host")).to eq([])
      expect(page.at_css("#no_entries strong").text).to eq("No entries match these filters.")
      expect(ids_for(host_id: Host.maximum(:id) + 1)).to eq([])
      expect(page.at_css("#applied_filters").text).to include("(no such host)")
      expect(ids_for(host_id: "abc")).to eq([ e5, e4, e3, e2, e1 ].map(&:id)) # not an id: ignored
    end

    it "treats LIKE wildcards in typed text literally" do
      expect(ids_for(target: "%")).to eq([])
      expect(ids_for(target: "vm_01")).to eq([])
    end

    it "shows a wrong-way date range as matching nothing, in words" do
      expect(ids_for(from: "2026-10-28", to: "2026-10-01")).to eq([])
      expect(page.at_css("#no_entries").text.squish).to include("28 to 1 Oct 2026")
    end

    it "rejects invalid dates in place, without listing entries" do
      [ "2026-02-30", "yesterday", "2026-1-5", "20261-01-01", "2026-13-01" ].each do |bad|
        get "/audit", params: { from: bad, to: "2026-10-28" }
        expect(response).to have_http_status(:unprocessable_content), bad
        expect(page.at_css("table.audit")).to be_nil
        expect(page.at_css("#filter_errors").text).to include("Fix the dates")
        expect(page.at_css("input[name=from]")["aria-invalid"]).to eq("true")
        expect(page.at_css("#from_error").text).to include("“#{bad}”", "YYYY-MM-DD")
        expect(page.at_css("#applied_filters")).to be_nil
        expect(page.at_css("input[name=to]")["aria-invalid"]).to be_nil
      end
    end
  end

  describe "onboarding entries and their host (owner answer 1)" do
    it "links an approved request to the host it became and includes it when filtering by that host" do
      started = start_onboarding(hostname: "vm-08.example.lan")
      Onboarding::Approve.call(request: started.record, operator:, attributes: { "name" => "Build runner 2" })
      collect_onboarding(started.device_code)
      host = Host.find_by!(name: "Build runner 2")
      rejected = start_onboarding(hostname: "vm-08.example.lan", client_ip: "192.0.2.11")
      Onboarding::Reject.call(request: rejected.record, operator:)

      get "/audit", params: { host_id: host.id }
      expect(rows.map { |tr| cells(tr)[2] }).to eq([ "Enrolled", "Host created", "Onboarding approved" ])
      approval = rows.last
      expect(cells(approval)[3]).to eq("Onboarding request #{started.record.id} vm-08.example.lan Host Build runner 2")
      expect(approval.at_css("td:nth-child(4) a")["href"]).to eq("/hosts/#{host.id}")
      enrolled = rows.first
      expect(enrolled.css(".change-list li").map { |li| li.text.squish }).to include("Onboarding request #{started.record.id}")

      get "/audit", params: { target: "vm-08" }
      expect(rows.map { |tr| cells(tr)[2] }).to eq([ "Enrolled", "Host created", "Onboarding approved" ]) # the rejection names no host
    end

    it "keeps the link after the request is pruned, and includes a re-enrollment approval before collection" do
      host, = enrolled_host(name: "Media server", hostname: "vm-01.example.lan")
      started = start_onboarding(hostname: "vm-01.example.lan")
      Onboarding::Approve.call(request: started.record, operator:, target_host: host)
      approval = AuditEntry.find_by!(action: Audit::Actions::ONBOARDING_APPROVED)

      get "/audit", params: { host_id: host.id }
      expect(row_ids).to include(approval.id)
      expect(row(approval).css(".change-list li").map { |li| li.text.squish }).to eq([ "State open approved", "Re-enroll yes", "Host Media server" ])
      expect(row(approval).at_css(".change-list a")["href"]).to eq("/hosts/#{host.id}")

      collect_onboarding(started.device_code)
      OnboardingPruneJob.new.perform(now: 2.days.from_now)
      expect(OnboardingRequest.exists?(started.record.id)).to be(false)
      get "/audit", params: { target: "Media server" }
      expect(row_ids).to include(approval.id)
      expect(cells(page.at_css("#audit_entry_#{approval.id}"))[3]).to eq("Onboarding request #{started.record.id} Host Media server")
    end

    it "does not link a request to another host that happens to share its id" do
      a = create(:host)
      b = create(:host)
      started = start_onboarding(hostname: "vm-09.example.lan")
      Onboarding::Reject.call(request: started.record, operator:)
      entry(target: b, changes: { "onboarding_request_id" => [ nil, started.record.id ] }) # not an Enrolled entry
      get "/audit", params: { host_id: a.id }
      expect(rows.map { |tr| cells(tr)[2] }).to eq([ "Host created" ])
      get "/audit", params: { host_id: b.id }
      expect(rows.map { |tr| cells(tr)[2] }).to eq([ "Host created", "Host edited" ]) # the edit is at base, before now
    end
  end

  describe "pagination (keyset on occurred_at and id, owner answer 7)" do
    # Entries on a host of their own, so the filter leaves out the sign-in entries. Its "Host created" entry
    # is the oldest; the others follow one second apart from the next whole second.
    let(:host) { create(:host, name: "Paged host") }
    let(:created) { AuditEntry.find_by!(action: Audit::Actions::HOST_CREATED, target_id: host.id) }
    let(:start) { created.occurred_at.ceil + 1 }

    def make(count, from: start) = Array.new(count) { |i| entry(at: from + i, target: host) }

    def visit(params = {}) = get("/audit", params: { host_id: host.id }.merge(params))

    def own_ids = row_ids - [ created.id ]

    def stamp(time) = time.utc.strftime("%Y-%m-%dT%H:%M:%S.%6NZ")

    it "shows 50 entries per page, with no older link when exactly 50 match" do
      host
      make(49)
      visit
      expect(rows.size).to eq(50) # 49 plus "Host created"
      expect(link("next")).to be_nil
      expect(page.at_css(".pager .off[aria-disabled]")).to be_present
    end

    it "pages through older and back to newer at the boundary, keeping the filters" do
      made = make(50)
      visit(hide_sign_ins: "1")
      expect(own_ids).to eq(made.reverse.map(&:id))
      expect(link("prev")).to be_nil
      older = link("next")
      expect(query(older)).to eq("host_id" => host.id.to_s, "hide_sign_ins" => "1", "before" => "#{stamp(made.first.occurred_at)},#{made.first.id}")
      get older
      expect(rows.size).to eq(1)
      expect(cells(rows.first)[2]).to eq("Host created")
      expect(link("next")).to be_nil
      newer = link("prev")
      expect(query(newer)["after"]).to be_present
      get newer
      expect(own_ids).to eq(made.reverse.map(&:id)) # back on the full first page
      expect(link("prev")).to be_nil
    end

    it "walks three pages each way without skipping or repeating an entry" do
      made = make(120)
      seen = []
      visit
      loop do
        seen.concat(row_ids)
        break unless link("next")

        get link("next")
      end
      all = AuditEntry.for_target(host).order(occurred_at: :desc, id: :desc).ids
      expect(seen).to eq(all)
      expect(seen.size).to eq(121)
      back = []
      loop do
        back.unshift(*row_ids)
        break unless link("prev")

        get link("prev")
      end
      expect(made.size).to eq(120)
      expect(back).to eq(all.first(back.size)) # back on the first page, every page in between in order
      expect(rows.size).to eq(50)
      expect(row_ids).to eq(all.first(50))
    end

    it "shows a full first page when going newer reaches the newest entry, and a full page otherwise" do
      made = make(60)
      visit(after: AuditLog::Cursor.of(made[30]).to_param) # only 29 entries are newer
      expect(own_ids).to eq(made.reverse.first(50).map(&:id))
      expect(link("prev")).to be_nil
      visit(after: AuditLog::Cursor.of(made[5]).to_param) # 54 are newer: the 50 just after the cursor
      expect(own_ids).to eq(made[6, 50].reverse.map(&:id))
      expect(query(link("prev"))["after"]).to eq(AuditLog::Cursor.of(made[55]).to_param)
      expect(query(link("next"))["before"]).to eq(AuditLog::Cursor.of(made[6]).to_param)
    end

    it "orders entries from the same instant by id, across a page boundary" do
      made = make(48)
      same = Array.new(4) { entry(at: start + 100, target: host) }
      visit
      expect(own_ids.first(4)).to eq(same.reverse.map(&:id))
      get link("next")
      second = own_ids
      first_page = [ *same.reverse, *made.reverse ].map(&:id).first(50)
      expect(second).to eq(([ *same.reverse, *made.reverse ].map(&:id) - first_page))
      expect(second.size).to eq(2)
      expect(row_ids.last).to eq(created.id)
    end

    it "keeps microseconds in the cursor, so entries in the same second are neither lost nor repeated" do
      a = entry(at: start + Rational(2, 1_000_000), target: host)
      b = entry(at: start + Rational(1, 1_000_000), target: host)
      make(49, from: start + 1)
      visit
      expect(row_ids.last).to eq(a.id)
      expect(query(link("next"))["before"]).to eq("#{stamp(start).sub('.000000Z', '.000002Z')},#{a.id}")
      get link("next")
      expect(row_ids).to eq([ b.id, created.id ])
    end

    it "ignores an invalid or tampered cursor and shows the newest entries" do
      made = make(3)
      [ "garbage", "2026-10-14T10:00:00Z", "2026-10-14T10:00:00Z,0", "2026-10-14T10:00:00Z,01", "2026-02-30T10:00:00Z,5",
        "2026-10-14T25:00:00Z,5", "2026-10-14T10:00:00.1234567Z,5", "2026-10-14T10:00:00Z,99999999999999999999",
        "2026-10-14T10:00:00Z,5;DROP TABLE hosts", "2026-10-14 10:00:00,5", "2026-10-14T10:00:00+01:00,5" ].each do |cursor|
        visit(before: cursor)
        expect(response).to have_http_status(:ok), cursor
        expect(page.at_css("#invalid_cursor")).to be_present, cursor
        expect(own_ids).to eq(made.reverse.map(&:id)), cursor
      end
      valid = AuditLog::Cursor.of(made.last).to_param
      visit(before: valid, after: valid)
      expect(page.at_css("#invalid_cursor")).to be_present
      expect(own_ids).to eq(made.reverse.map(&:id))
    end

    it "accepts a readable cursor written by hand, and shows an empty page past the oldest entry with a way back" do
      made = make(3)
      visit(before: "#{made.last.occurred_at.utc.strftime('%Y-%m-%dT%H:%M:%SZ')},#{made.last.id}")
      expect(page.at_css("#invalid_cursor")).to be_nil
      expect(own_ids).to eq(made.first(2).reverse.map(&:id))
      visit(before: "2000-01-01T00:00:00Z,1")
      expect(page.at_css("#no_entries").text).to include("No older entries.")
      expect(query(link("prev"))).to eq("host_id" => host.id.to_s)
      expect(link("next")).to be_nil
    end

    it "handles extreme but well-formed cursors and dates without error" do
      make(2)
      [ { before: "0000-01-01T00:00:00Z,1" }, { after: "0000-01-01T00:00:00Z,1" }, { before: "9999-12-31T23:59:59.999999Z,999999999999999999" },
        { after: "9999-12-31T23:59:59.999999Z,999999999999999999" }, { from: "0001-01-01" }, { to: "9999-12-31" }, { from: "9999-12-31" } ].each do |params|
        visit(params)
        expect(response).to have_http_status(:ok), params.inspect
      end
    end

    it "starts again from the newest entry when a filter changes" do
      make(60)
      visit
      expect(page.css("form.audit-filters input[name=before], form.audit-filters input[name=after]")).to be_empty
    end
  end

  describe AuditLog::Cursor do
    it "round-trips an entry's position to the microsecond" do
      cursor = described_class.new(occurred_at: Time.utc(2026, 10, 14, 10, 2, 31, 482_113), id: 4127)
      expect(cursor.to_param).to eq("2026-10-14T10:02:31.482113Z,4127")
      expect(described_class.parse(cursor.to_param)).to eq(cursor)
      expect(described_class.parse("2026-10-14T10:02:31Z,4127").occurred_at).to eq(Time.utc(2026, 10, 14, 10, 2, 31))
    end

    it "rejects anything else" do
      [ nil, "", "2026-10-14T10:02:31.482113Z", ",4127", "2026-10-14T10:02:31.482113Z,-1", "2026-10-14T10:02:61Z,1",
        "2026-02-29T10:00:00Z,1", "2026-10-14T10:02:31.482113Z,4127\n" ].each do |value|
        expect(described_class.parse(value)).to be_nil, value.inspect
      end
    end
  end
end
