require "rails_helper"

# Rollouts on the dashboard (P1-D09, FR-S.5, AC-1.9, AC-1.10; approved mockups agents.html, agents-halted.html,
# dialogs.html, and host.html's "Agent updates"). Every action is a confirmation page and a CSRF-protected POST
# to the Rollouts service, audited with the signed-in operator as actor.
RSpec.describe "Rollouts", :signed_in, type: :request do
  include ActiveJob::TestHelper

  let(:release) { release_for_rollout("0.3.0") }
  let!(:canary) { host_running("0.2.0", name: "Media server", hostname: "vm-01.example.lan", tags: [ "canary" ]) }
  let!(:other) { host_running("0.2.0", name: "Web A", hostname: "vm-02.example.lan") }
  let!(:third) { host_running("0.2.0", name: "Web B", hostname: "vm-03.example.lan") }

  def canary_host = canary.first

  # An element's text with a space between its parts, as a reader sees it.
  def words(node) = node.xpath(".//text()").map(&:text).join(" ").squish

  def stage_cards = page.css("#rollout_stages li").map { |li| li.then { words(_1) } }

  def host_rows = page.css("#rollout_hosts tbody tr").map { |row| row.css("td").map { |cell| cell.then { words(_1) } } }

  def started(**options) = start_rollout(release:, canaries: [ canary_host ], operator:, **options)

  def report(rollout, host, **overrides)
    Host.transaction do
      Rollouts.record_result!(host_id: host.id, credential_id: host.agent_credentials.active.pick(:id),
                              payload: update_result(rollout, **overrides).deep_stringify_keys)
    end
  end

  def offer(host, version = "0.2.0") = Host.transaction { Rollouts.directive_for(host_id: host.id, agent_version: version) }

  describe "the start form" do
    it "offers the newest release, the canary tag, the active hosts, and the default stages" do
      release
      release_for_rollout("0.2.5")
      get "/agents"
      form = page.at_css("form#start_rollout")
      expect(form["action"]).to eq("/agents/rollouts/new")
      expect(form["method"]).to eq("get")
      expect(form.css("#release option").map { |o| [ o.text, o["selected"] ] }).to eq([ [ "0.3.0 (newest)", "selected" ], [ "0.2.5", nil ] ])
      expect(form.css("#canary_tag option").map(&:text)).to eq([ "Only the hosts chosen below", "Hosts tagged canary (1)" ])
      expect(form.at_css("#canary_tag option[selected]")["value"]).to eq("canary")
      expect(form.css(".canary-list label").map { |l| l.then { words(_1) } }).to eq([ "Media server vm-01.example.lan 0.2.0", "Web A vm-02.example.lan 0.2.0", "Web B vm-03.example.lan 0.2.0" ])
      expect(form.at_css("#stages")["value"]).to eq("25, 100")
      expect(form.at_css("button[type=submit]")["disabled"]).to be_nil
      expect(page.at_css("#rollout_heading")).to be_nil
    end

    it "is disabled, saying why, without a release or while a rollout is open" do
      get "/agents"
      expect(page.at_css("#start_rollout .notice strong").text).to eq("Import a release first.")
      expect(page.at_css("#start_rollout button")["disabled"]).to eq("disabled")

      started
      get "/agents"
      expect(page.at_css("#start_rollout .notice").then { words(_1) }).to eq("One rollout at a time. Available when the rollout to 0.3.0 completes or is cancelled.")
      expect(page.css("#start_rollout select, #start_rollout input[type=text], #start_rollout input[type=checkbox]").map { |e| e["disabled"] }.uniq).to eq([ "disabled" ])
    end

    it "says how many active hosts it leaves out of the list" do
      stub_const("AgentsPage::CANARY_CHOICE_LIMIT", 2)
      get "/agents"
      expect(page.css(".canary-list label").size).to eq(2)
      expect(page.at_css("#canary_choices .hint").text).to eq("Showing the first 2 of 3 active hosts. Use a tag to choose others.")
    end

    it "says when there is no active host to choose and no tag" do
      Host.update_all(enrollment_state: "pending")
      release
      get "/agents"
      expect(page.css("#canary_tag option").map(&:text)).to eq([ "Only the hosts chosen below" ])
      expect(page.at_css("#canary_choices p.muted").text).to eq("No active host yet.")
    end
  end

  describe "starting" do
    it "asks for confirmation, naming the canaries and stages, and starts only on the POST" do
      release
      get "/agents/rollouts/new", params: { release: "0.3.0", canary_tag: "canary", canary_host_ids: [ other.first.id.to_s, "" ], stages: "25, 100" }
      expect(response).to have_http_status(:ok)
      expect(Rollout.count).to eq(0)
      expect(page.at_css("nav a[aria-current='page']").text).to eq("Agents")
      expect(page.at_css("#dialog_title").text).to eq("Start rolling out 0.3.0?")
      expect(page.at_css(".dialog p").then { words(_1) }).to eq("2 canary hosts (tag canary and the hosts chosen) update first:")
      expect(page.css("#canary_hosts li").map { |li| li.then { words(_1) } }).to eq([ "Media server vm-01.example.lan , on 0.2.0", "Web A vm-02.example.lan , on 0.2.0" ])
      expect(page.css(".dialog p")[1].text).to start_with("Then 25% of the hosts on an older version and everyone else.")
      form = page.at_css(".dialog form")
      expect(form["action"]).to eq("/agents/rollouts")
      expect(form.css("input[type=hidden]").to_h { |i| [ i["name"], i["value"] ] }).to include("release" => "0.3.0", "canary_tag" => "canary", "canary_host_ids[]" => other.first.id.to_s, "stages" => "25, 100")

      expect { post "/agents/rollouts", params: { release: "0.3.0", canary_tag: "canary", canary_host_ids: [ other.first.id.to_s ], stages: "25, 100" } }
        .to change(Rollout, :count).by(1)
      expect(response).to redirect_to("/agents")
      rollout = Rollout.sole
      expect(rollout).to have_attributes(state: "running", started_by: operator, canary_tag: "canary", canary_host_ids: [ other.first.id ], stage_percents: [ 25, 100 ])
      expect(AuditEntry.find_by!(action: Audit::Actions::ROLLOUT_STARTED)).to have_attributes(actor_type: "operator", actor_id: operator.id)
      expect(rollout.rollout_hosts.order(:host_id).pluck(:from_version)).to eq(%w[0.2.0 0.2.0])

      follow_redirect!
      expect(page.at_css(".flash").then { words(_1) }).to eq("Rollout to 0.3.0 started. 2 canary hosts are offered it on their next heartbeat.")
      expect(page.at_css("#rollout_heading").text).to eq("Rolling out 0.3.0")
      expect(stage_cards).to eq([ "1. Canary 0 of 2 confirmed, 2 waiting Media server, Web A", "2. 25% of hosts Waiting Hosts are chosen when it opens",
                                  "3. Everyone else Waiting Hosts are chosen when it opens" ])
      expect(page.at_css("#rollout_stages li.current .name").text).to eq("1. Canary")
      expect(host_rows.map(&:first)).to eq([ "Media server", "Web A" ])
      expect(host_rows.first[1..3]).to eq([ "Canary", "0.2.0", "Waiting for its next heartbeat" ])
      expect(page.css("#rollout_actions a").map { |a| [ a.text, a["href"] ] }).to eq(
        [ [ "Advance to the next stage", "/agents/rollouts/#{rollout.id}/advance" ], [ "Halt", "/agents/rollouts/#{rollout.id}/halt" ],
          [ "Cancel rollout", "/agents/rollouts/#{rollout.id}/cancel" ] ]
      )
    end

    it "takes stages as text and says it singly for one canary" do
      release
      post "/agents/rollouts", params: { release: "0.3.0", canary_host_ids: [ canary_host.id.to_s ], stages: "50% 100" }
      expect(Rollout.sole.stage_percents).to eq([ 50, 100 ])
      follow_redirect!
      expect(page.at_css(".flash").then { words(_1) }).to eq("Rollout to 0.3.0 started. 1 canary host is offered it on its next heartbeat.")
    end

    # The last value is the control marked aria-invalid, which also keeps live refreshes from replacing the refused
    # choices and the error (keep-edits#protect; review of #89).
    {
      "an unknown release" => [ { release: "9.9.9", canary_tag: "canary", stages: "25, 100" }, "Choose a release to roll out.", "release" ],
      "no canary" => [ { release: "0.3.0", stages: "25, 100" }, "Name the canary hosts or a canary tag.", "canary_tag" ],
      "stages that do not end at 100" => [ { release: "0.3.0", canary_tag: "canary", stages: "25, 50" },
                                           "Stages must be increasing percentages ending at 100, such as 25, 100.", "stages" ],
      "canaries already on the release" => [ { release: "0.3.0", canary_tag: "nobody", stages: "25, 100" },
                                             "None of the chosen canaries is an active host running an older version than 0.3.0.", "canary_tag" ],
      "a canary tag longer than the column" => [ { release: "0.3.0", canary_tag: "t" * 33, stages: "25, 100" },
                                                 "A canary tag is at most 32 characters.", "canary_tag" ]
    }.each do |label, (params, message, field)|
      it "refuses #{label} on the Agents page, keeping the choices and marking the control invalid" do
        release
        get "/agents/rollouts/new", params: params.merge(canary_host_ids: [ "x" ])
        expect(response).to have_http_status(:unprocessable_content)
        expect(page.at_css("#start_rollout_error").then { words(_1) }).to eq("The rollout was not started. #{message}")
        expect(page.at_css("#stages")["value"]).to eq(params[:stages])
        expect(page.css("#start_rollout [aria-invalid=true]").map { |control| control["id"] }).to eq([ field ])
        expect(page.at_css("##{field}")["aria-errormessage"]).to eq("start_rollout_error")
        expect(page.at_css("#releases")).to be_present
        expect(Rollout.count).to eq(0)
      end
    end

    it "refuses an oversized canary tag on the POST too, with a valid canary, instead of a database error (review of #89)" do
      release
      post "/agents/rollouts", params: { release: "0.3.0", canary_tag: "t" * 33, canary_host_ids: [ other.first.id.to_s ], stages: "25, 100" }
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#start_rollout_error").then { words(_1) }).to eq("The rollout was not started. A canary tag is at most 32 characters.")
      expect(Rollout.count).to eq(0)
    end

    it "refuses while a rollout is open, on the confirmation and on the POST" do
      started
      get "/agents/rollouts/new", params: { release: "0.3.0", canary_host_ids: [ other.first.id.to_s ], stages: "25, 100" }
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#start_rollout_error p").text).to eq("A rollout is already open. Finish or cancel it first.")

      post "/agents/rollouts", params: { release: "0.3.0", canary_host_ids: [ other.first.id.to_s ], stages: "25, 100" }
      expect(response).to have_http_status(:unprocessable_content)
      expect(Rollout.count).to eq(1)
    end

    it "keeps the chosen hosts open and ticked when refused" do
      release
      get "/agents/rollouts/new", params: { release: "0.3.0", canary_host_ids: [ other.first.id.to_s ], stages: "100, 25" }
      expect(page.at_css("#canary_choices")["open"]).not_to be_nil
      expect(page.at_css("#canary_choices summary").text).to eq("Choose canary hosts (1 chosen)")
      expect(page.css(".canary-list input[checked]").map { |i| i["value"] }).to eq([ other.first.id.to_s ])
      expect(page.at_css("#canary_tag option[selected]")).to be_nil
    end
  end

  describe "halting" do
    it "asks first, then halts with the operator as actor and shows the halt prominently" do
      rollout = started
      get "/agents/rollouts/#{rollout.id}/halt"
      expect(page.at_css("#dialog_title").text).to eq("Halt the rollout to 0.3.0?")
      expect(page.at_css(".dialog p").text).to start_with("No more hosts are offered 0.3.0.")
      expect(page.at_css(".dialog form")["action"]).to eq("/agents/rollouts/#{rollout.id}/halt")
      expect(rollout.reload.state).to eq("running")

      post "/agents/rollouts/#{rollout.id}/halt"
      expect(response).to redirect_to("/agents")
      expect(rollout.reload).to have_attributes(state: "halted", halted_by: operator, halt_reason: "halted by an operator")
      expect(AuditEntry.find_by!(action: Audit::Actions::ROLLOUT_HALTED)).to have_attributes(actor_type: "operator", actor_id: operator.id)

      follow_redirect!
      notice = page.at_css("#rollout_halted")
      expect(notice["role"]).to eq("alert")
      expect(notice.at_css("strong").text).to eq("The rollout to 0.3.0 is halted: halted by an operator")
      expect(notice.at_css("p").text).to start_with("Halted by Example Operator, ")
      expect(page.at_css("#rollout_heading").text).to eq("Rollout to 0.3.0, halted")
      expect(page.at_css("#rollout_stages li.halted .name").text).to eq("1. Canary")
      expect(stage_cards.last).to eq("3. Everyone else Not started Hosts are chosen when it opens")
      expect(host_rows.first[3]).to eq("Not offered while the rollout is halted")
      expect(page.css("#rollout_actions a").map(&:text)).to eq([ "Resume", "Cancel rollout" ])
    end

    it "refuses an action the rollout's state no longer allows, changing nothing" do
      rollout = started
      Rollouts.halt!(rollout, actor: operator)
      post "/agents/rollouts/#{rollout.id}/halt"
      expect(response).to redirect_to("/agents")
      expect(flash[:alert]).to eq("Nothing changed: The rollout is halted, not running.")
      expect(AuditEntry.where(action: Audit::Actions::ROLLOUT_HALTED).count).to eq(1)

      get "/agents/rollouts/#{rollout.id}/halt"
      expect(page.at_css("#not_now").text).to eq("The rollout is halted now, so there is nothing to do here.")
      expect(page.at_css(".dialog form")).to be_nil
    end
  end

  describe "resuming" do
    it "shows why the rollout halted and which hosts failed before resuming" do
      rollout = started
      offer(canary_host)
      report(rollout, canary_host, outcome: "rolled_back", reason: "config: unknown option heartbeat_jitter_ms")
      expect(rollout.reload).to have_attributes(state: "halted", halted_by: nil)

      get "/agents"
      expect(page.at_css("#rollout_halted strong").text).to eq("The rollout to 0.3.0 is halted: Media server reported rolled back: config: unknown option heartbeat_jitter_ms")
      expect(page.at_css("#rollout_halted p").text).to start_with("Halted automatically, ")
      expect(host_rows.first[3]).to eq("Rolled back config: unknown option heartbeat_jitter_ms")
      expect(stage_cards.first).to start_with("1. Canary 0 of 1 confirmed, 1 rolled back")

      get "/agents/rollouts/#{rollout.id}/resume"
      expect(page.at_css("#halt_reason strong").text).to eq("Why it halted: Media server reported rolled back: config: unknown option heartbeat_jitter_ms")
      expect(page.css("#problem_hosts li").map { |li| li.then { words(_1) } }).to eq([ "Media server: Rolled back config: unknown option heartbeat_jitter_ms" ])

      post "/agents/rollouts/#{rollout.id}/resume"
      expect(response).to redirect_to("/agents")
      expect(rollout.reload).to have_attributes(state: "running", resumed_by: operator)
      expect(AuditEntry.find_by!(action: Audit::Actions::ROLLOUT_RESUMED)).to have_attributes(actor_type: "operator", actor_id: operator.id)
      follow_redirect!
      expect(page.at_css("#rollout_halted")).to be_nil
      expect(page.at_css(".host-head .sub").text).to include("Resumed by Example Operator")
    end

    it "says there is nothing to resume for a running rollout" do
      rollout = started
      get "/agents/rollouts/#{rollout.id}/resume"
      expect(page.at_css("#not_now")).to be_present
    end
  end

  describe "advancing" do
    it "opens the next stage on confirmation, and offers no advance from the final stage" do
      rollout = started(stage_percents: [ 50, 100 ])
      get "/agents/rollouts/#{rollout.id}/advance"
      expect(page.at_css("#dialog_title").text).to eq("Open stage 2 (50% of hosts) now?")

      expect(page.at_css("form[action='/agents/rollouts/#{rollout.id}/advance'] input[name=stage]")["value"]).to eq("0")
      post "/agents/rollouts/#{rollout.id}/advance", params: { stage: 0 }
      expect(rollout.reload.current_stage).to eq(1)
      expect(flash[:notice]).to eq("The rollout to 0.3.0 moved on to stage 2.")
      expect(AuditEntry.find_by!(action: Audit::Actions::ROLLOUT_ADVANCED)).to have_attributes(actor_type: "operator", actor_id: operator.id)

      Rollouts.advance!(rollout, actor: operator)
      get "/agents/rollouts/#{rollout.id}/advance"
      expect(page.at_css("#not_now").text).to eq("The rollout is in its final stage. It completes when every host confirms.")
      get "/agents"
      expect(page.css("#rollout_actions a").map(&:text)).to eq([ "Halt", "Cancel rollout" ])
      expect(page.css("#rollout_stages .name").map(&:text)).to eq([ "1. Canary", "2. 50% of hosts", "3. Everyone else" ])
      expect(host_rows.map { |row| row[1] }).to eq(%w[Canary 2 3])
    end

    it "refuses a stale confirmation: a stage opened since the page was shown is not skipped (review of #89)" do
      rollout = started(stage_percents: [ 50, 100 ])
      get "/agents/rollouts/#{rollout.id}/advance" # shows "Open stage 2", for stage 0 (the canaries)
      Rollouts.advance!(rollout, actor: operator) # another operator, or the last canary confirming, opens stage 2

      expect { post "/agents/rollouts/#{rollout.id}/advance", params: { stage: 0 } }.not_to(change { rollout.reload.current_stage })
      expect(flash[:alert]).to eq("Nothing changed: The rollout already moved on to stage 2 since you opened that page.")
      expect(AuditEntry.where(action: Audit::Actions::ROLLOUT_ADVANCED).count).to eq(1)

      post "/agents/rollouts/#{rollout.id}/advance" # no stage at all: refused the same way
      expect(rollout.reload.current_stage).to eq(1)
      expect(flash[:alert]).to start_with("Nothing changed: The rollout already moved on")
    end

    it "shows how long ago a later stage opened, or halted" do
      rollout = started(stage_percents: [ 50, 100 ])
      Rollouts.advance!(rollout, actor: operator)
      get "/agents"
      expect(stage_cards[1]).to end_with("Opened less than a minute ago")
      Rollouts.halt!(rollout, actor: operator)
      get "/agents"
      expect(stage_cards[1]).to end_with("Halted less than a minute ago")
      expect(page.at_css("#rollout_stages li.halted .name").then { words(_1) }).to eq("2. 50% of hosts")
    end

    it "says there is nothing to advance in a halted rollout" do
      rollout = started
      Rollouts.halt!(rollout, actor: operator)
      get "/agents/rollouts/#{rollout.id}/advance"
      expect(page.at_css("#not_now").text).to eq("The rollout is halted now, so there is nothing to do here.")
    end
  end

  describe "cancelling" do
    it "asks first, then cancels, and the finished rollout stays on the page" do
      rollout = started
      get "/agents/rollouts/#{rollout.id}/cancel"
      expect(page.at_css("#dialog_title").text).to eq("Cancel the rollout to 0.3.0?")
      post "/agents/rollouts/#{rollout.id}/cancel"
      expect(rollout.reload.state).to eq("cancelled")
      expect(AuditEntry.find_by!(action: Audit::Actions::ROLLOUT_CANCELLED)).to have_attributes(actor_type: "operator", actor_id: operator.id)
      follow_redirect!
      expect(page.at_css("#rollout_heading").text).to eq("Rollout to 0.3.0, cancelled")
      expect(page.at_css(".host-head .sub").text).to include("Cancelled ")
      expect(page.css("#rollout_actions a")).to be_empty
      expect(host_rows.first[3]).to eq("Not offered: the rollout was cancelled")
      expect(page.at_css("#start_rollout button")["disabled"]).to be_nil

      get "/agents/rollouts/#{rollout.id}/cancel"
      expect(page.at_css("#not_now")).to be_present
    end
  end

  it "refuses every action without the CSRF token (FR-S.4)" do
    rollout = started
    ActionController::Base.allow_forgery_protection = true
    %w[advance halt cancel].each { |action| post "/agents/rollouts/#{rollout.id}/#{action}" }
    post "/agents/rollouts", params: { release: "0.3.0", canary_host_ids: [ other.first.id.to_s ], stages: "25, 100" }
    expect(rollout.reload).to have_attributes(state: "running", current_stage: 0)
    expect(Rollout.count).to eq(1)
  ensure
    ActionController::Base.allow_forgery_protection = false
  end

  # AC: an operator runs a rollout end to end from the dashboard and sees each host's outcome without reloading.
  it "runs a rollout end to end, each outcome reaching open pages as a live refresh" do
    release
    post "/agents/rollouts", params: { release: "0.3.0", canary_tag: "canary", stages: "50, 100" }
    rollout = Rollout.sole
    clear_enqueued_jobs

    expect(offer(canary_host)).to include(version: "0.3.0")
    expect(enqueued_jobs.map { |j| j["job_class"] }).to include("FleetBroadcastJob")
    get "/agents"
    expect(host_rows.first[3]).to eq("Offered 0.3.0, waiting for its result")
    expect(stage_cards.first).to start_with("1. Canary 0 of 1 confirmed, 1 updating")

    clear_enqueued_jobs
    report(rollout, canary_host)
    expect(enqueued_jobs.map { |j| j["job_class"] }).to include("FleetBroadcastJob")
    expect(rollout.reload.current_stage).to eq(1) # all canaries confirmed: stage 2 opened by itself
    get "/agents"
    expect(host_rows.map { |row| [ row[0], row[3] ] }).to eq([ [ "Media server", "Confirmed on 0.3.0" ], [ "Web A", "Waiting for its next heartbeat" ] ])
    expect(stage_cards.first).to eq("1. Canary 1 of 1 confirmed Media server")
    expect(page.at_css("#rollout_stages li.current .name").text).to eq("2. 50% of hosts")

    [ other.first, third.first ].each do |host|
      offer(host)
      report(rollout, host)
    end
    expect(rollout.reload.state).to eq("completed")
    get "/agents"
    expect(page.at_css("#rollout_heading").text).to eq("Rollout to 0.3.0, completed")
    expect(host_rows.map { |row| row[3] }).to eq([ "Confirmed on 0.3.0" ] * 3)
    expect(stage_cards).to eq([ "1. Canary 1 of 1 confirmed Media server", "2. 50% of hosts 1 of 1 confirmed 1 host", "3. Everyone else 1 of 1 confirmed 1 host" ])
  end

  it "counts every host in the stages but lists only the first ones" do
    stub_const("AgentsPage::ROLLOUT_HOST_LIMIT", 1)
    start_rollout(release:, canaries: [ canary_host, other.first ], operator:)
    get "/agents"
    expect(host_rows.size).to eq(1)
    expect(page.at_css("#rollout_hosts_more").text).to eq("Showing the first 1 of 2 hosts. The stage counts above include all of them.")
    expect(stage_cards.first).to eq("1. Canary 0 of 2 confirmed, 2 waiting Media server, Web A")
  end

  it "names three canaries and counts the rest" do
    four = Array.new(4) { |i| host_running("0.2.0", name: "Canary #{i}", hostname: "vm-1#{i}.example.lan").first }
    start_rollout(release:, canaries: four, operator:)
    get "/agents"
    expect(stage_cards.first).to end_with("Canary 0, Canary 1, Canary 2 and 1 more")
  end

  describe "the host page's agent updates" do
    it "says when the host has not been part of a rollout" do
      get "/hosts/#{canary_host.id}"
      expect(page.at_css("#agent_updates p.muted").text).to eq("This host has not been part of a rollout.")
      expect(page.at_css("#agent_updates a[href='/agents']").text).to eq("Agent versions and rollouts")
    end

    it "lists each rollout the host took part in, newest first, with its outcome" do
      first = travel_to(Time.utc(2026, 1, 1, 8, 0)) do
        started.tap { offer(canary_host) }
      end
      travel_to(Time.utc(2026, 1, 1, 8, 0, 41)) do
        report(first, canary_host)
        Rollouts.cancel!(first, actor: operator)
      end
      newer = release_for_rollout("0.4.0")
      second = travel_to(Time.utc(2026, 1, 2, 8, 0)) do
        canary_host.update_columns(agent_version: "0.3.0")
        start_rollout(release: newer, canaries: [ canary_host ], operator:).tap { offer(canary_host, "0.3.0") }
      end
      travel_to(Time.utc(2026, 1, 2, 8, 2)) do
        report(second, canary_host, version: "0.4.0", agent_version: "0.3.0", outcome: "rolled_back", reason: "no heartbeat within 5 minutes")
        Rollouts.cancel!(second, actor: operator)
      end
      newest = release_for_rollout("0.5.0")
      travel_to(Time.utc(2026, 1, 3, 8, 0)) do
        third_rollout = start_rollout(release: newest, canaries: [ canary_host ], operator:)
        offer(canary_host, "0.3.0")
        Rollouts.expire_unconfirmed!(now: 31.minutes.from_now)
        Rollouts.cancel!(third_rollout, actor: operator)
      end

      get "/hosts/#{canary_host.id}"
      rows = page.css("#agent_updates tbody tr").map { |row| row.then { words(_1) } }
      expect(rows).to eq([
        "0.3.0 → 0.5.0, not confirmed No result within 30 minutes. 2026-01-03 08:31 UTC",
        "0.3.0 → 0.4.0, rolled back No heartbeat within 5 minutes; reported by 0.3.0. 2026-01-02 08:02 UTC",
        "0.2.0 → 0.3.0 Confirmed in 41 seconds. 2026-01-01 08:00 UTC"
      ])
      expect(page.css("#agent_updates .lamp").map { |l| l["class"] }).to eq([ "lamp offline", "lamp offline", "lamp online" ])
    end

    it "shows an update in progress, a failure without a reason, a slow confirmation, and hosts chosen before versions were kept" do
      # Whole seconds: `travel` drops the sub-second part, so an offer at x.7s and a result 3 minutes later would be
      # 179.3s apart and read "2 minutes" (failed on CI with seed 19571).
      freeze_time
      rollout = started
      get "/hosts/#{canary_host.id}"
      expect(page.at_css("#agent_updates tbody tr").then { words(_1) }).to start_with("0.2.0 → 0.3.0, waiting Waiting for its next heartbeat.")
      offer(canary_host)
      get "/hosts/#{canary_host.id}"
      expect(page.at_css("#agent_updates tbody tr").then { words(_1) }).to start_with("0.2.0 → 0.3.0, updating Offered 0.3.0, waiting for its result.")

      travel 3.minutes do
        report(rollout, canary_host, outcome: "failed")
      end
      RolloutHost.update_all(from_version: nil)
      get "/hosts/#{canary_host.id}"
      expect(page.at_css("#agent_updates tbody tr").then { words(_1) }).to start_with("0.3.0, failed Reported by 0.2.0.")
      get "/agents"
      expect(host_rows.first[2..3]).to eq([ "—", "Failed" ])

      RolloutHost.update_all(state: "rolled_back")
      get "/agents"
      expect(host_rows.first[3]).to eq("Rolled back")

      RolloutHost.update_all(state: "confirmed")
      get "/hosts/#{canary_host.id}"
      expect(page.at_css("#agent_updates tbody tr").then { words(_1) }).to start_with("0.3.0 Confirmed in 3 minutes.")
      RolloutHost.update_all(offered_at: nil)
      get "/hosts/#{canary_host.id}"
      expect(page.at_css("#agent_updates tbody tr").then { words(_1) }).to start_with("0.3.0 Confirmed.")
    end

    it "shows a pending host's offer time while it is still ahead, and a halted rollout's waiting hosts as not offered" do
      rollout = started
      member = rollout.rollout_hosts.sole
      member.update_columns(offer_at: Time.utc(2030, 1, 1, 9, 5))
      get "/agents"
      expect(host_rows.first[3]).to eq("Offered 0.3.0 from 09:05 UTC")
      Rollouts.halt!(rollout, actor: operator)
      get "/hosts/#{canary_host.id}"
      expect(page.at_css("#agent_updates tbody tr").then { words(_1) }).to start_with("0.2.0 → 0.3.0, not offered Not offered while the rollout is halted.")
    end
  end
end
