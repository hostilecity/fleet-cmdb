require "rails_helper"

# Onboarding approval in the dashboard (P1-D07, DEC-17, FR-S.1, AC-1.8).
RSpec.describe "Onboarding approval", type: :request do
  before do
    host! dashboard_host
    sign_in_operator
  end

  let(:operator) { Operator.find_by!(email: "operator@example.com") }
  let(:started) { start_onboarding(hostname: "vm-08.example.lan", machine_id: "89abcdef0123456789abcdef01234567") }
  let(:request_record) { started.record }
  let(:code) { request_record.user_code }

  def page = Nokogiri::HTML(response.body)

  def facts = page.css("dl.facts dt").to_h { |dt| [ dt.text, dt.next_element.text.squish ] }

  describe "the waiting list and code box" do
    it "lists waiting VMs without their codes, and shows the empty state otherwise" do
      get "/onboard"
      expect(page.at_css("#nothing_waiting").text).to include("No VMs are waiting for approval.")

      request_record
      get "/onboard"
      row = page.at_css("tr#onboarding_request_#{request_record.id}")
      expect(row.css("td").map { |td| td.text.squish }.first(3)).to eq([ "vm-08.example.lan", "Debian GNU/Linux 13 (trixie)", "192.0.2.10" ])
      expect(page.at_css("main").text).not_to include(code) # compared on the review page, next to the reported facts
      expect(row.at_css("a")["href"]).to eq("/onboard/#{code}")
    end

    it "lists the newest request first, also when two arrived at the same time (#69)" do
      older = start_onboarding(client_ip: "192.0.2.11", hostname: "vm-30.example.lan").record
      newer = start_onboarding(client_ip: "192.0.2.12", hostname: "vm-31.example.lan").record
      OnboardingRequest.where(id: [ older.id, newer.id ]).update_all(created_at: Time.current.change(usec: 0))
      get "/onboard"
      expect(page.css("tr[id^=onboarding_request_]").map { |tr| tr["id"] }).to eq([ "onboarding_request_#{newer.id}", "onboarding_request_#{older.id}" ])
    end

    it "finds a waiting request from the code as typed" do
      [ code, code.downcase, code.delete("-"), " #{code.downcase} " ].each do |typed|
        post "/onboard", params: { code: typed }
        expect(response).to redirect_to("/onboard/#{code}")
      end
    end

    it "gives unknown, expired, and decided codes the same answer, in place" do
      answers = []
      other = start_onboarding(client_ip: "192.0.2.11").record
      Onboarding::Reject.call(request: other, operator:)
      [ "BBBB-BBBB", other.user_code ].each do |typed|
        post "/onboard", params: { code: typed }
        expect(response).to have_http_status(:unprocessable_content)
        answers << page.at_css("#code_error").text
      end
      expired = code # started now, typed after it expired
      travel_to(11.minutes.from_now) { post "/onboard", params: { code: expired } }
      answers << page.at_css("#code_error").text
      expect(answers.uniq).to eq([ "No waiting VM has this code. Check the terminal; codes expire after 10 minutes." ])
      expect(page.at_css("#code")["aria-invalid"]).to eq("true")
    end

    it "limits code lookups per operator" do
      ApprovalsController::CODE_LOOKUPS_PER_MINUTE.times { post "/onboard", params: { code: "BBBB-BBBB" } }
      post "/onboard", params: { code: }
      expect(response).to redirect_to("/onboard")
      follow_redirect!
      expect(page.at_css(".flash").text.squish).to eq("Too many codes tried. Wait a minute and try again.")
    end

    it "spends the same budget on direct code URLs that find nothing, but not on a found request's live refreshes (review of #63)" do
      limit = ApprovalsController::CODE_LOOKUPS_PER_MINUTE
      (limit + 5).times { get "/onboard/#{code}" } # an open review page refreshing
      expect(response).to have_http_status(:ok)

      (limit / 2).times { post "/onboard", params: { code: "BBBB-BBBB" } }
      (limit - (limit / 2)).times do
        get "/onboard/CCCC-CCCC"
        expect(response).to have_http_status(:not_found)
      end
      # Spent: a real code no longer resolves either, so guessed URLs cannot tell a hit from a miss.
      [ -> { get "/onboard/#{code}" }, -> { get "/onboard/DDDD-DDDD" }, -> { post "/onboard/#{code}/reject" }, -> { post "/onboard", params: { code: } } ].each do |attempt|
        attempt.call
        expect(response).to redirect_to("/onboard")
      end
      follow_redirect!
      expect(page.at_css(".flash").text.squish).to eq("Too many codes tried. Wait a minute and try again.")
      expect(request_record.reload.state).to eq("open")
    end

    it "finds the matching hosts for the whole list in a fixed number of queries (review of #63)" do
      add_matched_request = lambda do |n|
        machine_id = format("%032x", 0xabc000 + n)
        by_machine, = enrolled_host(name: "Machine #{n}", hostname: "vm-#{70 + n}.example.lan")
        by_machine.agent_credentials.active.sole.update_column(:machine_id, machine_id)
        create(:host, name: "Name #{n}", hostname: "vm-#{20 + n}.example.lan")
        start_onboarding(client_ip: "192.0.2.#{20 + n}", hostname: "vm-#{20 + n}.example.lan", machine_id:).record
      end
      first = add_matched_request.call(1)
      one = count_queries { get "/onboard" }
      others = (2..5).map { |n| add_matched_request.call(n) }
      five = count_queries { get "/onboard" }
      expect(five).to eq(one)
      [ first, *others ].each.with_index(1) do |request, n|
        expect(page.at_css("tr#onboarding_request_#{request.id} .tag").text).to eq("matches Machine #{n}")
      end
    end
  end

  describe "reviewing" do
    it "shows the code and what the VM reported before the host fields, prefilled from the hostname" do
      get "/onboard/#{code}"
      expect(page.at_css("#user_code").text).to eq(code)
      expect(facts).to include("Hostname" => "vm-08.example.lan", "Machine ID" => "89abcdef0123456789abcdef01234567", "Agent" => "0.1.0", "From address" => "192.0.2.10")
      expect(page.at_css("#host_name")["value"]).to eq("vm-08")
      expect(page.at_css("#host_hostname")["value"]).to eq("vm-08.example.lan")
      expect(response.body).to include("No existing host has this machine ID or hostname.")
      expect(page.css("input[name=choice]")).to be_empty
    end

    it "renders reported text escaped" do
      hostile = start_onboarding(client_ip: "192.0.2.11", os: { "id" => "debian", "version_id" => "13", "pretty_name" => HOSTILE }).record
      get "/onboard/#{hostile.user_code}"
      expect(page.css("script:not([type])").map(&:text).grep(/alert/)).to eq([])
      expect(facts["Operating system"]).to start_with(HOSTILE)
    end

    it "offers re-enrollment of a host with the same machine ID, chosen by default" do
      media, = enrolled_host(name: "Media server", hostname: "vm-01.example.lan")
      media.agent_credentials.active.sole.update_column(:machine_id, "89abcdef0123456789abcdef01234567")
      get "/onboard/#{code}"
      expect(page.at_css("#onboard_match strong").text).to eq("This VM has the same machine ID as Media server.")
      expect(page.css("input[name=choice]").map { |i| [ i["value"], i["checked"].present? ] }).to eq([ [ "reenroll-#{media.id}", true ], [ "new", false ] ])
    end

    it "puts a machine-ID match that also has the reported hostname first, as the default" do
      clone, = enrolled_host(name: "Alpha clone", hostname: "vm-50.example.lan")
      same, = enrolled_host(name: "Zulu", hostname: "vm-08.example.lan")
      [ clone, same ].each { |h| h.agent_credentials.active.sole.update_column(:machine_id, "89abcdef0123456789abcdef01234567") }
      get "/onboard/#{code}"
      expect(page.css("input[name=choice]").map { |i| [ i["value"], i["checked"].present? ] })
        .to eq([ [ "reenroll-#{same.id}", true ], [ "reenroll-#{clone.id}", false ], [ "new", false ] ])
    end

    it "defaults to a new host when only the hostname matches, and never offers a retired host" do
      same_name = create(:host, name: "Old build", hostname: "vm-08.example.lan")
      create(:host, :retired, name: "Gone", hostname: "vm-08.example.lan")
      retired_clone, = enrolled_host(name: "Retired clone", hostname: "vm-77.example.lan")
      retired_clone.agent_credentials.active.sole.update_column(:machine_id, "89abcdef0123456789abcdef01234567")
      retired_clone.retire!(actor: Audit::SYSTEM)
      get "/onboard/#{code}"
      expect(page.at_css("#onboard_match strong").text).to eq("This VM has the same hostname as Old build.")
      expect(page.css("input[name=choice]").map { |i| [ i["value"], i["checked"].present? ] }).to eq([ [ "reenroll-#{same_name.id}", false ], [ "new", true ] ])
    end

    it "orders matching hosts with the same name by age, so the default never changes between renders (#69)" do
      twins = Array.new(2) { |i| enrolled_host(name: "Twin", hostname: "vm-6#{i}.example.lan").first }
      twins.each { |h| h.agent_credentials.active.sole.update_column(:machine_id, "89abcdef0123456789abcdef01234567") }
      named = [ create(:host, name: "Same", hostname: "vm-08.example.lan"), create(:host, name: "Same", hostname: "vm-08.example.lan") ]
      get "/onboard/#{code}"
      expect(page.css("input[name=choice]").map { |i| i["value"] }).to eq((twins + named).map { |h| "reenroll-#{h.id}" } + [ "new" ])
    end

    it "matches by hostname alone when the VM could not read its machine ID" do
      blind = start_onboarding(client_ip: "192.0.2.11", hostname: "vm-05.example.lan", machine_id: nil).record
      dns = create(:host, name: "DNS resolver", hostname: "vm-05.example.lan")
      get "/onboard/#{blind.user_code}"
      expect(facts["Machine ID"]).to eq("Not reported")
      expect(page.css("input[name=choice]").map { |i| i["value"] }).to eq([ "reenroll-#{dns.id}", "new" ])
    end

    it "answers 404 for a code no request ever had" do
      get "/onboard/BBBB-BBBB"
      expect(response).to have_http_status(:not_found)
      expect(page.text).to include("There is no request with this code.")
    end
  end

  describe "approving" do
    it "approves as a new host with the entered fields; the installer's collection creates it (AC-1.8)" do
      post "/onboard/#{code}/approve", params: { choice: "new", host: { name: "Build runner 2", hostname: "", tags: "ci, lab", description: "", notes: "Fast disk" } }
      expect(response).to redirect_to("/onboard/#{code}")
      expect(request_record.reload).to have_attributes(state: "approved", decided_by: operator, reenroll: false)
      follow_redirect!
      expect(page.at_css("#onboard_outcome strong").text).to eq("Approved. Waiting for the installer on vm-08.example.lan.")

      result = collect_onboarding(started.device_code)
      expect(result.host).to have_attributes(name: "Build runner 2", hostname: "vm-08.example.lan", tags: %w[ci lab], notes: "Fast disk")
      get "/onboard/#{code}"
      expect(page.at_css("#onboard_outcome strong").text).to eq("Build runner 2 has joined the fleet.")
      expect(page.at_css("#onboard_outcome a")["href"]).to eq("/hosts/#{result.host.id}")
    end

    it "shows field errors in place and leaves the request waiting" do
      post "/onboard/#{code}/approve", params: { choice: "new", host: { name: "Runner", tags: "ci, Build Runner!" } }
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css(".notice.error strong").text).to eq("Not approved yet.")
      expect(page.at_css("#host_tags")["aria-invalid"]).to eq("true")
      expect(page.at_css("#host_tags")["value"]).to eq("ci, build-runner!")
      expect(page.at_css("#user_code").text).to eq(code) # still the review page
      expect(request_record.reload.state).to eq("open")
    end

    it "approves as the re-enrollment of the chosen matching host" do
      media, credential = enrolled_host(name: "Media server", hostname: "vm-08.example.lan")
      post "/onboard/#{code}/approve", params: { choice: "reenroll-#{media.id}", host: { name: "ignored" } }
      expect(request_record.reload).to have_attributes(state: "approved", reenroll: true, host: media)
      result = collect_onboarding(started.device_code)
      expect(result.host).to eq(media)
      expect(media.reload.name).to eq("Media server")
      expect(AgentCredential.authenticate("Bearer #{credential}")).to be_nil
    end

    it "refuses to attach to a host that is not one of the request's matches" do
      unrelated = create(:host, name: "Unrelated", hostname: "vm-99.example.lan")
      post "/onboard/#{code}/approve", params: { choice: "reenroll-#{unrelated.id}" }
      expect(response).to redirect_to("/onboard/#{code}")
      expect(request_record.reload.state).to eq("open")
      expect(unrelated.reload.enrollment_state).to eq("pending")
    end

    it "shows who decided when another operator got there first" do
      second = create(:operator, name: "Second Operator")
      Onboarding::Approve.call(request: request_record, operator: second, attributes: { name: "VM" })
      post "/onboard/#{code}/approve", params: { choice: "new", host: { name: "Mine" } }
      follow_redirect!
      expect(page.at_css("#onboard_outcome strong").text).to match(/\ASecond Operator approved this request .* ago\.\z/)
      expect(request_record.reload.host_attributes["name"]).to eq("VM")
    end

    it "shows an expired request as expired, even if it was approved but not collected" do
      Onboarding::Approve.call(request: request_record, operator:, attributes: { name: "VM" })
      travel_to(11.minutes.from_now) { get "/onboard/#{code}" }
      expect(page.at_css("#onboard_outcome strong").text).to match(/\AThis request expired at .* UTC\. Nothing was created\.\z/)
    end
  end

  describe "a decision that loses a race" do
    it "shows the request's state instead of an error when it stops being decidable mid-request" do
      %w[approve reject].each do |action|
        klass = action == "approve" ? Onboarding::Approve : Onboarding::Reject
        allow(klass).to receive(:call).and_raise(Onboarding::NotDecidable)
        post "/onboard/#{code}/#{action}", params: { choice: "new", host: { name: "VM" } }
        expect(response).to redirect_to("/onboard/#{code}")
      end
    end
  end

  describe "rejecting" do
    it "keeps showing a rejection after the request's TTL, as the installer is still told (review of #63)" do
      second = create(:operator, name: "Second Operator")
      other = start_onboarding(client_ip: "192.0.2.11")
      post "/onboard/#{code}/reject"
      Onboarding::Reject.call(request: other.record, operator: second)
      travel_to(11.minutes.from_now) do
        get "/onboard/#{code}"
        expect(page.at_css("#onboard_outcome strong").text).to eq("Rejected. Nothing was created.")
        get "/onboard/#{other.record.user_code}"
        expect(page.at_css("#onboard_outcome strong").text).to match(/\ASecond Operator rejected this request .* ago\.\z/)
        expect { collect_onboarding(started.device_code) }.to raise_error(AgentApi::OnboardingRejected)
      end
    end

    it "rejects without creating anything" do
      post "/onboard/#{code}/reject"
      expect(response).to redirect_to("/onboard/#{code}")
      follow_redirect!
      expect(page.at_css("#onboard_outcome strong").text).to eq("Rejected. Nothing was created.")
      expect(request_record.reload.state).to eq("rejected")
      expect(Host.count).to eq(0)
    end

    it "uses the same form as approval, so a typed code is never needed twice" do
      get "/onboard/#{code}"
      expect(page.at_css("button[formaction='/onboard/#{code}/reject']")).to be_present
    end
  end

  describe "the fleet page" do
    it "says how many VMs are waiting, linking to the list, only while some are" do
      get "/"
      expect(page.at_css("#awaiting_approval")).to be_nil
      request_record
      start_onboarding(client_ip: "192.0.2.11")
      get "/"
      expect(page.at_css("#awaiting_approval strong").text).to eq("2 VMs are waiting for approval.")
      expect(page.at_css("#awaiting_approval a")["href"]).to eq("/onboard")
    end
  end

  describe "live updates (P1-D05)" do
    include ActiveJob::TestHelper

    it "refreshes open dashboards when a request arrives or is decided" do
      expect { request_record }.to have_enqueued_job(FleetBroadcastJob).with([])
      expect { Onboarding::Reject.call(request: request_record, operator:) }.to have_enqueued_job(FleetBroadcastJob).with([])
      other = start_onboarding(client_ip: "192.0.2.11").record
      expect { Onboarding::Approve.call(request: other, operator:, attributes: { name: "VM" }) }.to have_enqueued_job(FleetBroadcastJob).with([])
    end
  end

  describe "signing in from an approval link" do
    it "returns to the request after sign-in" do
      delete "/sign_out"
      get "/onboard/#{code}"
      expect(response).to redirect_to("/sign_in")
      sign_in_with_google
      expect(response).to redirect_to("/onboard/#{code}")
    end

    it "never returns to another site" do
      delete "/sign_out"
      ApplicationController.new.then do |controller|
        [ "//evil.example.com/x", "https://evil.example.com", "/\\evil.example.com", "/sign_in", "/#{'a' * 600}" ].each do |path|
          expect(controller.send(:safe_return_path?, path)).to be(false), path
        end
        expect(controller.send(:safe_return_path?, "/onboard/#{code}?x=1")).to be(true)
      end
    end
  end

  it "refuses approvals without the CSRF token (FR-S.4)" do
    ActionController::Base.allow_forgery_protection = true
    post "/onboard/#{code}/approve", params: { choice: "new", host: { name: "VM" } }
    expect(request_record.reload.state).to eq("open")
  ensure
    ActionController::Base.allow_forgery_protection = false
  end
end
