require "rails_helper"

# The reusable step-up check (P3-S09): the create, cancel, and allowlist endpoints of #31, #32, and #33 call
# require_second_factor. Tested through a controller that exists only in this spec, with the routes appended for it.
class StepUpProbeController < ApplicationController
  require_second_factor "create_task", only: :create
  require_second_factor "change_task_settings", fresh: true, only: :widen

  def form
    render inline: <<~ERB, layout: "application"
      <%= form_with url: "/step-up-probe", method: :post do %><%= render "second_factors/prompt", result: second_factor_result %><% end %>
    ERB
  end

  def create = render(plain: "created")

  def widen = render(plain: "widened")
end

RSpec.describe "The step-up check (require_second_factor)", type: :request do
  before(:all) do
    Rails.application.reload_routes_unless_loaded # routes load lazily; append to them, not before them
    routes = Rails.application.routes
    routes.disable_clear_and_finalize = true
    routes.draw do
      get "step-up-probe", to: "step_up_probe#form"
      post "step-up-probe", to: "step_up_probe#create"
      post "step-up-probe/widen", to: "step_up_probe#widen"
    end
  ensure
    routes.disable_clear_and_finalize = false
  end

  after(:all) { Rails.application.reload_routes! }

  let(:operator) { Operator.find_by!(email: "operator@example.com") }
  let(:secret) { @secret }

  before do
    sign_in_operator
    @secret = enrol_second_factor(operator).first
  end

  it "refuses a forged POST with no code: nothing is done, 403, and the page says why" do
    post "/step-up-probe"
    expect(response).to have_http_status(:forbidden)
    expect(response.body).not_to include("created")
    expect(page.at_css("h1").text).to eq("Nothing was done")
    expect(page.text).to include("type a code from your authenticator app")
    expect(response.headers["Cache-Control"]).to eq("no-store")
  end

  it "does the action with a right code, then for 5 minutes without one, in this session only" do
    post "/step-up-probe", params: { second_factor_code: totp_code(secret) }
    expect(response.body).to eq("created")

    travel 4.minutes
    post "/step-up-probe"
    expect(response.body).to eq("created")

    other = open_session
    other.host! dashboard_host
    OmniAuth.config.mock_auth[:google_oauth2] = google_auth
    other.post "/auth/google_oauth2"
    other.follow_redirect!
    other.post "/step-up-probe"
    expect(other.response).to have_http_status(:forbidden) # a window on session A does not authorise session B

    travel 61.seconds # travel drops sub-seconds, so a second more than the window
    post "/step-up-probe"
    expect(response).to have_http_status(:forbidden)
    expect(page.text).to include("type a code")
  end

  it "puts every attempt in the audit log, in words" do
    post "/step-up-probe", params: { second_factor_code: "000000" }
    post "/step-up-probe", params: { second_factor_code: totp_code(secret) }
    get "/audit"
    rows = page.css("table tbody tr").map { |row| row.text.squish }.first(2)
    expect(rows.first).to include("operator@example.com", "Code accepted", "Second factor", "For creating a task", "Method authenticator app", "Valid until")
    expect(rows.second).to include("Code refused", "For creating a task", "Reason wrong", "Attempts left 4")
    expect(response.body).not_to include(secret)
  end

  it "ends the window at sign-out" do
    post "/step-up-probe", params: { second_factor_code: totp_code(secret) }
    delete sign_out_path
    sign_in_operator
    post "/step-up-probe"
    expect(response).to have_http_status(:forbidden)
  end

  it "says how many attempts are left after a wrong code, and 429 once locked" do
    post "/step-up-probe", params: { second_factor_code: "000000" }
    expect(response).to have_http_status(:forbidden)
    expect(page.text).to include("4 attempts left")
    4.times { post "/step-up-probe", params: { second_factor_code: "000000" } }
    expect(response).to have_http_status(:too_many_requests)
    expect(page.text).to include("locked until")
    post "/step-up-probe", params: { second_factor_code: totp_code(secret) }
    expect(response).to have_http_status(:too_many_requests)
  end

  it "asks for a fresh code for an action declared fresh: true, even inside the window" do
    post "/step-up-probe", params: { second_factor_code: totp_code(secret) }
    post "/step-up-probe/widen"
    expect(response).to have_http_status(:forbidden)
    travel 30.seconds
    post "/step-up-probe/widen", params: { second_factor_code: totp_code(secret) }
    expect(response.body).to eq("widened")
  end

  it "refuses an operator with no second factor and links to setting one up" do
    SecondFactors.reset!(operator.email)
    post "/step-up-probe", params: { second_factor_code: "123456" }
    expect(response).to have_http_status(:forbidden)
    expect(page.at_css("main a[href='#{second_factor_path}']").text).to eq("Set up an authenticator app")
  end

  it "rejects an unknown purpose when the controller is defined" do
    expect { Class.new(ApplicationController) { require_second_factor "anything" } }.to raise_error(ArgumentError)
  end

  describe "the code box (second_factors/prompt)" do
    it "asks, then shows the window, then the lock, and the missing factor" do
      get "/step-up-probe"
      box = page.at_css("form .stepup")
      expect(box.at_css("input[name=second_factor_code][autocomplete=one-time-code][required]")).to be_present
      expect(box.text).to include("You will not be asked again for 5 minutes.")

      post "/step-up-probe", params: { second_factor_code: totp_code(secret) }
      get "/step-up-probe"
      expect(page.at_css(".stepup.passed").text).to include("Not asked again until #{5.minutes.from_now.utc.strftime('%Y-%m-%d %H:%M')} UTC")

      operator.second_factor.update!(locked_until: 15.minutes.from_now)
      get "/step-up-probe"
      expect(page.at_css(".stepup.locked").text).to include("Second factor locked until")

      SecondFactors.reset!(operator.email)
      get "/step-up-probe"
      expect(page.at_css(".stepup.locked").text).to include("You have no second factor")
    end

    it "marks a reused code and a run-out window in place" do
      allow_any_instance_of(StepUpProbeController).to receive(:second_factor_refused) do |controller, _result|
        controller.render inline: '<%= render "second_factors/prompt", result: second_factor_result %>', status: :forbidden
      end
      code = totp_code(secret)
      post "/step-up-probe", params: { second_factor_code: code }
      post "/step-up-probe/widen", params: { second_factor_code: code }
      expect(page.at_css("#second_factor_error").text).to include("That code was already used", "4 attempts left")
      expect(page.at_css("input#second_factor_code")["aria-invalid"]).to eq("true")

      travel 5.minutes + 1.second
      get "/step-up-probe"
      expect(page.text).not_to include("ran out") # only after a submit
      post "/step-up-probe"
      expect(page.text).to include("Nothing was done: your second factor check ran out.")
    end
  end
end
