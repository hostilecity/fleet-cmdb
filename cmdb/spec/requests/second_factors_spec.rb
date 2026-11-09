require "rails_helper"

# Your second factor under Settings (P3-S09, mockups second-factor.html, totp-enrol.html, totp-recovery-codes.html):
# setting up after a fresh Google sign-in, the key and recovery codes shown once, moving to a new phone, and new
# recovery codes.
RSpec.describe "Your second factor", :signed_in, type: :request do
  def shown_key = page.at_css("#totp_key").text.delete(" ")

  def shown_codes = page.css("#recovery_codes li").map(&:text)

  def fresh_google_sign_in(**options)
    OmniAuth.config.mock_auth[:google_oauth2] = google_auth(**options)
    post "/auth/google_oauth2", params: { intent: "second_factor" }
    follow_redirect!
  end

  it "says there is none yet, how to set one up, and how a lost authenticator is reset" do
    get second_factor_path
    expect(response).to have_http_status(:ok)
    expect(response.headers["Cache-Control"]).to eq("no-store")
    expect(page.at_css("nav.tabs a[aria-current=page]").text).to eq("Your second factor")
    expect(page.text).to include("You have no second factor", "bin/rails second_factor:reset EMAIL=operator@example.com")
    expect(page.at_css("a.btn[href='#{setup_second_factor_path}']").text).to eq("Set up an authenticator app")
  end

  it "sets up: the key once as a server-drawn QR code and text, then 10 recovery codes once, with the factor already on" do
    get setup_second_factor_path # just signed in, so the Google sign-in is fresh
    expect(response).to have_http_status(:ok)
    expect(response.headers["Cache-Control"]).to eq("no-store")
    expect(page.at_css('meta[name="turbo-cache-control"]')["content"]).to eq("no-cache")
    expect(page.at_css("ol.flow")["aria-label"]).to eq("Set up: step 2 of 3")
    key = shown_key
    expect(key).to match(/\A[A-Z2-7]{32}\z/)
    expect(page.at_css("svg.qr path")["d"]).to start_with("M4 4h7v1h-7z") # the finder pattern's top edge, drawn here
    expect(page.css("[style], img[src^=http], script[src^=http]")).to be_empty

    post setup_second_factor_path, params: { second_factor_code: "000000" }
    expect(response).to have_http_status(:unprocessable_content)
    expect(page.at_css("#enrol_error").text).to include("That code does not match")
    expect(shown_key).to eq(key) # the same key, so the phone that scanned it still works
    expect(operator.reload.second_factor).to be_nil

    post setup_second_factor_path, params: { second_factor_code: totp_code(key) }
    expect(response).to have_http_status(:ok)
    expect(response.headers["Cache-Control"]).to eq("no-store")
    expect(page.at_css("ol.flow")["aria-label"]).to eq("Set up: step 3 of 3")
    codes = shown_codes
    expect(codes.size).to eq(10)
    expect(codes).to all(match(/\A[2-9A-HJKMNP-TV-Z]{5}-[2-9A-HJKMNP-TV-Z]{5}\z/))
    download = page.at_css("a[download]")
    expect(download["download"]).to eq("fleet-cmdb-recovery-codes.txt")
    expect(CGI.unescape(download["href"].delete_prefix("data:text/plain;charset=utf-8,"))).to include(*codes)
    expect(page.at_css("input[type=checkbox][required]")).to be_present
    expect(operator.reload.second_factor.secret).to eq(key)
    expect(second_factor_audits.sole).to have_attributes(action: "second_factor.enrolled", actor_id: operator.id)
    expect(response.body).not_to include(key) # nor anywhere later

    get second_factor_path
    expect(page.text).to include("Authenticator app set up", "10 of 10 unused")
    expect(page.text).not_to include(*codes)
  end

  it "shows a new key each time the page is shown, so a key is shown only once" do
    get setup_second_factor_path
    first = shown_key
    get setup_second_factor_path
    expect(shown_key).not_to eq(first)
    post setup_second_factor_path, params: { second_factor_code: totp_code(first) }
    expect(response).to have_http_status(:unprocessable_content)
  end

  describe "the fresh Google sign-in" do
    before { travel 11.minutes }

    it "asks for one when the session's sign-in is older than 10 minutes, then shows the key" do
      get setup_second_factor_path
      expect(page.at_css("ol.flow")["aria-label"]).to eq("Set up: step 1 of 3")
      button = page.at_css("form[action='/auth/google_oauth2']")
      expect(button.at_css("input[name=intent]")["value"]).to eq("second_factor")
      expect(button.at_css("input[name=login_hint]")["value"]).to eq("operator@example.com")
      expect(page.at_css("#totp_key")).to be_nil

      session_id = OperatorSession.sole.id
      fresh_google_sign_in
      expect(response).to redirect_to(setup_second_factor_path)
      expect(OperatorSession.sole).to have_attributes(id: session_id, google_authenticated_at: be_within(1.second).of(Time.current)) # the same session
      follow_redirect!
      expect(shown_key).to be_present
    end

    it "does not count a sign-in for another account, an ID token that is not fresh, or a refused sign-in" do
      allow_operator("other.person@example.com")
      fresh_google_sign_in(email: "other.person@example.com", uid: "1000000000077")
      expect(response).to redirect_to(setup_second_factor_path)
      expect(flash[:alert]).to eq("That was a different Google account (other.person@example.com). Sign in again as operator@example.com.")

      OmniAuth.config.mock_auth[:google_oauth2] = google_auth.tap { |auth| auth.extra.id_info["iat"] = 11.minutes.ago.to_i }
      post "/auth/google_oauth2", params: { intent: "second_factor" }
      follow_redirect!
      expect(flash[:alert]).to eq("The Google sign-in did not count. Sign in again as operator@example.com.")

      fresh_google_sign_in(verified: false)
      expect(flash[:alert]).to eq("The Google sign-in did not count. Sign in again as operator@example.com.")

      get setup_second_factor_path
      expect(page.at_css("#totp_key")).to be_nil
      expect(Operator.pluck(:email)).to eq([ "operator@example.com" ]) # the other account was never signed in
    end

    it "runs out 10 minutes after the sign-in, even with the page open" do
      fresh_google_sign_in
      get setup_second_factor_path
      key = shown_key
      travel 10.minutes
      post setup_second_factor_path, params: { second_factor_code: totp_code(key) }
      expect(response).to redirect_to(setup_second_factor_path)
      expect(flash[:alert]).to include("ran out")
      expect(operator.reload.second_factor).to be_nil
    end
  end

  it "is an ordinary sign-in when the round trip has no live session" do
    delete sign_out_path
    fresh_google_sign_in
    expect(response).to redirect_to(root_path)
  end

  describe "with a second factor" do
    let!(:enrolment) { enrol_second_factor(operator) }
    let(:secret) { enrolment.first }
    let(:recovery_codes) { enrolment.last }

    it "moves to a new phone: a current code, the fresh sign-in, the new key, and new recovery codes" do
      get setup_second_factor_path
      expect(page.at_css("label[for=second_factor_code]").text).to eq("Code from your current app, or a recovery code")
      expect(page.at_css("#totp_key")).to be_nil

      post verify_second_factor_path, params: { second_factor_code: "000000" }
      expect(response).to have_http_status(:unprocessable_content)
      expect(page.at_css("#second_factor_error").text).to include("4 attempts left")

      post verify_second_factor_path, params: { second_factor_code: recovery_codes.first }
      expect(response).to redirect_to(setup_second_factor_path)
      follow_redirect!
      expect(page.text).to include("Recovery code used. You have 9 left.")
      key = shown_key # signed in moments ago, so the sign-in is fresh

      post setup_second_factor_path, params: { second_factor_code: totp_code(key) }
      expect(page.text).to include("Your new phone is set up and the old one no longer works.")
      expect(shown_codes.size).to eq(10)
      expect(operator.reload.second_factor.secret).to eq(key)
      expect(second_factor_audits.pluck(:action)).to eq(%w[second_factor.step_up_failed second_factor.step_up_passed second_factor.recovery_code_used second_factor.replaced])
      expect(second_factor_audits.second.changeset["purpose"]).to eq("replace_second_factor")
    end

    it "asks for its own code to move to a new phone, even inside an ordinary window (review of #165)" do
      SecondFactors.step_up(operator_session: OperatorSession.sole, code: totp_code(secret), purpose: "create_task")
      get setup_second_factor_path
      expect(page.at_css("#totp_key")).to be_nil
      expect(page.at_css("label[for=second_factor_code]").text).to eq("Code from your current app, or a recovery code")
    end

    it "refuses to finish moving to a new phone if the step-up locked after the key was shown" do
      post verify_second_factor_path, params: { second_factor_code: totp_code(secret) }
      get setup_second_factor_path
      key = shown_key
      operator.second_factor.update!(locked_until: 15.minutes.from_now)
      post setup_second_factor_path, params: { second_factor_code: totp_code(key) }
      expect(response).to have_http_status(:too_many_requests)
      expect(page.text).to include("Second factor locked until")
      expect(operator.second_factor.reload.secret).to eq(secret)
    end

    it "asks for a code to move to a new phone even inside the window, and refuses while locked" do
      5.times { |i| post verify_second_factor_path, params: { second_factor_code: "00000#{i}" } }
      expect(response).to have_http_status(:too_many_requests)
      expect(page.text).to include("Second factor locked until")
      get setup_second_factor_path
      expect(page.text).to include("Second factor locked until")
      expect(page.at_css("#totp_key")).to be_nil
    end

    it "makes new recovery codes after a code, and shows them once" do
      get new_recovery_codes_path
      expect(page.text).to include("Make 10 new recovery codes?", "Your 10 unused codes stop working now.")
      post recovery_codes_path, params: { second_factor_code: "" }
      expect(response).to have_http_status(:unprocessable_content)
      expect(SecondFactorRecoveryCode.pluck(:code_digest)).to match_array(recovery_codes.map { |code| SecondFactors::RecoveryCodes.digest(code) })

      post recovery_codes_path, params: { second_factor_code: totp_code(secret) }
      expect(response).to have_http_status(:ok)
      expect(page.text).to include("Your old recovery codes no longer work.")
      expect(page.at_css("ol.flow")).to be_nil
      expect(shown_codes.size).to eq(10)
      expect(shown_codes.map { |code| code.delete("-") } & recovery_codes).to be_empty
      expect(second_factor_audits.last).to have_attributes(action: "second_factor.recovery_codes_replaced")

      get second_factor_path
      expect(page.text).to include("10 of 10 unused")
    end

    it "shows when recovery codes were used and when the factor is locked" do
      SecondFactorRecoveryCode.first.update!(used_at: Time.zone.parse("2026-11-08 12:40 UTC"))
      operator.second_factor.update!(locked_until: 10.minutes.from_now)
      get second_factor_path
      expect(page.text).to include("9 of 10 unused. Last one used 2026-11-08 12:40 UTC.", "Locked until")
    end
  end

  it "has nothing to replace without a second factor" do
    post verify_second_factor_path, params: { second_factor_code: "123456" }
    expect(response).to redirect_to(setup_second_factor_path)
    get new_recovery_codes_path
    expect(response).to redirect_to(second_factor_path)
    post recovery_codes_path, params: { second_factor_code: "123456" }
    expect(response).to redirect_to(second_factor_path)
    expect(second_factor_audits).to be_empty
  end

  it "shows only your own second factor; there is no page for another operator's" do
    other = create(:operator)
    enrol_second_factor(other)
    get second_factor_path
    expect(page.text).to include("You have no second factor")
    expect(Rails.application.routes.routes.map { |route| route.path.spec.to_s.delete_suffix("(.:format)") }.grep(/second-factor/)).to all(satisfy { |path| !path.include?(":") })
  end
end
