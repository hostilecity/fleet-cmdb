require "rails_helper"

# Operator sign-in (P1-S01, FR-S.4, DEC-06, NFR-1)
RSpec.describe "Operator sign-in", type: :request do
  before { allow_operator("operator@example.com") }

  it "signs in an allowlisted, verified Google account and records it" do
    sign_in_with_google
    expect(response).to redirect_to(root_path)
    follow_redirect!
    expect(response.body).to include("Signed in as Example Operator")

    operator = Operator.sole
    expect(operator).to have_attributes(google_uid: "1000000000001", email: "operator@example.com", last_signed_in_at: be_present)
    expect(AuditEntry.where(action: Audit::Actions::OPERATOR_SIGNED_IN).sole).to have_attributes(actor_type: "operator", actor_id: operator.id)
  end

  it "keeps one record per Google account across sign-ins" do
    2.times { sign_in_with_google }
    expect(Operator.count).to eq(1)
  end

  describe "refusals (no record is created)" do
    {
      "an email not on the allowlist" => { email: "stranger@example.com" },
      "an email Google has not verified" => { verified: false },
      "a missing email_verified claim" => { verified: nil },
      "an ID token for another account" => { sub: "2000000000002" },
      "a response without an ID token" => { id_info: false }
    }.each do |label, options|
      it "refuses #{label}" do
        sign_in_with_google(**options)
        expect(response).to redirect_to(sign_in_path)
        expect(flash[:alert]).to eq(SessionsController::REFUSED)
        expect(Operator.count).to eq(0)
        get "/"
        expect(response).to redirect_to(sign_in_path)
      end
    end

    it "matches the allowlist case-insensitively" do
      sign_in_with_google(email: "Operator@Example.COM")
      expect(response).to redirect_to(root_path)
    end

    it "handles a failed Google round trip" do
      OmniAuth.config.mock_auth[:google_oauth2] = :access_denied
      post "/auth/google_oauth2"
      follow_redirect! # callback -> /auth/failure
      follow_redirect! if response.redirect? && response.location.include?("/auth/failure")
      expect(response).to redirect_to(sign_in_path)
      expect(Operator.count).to eq(0)
    end
  end

  describe "the OAuth request phase" do
    it "is POST-only (no sign-in by a plain link or GET)" do
      get "/auth/google_oauth2"
      expect(response).to have_http_status(:not_found)
    end

    it "requires the CSRF token from the sign-in page (omniauth-rails_csrf_protection)" do
      # Test mode skips OmniAuth's request validation, so run the real request phase. It only builds the
      # redirect to Google; nothing leaves the process.
      OmniAuth.config.test_mode = false
      ActionController::Base.allow_forgery_protection = true

      post "/auth/google_oauth2"
      expect(response.location).to start_with("/auth/failure").and include("InvalidAuthenticityToken")

      get "/sign_in"
      token = response.body[/name="authenticity_token" value="([^"]+)"/, 1]
      post "/auth/google_oauth2", params: { authenticity_token: token }
      expect(response.location).to start_with("https://accounts.google.com/o/oauth2/auth")
      expect(Rack::Utils.parse_query(URI(response.location).query)).to include("state" => be_present, "scope" => "openid email profile")
    ensure
      ActionController::Base.allow_forgery_protection = false
      OmniAuth.config.test_mode = true
    end
  end

  describe "sessions" do
    it "lets two allowlisted operators sign in independently" do
      allow_operator("second@example.com")
      first = open_session { |s| s.host! dashboard_host }
      second = open_session { |s| s.host! dashboard_host }
      OmniAuth.config.mock_auth[:google_oauth2] = google_auth
      first.post "/auth/google_oauth2"
      first.follow_redirect!
      OmniAuth.config.mock_auth[:google_oauth2] = google_auth(email: "second@example.com", uid: "1000000000002", name: "Second")
      second.post "/auth/google_oauth2"
      second.follow_redirect!

      first.get "/"
      second.get "/"
      expect(first.response.body).to include("Signed in as Example Operator")
      expect(second.response.body).to include("Signed in as Second")
      expect(Operator.pluck(:email)).to contain_exactly("operator@example.com", "second@example.com")
    end

    it "signs out" do
      sign_in_with_google
      delete "/sign_out"
      expect(response).to redirect_to(sign_in_path)
      get "/"
      expect(response).to redirect_to(sign_in_path)
    end

    it "ends after the idle timeout" do
      sign_in_with_google
      travel(Rails.configuration.x.sessions.idle_timeout - 1.minute) { get "/" }
      expect(response).to have_http_status(:ok)
      travel(2 * Rails.configuration.x.sessions.idle_timeout) { get "/" }
      expect(response).to redirect_to(sign_in_path)
    end

    it "ends after the absolute timeout even when active" do
      sign_in_with_google
      step = Rails.configuration.x.sessions.idle_timeout - 1.minute
      elapsed = 0.seconds
      while elapsed < Rails.configuration.x.sessions.absolute_timeout - step
        elapsed += step
        travel_to(elapsed.from_now) { get "/" }
        expect(response).to have_http_status(:ok)
        travel_back
      end
      travel_to((Rails.configuration.x.sessions.absolute_timeout + 1.minute).from_now) { get "/" }
      expect(response).to redirect_to(sign_in_path)
    end

    it "signs an operator out on the next request once they leave the allowlist" do
      sign_in_with_google
      get "/"
      expect(response).to have_http_status(:ok)
      OperatorAllowlistEntry.disallow!("operator@example.com", actor: Audit::SYSTEM)
      get "/"
      expect(response).to redirect_to(sign_in_path)
    end

    it "issues a new session id at sign-in" do
      get "/sign_in"
      before = cookies["_fleet_cmdb_session"]
      sign_in_with_google
      expect(cookies["_fleet_cmdb_session"]).to be_present
      expect(cookies["_fleet_cmdb_session"]).not_to eq(before)
    end
  end

  it "never logs OAuth tokens, the authorization code, state, or the session cookie (NFR-1)" do
    log = captured_log do
      OmniAuth.config.mock_auth[:google_oauth2] = google_auth
      post "/auth/google_oauth2"
      get response.location, params: { code: "EXAMPLE-oauth-code-4/0Ab", state: "EXAMPLE-oauth-state-123" }
      follow_redirect!
    end
    expect(log).to include("SessionsController#create")
    [ "ya29.EXAMPLE-access-token", "1//EXAMPLE-refresh-token", "eyJEXAMPLE.id-token.signature",
      "EXAMPLE-oauth-code-4/0Ab", "EXAMPLE-oauth-state-123", cookies["_fleet_cmdb_session"] ].each do |secret|
      expect(log).not_to include(secret)
    end
  end
end
