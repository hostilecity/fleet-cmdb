# Google sign-in in tests (P1-S01): OmniAuth test mode, so no request leaves the test process.
module OmniAuthHelpers
  def google_auth(email: "operator@example.com", uid: "1000000000001", verified: true, sub: uid, id_info: true, name: "Example Operator")
    claims = { "iss" => "https://accounts.google.com", "aud" => "EXAMPLE-client-id", "sub" => sub, "email" => email, "email_verified" => verified }
    OmniAuth::AuthHash.new(
      provider: "google_oauth2", uid:,
      info: { email:, name: },
      credentials: { token: "ya29.EXAMPLE-access-token", refresh_token: "1//EXAMPLE-refresh-token", expires_at: 1.hour.from_now.to_i },
      extra: id_info ? { id_token: "eyJEXAMPLE.id-token.signature", id_info: claims } : {}
    )
  end

  # Signs in through the real OAuth routes with a mocked Google response.
  def sign_in_with_google(**options)
    OmniAuth.config.mock_auth[:google_oauth2] = google_auth(**options)
    post "/auth/google_oauth2"
    follow_redirect! # to the callback, which OmniAuth answers with the mock
  end

  def allow_operator(email) = OperatorAllowlistEntry.allow!(email, actor: Audit::SYSTEM)
end

RSpec.configure do |config|
  config.include OmniAuthHelpers
  config.before(:suite) { OmniAuth.config.test_mode = true }
  config.after { OmniAuth.config.mock_auth[:google_oauth2] = nil }
end
