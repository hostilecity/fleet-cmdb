# Operator sign-in with Google (DEC-06, P1-S01). The request phase is POST-only with Rails CSRF protection
# (omniauth-rails_csrf_protection); OmniAuth validates `state` on the callback.
test_value = ->(name) { "EXAMPLE-#{name}" if Rails.env.test? } # tests never contact Google

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :google_oauth2, ENV.fetch("GOOGLE_CLIENT_ID") { test_value.("client-id") }, ENV.fetch("GOOGLE_CLIENT_SECRET") { test_value.("client-secret") },
           scope: "openid,email,profile", prompt: "select_account", skip_jwt: false
end

OmniAuth.config.allowed_request_methods = [ :post ]
OmniAuth.config.logger = Rails.logger

Rails.application.config.after_initialize do
  # Callbacks always go to the dashboard host over HTTPS in production, whatever the request said.
  OmniAuth.config.full_host = "https://#{Rails.configuration.x.fleet_hosts.dashboard}" if Rails.env.production?

  if Rails.env.production? && !ENV["SECRET_KEY_BASE_DUMMY"] && (ENV["GOOGLE_CLIENT_ID"].blank? || ENV["GOOGLE_CLIENT_SECRET"].blank?)
    raise "Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET for operator sign-in"
  end
end
