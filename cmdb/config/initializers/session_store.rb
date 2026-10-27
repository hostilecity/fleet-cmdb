# Dashboard session cookie (NFR-1, P1-S01): secure in production, HTTP-only, SameSite=Lax (the OAuth
# callback is a top-level redirect from Google). Idle and absolute timeouts are enforced by
# ApplicationController.
Rails.application.config.session_store :cookie_store,
  key: "_fleet_cmdb_session", secure: Rails.env.production?, httponly: true, same_site: :lax

Rails.application.configure do
  config.x.sessions.idle_timeout = Integer(ENV.fetch("FLEET_SESSION_IDLE_MINUTES", "120")).minutes
  config.x.sessions.absolute_timeout = Integer(ENV.fetch("FLEET_SESSION_ABSOLUTE_HOURS", "12")).hours
end
