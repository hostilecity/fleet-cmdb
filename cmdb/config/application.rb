require_relative "boot"

require "rails"
# Pick the frameworks you want:
require "active_model/railtie"
require "active_job/railtie"
require "active_record/railtie"
# require "active_storage/engine"
require "action_controller/railtie"
# require "action_mailer/railtie"
# require "action_mailbox/engine"
# require "action_text/engine"
require "action_view/railtie"
require "action_cable/engine"
# require "rails/test_unit/railtie"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

module Cmdb
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 8.1

    # Please, add to the `ignore` list any other `lib` subdirectories that do
    # not contain `.rb` files, or that should not be reloaded or eager loaded.
    # Common ones are `templates`, `generators`, or `middleware`, for example.
    config.autoload_lib(ignore: %w[assets ci middleware tasks]) # lib/ci is bin/ci and spec tooling only

    # Configuration for the application, engines, and railties goes here.
    #
    # These settings can be overridden in specific environments using the files
    # in config/environments, which are processed later.
    #
    # config.time_zone = "Central Time (US & Canada)"
    # config.eager_load_paths << Rails.root.join("extras")

    # Don't generate system test files.
    config.generators.system_tests = nil

    # Agent API body limit and no Rails parameter parsing for /api/ (lib/middleware, P1-S06).
    require Rails.root.join("lib/middleware/agent_api_request_guard").to_s
    config.middleware.insert_after ActionDispatch::RequestId, AgentApiRequestGuard

    # Dashboard and agent API on separate hostnames, before anything else sees the request (P1-S13).
    require Rails.root.join("lib/middleware/host_separation").to_s
    config.middleware.insert_before 0, HostSeparation

    # The dashboard and private agent API hostnames (DEC-05). Required in production; development and test
    # set defaults in their environment files.
    config.x.fleet_hosts.dashboard = ENV["FLEET_DASHBOARD_HOST"]&.downcase.presence
    config.x.fleet_hosts.agent = ENV["FLEET_AGENT_HOST"]&.downcase.presence

    # Proxies allowed to set X-Forwarded-Host and X-Forwarded-For (the tunnel connector and the agent TLS
    # proxy), as comma-separated addresses or CIDRs. Unset means only loopback is trusted.
    trusted = ENV.fetch("FLEET_TRUSTED_PROXIES", "").split(",").map(&:strip).reject(&:empty?).map { |cidr| IPAddr.new(cidr) }
    config.x.fleet_hosts.trusted_proxies = [ IPAddr.new("127.0.0.0/8"), IPAddr.new("::1") ] + trusted
    config.action_dispatch.trusted_proxies = config.x.fleet_hosts.trusted_proxies

    # Action Cable is mounted explicitly in config/routes.rb, inside the dashboard host constraint, and its
    # connections are operator-authenticated (ApplicationCable::Connection, P1-D05).
    config.action_cable.mount_path = nil

    # No Turbo Native apps, so no public historical-location routes.
    config.turbo.draw_routes = false
  end
end
