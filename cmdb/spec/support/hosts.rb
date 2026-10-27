# Request specs run on the dashboard host by default; specs under spec/requests/api run on the agent host
# (P1-S13). Use host! to override.
module HostHelpers
  def dashboard_host = HostSeparation.dashboard_host

  def agent_host = HostSeparation.agent_host
end

RSpec.configure do |config|
  config.include HostHelpers
  config.define_derived_metadata(file_path: %r{/spec/requests/api/}) { |metadata| metadata[:agent_host] = true }
  config.before(type: :request) { host! dashboard_host }
  config.before(type: :request, agent_host: true) { host! agent_host }
end
