# Checks the two public hostnames at boot (DEC-05, P1-S13). They are read from FLEET_DASHBOARD_HOST and
# FLEET_AGENT_HOST in config/application.rb; lib/middleware/host_separation.rb decides what each serves.
Rails.application.config.after_initialize do
  next if ENV["SECRET_KEY_BASE_DUMMY"] # the Docker build precompiles assets without runtime settings

  hosts = Rails.configuration.x.fleet_hosts
  if hosts.dashboard.blank? || hosts.agent.blank?
    raise "Set FLEET_DASHBOARD_HOST and FLEET_AGENT_HOST (the dashboard and private agent API hostnames)"
  end
  raise "FLEET_DASHBOARD_HOST and FLEET_AGENT_HOST must differ" if hosts.dashboard == hosts.agent
end
