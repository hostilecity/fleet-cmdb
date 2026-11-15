# A host's heartbeat state written directly (host_liveness, #192), as specs once wrote it with update_columns on hosts.
module LivenessHelpers
  # Creates or changes the host's host_liveness row: unset attributes keep their value, or default to online now.
  # Returns the host, with its liveness reloaded.
  def set_liveness(host, **attributes)
    current = HostLiveness.find_by(host_id: host.id)&.attributes&.symbolize_keys || { liveness_status: "online", last_seen_at: Time.current, agent_reported_at: nil }
    HostLiveness.upsert(current.merge(attributes, host_id: host.id), unique_by: :host_id)
    host.reload_liveness
    host
  end
end

RSpec.configure do |config|
  config.include LivenessHelpers

  # Specs outside the test transaction delete their hosts with triggers off (hosts cannot be deleted), which skips the
  # foreign key and leaves their host_liveness rows behind; later specs and evaluation runs would find them.
  config.after do |example|
    next if example.example_group.use_transactional_tests

    HostLiveness.where.not(host_id: Host.select(:id)).delete_all
  end
end
