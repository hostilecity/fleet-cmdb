FactoryBot.define do
  factory :host do
    sequence(:name) { |n| "VM #{n}" }
    sequence(:hostname) { |n| "vm-#{n}.example.lan" }
    tags { [] }

    # The heartbeat state (host_liveness, #192): given either, the host gets a row, online now by default.
    transient do
      liveness_status { nil }
      last_seen_at { nil }
      agent_reported_at { nil }
    end

    # Created hosts get their "host created" audit entry, as Host.register! would write.
    to_create do |host|
      Host.transaction do
        host.save!
        Audit.record(actor: Audit::SYSTEM, action: Audit::Actions::HOST_CREATED, target: host)
      end
    end

    after(:create) do |host, context|
      if context.liveness_status || context.last_seen_at
        HostLiveness.upsert({ host_id: host.id, liveness_status: context.liveness_status || "online", last_seen_at: context.last_seen_at || Time.current,
                              agent_reported_at: context.agent_reported_at }, unique_by: :host_id)
      end
    end

    # Hosts in other states, reached through the real transitions so the audit trail is realistic.
    %w[active revoked retired].each do |state|
      trait state.to_sym do
        after(:create) do |host|
          host.activate!(actor: Audit::SYSTEM) unless state == "retired"
          host.revoke!(actor: Audit::SYSTEM) if state == "revoked"
          host.retire!(actor: Audit::SYSTEM) if state == "retired"
        end
      end
    end
  end
end
