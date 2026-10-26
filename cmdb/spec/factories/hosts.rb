FactoryBot.define do
  factory :host do
    sequence(:name) { |n| "VM #{n}" }
    sequence(:hostname) { |n| "vm-#{n}.example.lan" }
    tags { [] }

    # Created hosts get their "host created" audit entry, as Host.register! would write.
    to_create do |host|
      Host.transaction do
        host.save!
        Audit.record(actor: Audit::SYSTEM, action: Audit::Actions::HOST_CREATED, target: host)
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
