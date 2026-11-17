class ApplicationRecord < ActiveRecord::Base
  primary_abstract_class

  # With a replica configured (REPLICA_DATABASE_URL, #198), the reading role is that replica. Only the pages listed in
  # ReplicaReads switch to it, and only once it has caught up; everything else, every write included, stays on the
  # primary. Without one, nothing changes: there is no reading role.
  connects_to database: { writing: :primary, reading: :replica } if configurations.configs_for(env_name: Rails.env, name: "replica", include_hidden: true)
end
